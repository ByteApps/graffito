//! Boot sequence: data dir, config/migration load, contacts load/merge,
//! and `State` construction — everything `run()` used to do before
//! constructing the window. Moved verbatim from `run()` (U4,
//! PLAN-graffito-app-arch.md); the only new code is the trailing `st`
//! return.

use crate::*;

pub(crate) fn boot() -> Rc<RefCell<State>> {
    let data_dir = std::env::var("APP_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("Library/Application Support/Graffito")
    });
    let _ = std::fs::create_dir_all(&data_dir);
    // Data-at-rest (audit M1). Directory first: every file created inside
    // inherits the protection class, so this one call covers all the
    // temp-then-rename churn that follows. Then re-assert backup exclusion on
    // the store files — the flag dies with the inode each save replaces, and
    // a build that predates `save_store_file` left them all enrolled.
    platform::protect_data_dir(&data_dir);
    if let Ok(entries) = std::fs::read_dir(&data_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("store-") && name.ends_with(".json") {
                platform::exclude_from_backup(&e.path());
            }
        }
    }
    let config: serde_json::Value = std::fs::read_to_string(data_dir.join("config.json"))
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(serde_json::Value::Null);
    let network = std::env::var("APP_NETWORK")
        .ok()
        .or_else(|| config.get("network").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| Network::from_str_opt(&s))
        // First-run default only (APP_NETWORK env + a saved config.json network
        // both win above): release builds — the ones shipped to iOS / Mac /
        // Android — start a fresh install on MAINNET; dev/debug builds start on
        // testnet4 for safe testing.
        .unwrap_or(if cfg!(debug_assertions) {
            Network::Testnet4
        } else {
            Network::Mainnet
        });
    let account: u32 = std::env::var("APP_ACCOUNT")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("account").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);
    let nb_index: u32 = std::env::var("APP_INDEX")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("index").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);
    let chunk: Option<usize> =
        config.get("chunk").and_then(|v| v.as_u64()).map(|v| v as usize);
    let terms_accepted = config
        .get("terms_accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let auto_unlock = config.get("auto_unlock").and_then(|v| v.as_bool()).unwrap_or(false);
    // Absent (every pre-2026-07-27 config) => Tip: existing installs adopt
    // anti-fee-sniping on upgrade rather than silently keeping locktime 0.
    let lock_time_policy: app_core::notes_core::tx::LockTimePolicy = config
        .get("locktime")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    // Quantum keys (screen 29) level picker — absent config key (every
    // pre-C2 config) => the same DEFAULT (768) the picker pre-selects.
    let pq_level: app_core::passphrase::MlKemLevel = config
        .get("pq_level")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(app_core::passphrase::MlKemLevel::DEFAULT);
    // Compose "Unlock cost" preset for the passphrase layer — persisted like
    // the ML-KEM level; absent (every earlier config) => PwCost::DEFAULT.
    let pq_pw_cost = config
        .get("pq_pw_cost")
        .and_then(|v| v.as_str())
        .and_then(app_core::notes_core::pq::PwCost::parse)
        .unwrap_or(app_core::notes_core::pq::PwCost::DEFAULT);
    // The user switched the ML-KEM hybrid off by hand (persisted, Sal
    // 2026-09-05); absent => false, i.e. hybrid ON whenever a key exists.
    let pq_mlkem_user_off = config.get("pq_mlkem_off").and_then(|v| v.as_bool()).unwrap_or(false);
    // Device-level per-network Settings (Bitcoin node / block explorer URLs).
    let str_map = |key: &str| -> HashMap<String, String> {
        config
            .get(key)
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut node_urls = str_map("nodes");
    let explorers = str_map("explorers");
    // "Save credentials" switch per network (plan §2.4 / U10) — a preference,
    // not a secret, so it lives in config.json exactly like `nodes`/
    // `explorers` above. Absent key (every pre-U10 config) => true per
    // network via `core_rpc_should_persist`'s default, so this map can stay
    // empty rather than needing every known network pre-filled.
    let core_rpc_save_creds = parse_core_rpc_save_creds(&config);
    // U11 defense-in-depth: a `config.json` written by an older build (or
    // hand-edited/migrated) can still carry `bitcoind+http://user:pass@
    // host:port` verbatim — `on_set_node_custom`'s stripping only ever ran
    // on a URL typed/pasted THIS session. Clean every loaded entry now; the
    // extracted creds go straight into the in-memory session slot (safe,
    // zero Keychain calls) and their network into
    // `core_rpc_migrate_pending` for `flush_core_rpc_migration` to route to
    // the Keychain LATER, from `refresh_node_health` — never here, or the
    // boot/launch path would make a Keychain call (the exact mistake that
    // crashed builds 42/44).
    let migrated_core_rpc_creds = migrate_inline_node_creds(&mut node_urls);
    let mut core_rpc_session_creds: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    let mut core_rpc_migrate_pending: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (net, user, pass) in migrated_core_rpc_creds {
        core_rpc_migrate_pending.insert(net.clone());
        core_rpc_session_creds.insert(net, (user, Zeroizing::new(pass)));
    }
    let core_rpc_migrated = !core_rpc_migrate_pending.is_empty();
    let funding_wallets = load_funding_wallets(&data_dir);
    // Device-level contacts (iCloud-contacts feature): load or, on an
    // existing install's first boot under this scheme, migrate from every
    // per-notebook store — see `load_or_migrate_contacts`. Tombstone-aware
    // (contacts-tombstones feature) since that function's tolerant parse
    // handles both v1 (bare array, every existing install today) and v2.
    let contacts_json_existed = data_dir.join("contacts.json").exists();
    let initial_state = load_or_migrate_contacts(&data_dir);

    let st = Rc::new(RefCell::new(State {
        data_dir,
        network,
        account,
        nb_index,
        lock_time_policy,
        tx_lock_time_override: None,
        node_urls,
        explorers,
        core_rpc_save_creds,
        core_rpc_session_creds,
        core_rpc_migrate_pending,
        ident: None,
        store: None,
        fees: None,
        usd: None,
        fees_fetched_at: None,
        to_address: None,
        to_addresses_extra: Vec::new(),
        picking_extra: false,
        pq_passphrase_verified: false,
        pq_pw_cost,
        pq_mlkem_user_off,
        pq_passphrase_generated: None,
        pq_recipient_cache: None,
        pq_level,
        pq_imported: None,
        pq_pending_replace: None,
        selected_coins: Vec::new(),
        coins_overridden: false,
        consolidate_coins: false,
        material: None,
        core_rpc_watch: Vec::new(),
        icloud_backup: false,
        terms_accepted,
        auto_unlock,
        saved_key_present: false,
        pending_import: None,
        pending_mnemonic: None,
        dice_rolls: Zeroizing::new(String::new()),
        new_word_count: 12,
        quiz_indices: Vec::new(),
        compose_oversize: false,
        compose_fold_shown: 0,
        mixed_est_shown: None,
        funding: None,
        funding_coins: Vec::new(),
        funding_change_index: 0,
        built_psbt: None,
        ur_frames: Vec::new(),
        signed_psbt: None,
        funding_wallets,
        active_funding_id: None,
        watch_spend: None,
        watch_bump: None,
        watch_note: None,
        chunk,
        notebooks: None,
        notebooks_fp8: None,
        nb_addrs: Vec::new(),
        xacct_addrs: Vec::new(),
        discovery_pending: false,
        wconsol: None,
        reveal_formats: None,
        spending_capable: false,
        spending_source: None,
        spending_coins: Vec::new(),
        spending_scanned: false,
        change_coins: Vec::new(),
        change_coins_ctx: None,
        pending_spending_sweep_index: None,
        mixed_selected: Vec::new(),
        payfrom_expanded_source: String::new(),
        nb_expanded: false,
        sp_expanded: false,
        payfrom_active_source: String::new(),
        payfrom_wallet_coins: std::collections::HashMap::new(),
        payfrom_aligning: false,
        change_choice: String::new(),
        compose_busy: false,
        act_pending_ref: None,
        payfrom_manual: false,
        wallet_tx_busy: false,
        scan_gate: app_core::scan_gate::ScanGate::new(),
        pending_broadcast: None,
        contacts: initial_state.contacts,
        tombstones: initial_state.tombstones,
        // Real value stamped right below, before the window is shown —
        // see the sync-status init just after this block.
        last_sync: std::cell::Cell::new(SyncStatus::Unknown),
    }));
    // U11 defense-in-depth, continued: `node_urls` above was already
    // cleaned of inline creds before `State` was built, but the ON-DISK
    // config.json still has the old (credential-carrying) text until it's
    // rewritten — do that now. A plain file write, not a Keychain/network
    // call, so it's safe on the launch path; the Keychain side
    // (`flush_core_rpc_migration`) is deliberately NOT called here.
    if core_rpc_migrated {
        st.borrow().save_config();
        println!("cb: core-rpc-migrate config-resaved");
    }
    // Contacts boot sequence (iCloud-contacts feature): persist a fresh
    // migration (so `contacts.json` exists from here on and the union is
    // never redone), then merge in whatever the OTHER device last synced to
    // iCloud — sync-on-boot, independent of the live observer below (which
    // covers a change that arrives WHILE this device is already running).
    // Tombstone-aware (contacts-tombstones feature): a deletion synced from
    // the other device while this one was closed is applied right here.
    {
        let mut s = st.borrow_mut();
        // Read the OTHER device's blob and merge BEFORE any save, so a fresh
        // migration's (all-unsynced) synced_only push can never clobber an
        // existing cloud blob before we've merged it in. Every incoming
        // contact is synced by definition (opt-in-sync): mark it so it stays
        // flagged synced locally after the merge.
        let local = s.contact_state();
        let mut incoming = app_core::contacts::parse_contacts_blob(
            icloud::load_blob().as_deref().unwrap_or(""),
        );
        mark_incoming_synced(&mut incoming);
        let merged = app_core::contacts::merge_state(&local, &incoming, now_ms());
        let changed = merged.contacts != s.contacts || merged.tombstones != s.tombstones;
        if changed {
            s.contacts = merged.contacts;
            s.tombstones = merged.tombstones;
            println!(
                "cb: icloud-contacts merged n={} tombstones={}",
                s.contacts.len(),
                s.tombstones.len()
            );
        }
        // Persist if we changed anything OR this is the first boot on the
        // global-contacts scheme (so contacts.json exists from here on and the
        // one-time store migration is never redone). save_contacts pushes the
        // synced-only subset — after the merge above, an existing cloud blob is
        // already reflected locally, so this push is safe.
        if changed || !contacts_json_existed {
            s.save_contacts();
        }
        // Sync-status UI (2026-07-20): stamp a real status from
        // `icloud::available()` before the window ever shows, so a synced
        // contact's row always has a status icon at first paint — not just
        // the `Unknown` `Cell` default. `save_contacts` above already set a
        // (numerically identical) value when it ran, but this covers the
        // "nothing changed, no write happened" boot path too.
        s.last_sync.set(if icloud::available() { SyncStatus::Ok } else { SyncStatus::Failed });
    }
    st
}
