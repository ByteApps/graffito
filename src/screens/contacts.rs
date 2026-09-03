//! Screen.contacts — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// Every contact in the iCloud KV blob is there BECAUSE it's synced —
/// stamp `synced = true` on each incoming contact before merging, so a
/// contact that lives in the cloud stays flagged synced locally (and
/// `merge_state` carries that flag through when incoming wins). See the
/// opt-in-sync rule in `app_core::contacts`.
pub(crate) fn mark_incoming_synced(state: &mut app_core::contacts::ContactState) {
    for c in &mut state.contacts {
        c.synced = true;
    }
}

/// Boot-time source for the device-level contacts list (iCloud-contacts
/// feature, 2026-07-20; tombstone-aware since contacts-tombstones,
/// 2026-07-20): if `contacts.json` already exists, it's authoritative —
/// just load it via the same tolerant parse the iCloud blob uses
/// (`app_core::contacts::parse_contacts_blob`, which accepts both the
/// current v2 shape and a bare v1 array — every existing install's
/// `contacts.json` on disk today is a bare array, predating tombstones
/// entirely, so it loads with an empty tombstone list). Otherwise this is
/// an existing install's FIRST boot on the global-contacts scheme: union
/// every per-notebook `store-*.json`'s `contacts` (by address, preferring
/// whichever copy has a non-empty name) so nobody's existing contacts
/// vanish — this migration path predates tombstones too, so it always
/// produces an empty tombstone list. `contacts.json` itself is written by
/// the caller via `State::save_contacts` once the (possibly-migrated)
/// state is in place — this function only READS.
pub(crate) fn load_or_migrate_contacts(data_dir: &std::path::Path) -> app_core::contacts::ContactState {
    let path = data_dir.join("contacts.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        return app_core::contacts::parse_contacts_blob(&text);
    }
    let mut merged: Vec<app_core::store::Contact> = Vec::new();
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return app_core::contacts::ContactState { contacts: merged, tombstones: Vec::new() };
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("store-") && name.ends_with(".json")) {
            continue;
        }
        let Ok(store) = Store::load(&entry.path()) else { continue };
        // Every pre-existing store's `contacts` predates the network tag,
        // so `c.network` deserializes as "" via serde-default no matter
        // which network the store is actually for — stamp the STORE's own
        // `network` field here instead of trusting the (always-blank)
        // per-contact tag, so migrated contacts land correctly tagged
        // rather than as untagged wildcards. Dedup key is (address,
        // network): a testnet4 store and a signet store both listing the
        // same `tb1…` string must stay two distinct migrated contacts.
        let net = store.network.clone();
        for mut c in store.contacts {
            c.network = net.clone();
            match merged.iter_mut().find(|m| m.address == c.address && m.network == c.network) {
                Some(existing) => {
                    if existing.name.is_empty() && !c.name.is_empty() {
                        existing.name = c.name;
                    }
                }
                None => merged.push(c),
            }
        }
    }
    app_core::contacts::ContactState { contacts: merged, tombstones: Vec::new() }
}

impl State {
/// Push the device-level contacts list into the "Send to" recents list.
/// Kept separate from `update_home` so it can be called the moment a
/// contact is added (pick-contact) — otherwise a freshly-used address only
/// appears after the next full home refresh, not when you press Back from
/// compose.
///
/// Storage/sync is fully GLOBAL (`State.contacts` spans every notebook/
/// identity/network on this device — iCloud-contacts feature, 2026-07-20),
/// but the PICKER only SHOWS contacts TAGGED for the ACTIVE network (or
/// left untagged by legacy data) — so a testnet4 contact doesn't clutter a
/// mainnet compose, and critically a testnet4 contact never bleeds into a
/// signet compose either, since the two networks share the same `tb1…`
/// address prefix and an address-parse filter can't tell them apart (only
/// the explicit `Contact::network` tag can) — while the underlying synced
/// list still carries every network's contacts together.
pub(crate) fn refresh_contacts(&self, w: &AppWindow) {
    let st = self;
    let net = st.network.as_str();
    // Global (not per-contact): one `synchronize()` call covers the whole
    // blob, so every synced row shares the same last-observed outcome.
    let sync_status = match st.last_sync.get() {
        SyncStatus::Unknown => 1,
        SyncStatus::Ok => 2,
        SyncStatus::Failed => 3,
    };
    let contacts: Vec<ContactItem> = st
        .contacts
        .iter()
        .filter(|c| c.network == net || c.network.is_empty())
        .map(|c| ContactItem {
            address: c.address.clone().into(),
            name: c.name.clone().into(),
            synced: c.synced,
            sync_status: if c.synced { sync_status } else { 0 },
            pq: c.mlkem_ek.is_some(),
        })
        .collect();
    w.global::<Ui>().set_contacts(VecModel::from_slice(&contacts));
}

/// The rename dialog's "Quantum key" display line for the contact at
/// `addr` on the active network — `""` when the contact has no key on
/// file (or isn't found at all), else `pqkeys::contact_pq_display`'s
/// "<level> · <fingerprint>" (armor that fails to re-parse degrades to
/// empty too — the dialog's own "Set" flow is what would have rejected a
/// bad paste in the first place, so this should never actually hit that
/// branch in practice).
pub(crate) fn contact_pq_display_for(&self, addr: &str) -> String {
    let st = self;
    let net = st.network.as_str();
    st.contacts
        .iter()
        .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        .and_then(|c| c.mlkem_ek.as_deref())
        .and_then(|armor| app_core::pqkeys::contact_pq_display(armor).ok())
        .map(|(_, line)| line)
        .unwrap_or_default()
}

/// Apply an iCloud KV change that synced in from the user's OTHER device
/// (`icloud::start_observer`'s callback, via the `apply-pending-icloud-
/// contacts` trampoline — this runs on the UI thread with full `State`
/// access, same shape as every other `apply_*` trampoline target). Reads
/// whatever's in the KV store RIGHT NOW (not what triggered the
/// notification — there's no payload, just "something changed"), merges
/// it into the live state (tombstone-aware — see `app_core::contacts`),
/// persists + re-syncs only if that actually changed anything, and
/// refreshes the picker so a change made on the other device (including a
/// DELETION) shows up here without a restart.
pub(crate) fn apply_icloud_contacts_merge(&mut self, w: &AppWindow) {
    let st = self;
    let local = st.contact_state();
    let mut incoming =
        app_core::contacts::parse_contacts_blob(icloud::load_blob().as_deref().unwrap_or(""));
    mark_incoming_synced(&mut incoming);
    let merged = app_core::contacts::merge_state(&local, &incoming, now_ms());
    if merged.contacts != st.contacts || merged.tombstones != st.tombstones {
        st.contacts = merged.contacts;
        st.tombstones = merged.tombstones;
        println!(
            "cb: icloud-contacts merged n={} tombstones={}",
            st.contacts.len(),
            st.tombstones.len()
        );
        st.save_contacts();
        st.refresh_contacts(w);
    }
}

/// Pull the latest contacts from iCloud and merge them in before showing
/// the send-to picker (screen 7), so a contact named/synced on the user's
/// OTHER device appears the moment they open the picker — not only after a
/// restart or a live observer notification. `icloud::load_blob` calls
/// `synchronize()` (a local-cache sync, not a blocking network round trip),
/// so this is cheap enough to call directly on the UI thread. Every
/// incoming contact is synced by definition — mark it before merging.
pub(crate) fn pull_icloud_contacts_on_open(&mut self, w: &AppWindow) {
    let st = self;
    let local = st.contact_state();
    let mut incoming =
        app_core::contacts::parse_contacts_blob(icloud::load_blob().as_deref().unwrap_or(""));
    mark_incoming_synced(&mut incoming);
    let merged = app_core::contacts::merge_state(&local, &incoming, now_ms());
    if merged.contacts != st.contacts || merged.tombstones != st.tombstones {
        st.contacts = merged.contacts;
        st.tombstones = merged.tombstones;
        println!(
            "cb: icloud-contacts pull-on-open merged n={} tombstones={}",
            st.contacts.len(),
            st.tombstones.len()
        );
        st.save_contacts();
    }
    st.refresh_contacts(w);
}

/// Manual "Sync now" — the send-to picker header button (sync-status UI,
/// 2026-07-20). Same re-merge `pull_icloud_contacts_on_open` does, but
/// then FORCES a push regardless of whether the local blob already
/// matches what's in the cloud: the whole point of a manual tap is to
/// reassure the user their contacts really did (or didn't) reach iCloud
/// right now, so a silent no-op here would defeat the feature — unlike
/// `save_contacts`'s normal change-gated push, used everywhere else to
/// avoid needless sync churn between two devices that just merged the
/// same result. Stamps `last_sync` from the push's own outcome (falling
/// back to `icloud::available()`, same rule `save_contacts` uses) and
/// refreshes the picker so every synced row's icon updates immediately.
pub(crate) fn sync_contacts_now(&mut self, w: &AppWindow) {
    let st = self;
    let local = st.contact_state();
    let mut incoming =
        app_core::contacts::parse_contacts_blob(icloud::load_blob().as_deref().unwrap_or(""));
    mark_incoming_synced(&mut incoming);
    let merged = app_core::contacts::merge_state(&local, &incoming, now_ms());
    if merged.contacts != st.contacts || merged.tombstones != st.tombstones {
        st.contacts = merged.contacts;
        st.tombstones = merged.tombstones;
    }
    let state = st.contact_state();
    if let Ok(json) = serde_json::to_string_pretty(&state) {
        let _ = std::fs::write(st.contacts_path(), json);
    }
    let synced = state.synced_only();
    let blob = app_core::contacts::serialize_contacts_blob(&synced);
    let accepted = icloud::save_blob(&blob);
    let ok = accepted || icloud::available();
    st.last_sync.set(if ok { SyncStatus::Ok } else { SyncStatus::Failed });
    println!(
        "cb: icloud-contacts sync-now status={} n={}",
        if ok { "ok" } else { "failed" },
        synced.contacts.len()
    );
    st.refresh_contacts(w);
}

/// The ONE sanctioned recipient-setting path for normal (non-sweep) compose:
/// validates/normalizes `addr`, saves it to contacts (creates-if-absent +
/// bumps recency), refreshes recents, sets `to-label`/`to-address`/
/// `directed`, resets every compose-session field (fee tier, coin
/// selection, change choice, gift amount, pay-from default), and lands on
/// screen 6. Shared by the normal contact picker (`on_pick_contact`) and
/// Reply (`on_reply_to_note`) so both go through identical logic.
pub(crate) fn pick_contact_core(&mut self, w: &AppWindow, addr: &str) {
    let st = self;
    // Lands on compose (screen 6), which shows fee tiers + the USD cost
    // line — lazily (re)fetch before the cost-line math below reads
    // `st.fees`/`st.usd` (network-efficiency, 2026-07-23).
    st.refresh_fees_price(w);
    if addr == "self" {
        st.to_address = None;
        // Uniform To section (Sal, 2026-07-19): the row shows just the
        // name/address now — the "To" CAPTION above it carries that label,
        // so the value itself drops the "To: " prefix.
        w.global::<Ui>().set_to_label("Self (my notebook)".into());
        w.global::<Ui>().set_directed(false);
        println!("cb: pick-contact to=self");
    } else {
        let mut a = normalize_addr(addr);
        if Recipient::parse(st.network, &a).is_err() {
            let lower = a.to_lowercase();
            if Recipient::parse(st.network, &lower).is_ok() {
                a = lower;
            } else {
                println!("cb: pick-contact err=bad-address");
                w.global::<Ui>().set_status(format!("not a valid {} address", st.network.as_str()).into());
                return;
            }
        }
        println!("cb: pick-contact to={a}");
        st.touch_contact(&a);
        st.save_contacts();
        // Rebuild the recents now so the address is in the list when the
        // user presses Back from compose.
        st.refresh_contacts(w);
        // Show the contact's name when it has one — same resolution the
        // extra-recipient chips use (a raw address next to a named chip
        // read as inconsistent; Sal 2026-07-19). The address stays
        // verifiable on the byte-truth confirm screen.
        let display = st
            .contacts
            .iter()
            .find(|c| c.address == a && !c.name.is_empty())
            .map(|c| c.name.clone())
            .unwrap_or_else(|| a.clone());
        w.global::<Ui>().set_to_label(display.into());
        st.to_address = Some(a);
        w.global::<Ui>().set_directed(true);
    }
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    if st.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        w.global::<Compose>().set_compose_private(false); // no sealing key on this device
    }
    w.global::<Compose>().set_fee_tier(1);
    w.global::<Compose>().set_rate_text(format!("{rate}").into());
    w.global::<Ui>().set_change_address("".into());
    w.global::<Ui>().set_change_expanded(false);
    w.global::<Ui>().set_spend_expanded(false);
    st.coins_overridden = false;
    st.consolidate_coins = false;
    w.global::<PayFrom>().set_coin_strategy(0);
    w.global::<Compose>().set_gift_sats(format!("{DUST_SATS}").into());
    w.global::<Compose>().set_gift_expanded(false);
    st.selected_coins.clear();
    w.global::<Ui>().set_status("".into());
    w.global::<Ui>().set_payfrom_expanded(false);
    // Funding-unification UI rework: fresh compose session, fresh
    // cross-wallet coin memory + change pick (an explicit change choice
    // from a PRIOR note must never leak into this one).
    st.mixed_selected.clear();
    st.change_choice.clear();
    w.global::<Ui>().set_change_choice("".into());
    st.payfrom_manual = false; // a fresh compose session — see resolve_payfrom_default
    // Independent-expand rework (2026-07-18): visual expansion + the
    // external-wallet peek cache are per-compose-session UI state, never
    // carried over from a prior note.
    st.nb_expanded = false;
    st.sp_expanded = false;
    st.payfrom_expanded_source.clear();
    st.payfrom_wallet_coins.clear();
    // A fresh primary pick starts a fresh recipient list — extra
    // multi-select chips from a PRIOR compose must never leak into this
    // one (mirrors every other per-compose-session reset above).
    st.to_addresses_extra.clear();
    st.picking_extra = false;
    w.global::<Ui>().set_picking_extra(false);
    st.refresh_to_chips(w);
    st.resolve_payfrom_default(w);
    // A fresh compose session — the locktime override never survives past
    // the screen it was set on (see `reset_tx_lock_time_override`'s doc
    // comment).
    st.reset_tx_lock_time_override();
    w.global::<Compose>().set_compose_locktime_expanded(false);
    st.refresh_compose_locktime_panel(w);
    // Post-quantum layers: a fresh compose session starts fresh too — a
    // passphrase or ML-KEM choice from a PRIOR note must never leak into
    // this one, same rule as every other field reset above.
    w.global::<Compose>().set_pq_expanded(false);
    w.global::<Compose>().set_pq_passphrase_enabled(false);
    w.global::<Compose>().set_pq_passphrase_text("".into());
    w.global::<Compose>().set_pq_mlkem_enabled(false);
    st.pq_passphrase_verified = false;
    st.pq_passphrase_generated = None;
    st.pq_recipient_cache = None;
    w.global::<Ui>().set_screen(Screen::Compose);
    st.refresh_compose(w);
}
}
