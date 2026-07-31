//! M6 shell: onboarding (import / create+quiz), home + notes, compose
//! with live cost, contacts picker, settings. Every callback emits a
//! `cb:` log-contract line (grep targets for the M7 UI e2e).
//!
//! Env overrides for tests: APP_DATA_DIR, APP_KEY (bypasses keychain),
//! APP_NETWORK.

mod camera;
mod icloud;
mod keychain;
mod platform;
mod qr;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use app_core::bitcoin;
use app_core::chain::{
    default_base, explorer_presets, explorer_tx_url, node_backend_label, node_presets,
    scan_change_chain, scan_change_chain_watch, AddrStats, AnyTransport, ChainClient, ChangeCoin,
    NodeStatus, TxLookupStatus,
};
use app_core::compose::ComposeRequest;
use app_core::funding::{FundingSource, FundingUtxo, FundingWallet};
use app_core::identity::{
    active_notebook_spks, generate_mnemonic, generate_mnemonic_with_salt, index_fp8,
    parse_key_material, realize, realize_change, AppIdentity,
};
use app_core::notebooks::{NotebookIndex, SpendingAddr};
use app_core::psbt_build::{
    build_funded_sweep_psbt, build_funding_psbt, build_watch_bump_psbt, build_watch_note_psbt_multi,
    build_watch_spend_psbt, predict_keyspend_vsize, sign_own_taproot_inputs, BuiltPsbt,
    FundingPlan, NoteParams, WatchCoin,
};
use app_core::psbt_finalize::{
    finalize_extract, parse_psbt, summarize, validate_signed, OutputRole, SummaryContext,
};
use app_core::notes_core::address::{p2tr_script_pubkey, Recipient};
use app_core::notes_core::bundle::{estimate_note_cost, FeeRates};
use app_core::notes_core::Network;
use app_core::store::{NoteStatus, Store, DEFAULT_CHUNK};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use slint::{ComponentHandle, Model, SharedString, VecModel};
use zeroize::{Zeroize, Zeroizing};

slint::include_modules!();

const KEYCHAIN_ACCOUNT: &str = "identity-key";

/// Opened by Settings → About & help → "Source code".
const SOURCE_URL: &str = "https://github.com/ObjSal/chain-notes-app";
/// Minimum (and default) sats sent to a directed-note recipient.
const DUST_SATS: u64 = app_core::notes_core::DUST_LIMIT;

// ---- About / Help / Privacy / Q&A / disclaimer copy (info screens 24/25) ----

const DISCLAIMER: &str = "Chain Notes is free software provided \"as is\", without warranty of any kind. You alone control your keys and funds. The authors accept no liability for any loss of funds or data — from lost or leaked keys, fees, failed or malformed transactions, or bugs. Bitcoin transactions are irreversible and on-chain data is public and permanent. This is a hot wallet: keep only small, note-fee amounts here and use it at your own risk.";

const ABOUT_INTRO: &str = "Chain Notes writes short personal notes onto the Bitcoin blockchain, signed by keys that never leave your device. Notes can be public, or private — encrypted so only you (or a chosen recipient) can read them. Read them back on any device from your key alone.";
const ABOUT_FOOTER: &str = "Companion & viewer:\nobjsal.github.io/chain-notes-companion";

/// About-screen body, built at runtime so the version line can carry the
/// bundle's build number (`platform::build_number`) — "Version 0.1.0 (30)"
/// on a real build, "Version 0.1.0" on a host/dev binary with no bundle.
fn about_body() -> String {
    let version = match platform::build_number() {
        Some(build) => format!("Version {} ({build})", env!("CARGO_PKG_VERSION")),
        None => format!("Version {}", env!("CARGO_PKG_VERSION")),
    };
    format!("{ABOUT_INTRO}\n\n{version}\n\n{ABOUT_FOOTER}")
}

const PRIVACY: &str = "Chain Notes collects no personal data, has no accounts, and runs no servers of its own.\n\nYour keys stay in your device's secure keychain — and in iCloud Keychain only if you turn on iCloud backup.\n\nTo read the chain and broadcast, the app talks to the Bitcoin node / block explorer you choose in Settings. That server sees the addresses you look up and your IP address.\n\nNotes you publish are stored on the public Bitcoin blockchain. Private-note contents are encrypted so only you (or a note's intended recipient) can read them, but the fact that a transaction exists, its timing, and its amounts are public and permanent.";

const HELP: &str = "Getting started\n\n1. Create a new key (12/18/24 words) or import one — a BIP-39 phrase, xprv, WIF, or hex — by typing it, scanning a QR, or loading a file. You can also import an account xpub as a watch-only notebook.\n\n2. Fund your notebook's address with a small amount for fees. This is a hot wallet — keep only note-fee amounts here.\n\n3. Write a note, pick a fee, and broadcast. Notes can be public, private to you, or directed to another address.\n\n4. Read your notes back any time — they live on-chain. Recover everything on a new device from your recovery phrase or iCloud backup.\n\nTip: for real savings, keep your bitcoin on a hardware wallet and import it here as watch-only.";

const FAQ: &str = "Q.  What is Chain Notes?\nA.  A way to write short personal notes onto the Bitcoin blockchain, signed by keys that stay on your device. A note can be public (anyone can read it) or private (encrypted for you or a chosen recipient).\n\nQ.  Is my money safe here?\nA.  This is a hot wallet — its keys live on an online device. Keep only small, note-fee amounts here; hold savings on a hardware wallet and import it as watch-only.\n\nQ.  Can I recover my notes and funds?\nA.  Yes. Your recovery phrase is a standard BIP-39 seed — re-import it (or restore from iCloud backup) in Chain Notes to bring back your notes and funds. Your funds sit at taproot addresses, so any taproot-capable wallet can recover the funds too; but only Chain Notes (or a compatible app) can decrypt and read your private notes.\n\nQ.  Are my private notes really private?\nA.  Yes — a private note's contents are encrypted so only you or the intended recipient can read them (public notes are readable by anyone). Either way, the transaction itself — that it happened, when, and for how much — is public and permanent.\n\nQ.  Who can see my activity?\nA.  Anyone who has your address or public keys can see this notebook's balance and full transaction history. The block explorer you pick also sees your IP. Share your public keys only with people you trust.";

/// Process-global "how many logical network operations are in flight"
/// counter, driving the ambient `net-busy` dot beside a screen's title
/// (`NetDot` in app.slint). Every worker thread that touches
/// `ChainClient`/transport constructs a [`NetOpGuard`] as its first line —
/// it increments on creation and decrements on `Drop`, so every early
/// return/error path still clears it. Counts LOGICAL operations, not
/// individual HTTP requests (a single refresh/broadcast issues several —
/// per-request toggling would flicker as requests are paced/slower).
static NET_OPS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard for one logical network operation — see [`NET_OPS`]. Push
/// the new busy state to the UI thread via the same `slint::Weak` +
/// `upgrade_in_event_loop` trampoline every async worker already uses
/// (`REFRESH_RESULTS` et al.); logs `cb: net-ops n=<count>` ONLY on the
/// 0→1 and →0 transitions (counts only, matching the `cb:` log contract —
/// never per-request).
struct NetOpGuard {
    weak: slint::Weak<AppWindow>,
}

impl NetOpGuard {
    fn new(weak: slint::Weak<AppWindow>) -> Self {
        let prev = NET_OPS.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("cb: net-ops n=1");
            let w = weak.clone();
            let _ = w.upgrade_in_event_loop(|w| w.set_net_busy(true));
        }
        NetOpGuard { weak }
    }
}

impl Drop for NetOpGuard {
    fn drop(&mut self) {
        let prev = NET_OPS.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            println!("cb: net-ops n=0");
            let weak = self.weak.clone();
            let _ = weak.upgrade_in_event_loop(|w| w.set_net_busy(false));
        }
    }
}

/// The deferred network-operation queue's SCAN lane (design:
/// `../PLAN-chain-notes-app.md` "Deferred: network operation queue" — the
/// scan-freshness gate counters and `spending_refresh_async`'s
/// coalescing early-return shipped as earlier slices; this is the general
/// scheduling mechanism behind them). `app_core::netq::Lane` is the pure
/// admit/complete state machine; this Mutex pairs it with the boxed job
/// closures for whatever is currently RUNNING or QUEUED (the pure Lane
/// only ever tracks keys/ids, never the work itself). `HashMap::new` isn't
/// `const`, hence `LazyLock` rather than a plain `Mutex::new(..)` static
/// like the `*_RESULTS` ones below.
///
/// **Deliberate priority bypass**: ONLY the four scan-class spawn sites
/// migrated to this lane (`refresh_async`, `spending_refresh_async`,
/// `wallet_stores_refresh_async`, `maybe_start_discovery`'s worker).
/// EVERYTHING ELSE — all nine broadcast paths, act-retry/bump fetches,
/// the account-picker probe (`show_notebook_picker`), iCloud ops — stays
/// a plain `std::thread::spawn`: money movements and user-facing probes
/// must never wait behind a queued scan.
static SCAN_LANE: std::sync::LazyLock<
    std::sync::Mutex<(app_core::netq::Lane, HashMap<app_core::netq::JobId, Box<dyn FnOnce() + Send>>)>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new((app_core::netq::Lane::new(), HashMap::new())));

/// Submit a scan-class job to [`SCAN_LANE`] — the impure half of
/// `app_core::netq::Lane`'s pure admission rules. `key` identifies the
/// operation class + identity/network/account it scans (e.g.
/// `format!("nbscan/{address}")`); `job` is the SAME worker-thread body a
/// call site used to hand straight to `std::thread::spawn` (unchanged —
/// its `NetOpGuard`, result push, and `upgrade_in_event_loop` trampoline
/// all stay exactly as they were).
///
/// Returns `false` when the lane coalesced this submission (a job with
/// the same key was already queued) — the caller must then skip its own
/// gate-counter increment and status line, since no work was actually
/// scheduled; the `cb: netq coalesced …` line below is the only trace.
/// Returns `true` when the job either started running immediately or was
/// queued behind another already-running job for a different (or the
/// same, mid-scan) key.
fn scan_lane_submit(key: String, job: impl FnOnce() + Send + 'static) -> bool {
    let short = key[..24.min(key.len())].to_string();
    let mut guard = SCAN_LANE.lock().expect("scan lane mutex");
    let (lane, jobs) = &mut *guard;
    match lane.admit(&key) {
        app_core::netq::Admit::Coalesced => {
            println!("cb: netq coalesced key={short}");
            false
        }
        app_core::netq::Admit::Queued(id) => {
            jobs.insert(id, Box::new(job));
            println!("cb: netq queued key={short} depth={}", lane.depth());
            true
        }
        app_core::netq::Admit::Run(id) => {
            drop(guard);
            spawn_scan_lane_worker(id, key, Box::new(job));
            true
        }
    }
}

/// Runs one already-admitted (`Admit::Run`) scan-class job on a fresh
/// worker thread, then drains [`SCAN_LANE`]'s queue behind it: on
/// completion it re-locks the lane, calls `Lane::complete`, and if that
/// promotes a queued job, takes its boxed closure out of the job map and
/// runs it next — looping until `complete` returns `None` (nothing left
/// queued). The lane lock is held only for the quick admit/complete/
/// lookup bookkeeping between jobs, never while a job itself runs.
///
/// Each job runs inside `catch_unwind` so a panicking scan logs
/// `cb: netq panic key=<trunc>` and the drain CONTINUES — a panicking
/// scan must not wedge the lane for every job queued behind it. Gate
/// counters are NOT repaired on a panic (a pre-existing risk this queue
/// doesn't change).
fn spawn_scan_lane_worker(id: app_core::netq::JobId, key: String, job: Box<dyn FnOnce() + Send>) {
    std::thread::spawn(move || {
        let mut id = id;
        let mut key = key;
        let mut job = job;
        loop {
            let short = key[..24.min(key.len())].to_string();
            if app_core::netq::run_catching(job) {
                println!("cb: netq panic key={short}");
            }
            let mut guard = SCAN_LANE.lock().expect("scan lane mutex");
            let (lane, jobs) = &mut *guard;
            let Some((next_id, next_key)) = lane.complete(id) else {
                break;
            };
            let Some(next_job) = jobs.remove(&next_id) else {
                break; // never observed: complete() only promotes a job this lane itself queued
            };
            drop(guard);
            id = next_id;
            key = next_key;
            job = next_job;
        }
    });
}

/// Push the scan-freshness gate to the UI: `wallet-scan-busy` is true while
/// ANY scan that feeds a money-flow's coin cache is in flight (notebook
/// refresh, spending-wallet scan, or the wallet-wide stores refresh). The
/// Sign buttons on compose and screen 16 read it — see the field docs on
/// `State.scan_gate`. Call after every counter/flag change.
fn update_scan_gate(w: &AppWindow, st: &State) {
    let busy = st.scan_gate.busy();
    if busy != w.get_wallet_scan_busy() {
        // Transition-only, like `cb: net-ops` — and a log contract: the UI
        // e2e suites wait for `busy=false` before tapping a money-flow
        // Sign (rapid ↻ retaps can queue several scans on a slow server;
        // the gate stays closed until EVERY one lands).
        println!("cb: scan-gate busy={busy}");
    }
    w.set_wallet_scan_busy(busy);
}

/// The last OBSERVED outcome of pushing `State.contacts` to iCloud's KV
/// store (contacts sync-status UI, 2026-07-20). Global, not per-contact —
/// `NSUbiquitousKeyValueStore.synchronize()` covers the whole blob in one
/// call, so every synced contact necessarily shares one status; the
/// picker just maps it onto each `synced` row (`refresh_contacts`).
/// `Unknown` only appears before the first `save_contacts`/boot-init call
/// ever runs — in practice `run()` stamps a real value before the window
/// is even shown, so the UI should never actually render it, but it's the
/// harmless neutral default for `Cell::new`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SyncStatus {
    Unknown,
    Ok,
    Failed,
}

struct State {
    data_dir: PathBuf,
    network: Network,
    /// The BIP-86 wallet account (Settings-level context; rev 3). Its
    /// notebooks are receive-chain address indexes — see `nb_index`.
    account: u32,
    /// Active notebook: the receive-chain address index within `account`.
    nb_index: u32,
    /// Device-level Settings (config.json, NOT the per-identity store): the
    /// custom Bitcoin-node / block-explorer URLs, keyed by network. Device-
    /// level so switching identity keeps them; per-network because a custom
    /// URL only makes sense on the chain it serves. Absent key = network
    /// default (mempool.space).
    node_urls: HashMap<String, String>,
    explorers: HashMap<String, String>,
    /// Bitcoin Core RPC "Save credentials" switch (config.json, per network
    /// — same device-level convention as `node_urls`/`explorers`): true
    /// persists to the Keychain (today's unconditional default behavior);
    /// false keeps credentials in `core_rpc_session_creds` only. An absent
    /// key (every pre-U10 config, and every network never touched) means
    /// true, so nobody who already saved credentials sees a change (plan
    /// §2.4 / U10, `core_rpc_should_persist`).
    core_rpc_save_creds: HashMap<String, bool>,
    /// Session-only Bitcoin Core RPC credentials — populated ONLY while
    /// `core_rpc_save_creds` is false for that network. Never serialized to
    /// config.json and never read by the launch path; gone on relaunch.
    /// `Zeroizing` wipes the password on drop (switch flipped back to
    /// persist-on, replaced with new text, or process exit).
    core_rpc_session_creds: HashMap<String, (String, Zeroizing<String>)>,
    /// U11 defense-in-depth: networks whose config.json node URL carried
    /// inline `user:pass@` userinfo when it was LOADED (a hand-edited,
    /// migrated, or pre-`on_set_node_custom`-stripping config) —
    /// `migrate_inline_node_creds` stashes the creds into
    /// `core_rpc_session_creds` at load time (safe: in-memory only) and
    /// records the network here; `flush_core_rpc_migration` (called from
    /// `refresh_node_health`, a Settings-only lazy point, NEVER the launch
    /// path) routes them to the Keychain if this network's "Save
    /// credentials" switch is on, exactly like a freshly typed credential.
    core_rpc_migrate_pending: std::collections::HashSet<String>,
    /// Device-level note-size limit (config.json). Some = the user chose
    /// one in Settings; applied to every notebook's store on activate, so
    /// the wallet-level Settings pill really is wallet-wide. None = each
    /// store keeps its own (legacy per-store value or the default).
    chunk: Option<usize>,
    /// nLockTime policy (anti-fee-sniping), device-level exactly like
    /// `chunk`: owned here + config.json, mirrored onto every store on
    /// activate so the Settings control is genuinely wallet-wide.
    lock_time_policy: app_core::notes_core::tx::LockTimePolicy,
    /// Per-tx locktime OVERRIDE set on the compose (screen 6) or sweep/
    /// consolidate (screen 16) collapsible panel — an override of
    /// `lock_time_policy` for THIS transaction only, never a replacement
    /// for it. `None` = use the device default; `Some(policy)` = the panel
    /// picked one. Reset to `None` every time either flow is (re)opened
    /// (`reset_tx_lock_time_override`), and NEVER written to config.json or
    /// any store — `State` itself isn't serialized, so this can't survive
    /// past the screen it was set on by construction, not by discipline.
    tx_lock_time_override: Option<app_core::notes_core::tx::LockTimePolicy>,
    ident: Option<AppIdentity>,
    store: Option<Store>,
    fees: Option<FeeRates>,
    usd: Option<f64>,
    /// Session cache stamp for [`refresh_fees_price`] (network-efficiency,
    /// 2026-07-23): `fees`/`usd` are only read by the fee-showing screens
    /// (compose/sweep/consolidate/pay-from/bump), not the scan path, so
    /// they're fetched lazily on those screens' open — this stamps WHEN,
    /// so a repeat open within ~60s is a free cache hit instead of another
    /// pair of requests. `None` = never fetched this session.
    fees_fetched_at: Option<std::time::Instant>,
    to_address: Option<String>, // None = self-note
    /// Multi-recipient directed notes: EXTRA recipient addresses beyond
    /// `to_address` (the compose screen's removable To-chips). Empty =
    /// today's ordinary single-recipient flow. Notebook-funded compose
    /// only (`pay_from == "notebook"`) — hidden/disabled for watch-only
    /// and for the spending/mixed/external funding paths (a later unit;
    /// see the PR description). Reset by `pick_contact_core` (a fresh
    /// primary pick starts a fresh recipient list) and on any compose-
    /// session reset.
    to_addresses_extra: Vec<String>,
    /// True while the send-to picker (screen 7) was opened via "+ Add
    /// recipient" on compose — `on_pick_contact` appends to
    /// `to_addresses_extra` instead of replacing the primary recipient,
    /// and Back returns to compose (screen 6) instead of home.
    picking_extra: bool,
    /// Coin control: selected inputs (display-txid, vout) for the compose
    /// in progress; `coins_overridden` = the user has touched the set (so
    /// stop auto-suggesting).
    selected_coins: Vec<(String, u32)>,
    coins_overridden: bool,
    /// Coin-suggestion strategy: false = fewest coins (largest-first),
    /// true = consolidate (smallest-first).
    consolidate_coins: bool,
    material: Option<Zeroizing<String>>, // session cache: avoids re-prompting Touch ID
    /// Bitcoin Core RPC ranged-watch descriptors (U7,
    /// `../PLAN-chain-notes-app-core-rpc.md` §2.2's "ranged descriptor
    /// import" finally gets a caller) for the ACTIVE (identity, account,
    /// network) — computed ONCE by `activate()` from `material` via
    /// `app_core::chain::identity_watch_descriptors` and cloned into every
    /// `open_client_watched` call from here, rather than re-derived (a
    /// handful of secp256k1 scalar multiplications each) on every one of
    /// `open_client`'s ~24 call sites. Empty for single-key (WIF/hex)
    /// material or when nothing is active — those addresses/identities are
    /// unaffected: `open_client_watched` degrades to the plain per-address
    /// `addr()` fallback exactly like `open_client` always has. Irrelevant
    /// (never read) for an Esplora backend.
    core_rpc_watch: Vec<app_core::chain::WatchDescriptor>,
    /// iCloud Keychain backup opt-in: when true the key is stored as a
    /// synchronizable Keychain item (syncs across the user's Apple devices and
    /// survives reinstall). Reflects the current stored item's sync state.
    icloud_backup: bool,
    /// First-run disclaimer accepted (config.json "terms_accepted"). When false
    /// the app opens on the accept gate (screen 24) before anything else.
    terms_accepted: bool,
    /// The user has opted into unlocking the saved key automatically
    /// (config.json "auto_unlock"). Set once they restore a saved key or save
    /// a new one; cleared by reset-identity. Even when true the unlock runs
    /// AFTER the first frame — never on the launch path, or the Face ID
    /// prompt blocks launch and the watchdog kills the app.
    auto_unlock: bool,
    /// A saved identity exists in the keychain (probed WITHOUT unlocking it).
    /// Drives onboarding's "Restore saved key" door.
    saved_key_present: bool,
    pending_import: Option<Zeroizing<String>>, // hierarchical import awaiting account pick
    pending_mnemonic: Option<String>,
    quiz_indices: Vec<usize>,
    /// Edge-tracks whether the current compose draft is over the broadcast
    /// ceiling, so the "too large" dialog pops once on crossing — not on
    /// every keystroke while the draft stays too big.
    compose_oversize: bool,
    /// Last-logged sub-dust fold amount (0 sats) for the compose cost-line
    /// prediction — a last-value guard so `cb: compose-est fold=<S>` prints
    /// once per distinct value instead of on every keystroke while a fold
    /// keeps holding at the same figure (honest-fee-label feature,
    /// 2026-07-18).
    compose_fold_shown: u64,
    /// Last-logged (dust_to_self, fee) pair from the MIXED compose preview
    /// (`mixed_compose_ui`) — same last-value guard style as
    /// `compose_fold_shown`, so `cb: compose-est shape=mixed dust=<n>
    /// fee=<n>` prints once per distinct value instead of every keystroke.
    /// The e2e asserts this line's fee equals the confirm screen's
    /// byte-truth fee for the same compose (TestFlight build-20 fix,
    /// 2026-07-18).
    mixed_est_shown: Option<(u64, u64)>,
    /// External-funding session (screens 12–14). The parsed funding source,
    /// its scanned spendable coins + next change index, the built unsigned
    /// PSBT, its animated-UR export frames, and the imported signed PSBT.
    funding: Option<FundingSource>,
    funding_coins: Vec<FundingUtxo>,
    funding_change_index: u32,
    built_psbt: Option<BuiltPsbt>,
    ur_frames: Vec<String>,
    signed_psbt: Option<bitcoin::Psbt>,
    /// Saved watch-only funding wallets (device-level, persisted); and which
    /// one is currently active for the compose in progress.
    funding_wallets: Vec<FundingWallet>,
    active_funding_id: Option<String>,
    /// Watch-only external-sign flow in progress: what the built PSBT on
    /// the sign screen is (sweep/consolidate/bump) and how to record it
    /// after broadcast. None while the sign screen serves external funding.
    watch_spend: Option<WatchSpend>,
    /// Chain data behind an open watch-mode bump dialog (fetched once at
    /// open; confirm rebuilds from it).
    watch_bump: Option<WatchBump>,
    /// Watch-mode compose awaiting external signature (screen 13/14).
    watch_note: Option<WatchNote>,
    /// Notebook index of the active identity (address-indexes-as-
    /// notebooks, per account: names + archive flags,
    /// `notebooks-<net>-<fp8>.json`), plus its filename key and the
    /// derived (index, address, store-fp8) cache — for the ACTIVE
    /// account — the list and sender labels read; rebuilt on activate,
    /// never per frame.
    notebooks: Option<NotebookIndex>,
    notebooks_fp8: Option<String>,
    nb_addrs: Vec<(u32, String, String)>,
    /// Cross-account self addresses: (account, address) for every OTHER
    /// account's listed notebooks (rev-3 follow-up 3, Sal 2026-07-12) —
    /// `sender_label` reads it so a directed note from a sibling account
    /// labels "Self · account N" instead of a bare address. Rebuilt on
    /// activate from the index file (cheap — it lists them all).
    xacct_addrs: Vec<(u32, String)>,
    /// Receive-chain gap discovery is due: activate() found a FRESH index
    /// file for multi-notebook material (a seed re-import). Consumed by
    /// `maybe_start_discovery` — the probe itself runs on a worker thread,
    /// never inline on the (iOS-watchdogged) launch path.
    discovery_pending: bool,
    /// Wallet-level consolidate in progress: sources snapshotted at open,
    /// destination + fee filled in by the picker, consumed by confirm.
    wconsol: Option<WConsol>,
    /// Private-keys reveal session (screen 19): populated by a FRESH
    /// `keychain::reveal_secret` at the Settings entry point (never from
    /// the cached `material`), so every distinct format the picker can
    /// switch to is already derived — `private-select` just reads a
    /// field, no re-derivation/re-auth. Dropped (zeroized) on hide/back/
    /// reset. Public keys never touch this — they derive from `material`.
    reveal_formats: Option<app_core::keyexport::ExportFormats>,
    /// Funding-unification M3: whether the active identity's key material
    /// can derive a BIP-84 spending wallet (mnemonic / master xprv) —
    /// computed once per `activate()`, gates the Settings toggle and the
    /// compose "Pay from · Spending wallet" option. Watch/WIF/hex/
    /// account-xprv identities are never capable.
    spending_capable: bool,
    /// The identity's spending wallet, once derived + scanned this
    /// session: the descriptor-backed source (scanning + funded-note
    /// assembly reuse the exact same `FundingSource` machinery external
    /// funding wallets use — see app-core `spending.rs`), its spendable
    /// coins, and whether a scan has completed at least once (gates the
    /// UI from showing a stale "0 sats" before the first scan finishes).
    spending_source: Option<FundingSource>,
    spending_coins: Vec<FundingUtxo>,
    spending_scanned: bool,
    /// Taproot CHANGE-chain coins (`m/86'/{coin}'/{account}'/1/{index}`,
    /// [`app_core::identity::realize_change`]) for the ACTIVE account —
    /// account-level (one change chain per account), not per-notebook.
    /// Gap-walked alongside every wallet-stores rescan
    /// ([`scan_change_chain`], gap 1 — external taproot wallets allocate
    /// change sequentially, so the app's own usage never leaves a gap) and
    /// folded into the Coins screen's unified coin list, each row tagged
    /// "change" (Sal's decision: ONE balance, not a separate segment —
    /// see `update_wallet_coins`). Empty for watch/WIF/hex identities
    /// (`scan_change_chain` is a no-op for non-hierarchical material).
    /// The wallet Sweep consumes these too (unit 4, see
    /// `../PLAN-chain-notes-app-taproot-change.md`): `build_sweep_confirm`
    /// derives each unique chain-1 index's owner via `realize_change` and
    /// folds its coins into the swept inputs, signed by that owner's own
    /// tweaked key — same own-coin discipline as notebook coins. Compose /
    /// pay-from ALSO consumes them now (unit 5): change coins fold into the
    /// Pay-from "Notebook" panel (tagged, `payfrom_panel_coins`), tracked
    /// under a DISTINCT `"change"` key in `mixed_selected` (their signing
    /// owner is per-index, unlike the notebook's one fixed leaf), and any
    /// selection containing one forces the mixed compose path
    /// (`payfrom_state`'s `PayfromShape::Mixed`) — see
    /// `mixed_compose_args`/`on_compose_send_mixed`. Watch-only still
    /// doesn't consume them (a later unit; `change_coins` is empty for
    /// watch material anyway, `realize_change` errors on it).
    change_coins: Vec<ChangeCoin>,
    /// The `(fp8, network, account)` context `change_coins` was last scanned
    /// under (taproot-change unit 7 fix). Change coins are ACCOUNT-level —
    /// shared by every notebook of the account — so `activate()` must NOT
    /// wipe them on a mere notebook switch within the SAME context (no
    /// wallet-stores rescan follows a plain notebook open, so a wipe left the
    /// compose Pay-from panel unable to offer change coins; the regtest e2e
    /// caught it). `activate()` clears `change_coins` only when this context
    /// changes; the wallet-stores apply stamps it whenever it repopulates.
    change_coins_ctx: Option<(String, Network, u32)>,
    /// Settings → "Sweep notebook funds here": the spending-wallet receive
    /// index the sweep destination was set to, so the broadcast handler
    /// can mark it used on success (fresh-address discipline). None for
    /// every other sweep destination.
    pending_spending_sweep_index: Option<u32>,
    /// Cross-wallet coin selection for the Pay-from screen (funding-
    /// unification UI rework, 2026-07-16): (source key, txid, vout). Source
    /// key uses the convention `pay_from`/`use-funding-wallet` already use:
    /// "notebook" | "spending" | "wallet:<id>" | "change" (taproot-change
    /// unit 5 — a chain-1 coin's owner is per-INDEX, unlike the notebook's
    /// one fixed leaf, so it gets its own key even though its rows render
    /// inside the SAME "Notebook" panel — see `payfrom_panel_coins`). A
    /// note may spend coins tagged with different source keys in ONE tx.
    /// This is a per-source MEMORY the existing single-source scratch state
    /// (`selected_coins`/`coins_overridden`) mirrors into/out of whenever
    /// the active source (`payfrom_active_source`) changes — so every
    /// existing single-source compute/send path keeps working on
    /// `selected_coins` unmodified, and re-expanding a previously-touched
    /// wallet row restores exactly what was selected there. "change" is
    /// NEVER mirrored into `selected_coins` (mirrors "wallet:<id>"'s
    /// treatment — see `on_toggle_coin`/`sync_and_finalize_payfrom`).
    mixed_selected: Vec<(String, String, u32)>,
    /// Which EXTERNAL WALLET row is expanded on the Pay-from screen — ""
    /// = none. Independent-expand rework (2026-07-18, Sal's iPhone
    /// feedback): Notebook/Spending got their own booleans below
    /// (`nb_expanded`/`sp_expanded`) that toggle without touching this or
    /// each other; external wallets stay an accordion AMONG THEMSELVES
    /// only (a pre-existing scope boundary — this app only ever keeps ONE
    /// external wallet's coins scanned/cached at a time, see
    /// `payfrom_wallet_coins`). A header tap here ONLY flips this string —
    /// it never selects/deselects coins or changes which source is the
    /// compose engine's active pay-from (`payfrom_active_source` below);
    /// that's `on_toggle_coin`'s job now, triggered by an actual coin tap.
    payfrom_expanded_source: String,
    /// Pay-from screen: is the Notebook section visually expanded?
    /// Independent of `sp_expanded`/`payfrom_expanded_source` — see the
    /// doc comment above. Re-derived (never persisted) every time the
    /// screen opens: every source holding a selected coin starts expanded.
    nb_expanded: bool,
    /// Pay-from screen: is the Spending-wallet section visually expanded?
    /// See `nb_expanded`.
    sp_expanded: bool,
    /// The compose engine's ACTIVE pay-from source — drives `pay_from`/
    /// `fund_external`/`spend_from_wallet` and which of `refresh_compose`'s
    /// three branches computes the live fee/change preview
    /// (`spend_coins`/`spend_title`/`spend_enough`/`cost_line`) that feeds
    /// the compose screen's compact row and the Pay-from screen's summary
    /// card. Renamed off `payfrom_expanded_source` in the independent-
    /// expand rework (2026-07-18): visibility and "active" are now two
    /// separate concerns — this only ever changes via `resolve_payfrom_default`
    /// (fresh compose session) or an explicit coin tap (`on_toggle_coin`),
    /// NEVER a mere header tap that only shows/hides a section.
    payfrom_active_source: String,
    /// Per-wallet coin cache for the Pay-from screen's independently-
    /// expandable external-wallet rows (2026-07-18 rework) — separate from
    /// `funding_coins`/`active_funding_id` (the SINGLE "real" active
    /// external source the compose/broadcast plumbing reads) so merely
    /// expanding a row to LOOK at a wallet can never clobber a DIFFERENT
    /// wallet's live selection. Populated by `payfrom_scan_wallet_for_display`
    /// on first expand; cleared at the start of every fresh compose session.
    payfrom_wallet_coins: std::collections::HashMap<String, Vec<FundingUtxo>>,
    /// Re-entrancy guard for `sync_and_finalize_payfrom`'s dispatch
    /// alignment (it re-runs `refresh_compose` once after switching the
    /// active source to match the verdict's shape — TestFlight-13 fix,
    /// 2026-07-18).
    payfrom_aligning: bool,
    /// Explicit change destination pick made this compose session (screen
    /// 21) — "" = unset, `app_core::mixed::resolve_change_default` applies.
    /// Never overridden by a refresh once chosen; cleared with the rest of
    /// the compose draft on open/broadcast.
    change_choice: String,
    /// Async sign+broadcast (2026-07-16): true while any of the three
    /// compose send paths (notebook/spending/mixed) has a build+broadcast
    /// in flight on a worker thread — re-entrancy guard so a double-tap on
    /// Sign can't double-broadcast, and drives the button's disabled
    /// "Signing…"/"Broadcasting…" state.
    compose_busy: bool,
    /// Activity screen (2026-07-16): the ref_id of a Rebroadcast/Speed-up
    /// currently in flight on a worker thread, if any — only that row's
    /// button shows the busy state and is disabled; other rows stay
    /// tappable. None when nothing is in flight.
    act_pending_ref: Option<String>,
    /// CHANGE 5 (activate()-spending-cache fix, 2026-07-17): true once the
    /// user has EXPLICITLY picked a "Pay from" source this compose session
    /// (the compact picker or the Pay-from screen's row tap) — guards a
    /// landed `spending_refresh_async` scan from yanking the default back
    /// to "spending" out from under a deliberate "notebook" pick. Reset to
    /// false at the start of every fresh compose session (`pick_contact_core`).
    payfrom_manual: bool,
    /// CHANGE 4 (async wallet-tx broadcast, 2026-07-17): true while a
    /// consolidate / sweep / wallet-consolidate / psbt-broadcast has a
    /// `client.broadcast()` in flight on a worker thread — re-entrancy
    /// guard so a double-tap can't double-broadcast (mirrors
    /// `compose_busy`, kept separate since the two never overlap but
    /// represent different flows).
    wallet_tx_busy: bool,
    /// Re-entrancy guard for `wallet_stores_refresh_async` — the Coins
    /// screen's and notebook-list's ↻ (TODO(watchdog) fix, 2026-07-20: both
    /// used to rescan every active notebook synchronously on the UI thread,
    /// same freeze class the auto-refresh timer had before it moved to
    /// `refresh_async`). True while a wallet-wide rescan is in flight on a
    /// worker thread; a second tap is ignored rather than queued (simpler
    /// than overlapping store-file writes) — see
    /// `apply_wallet_stores_refresh_results`'s own (fp8, network, account)
    /// staleness guard for the identity-switch-mid-scan case.
    /// Scan-freshness gate (2026-07-21, the stale-sign-window follow-up to
    /// the 429-politeness work): tracks in-flight notebook refreshes
    /// (`refresh_async`), spending-wallet scans (`spending_refresh_async`),
    /// and a wallet-wide stores refresh (`wallet_stores_refresh_async`) —
    /// the pure counter/flag bookkeeping lives in
    /// `app_core::scan_gate::ScanGate` (host-tested there), this field is
    /// just where `State` holds one. Incremented/set on the UI thread right
    /// before each worker spawn; decremented/cleared once per drained
    /// result in the apply half (BEFORE its staleness guard, so a
    /// stale-dropped result still releases its slot). Money-flow Sign
    /// buttons (compose + sweep/consolidate, screen 16) disable while
    /// `wallet-scan-busy` — signing against a mid-scan coin cache builds a
    /// tx that broadcasts into missing-inputs (loud + fund-safe, but
    /// user-hostile; the window grows as public-host pacing slows scans).
    /// Full serialization is the deferred network-operation-queue item in
    /// PLAN-chain-notes-app.md.
    scan_gate: app_core::scan_gate::ScanGate,
    /// The universal confirm screen (26) session in progress, if any — see
    /// [`PendingBroadcast`]. `show_confirm` sets it, `on_confirm_broadcast`
    /// consumes it, `on_confirm_cancel` drops it (leaving zero trace: stage
    /// A never mutates the store, so cancel is just a navigation).
    pending_broadcast: Option<PendingBroadcast>,
    /// DEVICE-LEVEL contacts (iCloud-contacts feature, 2026-07-20): ONE
    /// address book shared across every notebook/identity/network on this
    /// device — superseding the old per-notebook `Store.contacts` as the
    /// source of truth (that field stays on `Store` only for serde back-
    /// compat with existing store files; nothing reads it anymore).
    /// Persisted to `data_dir/contacts.json` (`save_contacts`) and mirrored
    /// to iCloud's `NSUbiquitousKeyValueStore` (`icloud.rs`) so it survives
    /// uninstall/reinstall and stays live across the user's iOS + Mac. Same
    /// recents rule as the old per-notebook list (front = latest use,
    /// dedupe by address) but a bigger cap (100) since this is now one
    /// list for the whole device. See `State::touch_contact`/
    /// `name_contact`/`remove_contact`/`save_contacts` and
    /// `load_or_migrate_contacts` (the one-time union-from-every-store
    /// migration for existing installs).
    contacts: Vec<app_core::store::Contact>,
    /// Tombstones for `(address, network)` contacts DELETED on this or
    /// another device (contacts-tombstones feature, 2026-07-20) — the
    /// synced record of "this was removed", so a device that still has an
    /// older copy of a deleted contact drops it on the next merge instead
    /// of resurrecting it. Together with `contacts` this is exactly the
    /// `app_core::contacts::ContactState` this device tracks; same
    /// persistence (`contacts.json`) and iCloud KV sync path as
    /// `contacts` — see that module's doc for the full merge design
    /// (wall-clock assumption, 90-day GC).
    tombstones: Vec<app_core::contacts::Tombstone>,
    /// Last-observed outcome of an iCloud contacts push (sync-status UI,
    /// 2026-07-20) — see `SyncStatus`. Interior mutability because
    /// `save_contacts` is `&self` (called from dozens of sites that only
    /// hold a shared borrow) but still needs to record the write's
    /// outcome; `Cell` is enough since `SyncStatus` is a plain `Copy` enum,
    /// no need for `RefCell`'s borrow machinery. Runtime-only: NOT
    /// serialized to `contacts.json` (a fresh boot always re-derives it —
    /// see `run()`'s init and `icloud::available()`).
    last_sync: std::cell::Cell<SyncStatus>,
}

/// Cap for the device-level contacts list — mirrors
/// `app_core::contacts::MERGE_CAP` (the iCloud merge cap); kept as its own
/// constant here since local mutations (touch/name) don't go through the
/// merge function.
const CONTACTS_CAP: usize = 100;

/// A build+sign result awaiting the user's explicit "Broadcast" tap on the
/// universal confirm screen (26). `raw_hex`/`txid` are the byte-truth of
/// the signed tx (already decoded once by `show_confirm`'s
/// `summarize_signed_tx` call — stage B doesn't re-derive them, just POSTs
/// `raw_hex`). `payload` carries exactly what each `kind` needs to finish:
/// record-then-broadcast for the notebook path, or (for every other path)
/// the same fields its pre-existing async broadcast thread already closed
/// over, now deferred from "right after Sign" to "right after Broadcast".
///
/// Cloned (not taken) out of `State` at the Broadcast tap — `on_psbt_broadcast`
/// (the "psbt" kind's stage B) reads `State.signed_psbt` directly and
/// manages its own retry, so leaving this in place lets a failed PSBT POST
/// be retried by tapping Broadcast again. Every other kind drops it
/// (`on_confirm_broadcast` sets `pending_broadcast = None` once stage B
/// fires): the notebook kind's record is one-shot (its existing failure
/// path redirects to Activity/Rebroadcast instead), and the spending/mixed
/// kinds' failure path returns to compose (screen 6, draft intact) to
/// rebuild rather than re-POST possibly-stale signed bytes.
#[derive(Clone)]
struct PendingBroadcast {
    kind: &'static str, // "compose" | "compose-spending" | "compose-mixed" | "psbt" |
    // "sweep" | "consolidate" | "wconsol" | "spending-consolidate" | "bump" | "rebroadcast"
    raw_hex: String,
    txid: String,
    vsize: usize,
    /// The confirm screen's one-liner caption (`confirm-context`), e.g.
    /// "Public note · testnet4" / "Sweep to bc1q…" — computed by the
    /// caller (it knows things `summarize_signed_tx`'s byte-truth view
    /// deliberately doesn't, like the human note-kind label) and just
    /// carried through by `show_confirm`.
    context: String,
    return_screen: i32,
    payload: PendingPayload,
}

#[derive(Clone)]
enum PendingPayload {
    /// Notebook compose (`on_compose_send`'s keyed non-watch path): stage A
    /// built + signed via `compose::compose_note` (no store mutation).
    /// Stage B calls `compose::record_composed_note` + `save_store()` —
    /// exactly what `compose_and_record` used to do before its POST — then
    /// spawns the SAME broadcast worker pushing `NotebookComposeResult`.
    Compose {
        composed: app_core::compose::ComposedNote,
        text: String,
        private: bool,
        change_to: Option<String>,
        created_at: u64,
        to: Option<String>,
    },
    /// Spending-wallet-funded compose (`on_spending_compose_send`): already
    /// recorded nothing until broadcast success today, so stage B is just
    /// the pre-existing thread-spawn verbatim — this carries exactly the
    /// fields `SpendingComposeResult` needs minus `result`/`raw`/`txid`/
    /// `vsize` (those live on `PendingBroadcast` itself).
    ComposeSpending {
        note_id: [u8; 4],
        text: String,
        private: bool,
        to: Option<String>,
        /// Multi-recipient (2+ only, empty for a self-note or an ordinary
        /// single-recipient directed note — same "empty means single"
        /// convention as `ComposedNote.recipients`/`NoteRecord.recipients`).
        recipients: Vec<String>,
        gift: u64,
        built_fee: u64,
        built_change: u64,
        spent_outpoints: Vec<(String, u32)>,
        change_index: u32,
        change_raw: String,
        source: FundingSource,
    },
    /// Mixed-source direct-broadcast compose (`on_compose_send_mixed`'s
    /// no-external-coin tail): same "nothing recorded until broadcast"
    /// shape as spending — stage B is the pre-existing thread-spawn
    /// verbatim.
    ComposeMixed {
        note_id: [u8; 4],
        text: String,
        private: bool,
        to: Option<String>,
        /// Multi-recipient (2+ only) — see `ComposeSpending.recipients`.
        recipients: Vec<String>,
        gift: u64,
        built_fee: u64,
        built_change: u64,
        change_default: app_core::mixed::ChangeDefault,
        notebook_spent: Vec<app_core::store::OutPointRef>,
        spent_spending: Vec<(String, u32)>,
        /// Taproot CHANGE-chain coins ridden as inputs (unit 5, see
        /// `../PLAN-chain-notes-app-taproot-change.md`) — same shape+timing
        /// as `SweepSnapshot.change_spent`: pruned from `State.change_coins`
        /// on broadcast success only (`apply_mixed_compose_result`).
        change_spent: Vec<(String, u32)>,
        payloads_len: usize,
        /// Recipient OUTPUT count (0 = self-note, 1 = ordinary directed
        /// note, 2+ = multi) — drives the change-vout arithmetic in
        /// `apply_mixed_compose_result`; was a `bool` before multi-
        /// recipient support, renamed since "present" no longer captures
        /// how many slots the recipient outputs occupy.
        recipient_count: usize,
        change_index: u32,
        spending_source: Option<FundingSource>,
    },
    /// External-wallet-funded / watch-only signed-PSBT path
    /// (`set_confirm_from_psbt` + `on_psbt_broadcast`): every bookkeeping
    /// field this needs (`State.signed_psbt`/`built_psbt`/`watch_note`/
    /// `watch_spend`) already lives in `State` untouched by the confirm
    /// screen's navigation, so stage B is the pre-existing
    /// `on_psbt_broadcast` body verbatim — this variant carries nothing.
    Psbt,
    /// Wallet-level sweep (`on_sweep_send`'s keyed self-paid tail → the
    /// (removed) sweep-confirm modal used to trigger `on_sweep`, kind
    /// "sweep"): build+sign already ran in stage A; stage B is the
    /// pre-existing `SWEEP_BROADCAST_RESULTS` thread-spawn, moved
    /// verbatim.
    Sweep { snap: SweepSnapshot },
    /// Single-notebook consolidate (`on_sweep_send`'s keyed self-paid
    /// tail, kind "consolidate") — same shape as `Sweep`.
    Consolidate { snap: ConsolidateSnapshot },
    /// Wallet-level consolidate (account picker "wconsol" mode — picking
    /// the destination row IS the trigger now, kind "wconsol").
    WConsol { snap: WConsolSnapshot },
    /// Spending-wallet consolidate ("Consolidate spending coins…", kind
    /// "spending-consolidate").
    SpendingConsolidate { snap: SpendingConsolidateSnapshot },
    /// Activity Speed-up (`on_act_bump_confirm`, kind "bump") — stage A
    /// runs the PURE `bump_*_build` halves only (zero-trace cancel: the
    /// store still points at the ORIGINAL pending tx until Broadcast);
    /// stage B applies the matching `record_bumped_*` mutation +
    /// `save_store()` FIRST (record-before-POST, exactly like the
    /// notebook-compose arm), re-arms `act_pending_ref`, and spawns the
    /// SAME broadcast worker pushing `ActBumpResult`.
    Bump { ref_id: String, fee: u64, new_rate: f64, bumped: BumpedBuild },
    /// Activity Rebroadcast (`on_act_retry`, kind "rebroadcast") — stage A
    /// already resolved the raw hex (locally cached, or via a worker
    /// fetch for chain-recovered/watch records with none cached); stage B
    /// is the pre-existing broadcast thread-spawn pushing `ActRetryResult`.
    Rebroadcast { ref_id: String },
}

/// A Speed-up's signed-but-not-yet-recorded replacement, built by the pure
/// `app_core::compose::bump_*_build` halves at stage A and applied by the
/// matching `record_bumped_*` at stage B's Broadcast tap. A note bump
/// carries the full [`app_core::compose::ComposedNote`] (its record step
/// also swaps the ledger change UTXO); a sweep/consolidate bump needs only
/// the bare signed tx.
#[derive(Clone)]
enum BumpedBuild {
    Note(app_core::compose::ComposedNote),
    Tx(app_core::notes_core::tx::NoteTx),
}

/// One wallet-consolidate session (Coins → "Consolidate into one coin…").
struct WConsol {
    /// (notebook index, spendable coins, their value) per source
    /// notebook — all within the ACTIVE account.
    sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)>,
    dest_index: u32,
    dest_addr: String,
    rate: f64,
    fee: u64,
    vsize: u64,
}

/// Watch-mode compose in progress on the sign screen: everything needed
/// to record the (public) note after the externally signed broadcast.
struct WatchNote {
    note_id: [u8; 4],
    text: String,
    recipient: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`. Covers every path that ends up on the shared PSBT sign
    /// screen with a note payload: `on_compose_send`'s watch branch
    /// (self-funded), `on_fund_build`'s watch branch (externally funded),
    /// and `on_compose_send_mixed`'s external-wallet branch (a keyed mixed
    /// compose that routes through this same screen).
    recipients: Vec<String>,
    gift: u64,
    chunks: usize,
    fee: u64,
    change: u64,
    spent: Vec<app_core::store::OutPointRef>,
    /// Funding-unification M3: `Some("wallet:<label>")` when an external
    /// funding wallet paid (Activity's source pill); `None` for a watch
    /// identity's own-coin self-funded compose. Funding-unification UI
    /// rework: `Some("mixed")` for a keyed mixed-source compose whose
    /// selection included an external wallet.
    funded: Option<String>,
    /// True for a genuine watch identity's compose (drives the broadcast
    /// log's `private=false`/`watch=1`, both hardcoded before this field
    /// existed). False for a keyed mixed-source compose routed through the
    /// same sign screen — those keep their real `private` flag.
    is_watch: bool,
    /// The real private/public flag — only meaningful when `is_watch` is
    /// false (a genuine watch compose is always public, unconditionally).
    private: bool,
    /// Whether the built tx carries a separate dust-to-self output BEFORE
    /// change (funding-unification UI rework's mixed builder always adds
    /// one; a watch identity's self-funded compose never does — it already
    /// spends from self) — shifts the change output's vout by one.
    dust_to_self: bool,
    /// Taproot CHANGE-chain coins (chain 1) ridden as inputs by a keyed
    /// mixed compose that ALSO pulled an external funding wallet (unit-5
    /// follow-up): the change inputs are signed in-app before this note is
    /// handed to the external signer, but — like `WatchSpend.change_spent`
    /// (unit 6) — they must be pruned from `State.change_coins` on broadcast
    /// success (`record_watch_note`), or the next compose would re-offer an
    /// already-spent coin until the next chain-1 rescan. Empty for a genuine
    /// watch identity's public-note compose (its coin control never offers
    /// change coins) and for any selection without a change coin.
    change_spent: Vec<(String, u32)>,
}

struct WatchSpend {
    kind: &'static str, // "sweep" | "consolidate" | "bump"
    dest: String,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    inputs: Vec<app_core::store::TxInput>,
    /// Owning notebook index per input (parallel to `inputs`) — watch
    /// wallet-level spends span several notebooks (rev-3 follow-up 1):
    /// bookkeeping locks each input in ITS store and the TxRecord carries
    /// `input_indexes` so a later bump re-derives every leaf.
    input_indexes: Vec<u32>,
    /// Consolidate-to-notebook: the destination's receive index — the
    /// TxRecord (+ the new unconfirmed coin) lands in THAT store,
    /// mirroring the keyed wallet-consolidate bookkeeping. None = the
    /// record stays in the active store (sweeps leave the wallet; bumps
    /// ride their original record).
    dest_index: Option<u32>,
    /// (ref_id, is_note) of the record being replaced when kind == "bump".
    bump_ref: Option<(String, bool)>,
    /// (txid, vout) of any taproot CHANGE-chain (chain 1) coins riding as
    /// inputs (unit 6, see `../PLAN-chain-notes-app-taproot-change.md`) —
    /// pruned from `State.change_coins` on broadcast success, same
    /// treatment `SweepSnapshot.change_spent` gives the keyed sweep.
    /// Non-empty makes the record non-bumpable (mirrors keyed CHANGE 2's
    /// `mixed_inputs`): the bump reconstruction (`fetch_tx_io`'s
    /// address→index resolver) only knows NOTEBOOK addresses, so it can't
    /// safely re-derive a chain-1 leaf — see `watch_bump_open`.
    change_spent: Vec<(String, u32)>,
}

struct WatchBump {
    ref_id: String,
    is_note: bool,
    txid: String,
    coins: Vec<WatchCoin>,
    outputs: Vec<(Vec<u8>, u64)>,
    old_fee: u64,
    vsize: u64,
}

/// Unlock the saved keychain identity — the half that PROMPTS. Split from
/// [`activate_restored`] so the caller isn't holding a `State` borrow across a
/// Face ID prompt that can sit there for as long as the user takes.
///
/// **Never call this on the launch path.** Both callers are safe by
/// construction: the onboarding "Restore saved key" tap (user-initiated) and
/// the deferred auto-unlock timer (after the first frame).
fn read_saved_material(window: &AppWindow) -> Option<String> {
    // `load_secret_gated`, NOT `load_secret_protected`: a synced item has no
    // ACL to prompt on, so the restore door read the seed silently — most
    // visibly on a fresh install, where tapping Restore on an unlocked phone
    // was the whole authentication story (Sal, 2026-07-26). The gated variant
    // adds an LAContext check for exactly that shape; the local-ACL shape is
    // unchanged, the OS already prompts. Only the TAP path uses it — the
    // deferred auto-unlock reads directly, off-thread.
    match keychain::load_secret_gated(KEYCHAIN_ACCOUNT, "unlock your Chain Notes identity") {
        Ok(Some(m)) => Some(m),
        Ok(None) => {
            // Probed present but gone by the time we read it (deleted from
            // another device, or an iCloud item that vanished).
            println!("cb: unlock none");
            window.set_saved_key_present(false);
            None
        }
        Err(e) if e == "cancelled" => {
            println!("cb: unlock cancelled");
            window.set_status("unlock cancelled — tap Restore to try again".into());
            None
        }
        Err(e) => {
            println!("cb: unlock err={e}");
            window.set_status(format!("keychain: {e}").into());
            None
        }
    }
}

/// Activate a just-unlocked saved identity and land on the notebook list.
/// Restoring IS the opt-in for automatic unlock: from here on launches unlock
/// on their own (still deferred past the first frame).
fn activate_restored(window: &AppWindow, s: &mut State, material: String, onboarding: bool) {
    match activate(s, &material, false) {
        Ok(()) => {
            if !s.auto_unlock {
                s.auto_unlock = true;
                s.save_config();
            }
            // Stamp the backup state from the ITEM, not from a boot guess.
            // Boot sets `icloud_backup = icloud_available()` while no key is
            // loaded (it's the default for a key about to be created), so a
            // restored LOCAL-ONLY key on an iCloud-signed-in device would
            // otherwise leave Settings claiming a backup that doesn't exist.
            // The removed "Restore from iCloud" door hid this by forcing
            // true — right for its case only. `is_synced` forbids auth UI, so
            // this cannot prompt.
            let synced = keychain::is_synced(KEYCHAIN_ACCOUNT);
            s.icloud_backup = synced;
            window.set_icloud_backup(synced);
            // Restoring from the onboarding door is an ONBOARDING EXIT, and
            // every other one (create-seed, import, iCloud restore) ensures
            // the account's notebook 0 — I added this path and skipped it, so
            // a restore after a fresh install landed on an empty list. The
            // keychain item survives app deletion but `notebooks-*.json` does
            // NOT, so a restored key genuinely has no index to load.
            //
            // Guarded two ways. Only on the onboarding tap, never on the
            // deferred auto-unlock, which is a BOOT path — "boot never
            // resurrects archived entries". And only when the account has NO
            // notebooks AT ALL, active or archived: zero ACTIVE notebooks is
            // legitimate (archive-all is allowed), and re-creating one there
            // would undo a deliberate archive.
            if onboarding {
                let none_at_all = s
                    .notebooks
                    .as_ref()
                    .map(|ix| ix.active(s.account).count() == 0 && ix.archived_count(s.account) == 0)
                    .unwrap_or(true);
                if none_at_all {
                    println!("cb: restore first-notebook");
                    ensure_first_onboarded_notebook(s);
                }
            }
            println!("cb: unlock ok auto-unlock=1");
            update_home(window, s);
            update_notebook_list(window, s);
            window.set_status("".into());
            window.set_screen(17);
            refresh_async(window, s);
            spending_refresh_async(window, s);
        }
        Err(e) => {
            println!("cb: unlock activate-err={e}");
            window.set_status(format!("stored key failed: {e}").into());
        }
    }
}

/// The ONE way a store reaches disk (audit M1). `Store::save` writes a temp
/// file and renames it over the target, so the backup-exclusion flag — which
/// lives on the file, not the path — is destroyed on every save and has to be
/// re-applied here. Routing every write through this is what keeps decrypted
/// note text out of unencrypted device backups; a `store.save(...)` called
/// directly would silently re-enrol that notebook.
///
/// Save failures stay swallowed, exactly as every call site already did:
/// the store is a chain-derived cache, and a failed write leaves the previous
/// file intact (temp-then-rename).
fn save_store_file(store: &app_core::store::Store, path: &std::path::Path) {
    if store.save(path).is_ok() {
        platform::exclude_from_backup(path);
    }
}

impl State {
    /// Per-identity, per-network store file — switching keys or accounts
    /// can never collide notebooks.
    fn store_path(&self) -> Option<PathBuf> {
        let fp = hex::encode(self.ident.as_ref()?.output_x());
        Some(
            self.data_dir
                .join(format!("store-{}-{}.json", self.network.as_str(), &fp[..8])),
        )
    }

    /// The Bitcoin-node base URL: the device-level Settings choice for this
    /// network, else the network default. Configured only through the Settings
    /// screen — no env override, so tests exercise the same path a user does.
    fn base_url(&self) -> Option<String> {
        self.node_urls
            .get(self.network.as_str())
            .cloned()
            .or_else(|| default_base(self.network).map(String::from))
    }

    /// The custom block-explorer base for this network (Settings), or None for
    /// the network default — see [`explorer_tx_url`].
    fn explorer_base(&self) -> Option<String> {
        self.explorers.get(self.network.as_str()).cloned()
    }

    /// Whether the "Save credentials" switch is ON for `network` — default
    /// true (an absent config key preserves today's unconditional-Keychain
    /// behavior; only an explicit `false` opts a network out). Plan §2.4 /
    /// U10. Delegates to the free function so the default-true rule is
    /// testable without constructing a `State`.
    fn core_rpc_should_persist(&self, network: Network) -> bool {
        core_rpc_persist_default_true(&self.core_rpc_save_creds, network.as_str())
    }

    fn save_store(&self) {
        if let (Some(s), Some(p)) = (&self.store, self.store_path()) {
            save_store_file(s, &p);
        }
    }

    /// Device-level contacts file (NOT per-identity — see `State.contacts`).
    fn contacts_path(&self) -> PathBuf {
        self.data_dir.join("contacts.json")
    }

    /// This device's full synced state (contacts + tombstones) — the
    /// `app_core::contacts::ContactState` `save_contacts`/the merge paths
    /// operate on.
    fn contact_state(&self) -> app_core::contacts::ContactState {
        app_core::contacts::ContactState {
            contacts: self.contacts.clone(),
            tombstones: self.tombstones.clone(),
        }
    }

    /// Persist `contacts.json` (contacts + tombstones) and mirror it into
    /// iCloud's KV store (a no-op off Apple platforms, or when the OS
    /// entitlement/iCloud account isn't available — see
    /// `icloud::save_blob`). Only WRITES the KV blob when this device's
    /// serialized state actually differs from what's already there, to
    /// avoid needless sync churn between two devices that just merged the
    /// same result.
    ///
    /// Sync-status UI (2026-07-20): every call stamps `self.last_sync` with
    /// what actually happened, since `synchronize()`'s `BOOL` is the only
    /// ground truth the OS gives us that a push reached iCloud (see
    /// `icloud::save_blob`'s doc). Three cases: (1) the blob changed and
    /// `save_blob` ran — its return value IS the verdict; (2) the blob
    /// changed but iCloud is simply unavailable (never reaches `save_blob`
    /// at all, same verdict either way); (3) the blob was UNCHANGED, so no
    /// write happens here at all — that's still a legitimate "in sync"
    /// state as long as iCloud is available, not an error, so it maps to
    /// `Ok`/`Failed` purely off `icloud::available()`.
    fn save_contacts(&self) {
        let state = self.contact_state();
        // LOCAL file keeps the FULL state (unchanged) — every contact, synced flag included.
        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let _ = std::fs::write(self.contacts_path(), json);
        }
        // iCloud gets ONLY the opt-in subset (synced==true contacts + all tombstones).
        let synced = state.synced_only();
        let blob = app_core::contacts::serialize_contacts_blob(&synced);
        let status = if icloud::load_blob().as_deref() != Some(blob.as_str()) {
            let accepted = icloud::save_blob(&blob);
            println!("cb: icloud-contacts synced n={}", synced.contacts.len());
            accepted || icloud::available()
        } else {
            icloud::available()
        };
        self.last_sync.set(if status { SyncStatus::Ok } else { SyncStatus::Failed });
    }

    /// Device-level contacts, Prime rules: front = latest use, dedupe by
    /// (address, network), cap [`CONTACTS_CAP`]; naming does not bump
    /// recency. Same shape as the old per-notebook `Store::touch_contact`,
    /// just scoped to the whole device (and every network on it) now.
    ///
    /// Identity is (address, network), NOT address alone — testnet4 and
    /// signet share the `tb1…` HRP, so the same address string can be two
    /// genuinely different contacts. This always stamps the address with
    /// the ACTIVE network (`self.network`) at touch time. The existing-
    /// entry match is a bit looser than a strict tuple match, though: it
    /// also matches a LEGACY untagged entry (`network == ""`, from before
    /// this field shipped) for the same address, so touching an old
    /// contact again upgrades it in place (tags it, keeps its name) rather
    /// than leaving a stale blank-tagged duplicate beside a new one.
    ///
    /// Contacts-tombstones (2026-07-20): stamps `updated_at = now_ms()`
    /// and drops any tombstone for this `(address, network)` — re-adding/
    /// touching a contact is an intentional resurrection, and its fresh
    /// `updated_at` is by construction newer than any prior deletion, so
    /// the stale tombstone must not survive to fight the next merge.
    fn touch_contact(&mut self, address: &str) {
        let net = self.network.as_str().to_string();
        let existing = self
            .contacts
            .iter()
            .position(|c| c.address == address && (c.network == net || c.network.is_empty()))
            .map(|i| self.contacts.remove(i));
        let name = existing.as_ref().map(|c| c.name.clone()).unwrap_or_default();
        // Preserve the opt-in sync flag across a re-touch — recency bumps
        // must never silently flip a contact's iCloud-sync opt-in either
        // way. A brand-new contact defaults unsynced (serde-default).
        let synced = existing.as_ref().map(|c| c.synced).unwrap_or(false);
        self.contacts.insert(
            0,
            app_core::store::Contact {
                address: address.to_string(),
                name,
                network: net.clone(),
                updated_at: now_ms(),
                synced,
            },
        );
        self.contacts.truncate(CONTACTS_CAP);
        self.tombstones
            .retain(|t| !(t.address == address && (t.network == net || t.network.is_empty())));
    }

    /// Same (address, network-or-legacy-blank) match as `touch_contact` —
    /// the rename dialog always opens from a network-filtered picker row,
    /// so "the entry this address means on the active network" is
    /// unambiguous even if the same address string also exists as a
    /// distinct contact on another network. Stamps `updated_at` and clears
    /// any tombstone, same reasoning as `touch_contact`.
    fn name_contact(&mut self, address: &str, name: &str, synced: bool) {
        let net = self.network.as_str().to_string();
        if let Some(c) = self
            .contacts
            .iter_mut()
            .find(|c| c.address == address && (c.network == net || c.network.is_empty()))
        {
            c.name = name.to_string();
            c.updated_at = now_ms();
            c.synced = synced;
        }
        self.tombstones
            .retain(|t| !(t.address == address && (t.network == net || t.network.is_empty())));
    }

    /// Same (address, network-or-legacy-blank) match as `touch_contact` —
    /// removes only the ACTIVE network's entry for this address, never a
    /// same-string contact that belongs to a different network.
    ///
    /// Contacts-tombstones (2026-07-20): deletion is now a first-class
    /// synced event, not just an absence — records/refreshes a
    /// `Tombstone { address, network: <active>, deleted_at: now_ms() }`
    /// so the other device drops its own (older) copy of this contact on
    /// the next merge instead of resurrecting it here. Re-deleting an
    /// already-tombstoned contact just bumps the timestamp (harmless,
    /// idempotent).
    fn remove_contact(&mut self, address: &str) {
        let net = self.network.as_str().to_string();
        self.contacts
            .retain(|c| !(c.address == address && (c.network == net || c.network.is_empty())));
        let now = now_ms();
        match self.tombstones.iter_mut().find(|t| t.address == address && t.network == net) {
            Some(t) => t.deleted_at = now,
            None => self.tombstones.push(app_core::contacts::Tombstone {
                address: address.to_string(),
                network: net,
                deleted_at: now,
            }),
        }
    }

    /// The `nLockTime` to build the next transaction with (anti-fee-sniping):
    /// the active store's policy resolved against the height it last scanned
    /// to. No store loaded (watch/PSBT flows before activate) falls back to 0,
    /// the same "we don't know a height" answer `LockTimePolicy::Tip` gives —
    /// never a guess, since a locktime in the FUTURE makes the transaction
    /// non-final and gets it rejected from the mempool.
    fn lock_time(&self) -> u32 {
        self.store.as_ref().map(|st| st.lock_time()).unwrap_or(0)
    }

    /// The resolved `nLockTime` override, if the compose/sweep panel set
    /// one THIS session — `None` when no override is active, meaning the
    /// caller should fall back to `lock_time()`. Resolved against the same
    /// tip `lock_time()` itself uses, so an override of `LockTimePolicy::Tip`
    /// (picking "Chain height" explicitly) behaves identically to leaving
    /// the device default alone.
    fn lock_time_override_value(&self) -> Option<u32> {
        self.tx_lock_time_override.map(|policy| {
            let tip = self.store.as_ref().and_then(|s| u32::try_from(s.tip_height).ok());
            policy.resolve(tip)
        })
    }

    /// The `nLockTime` THIS build should actually use: the per-tx override
    /// if the compose/sweep panel set one, else the device default
    /// (`lock_time()`) — every non-`ComposeRequest` builder call site
    /// (spending-wallet/mixed/watch compose, keyed + watch sweep/
    /// consolidate, watch bump) reads this instead of calling `lock_time()`
    /// directly, so the override reaches every path the panel is shown on.
    fn effective_lock_time(&self) -> u32 {
        self.lock_time_override_value().unwrap_or_else(|| self.lock_time())
    }

    /// Drop any per-tx locktime override — called every time a compose or
    /// sweep/consolidate flow is (re)opened, so the panel always starts
    /// from the device default and an override can never survive past the
    /// screen it was set on.
    fn reset_tx_lock_time_override(&mut self) {
        self.tx_lock_time_override = None;
    }

    /// The tip height to hand `ConfirmCtx.tip_height` — `None` when there's
    /// no store loaded OR it has never scanned (`tip_height == 0`, the
    /// fresh-`Store::new` default), same "never guess" filter
    /// `locktime_caption` already applies to its own caption. A confirm
    /// screen reached with a genuine tip of 0 is not realistically
    /// reachable (building a tx needs a scanned UTXO set first), so this
    /// only ever suppresses the warning on an honestly-unknown tip, never
    /// a real one.
    fn confirm_tip_height(&self) -> Option<u32> {
        self.store.as_ref().and_then(|s| u32::try_from(s.tip_height).ok()).filter(|h| *h > 0)
    }

    /// The exact `serde_json::Value` `save_config` writes to `config.json`
    /// — extracted to its own method (rather than inlined in `save_config`)
    /// so a test can assert on the REAL production payload instead of a
    /// hand-built mirror that can silently drift from it (U10 review fix:
    /// a mirror-based test kept passing after `save_config` was edited, in
    /// a review experiment, to leak `core_rpc_session_creds` in plaintext
    /// under a new key — see `core_rpc_settings_tests::
    /// config_payload_never_carries_session_credentials`). Deliberately
    /// does NOT take `core_rpc_session_creds` as a parameter anywhere in
    /// this list — the absence is what keeps it out.
    fn config_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "network": self.network.as_str(),
            "account": self.account,
            "index": self.nb_index,
            "nodes": self.node_urls,
            "explorers": self.explorers,
            "core_rpc_save_creds": self.core_rpc_save_creds,
            "chunk": self.chunk,
            "terms_accepted": self.terms_accepted,
            "auto_unlock": self.auto_unlock,
            "locktime": self.lock_time_policy,
        })
    }

    fn save_config(&self) {
        let _ = std::fs::write(self.data_dir.join("config.json"), self.config_payload().to_string());
    }

    /// Test-only full `State` builder — every field the config-payload
    /// tests don't care about gets the same inert default `run()`'s own
    /// boot literal uses (`None`/empty/`false`), so a fresh test `State`
    /// behaves like a just-booted app with no identity loaded. Only the
    /// fields `config_payload` (or a test wanting to poke at them) reads
    /// are parameters. Kept out of production builds entirely.
    #[cfg(test)]
    fn test_stub(
        network: Network,
        node_urls: HashMap<String, String>,
        explorers: HashMap<String, String>,
        core_rpc_save_creds: HashMap<String, bool>,
        core_rpc_session_creds: HashMap<String, (String, Zeroizing<String>)>,
    ) -> State {
        State {
            data_dir: PathBuf::new(),
            network,
            account: 0,
            nb_index: 0,
            node_urls,
            explorers,
            core_rpc_save_creds,
            core_rpc_session_creds,
            core_rpc_migrate_pending: std::collections::HashSet::new(),
            chunk: None,
            lock_time_policy: Default::default(),
            // Per-tx locktime override: always None in a stub. This builder
            // enumerates every `State` field on purpose, so a new field is a
            // COMPILE error here rather than a silently-defaulted one — which
            // is how this merge (per-tx locktime × the core-rpc config_payload
            // tests) surfaced at all.
            tx_lock_time_override: None,
            ident: None,
            store: None,
            fees: None,
            usd: None,
            fees_fetched_at: None,
            to_address: None,
            to_addresses_extra: Vec::new(),
            picking_extra: false,
            selected_coins: Vec::new(),
            coins_overridden: false,
            consolidate_coins: false,
            material: None,
            core_rpc_watch: Vec::new(),
            icloud_backup: false,
            terms_accepted: false,
            auto_unlock: false,
            saved_key_present: false,
            pending_import: None,
            pending_mnemonic: None,
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
            funding_wallets: Vec::new(),
            active_funding_id: None,
            watch_spend: None,
            watch_bump: None,
            watch_note: None,
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
            contacts: Vec::new(),
            tombstones: Vec::new(),
            last_sync: std::cell::Cell::new(SyncStatus::Unknown),
        }
    }

    fn save_funding_wallets(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.funding_wallets) {
            let _ = std::fs::write(self.data_dir.join("funding-wallets.json"), json);
        }
    }

    /// The notebook index file of the active identity: keyed by the BIP-32
    /// master fingerprint so every account's notebook shares one index (and
    /// switching identities can never mix indexes).
    fn notebooks_path(&self) -> Option<PathBuf> {
        let fp8 = self.notebooks_fp8.as_ref()?;
        Some(self.data_dir.join(format!("notebooks-{}-{}.json", self.network.as_str(), fp8)))
    }

    fn save_notebooks(&self) {
        if let (Some(ix), Some(p)) = (&self.notebooks, self.notebooks_path()) {
            let _ = ix.save(&p);
        }
    }

    /// Persist a spending-wallet mutation to its ACCOUNT-level home
    /// (funding-unification M3.1): copy the active store's runtime
    /// `spending` cache into the notebooks index entry for the active
    /// account, then save it — so every OTHER notebook of the account
    /// picks up the change the next time it activates (they share ONE
    /// section; see `app_core::notebooks::SpendingSection`). Callers
    /// mutate `store.spending` via the usual `Store::spending_*` methods
    /// FIRST, then call this instead of (or beside) `save_store()`.
    fn save_spending(&mut self) {
        let Some(section) = self.store.as_ref().map(|s| s.spending.clone()) else { return };
        let account = self.account;
        if let Some(ix) = self.notebooks.as_mut() {
            ix.set_spending(account, section);
        }
        self.save_notebooks();
    }

    /// A notebook's display name: its local name, else the 1-based default
    /// "Notebook <index+1>" (never empty — rows and the home title read
    /// this). Every notebook is created named, so the fallback only covers
    /// entries written before that rule.
    fn notebook_display_name(&self, index: u32) -> String {
        let named = self
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(self.account, index))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        if !named.is_empty() {
            return named;
        }
        app_core::notebooks::default_name(index)
    }

    /// The store file of another (not necessarily active) notebook.
    fn store_path_for(&self, address_output_x_fp8: &str) -> PathBuf {
        self.data_dir
            .join(format!("store-{}-{}.json", self.network.as_str(), address_output_x_fp8))
    }
}

/// "tb1p2ylq…q7ax" — the row/label short form of an address.
fn addr_short(a: &str) -> String {
    if a.len() > 14 {
        format!("{}…{}", &a[..9], &a[a.len() - 4..])
    } else {
        a.to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix MILLISECONDS — the clock for contacts-tombstones' `updated_at`/
/// `deleted_at` timestamps (`app_core::contacts` needs finer resolution
/// than `now()`'s seconds so two touches in the same second still order
/// correctly). The only place this crate calls `SystemTime::now()` for
/// that feature — every `app_core::contacts` function stays clock-free
/// and takes timestamps as parameters (see that module's doc for the
/// cross-device wall-clock assumption this relies on).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Show the transient "Copied" toast. Bumps toast-nonce so a repeat copy
/// while a toast is still on screen extends the ~1.5s auto-dismiss window
/// (the countdown reset lives in app.slint's `changed toast-nonce` handler).
fn show_toast(w: &AppWindow, text: &str) {
    w.set_toast_text(text.into());
    w.set_toast_nonce(w.get_toast_nonce() + 1);
    w.set_toast_open(true);
}

fn spendable_inputs(store: &Store) -> Vec<app_core::store::TxInput> {
    store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| app_core::store::TxInput { txid: u.txid.clone(), vout: u.vout, value: u.value })
        .collect()
}

/// "R.R sat/vB · F sats" (or just "F sats" without a known vsize).
fn fee_line_str(fee: Option<u64>, vsize: Option<u64>) -> String {
    match (fee, vsize) {
        (Some(f), Some(v)) if v > 0 => format!("{:.1} sat/vB · {f} sats", f as f64 / v as f64),
        (Some(f), _) => format!("{f} sats"),
        _ => "—".into(),
    }
}

/// "replaced N×" when a tx was RBF-bumped (>1 txids), else empty.
fn replaced_label(txid_count: usize) -> String {
    if txid_count > 1 {
        format!("replaced {}×", txid_count - 1)
    } else {
        String::new()
    }
}

/// The active external funding wallet's Activity pill value
/// (`"wallet:<label>"`), or `None` if no funding wallet is active — used
/// when recording a note an external wallet paid for.
fn active_funding_pill(st: &State) -> Option<String> {
    let id = st.active_funding_id.as_ref()?;
    let fw = st.funding_wallets.iter().find(|f| &f.id == id)?;
    Some(format!("wallet:{}", fw.label))
}

/// Activity's funding-source pill (funding-unification M3): `NoteRecord.
/// funded_by` is `Some("spending")` for the internal BIP-84 spending
/// wallet or `Some("wallet:<label>")` for an external funding wallet;
/// `None` (every pre-M3 record, and every notebook-funded note) shows no
/// pill at all — byte-identical to today's Activity row.
fn funded_pill(funded_by: Option<&str>) -> String {
    match funded_by {
        Some("spending") => "spending wallet".to_string(),
        Some(s) => s.strip_prefix("wallet:").map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// "New fee ~N sats (+D)" for a proposed rate over a tx of `vsize`.
fn new_fee_line(rate: f64, vsize: u64, old_fee: u64) -> String {
    let new_fee = (rate * vsize as f64).ceil() as u64;
    let delta = new_fee.saturating_sub(old_fee);
    format!("New fee ~{new_fee} sats  (+{delta} over current)")
}

/// Current rate (sat/vB), fee, vsize for a pending tx referenced by the
/// activity list (note_id if is_note, else txid).
fn tx_rate(store: &Store, ref_id: &str, is_note: bool) -> Option<(f64, u64, u64)> {
    if is_note {
        let n = store.notes.iter().find(|n| n.note_id == ref_id)?;
        let (f, v) = (n.fee?, n.vsize?);
        (v > 0).then(|| (f as f64 / v as f64, f, v))
    } else {
        let t = store.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id))?;
        (t.vsize > 0).then(|| (t.fee as f64 / t.vsize as f64, t.fee, t.vsize))
    }
}

/// Post-broadcast bookkeeping for a watch-mode compose: record the public
/// note as Pending with the same ledger effects as a keyed compose —
/// inputs locked, change (last vout) spendable unconfirmed, raw hex kept
/// for rebroadcast until confirmation.
fn record_watch_note(st: &mut State, wn: &WatchNote, txid: &str, raw: &str, vsize: u64) {
    let Some(store) = st.store.as_mut() else { return };
    // A mixed-source compose (funding-unification UI rework) always carries
    // a dust-to-self output BEFORE change; a genuine watch compose never
    // does (it already spends from self) — shifts the change vout by one.
    // Multi-recipient (2+): as many recipient outputs as `wn.recipients`
    // carries, in place of the single 0/1 slot — everything else about the
    // vout arithmetic (dust-to-self, then change) is unaffected by count.
    let recipient_outputs =
        if wn.recipients.len() >= 2 { wn.recipients.len() } else { usize::from(wn.recipient.is_some()) };
    let change_vout = wn.chunks + recipient_outputs + usize::from(wn.dust_to_self);
    let change = (wn.change > 0).then(|| app_core::store::LedgerUtxo {
        txid: txid.to_string(),
        vout: change_vout as u32,
        value: wn.change,
        height: None,
        pending_spend: false,
    });
    store.record_signed(
        app_core::store::NoteRecord {
            note_id: hex::encode(wn.note_id),
            status: NoteStatus::Pending,
            text: Some(wn.text.clone()),
            private: wn.private,
            directed: wn.recipient.is_some(),
            received: false,
            sender: None,
            recipient: wn.recipient.clone(),
            recipients: wn.recipients.clone(),
            txids: vec![txid.to_string()],
            height: None,
            blocktime: None,
            created_at: Some(now()),
            spent: wn.spent.clone(),
            raw_hex: Some(raw.to_string()),
            fee: Some(wn.fee),
            vsize: Some(vsize),
            change_to: None,
            gift_amount: wn.recipient.is_some().then_some(wn.gift),
            funded_by: wn.funded.clone(),
            dropped: false,
        },
        change,
    );
    // Touch every recipient (multi: all of them; single: just the one) —
    // same "recents list reflects the whole To list" rule the notebook
    // path's `record_composed_note` follows. The chip-add flow already
    // touches contacts at PICK time (`on_add_recipient`), so this is a
    // redundant (idempotent — `touch_contact` just bumps recency) safety
    // net, not the only place it happens.
    if wn.recipients.is_empty() {
        if let Some(addr) = &wn.recipient {
            st.touch_contact(addr);
        }
    } else {
        for addr in &wn.recipients {
            st.touch_contact(addr);
        }
    }
    // Taproot CHANGE-chain coins (unit-5 follow-up): a keyed mixed compose
    // that ALSO pulled an external funding wallet signed its change inputs
    // in-app, then routed through this external-sign path — prune them from
    // the runtime cache on broadcast success (same treatment as
    // `record_watch_spend`/`WatchSpend.change_spent`), so the next compose
    // doesn't re-offer an already-spent coin before the next chain-1 rescan.
    if !wn.change_spent.is_empty() {
        st.change_coins
            .retain(|c| !wn.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout));
    }
    st.save_store();
    st.save_contacts();
}

/// Post-broadcast bookkeeping for a watch-mode external-sign spend: sweep/
/// consolidate become TxRecords (Activity lifecycle + rebroadcast/RBF), a
/// bump rides on the record it replaces; spent coins get pending-locked.
fn record_watch_spend(st: &mut State, ws: &WatchSpend, txid: &str, raw: &str, vsize: u64) {
    if st.store.is_none() {
        return;
    }
    match &ws.bump_ref {
        Some((ref_id, is_note)) => {
            let store = st.store.as_mut().expect("checked above");
            if *is_note {
                if let Some(n) = store.notes.iter_mut().find(|n| n.note_id == *ref_id) {
                    if !n.txids.contains(&txid.to_string()) {
                        n.txids.push(txid.to_string());
                    }
                    n.fee = Some(ws.fee);
                    n.vsize = Some(vsize);
                }
            } else if let Some(t) =
                store.txs.iter_mut().find(|t| t.txids.iter().any(|x| x == ref_id))
            {
                if !t.txids.contains(&txid.to_string()) {
                    t.txids.push(txid.to_string());
                }
                t.fee = ws.fee;
                t.vsize = vsize;
                t.raw_hex = Some(raw.to_string());
            }
        }
        None => {
            // Wallet-level (rev 3): inputs may span notebooks — lock each
            // one in ITS OWN store (the active store in memory, siblings on
            // disk), mirroring the keyed sweep's bookkeeping.
            let active_index = st.ident.as_ref().map(|i| i.index);
            let mut owners: Vec<u32> = ws.input_indexes.clone();
            owners.sort_unstable();
            owners.dedup();
            if owners.is_empty() {
                owners.push(active_index.unwrap_or(0)); // legacy single-notebook shape
            }
            let lock = |store: &mut Store, index: u32| {
                for (i, input) in ws.inputs.iter().enumerate() {
                    let owner = ws.input_indexes.get(i).copied().unwrap_or(index);
                    if owner != index {
                        continue;
                    }
                    if let Some(u) =
                        store.utxos.iter_mut().find(|u| u.txid == input.txid && u.vout == input.vout)
                    {
                        u.pending_spend = true;
                    }
                }
            };
            for index in &owners {
                if active_index == Some(*index) {
                    if let Some(store) = st.store.as_mut() {
                        lock(store, *index);
                    }
                } else if let Some(mut store) = notebook_store(st, *index) {
                    lock(&mut store, *index);
                    if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                        save_store_file(&store, &st.store_path_for(fp8));
                    }
                }
            }
            // The TxRecord lands in the destination store for a consolidate-
            // to-notebook (plus its unconfirmed coin, so the balance shows
            // before the next scan); sweeps/legacy keep it in the ACTIVE
            // store — Activity is wallet-wide either way.
            let record = |store: &mut Store| {
                store.record_tx(
                    ws.kind,
                    txid.to_string(),
                    ws.value,
                    ws.fee,
                    vsize,
                    raw.to_string(),
                    ws.dest.clone(),
                    ws.inputs.clone(),
                    ws.dest_spk_hex.clone(),
                    now(),
                );
                if let Some(rec) = store.txs.last_mut() {
                    rec.input_indexes = ws.input_indexes.clone();
                    // Unit 6: a change-including watch spend is non-bumpable
                    // (see `WatchSpend.change_spent`'s doc comment) — same
                    // `mixed_inputs` flag keyed CHANGE 2 sweeps use, so the
                    // Activity screen's Speed-up affordance hides itself the
                    // same way (`ActivityItem.bumpable = !t.mixed_inputs`).
                    rec.mixed_inputs = !ws.change_spent.is_empty();
                }
            };
            match ws.dest_index {
                Some(dest) if active_index != Some(dest) => {
                    if let Some(mut dstore) = notebook_store(st, dest) {
                        record(&mut dstore);
                        dstore.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                        if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == dest) {
                            save_store_file(&dstore, &st.store_path_for(fp8));
                        }
                    }
                }
                Some(_) => {
                    // Destination IS the active notebook.
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                        store.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                    }
                }
                None => {
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                    }
                }
            }
            // Taproot CHANGE-chain coins (unit 6): pruned from the runtime
            // cache so they're not re-offered before the next wallet-stores
            // refresh re-scans chain 1 and finds them gone — same treatment
            // as the keyed sweep's `SweepSnapshot.change_spent`.
            if !ws.change_spent.is_empty() {
                st.change_coins.retain(|c| {
                    !ws.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
            }
        }
    }
    st.save_store();
}

/// Every ACTIVE notebook's spendable coins (chain 0) PLUS the account's
/// taproot CHANGE-chain coins (chain 1, `State.change_coins`, unit 6) as
/// WatchCoins stamped with their owning chain+index — the gather behind
/// the watch wallet-level flows (rev-3 follow-up 1: sweep/consolidate span
/// notebooks in ONE externally-signed PSBT; unit 6 extends that ONE PSBT
/// to the account's own change coins too, so a hardware signer recognizes
/// them via their `.../1/{index}` key origin). Falls back to the active
/// store alone when no index is loaded. `State.change_coins` is empty for
/// any identity that hasn't scanned chain 1 yet (or a keyed identity — this
/// function is only ever called for watch), so appending it is a no-op
/// until unit 6's watch scan (`wallet_stores_refresh_async`) populates it.
fn watch_wallet_coins(st: &State) -> Vec<WatchCoin> {
    let mut coins = Vec::new();
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
                txid: u.txid.clone(),
                vout: u.vout,
                value: u.value,
                chain: 0,
                index: m.index,
            }));
        }
    } else if let Some(store) = &st.store {
        let nb = st.ident.as_ref().map(|i| i.index).unwrap_or(0);
        coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
            txid: u.txid.clone(),
            vout: u.vout,
            value: u.value,
            chain: 0,
            index: nb,
        }));
    }
    coins.extend(st.change_coins.iter().map(|c| WatchCoin {
        txid: c.txid.clone(),
        vout: c.vout,
        value: c.value,
        chain: 1,
        index: c.index,
    }));
    coins
}

/// Watch mode: build the external-sign PSBT spending every ACTIVE
/// notebook's spendable coins into `dest_spk` and open the sign screen
/// (13) — wallet-level, like the keyed sweep (rev-3 follow-up 1). The
/// signed PSBT comes back through the same import paths external funding
/// uses.
fn watch_spend_build(
    w: &AppWindow,
    st: &mut State,
    kind: &'static str,
    dest: String,
    dest_spk: Vec<u8>,
    rate: f64,
) {
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let coins = watch_wallet_coins(st);
    if coins.is_empty() || (kind == "consolidate" && coins.len() < 2) {
        w.set_status(
            if kind == "consolidate" { "nothing to consolidate (need 2+ coins)" } else { "nothing to sweep" }.into(),
        );
        return;
    }
    let notebooks = {
        let mut ids: Vec<u32> = coins.iter().filter(|c| c.chain == 0).map(|c| c.index).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    };
    // Unit 6: chain-1 (change) inputs riding along — pruned from
    // `State.change_coins` on success and marked non-bumpable (see
    // `WatchSpend.change_spent`'s doc comment).
    let change_spent: Vec<(String, u32)> =
        coins.iter().filter(|c| c.chain == 1).map(|c| (c.txid.clone(), c.vout)).collect();
    let inputs: Vec<app_core::store::TxInput> = coins
        .iter()
        .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
        .collect();
    let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
    match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), rate, st.effective_lock_time()) {
        Ok(built) => {
            let cost = format!(
                "{kind} · {} sats · fee {} sats · {} input{} · sign with your external wallet",
                built.sent_to_recipient,
                built.fee,
                coins.len(),
                if coins.len() == 1 { "" } else { "s" }
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind,
                dest,
                dest_spk_hex: hex::encode(&dest_spk),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs,
                input_indexes,
                dest_index: None,
                change_spent: change_spent.clone(),
                bump_ref: None,
            });
            println!(
                "cb: watch-spend-build kind={kind} txid={} fee={} inputs={} notebooks={notebooks}{}",
                built.txid,
                built.fee,
                coins.len(),
                if change_spent.is_empty() { String::new() } else { format!(" change={}", change_spent.len()) }
            );
            show_psbt_sign_screen(w, st, built, cost);
        }
        Err(e) => w.set_status(format!("{e}").into()),
    }
}

/// Watch mode bump, step 1: fetch the pending tx from the node (chain-
/// recovered records carry no fee/vsize/raw hex), price it, open the dialog.
fn watch_bump_open(w: &AppWindow, st: &mut State, ref_id: String, is_note: bool) {
    // The bump dialog prices the replacement off `st.fees.fastest` below —
    // lazily (re)fetch first (network-efficiency, 2026-07-23).
    refresh_fees_price(w, st);
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    let txid = {
        let Some(store) = st.store.as_ref() else { return };
        if is_note {
            store.notes.iter().find(|n| n.note_id == ref_id).and_then(|n| n.txids.last().cloned())
        } else {
            store
                .txs
                .iter()
                .find(|t| t.txids.iter().any(|x| *x == ref_id))
                .and_then(|t| t.txids.last().cloned())
        }
    };
    let Some(txid) = txid else {
        w.set_status("transaction not found".into());
        return;
    };
    // Unit 6 defense-in-depth (mirrors keyed CHANGE 2's `mixed_inputs`
    // guard): a watch sweep/consolidate that included a chain-1 change coin
    // is recorded `mixed_inputs = true` and can't be bumped — the
    // `fetch_tx_io` rebuild below only resolves NOTEBOOK addresses, so it
    // can't safely reconstruct a chain-1 leaf's key origin.
    if !is_note
        && st
            .store
            .as_ref()
            .map(|s| s.txs.iter().any(|t| t.txids.iter().any(|x| *x == ref_id) && t.mixed_inputs))
            .unwrap_or(false)
    {
        w.set_status(
            "this sweep included a change-chain coin — it can't be sped up (rebroadcast still works)"
                .into(),
        );
        return;
    }
    // Multi-notebook records: stamp each input's owning receive index by
    // its prevout address (fetch_tx_io alone can't know our leaves) — the
    // rebuild derives every input's spk/key-origin from that index.
    let index_by_addr: HashMap<String, u32> =
        st.nb_addrs.iter().map(|(i, a, _)| (a.clone(), *i)).collect();
    let creds = core_rpc_creds_for(st, &base, st.network);
    let client = match open_client(&base, st.network, creds) {
        Ok(c) => c,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    match client.fetch_tx_io(&txid, |a| index_by_addr.get(a).copied()) {
        Ok((coins, outputs, confirmed)) => {
            if confirmed {
                w.set_status("already confirmed — nothing to speed up".into());
                return;
            }
            let in_v: u64 = coins.iter().map(|c| c.value).sum();
            let out_v: u64 = outputs.iter().map(|(_, v)| *v).sum();
            let old_fee = in_v.saturating_sub(out_v);
            let vsize = predict_keyspend_vsize(coins.len(), outputs.iter().map(|(s, _)| s.len()));
            let old_rate = if vsize > 0 { old_fee as f64 / vsize as f64 } else { 0.0 };
            let min_rate = old_rate + 1.0;
            let fast = st.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
            let recommended = fast.max(min_rate);
            println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1} watch=1");
            w.set_bump_ref(ref_id.clone().into());
            w.set_bump_is_note(is_note);
            w.set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
            w.set_bump_current(format!("Currently {old_rate:.1} sat/vB · {old_fee} sats fee").into());
            w.set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
            w.set_bump_error("".into());
            w.set_bump_rate(format!("{recommended:.1}").into());
            w.set_bump_new_fee(new_fee_line(recommended, vsize, old_fee).into());
            st.watch_bump = Some(WatchBump { ref_id, is_note, txid, coins, outputs, old_fee, vsize });
            w.set_show_bump_dialog(true);
        }
        Err(e) => w.set_status(format!("can't fetch the pending tx: {}", friendly_net_err(&e.to_string())).into()),
    }
}

/// Watch mode bump, step 2: rebuild the replacement PSBT (same in/outs, fee
/// delta out of our own output) and open the external-sign screen.
fn watch_bump_confirm(w: &AppWindow, st: &mut State, new_rate: f64) {
    let Some(wb) = st.watch_bump.take() else {
        w.set_bump_error("bump context lost — reopen the dialog".into());
        return;
    };
    let min_rate = (wb.old_fee as f64 / wb.vsize.max(1) as f64) + 1.0;
    if new_rate + 1e-9 < min_rate {
        w.set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
        st.watch_bump = Some(wb);
        return;
    }
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let self_spk = p2tr_script_pubkey(&st.ident.as_ref().map(|i| i.output_x()).unwrap_or_default());
    // Take the fee delta from our own output (largest), else the largest
    // non-OP_RETURN output (a sweep pays the fee out of the swept amount).
    let reduce = wb
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, (spk, _))| *spk == self_spk)
        .max_by_key(|(_, (_, v))| *v)
        .map(|(i, _)| i)
        .or_else(|| {
            wb.outputs
                .iter()
                .enumerate()
                .filter(|(_, (spk, _))| spk.first() != Some(&0x6a))
                .max_by_key(|(_, (_, v))| *v)
                .map(|(i, _)| i)
        });
    let Some(reduce) = reduce else {
        w.set_bump_error("no output can absorb the fee bump".into());
        return;
    };
    // Deliberately the DEVICE default, not `effective_lock_time()`: the
    // bump dialog (Activity screen) has no locktime panel and nothing
    // resets the compose/sweep override before it runs, so consulting it
    // here could silently leak a stale override from an earlier, unrelated
    // compose/sweep session into this replacement with no UI indication.
    match build_watch_bump_psbt(&src, &wb.coins, &wb.outputs, reduce, new_rate, st.lock_time()) {
        Ok(built) => {
            w.set_show_bump_dialog(false);
            let dest = st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let cost = format!(
                "speed-up · replaces {}… · new fee {} sats · sign with your external wallet",
                &wb.txid[..12.min(wb.txid.len())],
                built.fee
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind: "bump",
                dest,
                dest_spk_hex: hex::encode(&wb.outputs[reduce].0),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs: Vec::new(),
                input_indexes: Vec::new(),
                dest_index: None,
                bump_ref: Some((wb.ref_id.clone(), wb.is_note)),
                change_spent: Vec::new(),
            });
            println!("cb: watch-bump-build ref={} txid={} fee={}", wb.ref_id, built.txid, built.fee);
            show_psbt_sign_screen(w, st, built, cost);
        }
        Err(e) => {
            w.set_bump_error(format!("{e}").into());
            st.watch_bump = Some(wb);
        }
    }
}

/// The sweep screen's fee rate: tier pill (economy/hour/fastest) or the
/// custom sat/vB field — the compose mapping, mirrored.
fn resolve_sweep_rate(w: &AppWindow, st: &State) -> f64 {
    let f = st.fees.clone().unwrap_or_default();
    match w.get_sweep_tier() {
        0 => f.economy.max(1.0),
        2 => f.fastest.max(1.0),
        3 => w.get_sweep_rate_text().trim().parse().unwrap_or(0.0),
        _ => f.hour.max(1.0),
    }
}

/// Refresh the sweep screen (16): read-only inputs list (a sweep spends
/// every spendable coin), inputs title, and the live cost line for the
/// current fee tier / funding mode.
fn update_sweep_screen(w: &AppWindow, st: &mut State) {
    // Same freshness rule as `refresh_compose`'s locktime-panel repaint.
    refresh_sweep_locktime_panel(w, st);
    let net = st.network;
    let Some(store) = st.store.as_ref() else { return };
    let exb = st.explorer_base();
    // A SWEEP is wallet-level (leaving the wallet): every active
    // notebook's coins ride — scoped to the ACTIVE account, keyed AND
    // watch alike (rev-3 follow-up 1). Consolidate (kind) stays on the
    // active store (the legacy screen-16 flow).
    let wallet_mode = w.get_sweep_kind().as_str() == "sweep";
    let spendable: Vec<app_core::store::LedgerUtxo> = if wallet_mode {
        let mut v = Vec::new();
        if let Some(ix) = &st.notebooks {
            for m in ix.active(st.account) {
                if let Some(s2) = notebook_store(st, m.index) {
                    v.extend(s2.utxos.iter().filter(|u| !u.pending_spend).cloned());
                }
            }
        }
        v
    } else {
        store.utxos.iter().filter(|u| !u.pending_spend).cloned().collect()
    };
    // CHANGE 2: a WALLET sweep also gathers the spending wallet's coins —
    // UNLESS the destination IS the spending wallet's own next receive
    // address (`on_spending_sweep_here`; `pending_spending_sweep_index`),
    // where including them would sweep the spending wallet into itself.
    let spending_rows: Vec<FundingUtxo> = if wallet_mode
        && st.pending_spending_sweep_index.is_none()
        && st.spending_capable
        && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
    {
        st.spending_coins.clone()
    } else {
        Vec::new()
    };
    let nb_total: u64 = spendable.iter().map(|u| u.value).sum();
    let sp_total: u64 = spending_rows.iter().map(|c| c.value).sum();
    let total = nb_total + sp_total;
    let n = spendable.len();
    let sp_n = spending_rows.len();
    let mut rows: Vec<SpendCoin> = spendable
        .iter()
        .map(|u| SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected: true,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
            tag: "".into(),
        })
        .collect();
    rows.extend(spending_rows.iter().map(|c| SpendCoin {
        outpoint: format!("{}:{}", c.txid, c.vout).into(),
        value: c.value.to_string().into(),
        confirmed: c.confirmed,
        selected: true,
        txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
        explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
        tag: "".into(),
    }));
    rows.sort_by_key(|r| r.value.parse::<u64>().unwrap_or(0));
    w.set_sweep_coins(VecModel::from_slice(&rows));
    let plural = if n == 1 { "" } else { "s" };
    w.set_sweep_inputs_title(
        if sp_n > 0 {
            format!(
                "Inputs · {n} notebook coin{plural} + {sp_n} spending coin{} · {total} sats (all)",
                if sp_n == 1 { "" } else { "s" }
            )
        } else {
            format!("Inputs · {n} coin{plural} · {total} sats (all)")
        }
        .into(),
    );

    if n == 0 && sp_n == 0 {
        w.set_sweep_cost_line("nothing to sweep — no spendable coins".into());
        return;
    }
    let rate = resolve_sweep_rate(w, st);
    if rate <= 0.0 {
        w.set_sweep_cost_line("enter a fee rate".into());
        return;
    }
    let dest_spk_len = w
        .get_sweep_dest()
        .to_string()
        .parse_dest_len(net)
        .unwrap_or(34);
    if w.get_sweep_fund_external() {
        if st.funding.is_none() || st.funding_coins.is_empty() {
            w.set_sweep_cost_line(format!("sweeps {total} sats in full — pick a funding wallet for the fee").into());
            return;
        }
        // notes inputs (taproot) + funding inputs + dest + funding change.
        use app_core::bitcoin::transaction::{predict_weight, InputWeightPrediction};
        let fund_kind = st.funding.as_ref().map(|f| f.kind);
        let fund_w = match fund_kind {
            Some(app_core::funding::FundingKind::Wpkh) => InputWeightPrediction::P2WPKH_MAX,
            _ => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        };
        let weights = std::iter::repeat(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH)
            .take(n)
            .chain(std::iter::repeat(fund_w).take(st.funding_coins.len()));
        let vsize = predict_weight(weights, [dest_spk_len, 34usize].into_iter()).to_vbytes_ceil();
        let fee = (vsize as f64 * rate).ceil() as u64;
        let funding_total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
        if funding_total < fee {
            w.set_sweep_cost_line(
                format!("funding wallet holds {funding_total} sats — fee needs ~{fee}").into(),
            );
            return;
        }
        w.set_sweep_cost_line(
            format!(
                "destination receives {total} sats in full · fee ~{fee} sats from the funding wallet ({} sats change back)",
                funding_total.saturating_sub(fee)
            )
            .into(),
        );
    } else {
        // CHANGE 2: with spending coins riding along, size via
        // notes-core's mixed estimator (byte-exact — the same function
        // `build_wallet_sweep_mixed`/`build_sweep_tx_mixed` actually use
        // to build the tx); the all-taproot path is untouched.
        let vsize = if sp_n > 0 {
            use app_core::notes_core::tx::{estimate_vsize_mixed, InputKind};
            let kinds: Vec<InputKind> = std::iter::repeat(InputKind::Taproot)
                .take(n)
                .chain(std::iter::repeat(InputKind::P2wpkh).take(sp_n))
                .collect();
            estimate_vsize_mixed(&kinds, &[], &[dest_spk_len]) as u64
        } else {
            predict_keyspend_vsize(n, std::iter::once(dest_spk_len))
        };
        let fee = (vsize as f64 * rate).ceil() as u64;
        if total <= fee {
            w.set_sweep_cost_line(format!("balance {total} sats can't cover the ~{fee} sat fee").into());
            return;
        }
        let line = if w.get_sweep_kind().as_str() == "consolidate" {
            format!("combines {n} coins → 1 · fee ~{fee} sats · keeps {}", total - fee)
        } else {
            format!("sweeps {total} sats · fee ~{fee} sats · destination receives {}", total - fee)
        };
        w.set_sweep_cost_line(line.into());
    }
}

trait DestLen {
    fn parse_dest_len(&self, net: Network) -> Option<usize>;
}
impl DestLen for String {
    fn parse_dest_len(&self, net: Network) -> Option<usize> {
        Recipient::parse(net, self).ok().map(|r| r.spk.len())
    }
}

/// chain-notes companion note.html permalink, or empty on regtest.
fn note_web_url(network: Network, address: &str, note_id: &str) -> String {
    match network {
        Network::Regtest => String::new(),
        net => format!(
            "https://objsal.github.io/chain-notes-companion/note.html?address={address}&network={}&note={note_id}",
            net.as_str()
        ),
    }
}

/// Populate the Settings node + explorer dropdown models, selected indices,
/// and custom-URL text from the device-level config (this network's entry).
/// The value is matched against the network's presets; a non-preset value
/// selects the trailing "Custom…" row and prefills its text field. An absent
/// entry (None) matches the first preset (mempool.space, the network default).
fn load_backend_settings(w: &AppWindow, st: &State) {
    fn fill(
        presets: Vec<(&'static str, Option<&'static str>)>,
        cur: Option<&str>,
    ) -> (Vec<SharedString>, i32, SharedString) {
        let mut opts: Vec<SharedString> = presets.iter().map(|(l, _)| (*l).into()).collect();
        opts.push("Custom…".into());
        let idx = presets
            .iter()
            .position(|(_, u)| match (u, cur) {
                (None, None) => true,
                (Some(a), Some(b)) => *a == b,
                _ => false,
            })
            .unwrap_or(presets.len());
        let custom = if idx == presets.len() { cur.unwrap_or("") } else { "" };
        (opts, idx as i32, custom.into())
    }

    let net = st.network;
    let (n_opts, n_idx, n_custom, n_core_addr) =
        fill_node(node_presets(net), st.node_urls.get(net.as_str()).map(String::as_str));
    w.set_node_options(VecModel::from_slice(&n_opts));
    w.set_node_index(n_idx);
    w.set_node_custom_text(n_custom);
    w.set_node_address_text(n_core_addr);

    let (e_opts, e_idx, e_custom) =
        fill(explorer_presets(net), st.explorers.get(net.as_str()).map(String::as_str));
    w.set_explorer_options(VecModel::from_slice(&e_opts));
    w.set_explorer_index(e_idx);
    w.set_explorer_custom_text(e_custom);
}

/// [`load_backend_settings`]'s node-dropdown counterpart to its local
/// `fill` — the node picker gets an extra UI-managed row `fill` doesn't
/// (the explorer picker has no "Bitcoin Core" concept, so it stays on the
/// plain two-row-tail `fill`): `<presets…>, "Bitcoin Core", "Custom…"`.
/// U12 (`PLAN-chain-notes-app-core-rpc.md` §2.5) moves the `bitcoind+`
/// storage prefix out of user-facing text — a stored Core base now selects
/// the dedicated row and displays as bare `host:port` (`display_core_url`),
/// never the raw prefixed string; anything else follows the original
/// preset-or-Custom matching unchanged. Returns
/// `(options, selected_index, esplora_custom_text, core_address_text)` —
/// exactly one of the last two is ever non-empty.
fn fill_node(
    presets: Vec<(&'static str, Option<&'static str>)>,
    cur: Option<&str>,
) -> (Vec<SharedString>, i32, SharedString, SharedString) {
    let mut opts: Vec<SharedString> = presets.iter().map(|(l, _)| (*l).into()).collect();
    let core_row = presets.len();
    let custom_row = presets.len() + 1;
    opts.push("Bitcoin Core".into());
    opts.push("Custom…".into());

    if let Some(u) = cur {
        if u.starts_with("bitcoind+") {
            return (opts, core_row as i32, "".into(), display_core_url(u).into());
        }
    }
    let idx = presets.iter().position(|(_, u)| match (u, cur) {
        (None, None) => true,
        (Some(a), Some(b)) => *a == b,
        _ => false,
    });
    match idx {
        Some(i) => (opts, i as i32, "".into(), "".into()),
        None => (opts, custom_row as i32, cur.unwrap_or("").into(), "".into()),
    }
}

/// Default Bitcoin Core `-rpcport` per network — confirmed against the
/// installed `bitcoind` v30.2.0's own `-help-debug` text: `-rpcport=<port>
/// … (default: 8332, testnet3: 18332, testnet4: 48332, signet: 38332,
/// regtest: 18443)`. This app has no Testnet3 variant.
fn core_rpc_default_port(network: Network) -> u16 {
    match network {
        Network::Mainnet => 8332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    }
}

/// Normalize what a person types into the Settings "Bitcoin Core" node-
/// address field into the stored `bitcoind+http(s)://host:port` form (U12,
/// `PLAN-chain-notes-app-core-rpc.md` §2.5) — the ONLY thing that changes is
/// how the field is spelled; `AnyTransport::new`/`node_backend_label` in
/// app-core/src/chain.rs still read/produce exactly this prefix, untouched.
/// Strips inline `user:pass@` userinfo first, same authority-vs-path guard
/// [`split_url_userinfo`] uses (that function needs a `://` to anchor on,
/// so it can't be reused directly on a bare `host` or `host:port` input —
/// this reimplements the same rule on the post-scheme authority instead),
/// and returns it separately so the caller can route it through
/// `route_core_rpc_creds` exactly like a typed credential — a credential
/// pasted here must never reach `config.json` either.
///
/// Accepted shapes (network default port fills in whenever none is given):
///   `host`                   -> `bitcoind+http://host:<default>`
///   `host:port`               -> `bitcoind+http://host:port`
///   `http://host[:port]`      -> `bitcoind+http://host:<port|default>`
///   `https://host[:port]`     -> `bitcoind+https://host:<port|default>`
///   `bitcoind+http(s)://…`    -> re-normalized the same way (paste-tolerant
///                                — a Sparrow-style export, or the app's own
///                                stored string, both still work if pasted)
/// Anything else (empty, a path component, an unsupported scheme, a
/// non-numeric port) is rejected with a message meant to be shown verbatim.
fn compose_core_url(input: &str, network: Network) -> Result<(String, Option<(String, String)>), String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }
    // Paste-tolerant: a full `bitcoind+…` base (this app's own stored
    // shape, or a Sparrow-style export) re-normalizes the same as a bare
    // host would.
    let raw = raw.strip_prefix("bitcoind+").unwrap_or(raw);
    if raw.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }

    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http", r)
    } else if let Some((s, _)) = raw.split_once("://") {
        return Err(format!("unsupported scheme {s:?} — use http:// or https://"));
    } else {
        ("http", raw)
    };

    // Strip inline `user:pass@` userinfo before touching the authority —
    // an '@' that belongs to a path segment is not userinfo (mirrors
    // `split_url_userinfo`'s guard).
    let (authority, creds) = match rest.find('@') {
        Some(at) if !rest[..at].contains('/') => {
            let (userinfo, hostpart) = rest.split_at(at);
            let hostpart = &hostpart[1..]; // drop '@'
            let creds = userinfo.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()));
            (hostpart, creds)
        }
        _ => (rest, None),
    };

    let authority = authority.trim_end_matches('/');
    if authority.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }
    if authority.contains('/') {
        return Err("node address must be host[:port] only, no path".to_string());
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal, e.g. `[::1]:8332`.
        let Some(end) = rest.find(']') else {
            return Err("unterminated IPv6 literal — missing ']'".to_string());
        };
        let (h, after) = rest.split_at(end);
        if h.is_empty() {
            return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
        }
        let after = &after[1..]; // drop ']'
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            if p.is_empty() {
                return Err("empty port after ':'".to_string());
            }
            Some(p.parse::<u16>().map_err(|_| format!("invalid port {p:?}"))?)
        } else {
            return Err(format!("unexpected text after IPv6 literal: {after:?}"));
        };
        (format!("[{h}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => {
                let port = p.parse::<u16>().map_err(|_| format!("invalid port {p:?}"))?;
                (h.to_string(), Some(port))
            }
            Some((h, _)) if h.is_empty() => {
                return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string())
            }
            _ => (authority.to_string(), None),
        }
    };
    let port = port.unwrap_or_else(|| core_rpc_default_port(network));
    Ok((format!("bitcoind+{scheme}://{host}:{port}"), creds))
}

/// The inverse of [`compose_core_url`] for display: a stored `bitcoind+
/// http(s)://host:port` base back into what the node-address field shows —
/// bare `host:port` for the (default) `http` scheme, `https://host:port`
/// when the scheme is `https` (kept explicit so redisplaying then
/// resubmitting the SAME text round-trips to the SAME stored URL — eliding
/// it would silently downgrade an https node back to http on next save).
/// Never called with credentials still embedded: every producer of a stored
/// node URL (`compose_core_url`, `migrate_inline_node_creds`) strips them
/// first, so there is nothing left to redact here.
fn display_core_url(base: &str) -> String {
    let rest = base.strip_prefix("bitcoind+").unwrap_or(base);
    if let Some(host_port) = rest.strip_prefix("http://") {
        host_port.trim_end_matches('/').to_string()
    } else if let Some(host_port) = rest.strip_prefix("https://") {
        format!("https://{}", host_port.trim_end_matches('/'))
    } else {
        rest.to_string()
    }
}

/// Populate the Bitcoin Core section of the node card (backend label + RPC
/// credential fields) from the CURRENT node config — called only from
/// Settings interactions (open, or a node/credentials edit while Settings
/// is open), never from `update_home`/the refresh paths, which call
/// [`load_backend_settings`] above on every repaint. That separation is
/// what keeps RPC-credential Keychain reads off the hot path: this is the
/// "Settings opened" lazy-load point the plan's §2.4 asks for
/// (`PLAN-chain-notes-app-core-rpc.md`), not something that runs on boot or
/// on every scan.
fn update_node_backend_ui(w: &AppWindow, st: &State) {
    let base = st.base_url();
    let is_core = base.as_deref().is_some_and(|b| b.starts_with("bitcoind+"));
    w.set_node_is_core(is_core);
    w.set_node_backend_label(base.as_deref().map(node_backend_label).unwrap_or("Esplora").into());
    // "Save credentials" switch (plan §2.4 / U10): a device-level per-network
    // preference, so it's meaningful even for an Esplora base (set it before
    // the early return) — the user may flip it before ever pointing at a
    // Core node.
    let persist = st.core_rpc_should_persist(st.network);
    w.set_node_core_save_creds(persist);
    if !is_core {
        w.set_node_core_user("".into());
        w.set_node_core_pass("".into());
        w.set_node_health_text("".into());
        w.set_node_health_warn(false);
        return;
    }
    if persist {
        match keychain::load_rpc_creds(st.network.as_str()) {
            Ok(Some((user, pass))) => {
                w.set_node_core_user(user.into());
                w.set_node_core_pass(pass.into());
            }
            Ok(None) => {
                w.set_node_core_user("".into());
                w.set_node_core_pass("".into());
            }
            Err(e) => {
                // Never expected — this item carries no ACL — but degrade to
                // blank fields rather than propagate a Keychain error into
                // Settings; the user can just retype credentials.
                println!("cb: rpc-creds load err={e}");
                w.set_node_core_user("".into());
                w.set_node_core_pass("".into());
            }
        }
    } else {
        // Switch OFF: the Keychain is never consulted — fields reflect
        // whatever this session's in-memory slot holds (empty if nothing
        // was typed yet since launch).
        match st.core_rpc_session_creds.get(st.network.as_str()) {
            Some((user, pass)) => {
                w.set_node_core_user(user.clone().into());
                w.set_node_core_pass(pass.to_string().into());
            }
            None => {
                w.set_node_core_user("".into());
                w.set_node_core_pass("".into());
            }
        }
    }
}

/// Render one [`app_core::chain::NodeStatus`] preflight (plan §2.2/§2.3) as
/// a single honest caption line, plus whether it should use the warning
/// tint. Every condition here is a WARNING, never something this app
/// silently works around or hides — a pruned node's missing history, a
/// missing txindex's degraded sender attribution, and an in-progress
/// rescan (which must never be mistaken for an empty wallet) all get named
/// explicitly. An all-clear reports the tip height so "it's actually
/// talking to your node" is visible too.
///
/// `prune_height` of `0` (or absent while `pruned` is true) means the node
/// is pruned-CAPABLE but hasn't actually deleted any blocks yet — a very
/// common state right after `-prune` is turned on, since Core only starts
/// deleting once it's past its target size. Telling the user "history
/// before block 0 can't be recovered" there is nonsense (nothing is
/// missing) and actively misleading, so that case gets an honest,
/// non-alarming note instead of the strong warning; only a real nonzero
/// prune height gets the "can't be recovered" wording and the warn tint.
fn format_node_status(status: &NodeStatus) -> (String, bool) {
    let mut parts: Vec<String> = Vec::new();
    let mut warn = false;
    if status.pruned {
        match status.prune_height {
            Some(h) if h > 0 => {
                warn = true;
                parts.push(format!(
                    "pruned below block {} — notes/history before it can't be recovered",
                    commas(h)
                ));
            }
            _ => parts.push(
                "pruned-capable — nothing pruned yet, all history still available".to_string(),
            ),
        }
    }
    if !status.txindex {
        warn = true;
        parts.push("no txindex — sender names on external notes may be missing".to_string());
    }
    if status.initial_block_download {
        warn = true;
        parts.push("still syncing to the chain tip (initial block download)".to_string());
    }
    if status.wallet_scanning == Some(true) {
        warn = true;
        parts.push("rescanning — balances/notes may be incomplete until it finishes".to_string());
    }
    if parts.is_empty() {
        parts.push(format!("connected · tip {}", commas(status.tip_height)));
    }
    // `parts` never contains an empty string, but filter defensively so a
    // future condition that pushes "" can never leave a dangling `· `
    // separator in the joined caption.
    (
        parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" · "),
        warn,
    )
}

/// Preflight a configured Bitcoin Core node (plan §2.2/§2.3/U4,
/// `CoreRpcTransport::preflight`) and render it honestly in Settings — a
/// bonus courtesy, never a gate: the user is never blocked from proceeding
/// on a pruned/scanning/no-txindex node, only told about it. A no-op for an
/// Esplora base (`update_node_backend_ui` clears the health line and
/// returns before any network call). Runs on a worker thread exactly like
/// the account-picker's used/new probe (`show_notebook_picker`) — a
/// one-off user-facing check, not a scan-lane job. Also the U11 lazy point
/// for `flush_core_rpc_migration` — a config.json loaded with an inline
/// credential still on it (see `migrate_inline_node_creds`) gets that
/// credential routed to the Keychain/session slot here, never on the
/// launch path.
fn refresh_node_health(w: &AppWindow, st: &mut State) {
    flush_core_rpc_migration(st);
    update_node_backend_ui(w, st);
    let Some(base) = st.base_url() else { return };
    if !base.starts_with("bitcoind+") {
        return;
    }
    let network = st.network;
    // Honest UI when credentials are missing (plan §2.4 / U10 design point
    // 5): with nothing to authenticate with, don't dial the node and let it
    // 401 into a generic "couldn't reach the node" line — say so directly.
    // Covers both the OFF-and-nothing-typed-this-session case and the
    // pre-existing ON-but-never-saved case identically.
    let creds = core_rpc_creds_for(st, &base, network);
    if creds.is_none() {
        w.set_node_health_text("enter RPC credentials to connect".into());
        w.set_node_health_warn(true);
        return;
    }
    w.set_node_health_text("checking node…".into());
    w.set_node_health_warn(false);
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let (text, warn) = match open_client(&base, network, creds) {
            Ok(client) => match &client.transport {
                AnyTransport::Core(t) => match t.preflight() {
                    Ok(status) => format_node_status(&status),
                    Err(e) => (format!("couldn't reach the node — {e}"), true),
                },
                // Unreachable: `base` was checked above to start with
                // "bitcoind+", which `AnyTransport::new` always maps to Core.
                AnyTransport::Esplora(_) => (String::new(), false),
            },
            Err(e) => (format!("couldn't reach the node — {e}"), true),
        };
        NODE_HEALTH_RESULTS.lock().expect("node health mutex").push(NodeHealthResult {
            network,
            base: base.clone(),
            text: text.into(),
            warn,
        });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_node_health());
    });
}

/// Build the unified activity list (note txs + sweep/consolidate),
/// actionable (pending) first, then newest.
fn update_activity(w: &AppWindow, st: &State) {
    let net = st.network;
    let exb = st.explorer_base();
    let ex = exb.as_deref();
    let mut items: Vec<(u64, bool, ActivityItem)> = Vec::new(); // (created, confirmed, item)

    // Wallet-wide: every ACTIVE notebook's notes + txs, tagged. Only the
    // active notebook's rows are actionable (bump/rebroadcast sign with
    // the live store + key); the rest keep the Explorer link.
    let current = st.ident.as_ref().map(|i| i.index);
    let mut sources: Vec<(String, bool, Store)> = Vec::new(); // (tag, actionable, store)
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            sources.push((
                st.notebook_display_name(m.index),
                current == Some(m.index),
                store,
            ));
        }
    } else if let Some(store) = &st.store {
        sources.push((String::new(), true, store.clone()));
    }

    for (tag, actionable, store) in &sources {
    for n in &store.notes {
        let Some(txid) = n.txids.last() else { continue };
        let kind = format!(
            "Note · {}{}",
            if n.private { "private" } else { "public" },
            if n.received {
                " · received"
            } else if n.directed {
                " · sent"
            } else {
                ""
            }
        );
        let status = match n.status {
            // Task #14: a dropped PENDING note renders distinctly (amber
            // "dropped — bump fee to retry" in the UI) — Bump/Rebroadcast
            // stay available exactly like an ordinary pending row (`pending`
            // below is unaffected by `dropped`).
            NoteStatus::Pending if n.dropped => "dropped",
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        items.push((
            n.created_at.or(n.blocktime).unwrap_or(0),
            n.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: n.note_id.clone().into(),
                is_note: true,
                kind: kind.into(),
                title: n.text.clone().unwrap_or_else(|| "(encrypted)".into()).into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(n.fee, n.vsize).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: *actionable && n.status == NoteStatus::Pending && n.raw_hex.is_some(),
                replaced: replaced_label(n.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: funded_pill(n.funded_by.as_deref()).into(),
                busy: st.act_pending_ref.as_deref() == Some(n.note_id.as_str()),
                bumpable: true, // notes bump via bump_fee — never a mixed record
            },
        ));
    }

    for t in &store.txs {
        let Some(txid) = t.txids.last() else { continue };
        let status = match t.status {
            // Task #14 — see the identical note-row rule above.
            NoteStatus::Pending if t.dropped => "dropped",
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        let title = if t.dest == "self" {
            format!("Consolidate · {} sats arrived here", t.value)
        } else {
            format!("To {} · {} sats", t.dest, t.value)
        };
        items.push((
            t.created_at.unwrap_or(0),
            t.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: txid.clone().into(),
                is_note: false,
                kind: if t.kind == "consolidate" { "Consolidate" } else { "Sweep" }.into(),
                title: title.into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(Some(t.fee), Some(t.vsize)).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: *actionable && t.status == NoteStatus::Pending && t.raw_hex.is_some(),
                replaced: replaced_label(t.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: "".into(), // sweeps/consolidates aren't funded-note records
                busy: st.act_pending_ref.as_deref() == Some(txid.as_str()),
                bumpable: !t.mixed_inputs, // CHANGE 2: a mixed sweep can't RBF (see TxRecord.mixed_inputs)
            },
        ));
    }
    }

    // Actionable (unconfirmed) first, then newest created.
    items.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
    let list: Vec<ActivityItem> = items.into_iter().map(|(_, _, it)| it).collect();
    let pending = list.iter().filter(|i| i.pending).count();
    w.set_activity_summary(
        if list.is_empty() {
            "No transactions yet.".to_string()
        } else {
            format!("{} transaction{} · {pending} pending", list.len(), if list.len() == 1 { "" } else { "s" })
        }
        .into(),
    );
    w.set_activity(VecModel::from_slice(&list));
}

fn normalize_addr(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")) {
        s = rest.to_string();
    }
    if let Some(q) = s.find('?') {
        s.truncate(q);
    }
    s
}

/// Group digits with thousands separators: 143473 → "143,473".
fn commas(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in b.iter().enumerate() {
        if i > 0 && (b.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// The structured cost card's "To recipient" row value (Sal, 2026-07-19):
/// "+G sats" for exactly one recipient (unchanged copy), "N × G = T sats"
/// for 2+ (uniform gift × N) — shared by every compose preview that shows a
/// gift row (notebook, mixed, spending) so the wording never drifts between
/// paths. `total` is the byte-true sum the builder actually paid, not
/// `gift * n_recipients` recomputed here (they're equal for a uniform gift,
/// but passing it through keeps this a pure formatter).
fn gift_row(n_recipients: usize, gift: u64, total: u64) -> String {
    match n_recipients {
        0 => String::new(),
        1 => format!("+{} sats", commas(total)),
        n => format!("{n} × {} = {} sats", commas(gift), commas(total)),
    }
}

/// " · G sats to recipient" (single) or " · N × G = T sats to N recipients"
/// (multi) — the ×N fee-copy rule (Sal, 2026-07-19) for the plain "sign
/// with your external wallet" cost strings on the PSBT-sign screen (mixed/
/// watch-note build paths, which don't use the structured cost card).
/// Empty for a self-note (`n_recipients == 0`).
fn gift_cost_suffix(n_recipients: usize, gift: u64) -> String {
    match n_recipients {
        0 => String::new(),
        1 => format!(" · {gift} sats to recipient"),
        n => format!(" · {n} × {gift} = {} sats to {n} recipients", gift * n as u64),
    }
}

/// The bare host from a Bitcoin-node base URL, e.g.
/// `https://mempool.space/testnet4/api` → `mempool.space`. Falls back to
/// "your node" when `base_url` is empty/unparseable (no node configured, or
/// the setting changed between the broadcast attempt and this being shown).
fn host_of(base_url: &str) -> String {
    let rest = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    match rest.split('/').next().filter(|h| !h.is_empty()) {
        Some(h) => h.to_string(),
        None => "your node".to_string(),
    }
}

/// Turn a raw HTTP-error-class message into a short, calm, user-safe status
/// line. A rate-limited esplora/mempool.space answers `429 Too Many
/// Requests` with an HTML body — before this helper, that landed verbatim
/// on screen ("spending wallet scan failed: http: 429 Too Many Requests:
/// <html>..."). Two rules: a 429 anywhere in the raw text becomes a calm
/// retry message (no status-code jargon); anything else has everything
/// from the first `<` onward stripped (so no future HTML error page can
/// ever reach the screen), its whitespace collapsed, and is capped at
/// ~120 chars — a defensive fallback, not just for HTML, in case a server
/// ever answers with an unexpectedly large body.
///
/// Pure and UI-independent (host-tested below); every call site keeps the
/// FULL raw error in its `cb:`/println! debug log and only feeds the
/// user-visible `set_status` text through this.
/// Byte offset of the first `<` that opens an HTML tag (`<html`, `</body`,
/// `<!DOCTYPE`) — `None` when every `<` is plain text (a comparison in a
/// rejection body). Shared rule with app-core's `trim_error_body`.
fn html_tag_start(s: &str) -> Option<usize> {
    s.match_indices('<').find_map(|(i, _)| {
        let next = s[i + 1..].chars().next()?;
        (next.is_ascii_alphabetic() || next == '/' || next == '!').then_some(i)
    })
}

fn friendly_net_err(raw: &str) -> String {
    // Anchored to the Error formats, NOT a bare `contains("429")` — server
    // rejection bodies embed literal sat amounts ("min relay fee not met,
    // 429 < 1000") that must never masquerade as a rate limit. app-core's
    // `trim_error_body` guarantees an HTTP-status message starts with the
    // numeric code (`429: …`), and `Error::Http`'s Display prefixes
    // `http: ` — so a real rate limit is only ever `429…` or `http: 429…`.
    if raw.starts_with("429") || raw.starts_with("http: 429") {
        return "server is busy — retrying shortly".to_string();
    }
    // Strip from the first '<' that actually opens a tag (`<html`, `</`,
    // `<!DOCTYPE`) — a bare comparison in a rejection body ("min relay fee
    // not met, 429 < 1000") must survive intact.
    let stripped = match html_tag_start(raw) {
        Some(i) => &raw[..i],
        None => raw,
    };
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return "server error — try again shortly".to_string();
    }
    if collapsed.chars().count() > 120 {
        collapsed.chars().take(120).collect::<String>() + "..."
    } else {
        collapsed
    }
}

#[cfg(test)]
mod net_err_tests {
    use super::*;

    #[test]
    fn rate_limit_becomes_a_calm_retry_message() {
        let raw = "http: 429 Too Many Requests: <html><body>rate limited</body></html>";
        assert_eq!(friendly_net_err(raw), "server is busy — retrying shortly");
        // app-core's trim_error_body format (no reason phrase) matches too.
        assert_eq!(friendly_net_err("http: 429: Too Many Requests"), "server is busy — retrying shortly");
        assert_eq!(friendly_net_err("429: Too Many Requests"), "server is busy — retrying shortly");
    }

    #[test]
    fn a_429_sat_amount_in_a_rejection_is_not_a_rate_limit() {
        // "429" as a literal fee value must pass through as the real
        // rejection, not become a misleading "server is busy".
        let raw = "http: 400: sendrawtransaction min relay fee not met, 429 < 1000";
        assert_eq!(friendly_net_err(raw), raw);
    }

    #[test]
    fn html_bodies_are_stripped_and_whitespace_collapsed() {
        let raw = "http: 500 Internal Server Error:  \n  <html>\n<body>boom</body></html>";
        assert_eq!(friendly_net_err(raw), "http: 500 Internal Server Error:");
    }

    #[test]
    fn short_plain_errors_pass_through_untouched() {
        assert_eq!(friendly_net_err("connection reset"), "connection reset");
    }

    #[test]
    fn very_long_errors_are_capped() {
        let raw = "e".repeat(200);
        let out = friendly_net_err(&raw);
        assert_eq!(out.chars().count(), 123); // 120 + "..."
        assert!(out.ends_with("..."));
    }
}

/// U5 (`../PLAN-chain-notes-app-core-rpc.md` §2.1/§2.4): Bitcoin Core's
/// rejection vocabulary — `testmempoolaccept` reject-reason tokens
/// (`"txn-already-known"`, `"min relay fee not met, ..."`,
/// `"bad-txns-inputs-missingorspent"`, `"non-final"`) and
/// `sendrawtransaction` RPC-error messages (codes -25/-26/-27, forwarded
/// verbatim by [`app_core::chain::CoreRpcTransport`]'s generic `rpc()`
/// path) — reads nothing like mempool.space's own rejection bodies. Left
/// alone, the exact same underlying condition (already broadcast, fee too
/// low, a missing input, a non-final locktime) would show the user two
/// completely different raw strings depending purely on which backend
/// they picked. This recognizes both vocabularies — real Esplora/
/// mempool.space bodies already tend to embed plain English for these
/// cases; Core's are short machine tokens or terse RPC messages — and
/// collapses the common ones to ONE calm, backend-agnostic phrase, so the
/// UI reads identically either way. Matched case-insensitively against the
/// FULL error text (whatever prefix `Error`'s `Display`/`trim_error_body`
/// put in front of it) rather than anchored to a position, since Core and
/// Esplora don't even agree on where in the string the reason token sits.
/// `None` for anything not recognized — the existing pass-through/
/// [`friendly_net_err`] path handles those exactly as before.
fn map_broadcast_rejection(e: &str) -> Option<&'static str> {
    let lower = e.to_ascii_lowercase();
    const ALREADY: &[&str] = &[
        "txn-already-known",
        "already-known",
        "already in block chain",
        "already have transaction",
        "already in the mempool",
        "already in mempool",
    ];
    const LOW_FEE: &[&str] = &[
        "min relay fee not met",
        "insufficient fee",
        "min-relay-fee-not-met",
        "mempool min fee not met",
    ];
    const MISSING_INPUTS: &[&str] =
        &["missing inputs", "missingorspent", "bad-txns-inputs-missingorspent"];
    const NON_FINAL: &[&str] =
        &["non-final", "non-bip68-final", "bad-txns-nonfinal", "transaction is not final"];

    if ALREADY.iter().any(|s| lower.contains(s)) {
        Some("already broadcast — this transaction is already on the network")
    } else if LOW_FEE.iter().any(|s| lower.contains(s)) {
        Some("fee too low — increase the fee and try again")
    } else if MISSING_INPUTS.iter().any(|s| lower.contains(s)) {
        Some("inputs missing or already spent — this transaction can't be sent")
    } else if NON_FINAL.iter().any(|s| lower.contains(s)) {
        Some("not final yet — try again once its timelock has passed")
    } else {
        None
    }
}

/// Broadcast-failure sites see a stringified `app_core::Error` (workers
/// already `.map_err(|e| format!("{e}"))` before crossing the thread
/// boundary — see the `client.broadcast()` call sites). A TRANSPORT-class
/// failure (`app_core::Error::Transport`, tagged by its Display impl with a
/// "transport: " prefix — chain.rs already retried it once and it still
/// didn't reach a server) reads as raw reqwest text like `error sending
/// request for url (...)`, which is Greek to a user on a weak connection;
/// swap it for a plain-language message naming the node host instead.
/// A recognized rejection condition (U5: already-broadcast, fee too low, a
/// missing input, a non-final locktime — [`map_broadcast_rejection`]) gets
/// ONE calm phrase regardless of which backend produced it. Anything else
/// — an unrecognized server rejection (`Error::Http`, e.g. "400 Bad
/// Request: bad-txns-in-belowout"), a local build/sign error, ... — goes
/// through [`friendly_net_err`] (a plain rejection like "400 Bad Request:
/// foo" passes through that untouched too; it only bites on a 429 or a
/// stray HTML body).
///
/// Applied ONLY at user-facing `set_status`/toast broadcast-failure sites;
/// every `cb:`/println! log line keeps the raw error verbatim (the
/// debugging contract — see the workspace CLAUDE.md's log-contract note).
fn friendly_broadcast_err(e: &str, base_url: &str) -> String {
    match e.strip_prefix("transport: ") {
        Some(_raw) => format!("network error reaching {} — check your connection", host_of(base_url)),
        None => match map_broadcast_rejection(e) {
            Some(msg) => msg.to_string(),
            None => friendly_net_err(e),
        },
    }
}

#[cfg(test)]
mod broadcast_err_tests {
    use super::*;

    #[test]
    fn transport_errors_become_a_friendly_host_message() {
        let e = "transport: error sending request for url (https://mempool.space/testnet4/api/tx)";
        assert_eq!(
            friendly_broadcast_err(e, "https://mempool.space/testnet4/api"),
            "network error reaching mempool.space — check your connection"
        );
    }

    #[test]
    fn transport_errors_fall_back_when_base_url_is_unknown() {
        let e = "transport: connection reset";
        assert_eq!(
            friendly_broadcast_err(e, ""),
            "network error reaching your node — check your connection"
        );
    }

    #[test]
    fn server_rejections_pass_through_untouched() {
        let e = "http: 400 Bad Request: bad-txns-in-belowout";
        assert_eq!(friendly_broadcast_err(e, "https://mempool.space/testnet4/api"), e);
    }

    #[test]
    fn non_broadcast_errors_pass_through_untouched() {
        let e = "no signed PSBT";
        assert_eq!(friendly_broadcast_err(e, "https://mempool.space/api"), e);
    }

    /// U5 (plan §2.1/§2.4): the four common rejection categories must read
    /// IDENTICALLY whether the raw text came from Core's short
    /// `testmempoolaccept` reject-reason tokens or from a
    /// `sendrawtransaction` RPC-error message forwarded verbatim — proving
    /// the mapping is keyed on the CONDITION, not on which backend's exact
    /// wording happened to arrive.
    #[test]
    fn already_broadcast_reads_identically_regardless_of_wording() {
        let core_testmempoolaccept = "http: 400: txn-already-known";
        let core_sendraw_rpc_error = "http: bitcoind [-27]: Transaction already in block chain";
        let esplora_like = "http: 400 Bad Request: already in mempool";
        let expected = "already broadcast — this transaction is already on the network";
        assert_eq!(friendly_broadcast_err(core_testmempoolaccept, "bitcoind+http://127.0.0.1:8332"), expected);
        assert_eq!(friendly_broadcast_err(core_sendraw_rpc_error, "bitcoind+http://127.0.0.1:8332"), expected);
        assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
    }

    #[test]
    fn fee_too_low_reads_identically_regardless_of_wording() {
        let core = "http: 400: min relay fee not met, 300 < 1000";
        let esplora_like = "http: 400 Bad Request: insufficient fee, rejecting replacement";
        let expected = "fee too low — increase the fee and try again";
        assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
        assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
    }

    #[test]
    fn missing_inputs_reads_identically_regardless_of_wording() {
        let core = "http: 400: bad-txns-inputs-missingorspent";
        let esplora_like = "http: 400 Bad Request: missing inputs";
        let expected = "inputs missing or already spent — this transaction can't be sent";
        assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
        assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
    }

    #[test]
    fn non_final_reads_identically_regardless_of_wording() {
        let core = "http: 400: non-final";
        let esplora_like = "http: 400 Bad Request: transaction is not final";
        let expected = "not final yet — try again once its timelock has passed";
        assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
        assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
    }

    /// The pre-existing 429-in-a-fee-body guard ([`friendly_net_err`]'s own
    /// `a_429_sat_amount_in_a_rejection_is_not_a_rate_limit` test) must
    /// stay intact through this new layer too: a literal "429" sat amount
    /// inside a min-relay-fee rejection must land on the FEE message, never
    /// the "server is busy" one — `map_broadcast_rejection` runs BEFORE
    /// `friendly_net_err`'s 429 check ever sees this text.
    #[test]
    fn a_429_sat_amount_in_a_fee_rejection_still_maps_to_fee_too_low_not_rate_limit() {
        let e = "http: 400: sendrawtransaction min relay fee not met, 429 < 1000";
        assert_eq!(
            friendly_broadcast_err(e, "bitcoind+http://127.0.0.1:8332"),
            "fee too low — increase the fee and try again"
        );
    }
}

fn activate(st: &mut State, material_str: &str, persist: bool) -> Result<(), String> {
    let material =
        parse_key_material(material_str, st.network).map_err(|e| e.to_string())?;
    let ident =
        realize(&material, st.network, st.account, st.nb_index).map_err(|e| e.to_string())?;
    if persist {
        // Overwrites any existing entry — including one the user just chose to
        // ignore at the "Restore saved key" door. Safe by construction: the
        // two-phase write never leaves the device without a copy (audit H1).
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim(), st.icloud_backup)?;
        // Saving a key IS the opt-in for automatic unlock, same as restoring
        // one — from here launches unlock on their own (after the first frame).
        st.saved_key_present = true;
        if !st.auto_unlock {
            st.auto_unlock = true;
            st.save_config(); // or the opt-in dies with the process
        }
    }
    st.material = Some(Zeroizing::new(material_str.trim().to_string()));
    // U7 (Bitcoin Core RPC ranged-watch wiring): (re)computed HERE, the
    // established choke point for every (identity, account, network)
    // change (boot, import, restore, network switch, account switch —
    // `activate()` is the sole place all of those funnel through), so the
    // account-level EC derivation this does runs once per such change
    // rather than on every one of `open_client_watched`'s call sites.
    // Cheap to always compute regardless of the active backend — it's only
    // READ when `open_client_watched` finds a Core transport underneath.
    st.core_rpc_watch =
        app_core::chain::identity_watch_descriptors(material_str.trim(), st.network, st.account);
    // Funding-unification M3: the spending wallet is per (identity,
    // account) — reset session state on every activate() (boot, network/
    // account switch, identity reset→reimport) and recompute capability
    // from the fresh material. Cheap: no chain call, just a key-type check.
    st.spending_capable = app_core::spending::can_derive_spending(&material);
    st.spending_source = None;
    st.spending_coins.clear();
    st.spending_scanned = false;
    // Taproot change-chain coins are per (identity, account, network) — but
    // UNLIKE the spending wallet above, they must survive a mere notebook
    // switch WITHIN the same context: they're account-level (shared by every
    // notebook of the account) and no wallet-stores rescan follows a plain
    // notebook open, so wiping them here left the compose Pay-from panel
    // unable to offer change coins (unit 7 regtest e2e caught this). Clear
    // ONLY when the (fp8, network, account) context actually changes — a
    // genuine identity/account/network switch; a same-context re-activation
    // keeps the last scan's coins until the next wallet-stores refresh
    // replaces them (its `(fp8,network,account)` staleness guard still drops
    // any result from the wrong context).
    let change_ctx = index_fp8(&material, st.network)
        .ok()
        .map(|fp8| (fp8, st.network, st.account));
    if st.change_coins_ctx != change_ctx {
        st.change_coins.clear();
        st.change_coins_ctx = None;
    }
    let fp = hex::encode(ident.output_x());
    let path = st
        .data_dir
        .join(format!("store-{}-{}.json", st.network.as_str(), &fp[..8]));
    let store_existed = path.exists();
    let mut store = Store::load(&path).unwrap_or_else(|_| Store::new(&ident.output_x(), st.network));
    // Migrate a legacy per-identity node URL (shipped as `esplora`) into the
    // device-level per-network config, then drop it from the store. Only if
    // this network has no node set yet, so a real config choice always wins.
    if let Some(url) = store.node_url.take() {
        st.node_urls.entry(st.network.as_str().to_string()).or_insert(url);
    }
    // The note-size limit is a device-level Settings choice: apply it to
    // whichever notebook is being activated (stores of users who never
    // touched the pill keep their own value).
    if let Some(c) = st.chunk {
        store.chunk_size = c;
    }
    store.lock_time = st.lock_time_policy;
    println!(
        "cb: identity kind={} account={} index={} network={} address={}",
        ident.kind,
        ident.account,
        ident.index,
        st.network.as_str(),
        ident.address
    );
    // Notebook index: load (or start) this identity's per-account
    // index→name/archive map (v1 accounts-as-notebooks files migrate on
    // load) and rebuild the (index, address) cache — for the ACTIVE
    // account — the notebook list + sender labels read. Notebooks are
    // created DELIBERATELY (the name-first dialog, an import's account
    // pick — via ensure_notebook); activate() itself adds one only for:
    //   * migration: a pre-notebooks install (no index file yet, but this
    //     leaf already has a store on disk) becomes notebook "Main"
    //     (the one notebook that does not take the default name);
    //   * non-multi-notebook identities (WIF/hex): exactly one intrinsic
    //     notebook — nothing to choose, nothing to create.
    // Saving the (possibly empty) index on first touch marks the identity
    // as initialized, so later boots respect an emptied list.
    let fp8 = index_fp8(&material, st.network).map_err(|e| e.to_string())?;
    let ix_path = st
        .data_dir
        .join(format!("notebooks-{}-{}.json", st.network.as_str(), fp8));
    let index_existed = ix_path.exists();
    let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
    let migrate = !index_existed && store_existed;
    let mut dirty = !index_existed;
    if (migrate || !material.is_multi_notebook()) && ix.ensure(ident.account, ident.index) {
        if migrate {
            ix.rename(ident.account, ident.index, app_core::notebooks::FIRST_NOTEBOOK_NAME);
        }
        dirty = true;
    }
    if dirty {
        let _ = ix.save(&ix_path);
    }
    st.nb_addrs = ix
        .books(st.account)
        .iter()
        .filter_map(|m| {
            realize(&material, st.network, st.account, m.index)
                .ok()
                .map(|i| (m.index, i.address.clone(), hex::encode(&i.output_x()[..4])))
        })
        .collect();
    // Cross-account self labels (rev-3 follow-up 3, Sal 2026-07-12):
    // realize every OTHER account's listed notebooks into an
    // address → account map, so sender_label can say "Self · account N"
    // for directed notes between our own accounts. Cheap — the index file
    // lists exactly what to derive.
    st.xacct_addrs = ix
        .accounts
        .iter()
        .filter(|a| a.account != st.account)
        .flat_map(|a| a.notebooks.iter().map(move |m| (a.account, m.index)))
        .filter_map(|(acct, idx)| {
            realize(&material, st.network, acct, idx).ok().map(|i| (acct, i.address.clone()))
        })
        .collect();
    // Gap discovery is due when this identity's index file is FRESH for
    // multi-notebook material (a seed re-import; rev-3 follow-up 2). The
    // probe itself runs later on a worker thread (maybe_start_discovery)
    // — NEVER here: activate() sits on the iOS-watchdogged launch path.
    if !index_existed && material.is_multi_notebook() {
        st.discovery_pending = true;
    }
    // Funding-unification M3.1: stamp the RUNTIME spending cache from the
    // ACCOUNT-level section in the notebooks index — every notebook of
    // this account (this one included) shares it, so re-activating any of
    // them always reads the same enabled flag / indexes / used list.
    store.spending = ix.spending_for(st.account);
    st.notebooks_fp8 = Some(fp8);
    st.notebooks = Some(ix);
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    st.save_config();
    Ok(())
}

fn is_hierarchical(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_hierarchical()).unwrap_or(false)
}

/// Whether the material can hold more than one notebook (receive indexes
/// of one account) — everything but raw WIF/hex keys, including ranged
/// watch-only descriptors.
fn is_multi_notebook(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_multi_notebook()).unwrap_or(false)
}

/// One picker page: 5 ACCOUNTS, each shown by its notebook-0 address.
fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i, 0).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

/// One picker page: 5 NOTEBOOK ADDRESSES — receive-chain indexes `0/i`
/// of the ACTIVE account (create-notebook / consolidate-destination
/// rows).
fn index_rows(st: &State, page: u32) -> Vec<AccountItem> {
    let Some(material_str) = st.material.as_deref() else { return vec![] };
    let Ok(material) = parse_key_material(material_str, st.network) else { return vec![] };
    let active = st.ident.as_ref().map(|i| i.index);
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, st.network, st.account, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

/// The create-notebook flavor of the picker: 5-per-page NOTEBOOK ADDRESS
/// rows (receive indexes of the active account), plus a "notebook" pill
/// for indexes already in the index file and — when a node is configured —
/// a used/new pill with the address's current balance, so recovering an
/// already-used address is a visible, deliberate choice.
fn show_notebook_picker(w: &AppWindow, st: &State, page: u32, mode: &str) {
    if st.material.is_none() {
        return;
    }
    // Paint immediately with local data — the "notebook" pill for indexes
    // already in the index file, plain rows otherwise. The used/new probe
    // is network, so it runs OFF the main thread below; before this, tapping
    // "+ New notebook" hung the UI on up to 5 blocking HTTP calls
    // (Sal 2026-07-13).
    let mut rows = index_rows(st, page);
    let mut to_probe: Vec<(u32, String)> = Vec::new(); // (receive index, address)
    for row in &mut rows {
        let index = row.index as u32;
        if st.notebooks.as_ref().and_then(|ix| ix.get(st.account, index)).is_some() {
            row.pill = "notebook".into();
        } else {
            to_probe.push((index, row.address.to_string()));
        }
    }
    w.set_account_page(page as i32);
    w.set_accounts(VecModel::from_slice(&rows));
    w.set_account_pick_mode(mode.into());
    w.set_screen(9);

    // Probe used/new on a worker thread; results fill the pills in via the
    // apply-pending-picker-probe trampoline (offline / no rows → plain rows).
    let Some(base) = st.base_url() else { return };
    if to_probe.is_empty() {
        return;
    }
    let network = st.network;
    let account = st.account;
    let creds = core_rpc_creds_for(st, &base, network);
    let watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let mut results: Vec<(u32, &'static str, String)> = Vec::new();
        // A malformed node URL degrades exactly like "offline" below (empty
        // results → plain rows) rather than a new error path.
        if let Ok(client) = open_client_watched(&base, network, creds, &watch) {
            for (index, addr) in &to_probe {
                if let Ok((used, balance)) = client.address_probe(addr) {
                    let pill = if used { "used" } else { "new" };
                    let bal = if used { format!("{} sats", commas(balance)) } else { String::new() };
                    results.push((*index, pill, bal));
                }
            }
        }
        PICKER_PROBE_RESULTS
            .lock()
            .expect("picker probe mutex")
            .push(PickerProbeResult { account, page, rows: results });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_picker_probe());
    });
}

fn show_account_picker(w: &AppWindow, material: &str, network: Network, page: u32, active: Option<u32>) {
    w.set_account_page(page as i32);
    w.set_accounts(VecModel::from_slice(&account_rows(material, network, page, active)));
    w.set_screen(9);
}

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
fn refresh_contacts(w: &AppWindow, st: &State) {
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
        })
        .collect();
    w.set_contacts(VecModel::from_slice(&contacts));
}

/// Every contact in the iCloud KV blob is there BECAUSE it's synced —
/// stamp `synced = true` on each incoming contact before merging, so a
/// contact that lives in the cloud stays flagged synced locally (and
/// `merge_state` carries that flag through when incoming wins). See the
/// opt-in-sync rule in `app_core::contacts`.
fn mark_incoming_synced(state: &mut app_core::contacts::ContactState) {
    for c in &mut state.contacts {
        c.synced = true;
    }
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
fn apply_icloud_contacts_merge(w: &AppWindow, st: &mut State) {
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
        refresh_contacts(w, st);
    }
}

/// Pull the latest contacts from iCloud and merge them in before showing
/// the send-to picker (screen 7), so a contact named/synced on the user's
/// OTHER device appears the moment they open the picker — not only after a
/// restart or a live observer notification. `icloud::load_blob` calls
/// `synchronize()` (a local-cache sync, not a blocking network round trip),
/// so this is cheap enough to call directly on the UI thread. Every
/// incoming contact is synced by definition — mark it before merging.
fn pull_icloud_contacts_on_open(w: &AppWindow, st: &mut State) {
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
    refresh_contacts(w, st);
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
fn sync_contacts_now(w: &AppWindow, st: &mut State) {
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
    refresh_contacts(w, st);
}

/// The ONE sanctioned recipient-setting path for normal (non-sweep) compose:
/// validates/normalizes `addr`, saves it to contacts (creates-if-absent +
/// bumps recency), refreshes recents, sets `to-label`/`to-address`/
/// `directed`, resets every compose-session field (fee tier, coin
/// selection, change choice, gift amount, pay-from default), and lands on
/// screen 6. Shared by the normal contact picker (`on_pick_contact`) and
/// Reply (`on_reply_to_note`) so both go through identical logic.
fn pick_contact_core(w: &AppWindow, st: &mut State, addr: &str) {
    // Lands on compose (screen 6), which shows fee tiers + the USD cost
    // line — lazily (re)fetch before the cost-line math below reads
    // `st.fees`/`st.usd` (network-efficiency, 2026-07-23).
    refresh_fees_price(w, st);
    if addr == "self" {
        st.to_address = None;
        // Uniform To section (Sal, 2026-07-19): the row shows just the
        // name/address now — the "To" CAPTION above it carries that label,
        // so the value itself drops the "To: " prefix.
        w.set_to_label("Self (my notebook)".into());
        w.set_directed(false);
        println!("cb: pick-contact to=self");
    } else {
        let mut a = normalize_addr(addr);
        if Recipient::parse(st.network, &a).is_err() {
            let lower = a.to_lowercase();
            if Recipient::parse(st.network, &lower).is_ok() {
                a = lower;
            } else {
                println!("cb: pick-contact err=bad-address");
                w.set_status(format!("not a valid {} address", st.network.as_str()).into());
                return;
            }
        }
        println!("cb: pick-contact to={a}");
        st.touch_contact(&a);
        st.save_contacts();
        // Rebuild the recents now so the address is in the list when the
        // user presses Back from compose.
        refresh_contacts(w, st);
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
        w.set_to_label(display.into());
        st.to_address = Some(a);
        w.set_directed(true);
    }
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    if st.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        w.set_compose_private(false); // no sealing key on this device
    }
    w.set_fee_tier(1);
    w.set_rate_text(format!("{rate}").into());
    w.set_change_address("".into());
    w.set_change_expanded(false);
    w.set_spend_expanded(false);
    st.coins_overridden = false;
    st.consolidate_coins = false;
    w.set_coin_strategy(0);
    w.set_gift_sats(format!("{DUST_SATS}").into());
    w.set_gift_expanded(false);
    st.selected_coins.clear();
    w.set_status("".into());
    w.set_payfrom_expanded(false);
    // Funding-unification UI rework: fresh compose session, fresh
    // cross-wallet coin memory + change pick (an explicit change choice
    // from a PRIOR note must never leak into this one).
    st.mixed_selected.clear();
    st.change_choice.clear();
    w.set_change_choice("".into());
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
    w.set_picking_extra(false);
    refresh_to_chips(w, st);
    resolve_payfrom_default(w, st);
    // A fresh compose session — the locktime override never survives past
    // the screen it was set on (see `reset_tx_lock_time_override`'s doc
    // comment).
    st.reset_tx_lock_time_override();
    w.set_compose_locktime_expanded(false);
    refresh_compose_locktime_panel(w, st);
    w.set_screen(6);
    refresh_compose(w, st);
}

/// Refresh the compose screen's removable To-chips (`AppWindow.to-chips`)
/// from `st.to_addresses_extra`, resolving each address to its contact
/// name (if any) the same way the confirm screen's `recipient_name`
/// lookup does. Called whenever the extra-recipient list changes: a fresh
/// primary pick (cleared), `on_add_chip` (appended), `on_remove_chip`
/// (removed).
fn refresh_to_chips(w: &AppWindow, st: &State) {
    let rows: Vec<ContactItem> = st
        .to_addresses_extra
        .iter()
        .map(|a| {
            let name = st
                .contacts
                .iter()
                .find(|c| &c.address == a && !c.name.is_empty())
                .map(|c| c.name.clone())
                .unwrap_or_default();
            ContactItem { address: a.clone().into(), name: name.into(), synced: false, sync_status: 0 }
        })
        .collect();
    w.set_to_chips(VecModel::from_slice(&rows));
}

/// Multi-select: append `addr` to `st.to_addresses_extra` (validated,
/// normalized/lowercased the same way `pick_contact_core` handles a typo'd
/// address case, deduped against BOTH the primary `to_address` and the
/// existing extras, capped at 255 total recipients — the UI selection cap;
/// notes-core's own compose-time 1..=255 dedupe is the wire-level
/// backstop). Touches the contact (recency) and returns to compose
/// (screen 6), reusing the SAME `refresh_compose` the primary picker uses
/// so the cost line/preview updates immediately.
fn add_recipient_chip(w: &AppWindow, st: &mut State, addr: &str) {
    let mut a = normalize_addr(addr);
    if a == "self" || a.is_empty() {
        w.set_status("pick an address".into());
        return;
    }
    let parsed = match Recipient::parse(st.network, &a) {
        Ok(r) => r,
        Err(_) => {
            let lower = a.to_lowercase();
            match Recipient::parse(st.network, &lower) {
                Ok(r) => {
                    a = lower;
                    r
                }
                Err(_) => {
                    println!("cb: add-chip err=bad-address");
                    w.set_status(format!("not a valid {} address", st.network.as_str()).into());
                    return;
                }
            }
        }
    };
    // Same inline error pattern as the single-recipient compose path
    // (notes-core's `Error::RecipientNotTaproot`, surfaced when Sign is
    // tapped) — checked proactively here too, before it's even added as a
    // chip, since private+non-taproot is knowable immediately.
    if w.get_compose_private() && parsed.p2tr_x.is_none() {
        println!("cb: add-chip err=not-taproot");
        w.set_status("private directed notes need a taproot (bc1p…) recipient".into());
        return;
    }
    let already = st.to_address.as_deref() == Some(a.as_str()) || st.to_addresses_extra.iter().any(|x| x == &a);
    st.picking_extra = false;
    w.set_picking_extra(false);
    if already {
        println!("cb: add-chip dup");
        w.set_status("already added".into());
        w.set_screen(6);
        return;
    }
    let total = 1 + st.to_addresses_extra.len();
    if total >= 255 {
        println!("cb: add-chip err=limit");
        w.set_status("recipient limit reached (255)".into());
        w.set_screen(6);
        return;
    }
    st.touch_contact(&a);
    st.save_contacts();
    refresh_contacts(w, st);
    st.to_addresses_extra.push(a.clone());
    println!("cb: add-chip n={}", st.to_addresses_extra.len() + 1);
    refresh_to_chips(w, st);
    w.set_screen(6);
    refresh_compose(w, st);
}

/// Funding-unification: default "Pay from" to the spending wallet ONLY when
/// the setting is on AND it actually has spendable balance (Sal
/// 2026-07-16) — an enabled-but-empty spending wallet still defaults to
/// Notebook. Balance is whatever's cached this session; an unscanned wallet
/// reads as 0 and falls through to Notebook too (never guess a positive
/// balance we haven't confirmed). A watch identity has no spending wallet
/// at all. Shared by `pick_contact_core` (fresh compose session) and
/// `apply_spending_refresh_results` (CHANGE 5: a landed scan re-resolves
/// the default for a user already sitting on compose, as long as they
/// haven't made an explicit pick yet this session — `payfrom_manual`).
fn resolve_payfrom_default(w: &AppWindow, st: &mut State) {
    let spending_balance: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    let spending_default = st.spending_capable
        && !st.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false)
        && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
        && spending_balance > 0;
    let default_source = if spending_default { "spending" } else { "notebook" };
    st.payfrom_active_source = default_source.to_string();
    apply_pay_from(w, st, default_source);
}

/// Deliberate notebook creation for receive `index` of the ACTIVE
/// account: add it to the index file (if missing), persist, and extend
/// the address cache. The ONLY entry points are user intent — the create
/// dialog, an import's account pick (notebook 0), and APP_KEY automation
/// boots (their index choice is explicit config).
fn ensure_notebook(st: &mut State, index: u32) {
    let account = st.account;
    let Some(ix) = st.notebooks.as_mut() else { return };
    if !ix.ensure(account, index) {
        return;
    }
    st.save_notebooks();
    if !st.nb_addrs.iter().any(|(a, ..)| *a == index) {
        if let Some(material_str) = st.material.as_deref() {
            if let Ok(material) = parse_key_material(material_str, st.network) {
                if let Ok(i) = realize(&material, st.network, account, index) {
                    st.nb_addrs.push((
                        index,
                        i.address.clone(),
                        hex::encode(&i.output_x()[..4]),
                    ));
                }
            }
        }
    }
}

/// Ensure the account's notebook 0 exists (first receive address) and, if it
/// has no name yet, auto-name it for the onboarding list view.
/// Sal 2026-07-21: onboarding (create/import/restore) lands on the notebook
/// LIST with this first row already named, rather than opening the
/// notebook's home. The name is the shared default, "Notebook 1"
/// (`notebooks::default_name`) — same as every other creation path since
/// 2026-07-26. (The pre-notebooks migration path names its first notebook
/// "Main" — see notebooks::FIRST_NOTEBOOK_NAME — that path is untouched.)
fn ensure_first_onboarded_notebook(s: &mut State) {
    ensure_notebook(s, 0);
    let account = s.account;
    if let Some(ix) = s.notebooks.as_mut() {
        let unnamed = ix.get(account, 0).map(|m| m.name.is_empty()).unwrap_or(true);
        if unnamed {
            ix.rename(account, 0, &app_core::notebooks::default_name(0));
        }
    }
    s.save_notebooks();
}

/// "Home" for flows that end at the active notebook — unless the active
/// account has no notebook entry, in which case home would be a trap only
/// reachable by accident: land on the notebook list instead. Since the
/// onboarding unification (Sal 2026-07-21: create/import/restore all
/// ensure notebook 0 and open its home) the unlisted case is rare —
/// e.g. an account whose every notebook was archived — but the guard
/// stays for exactly those.
/// Wipe any revealed key-export material from the UI (nav away / reset /
/// hide) AND drop the cached private-reveal formats (`State.reveal_formats`
/// — the only place a freshly-authenticated secret is held; dropping it
/// zeroizes via `Zeroizing`). Values otherwise live only in these props, so
/// clearing them is the wipe.
fn clear_reveal(w: &AppWindow, s: &mut State) {
    let empty: Vec<RevealRow> = Vec::new();
    w.set_reveal_public_rows(VecModel::from_slice(&empty));
    w.set_reveal_public_hint("".into());
    w.set_reveal_fingerprint("".into());
    w.set_reveal_has_recovery(false);
    w.set_reveal_has_xprv(false);
    w.set_reveal_has_hex(false);
    w.set_reveal_has_wif(false);
    w.set_reveal_private_format("".into());
    w.set_reveal_private_value("".into());
    w.set_reveal_private_qr(slint::Image::default());
    w.set_reveal_words_col1("".into());
    w.set_reveal_words_col2("".into());
    w.set_reveal_show_seedqr(false);
    w.set_reveal_seedqr_image(slint::Image::default());
    w.set_reveal_nb_rows(VecModel::from_slice(&Vec::<NbPickRow>::new()));
    w.set_reveal_nb_index(0);
    s.reveal_formats = None;
}

/// The active account's notebook picker rows for the Private-keys hex/WIF
/// views (archived notebooks excluded — matches the notebook list). `name`
/// falls back to the short address when unnamed (`notebook_display_name`),
/// `addr` is always the short address so an unnamed row isn't just a
/// duplicate string.
fn private_nb_rows(st: &State) -> Vec<NbPickRow> {
    let Some(ix) = &st.notebooks else { return Vec::new() };
    ix.books(st.account)
        .iter()
        .filter(|m| !m.archived)
        .map(|m| {
            let addr = st
                .nb_addrs
                .iter()
                .find(|(a, ..)| *a == m.index)
                .map(|(_, a, _)| addr_short(a))
                .unwrap_or_default();
            // Named notebooks show their name; unnamed ones read the
            // default "Notebook <index+1>" (not the address again — the
            // addr already sits in its own column).
            let name = if m.name.trim().is_empty() {
                app_core::notebooks::default_name(m.index)
            } else {
                m.name.clone()
            };
            NbPickRow {
                index: m.index as i32,
                name: name.into(),
                addr: addr.into(),
            }
        })
        .collect()
}

/// Derive the CURRENTLY-selected picker notebook's hex/WIF leaf key from
/// the session-cached material (no re-auth) — shared by `private-select`
/// (switching format pills) and `private-pick-notebook` (switching
/// notebooks), so whichever changes last always shows the right value.
fn derive_leaf_value(s: &State, w: &AppWindow, which: &str) -> Option<String> {
    let material = s.material.as_ref().map(|z| String::from(z.as_str()))?;
    let index = w.get_reveal_nb_index() as u32;
    let f = app_core::keyexport::export_formats(&material, s.network, s.account, index).ok()?;
    match which {
        "hex" => f.leaf_hex.as_ref().map(|z| z.as_str().to_string()),
        "wif" => f.leaf_wif.as_ref().map(|z| z.as_str().to_string()),
        _ => None,
    }
}

fn go_home_or_list(w: &AppWindow, st: &State) {
    let listed = st
        .ident
        .as_ref()
        .and_then(|i| st.notebooks.as_ref().map(|ix| ix.get(i.account, i.index).is_some()))
        .unwrap_or(false);
    if listed {
        update_home(w, st);
        w.set_screen(4);
    } else {
        update_notebook_list(w, st);
        w.set_screen(17);
    }
}

/// Route a validated sweep destination to the compose-like sweep screen:
/// label (notebook name → contact name → bare address), the on-chain
/// linkage caveat when the destination is one of OUR notebooks (and no
/// contacts pollution for those), fee tier defaults, screen 16.
fn set_sweep_dest(w: &AppWindow, st: &mut State, a: String) {
    // Lands on the sweep/consolidate screen (16), which shows fee tiers —
    // lazily (re)fetch before `update_sweep_screen` below reads `st.fees`
    // (network-efficiency, 2026-07-23).
    refresh_fees_price(w, st);
    let own_index = st.nb_addrs.iter().find(|(_, ad, _)| *ad == a).map(|(idx, ..)| *idx);
    match own_index {
        Some(acct) => {
            println!("cb: sweep-pick to={a} (notebook {acct})");
            w.set_sweep_to_label(
                format!(
                    "Everything to: {} · {}",
                    st.notebook_display_name(acct),
                    addr_short(&a)
                )
                .into(),
            );
            w.set_sweep_dest_note(
                "Heads up: sweeping between your own notebooks publicly links their addresses on-chain.".into(),
            );
        }
        None => {
            println!("cb: sweep-pick to={a}");
            st.touch_contact(&a);
            st.save_contacts();
            refresh_contacts(w, st);
            let name = st
                .contacts
                .iter()
                .find(|c| c.address == a)
                .map(|c| c.name.clone())
                .filter(|n| !n.is_empty());
            w.set_sweep_to_label(
                match &name {
                    Some(n) => format!("Everything to: {n} · {a}"),
                    None => format!("Everything to: {a}"),
                }
                .into(),
            );
            w.set_sweep_dest_note("".into());
        }
    }
    w.set_sweep_dest(a.into());
    w.set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.set_sweep_rate_text(format!("{rate}").into());
    w.set_sweep_fund_external(false);
    w.set_sweep_inputs_expanded(false);
    // A fresh sweep session — the locktime override never survives past
    // the screen it was set on (see `reset_tx_lock_time_override`'s doc
    // comment).
    st.reset_tx_lock_time_override();
    w.set_sweep_locktime_expanded(false);
    refresh_sweep_locktime_panel(w, st);
    w.set_status("".into());
    update_sweep_screen(w, st);
    w.set_screen(16);
}

/// The per-notebook self-consolidate flow (screen 16, kind
/// "consolidate") — still the watch-only path, where signing happens on
/// an external wallet and one notebook is all there is.
fn open_notebook_consolidate(w: &AppWindow, st: &mut State) {
    // Lands on screen 16 (fee tiers shown) — see the matching comment in
    // `set_sweep_dest` (network-efficiency, 2026-07-23).
    refresh_fees_price(w, st);
    let spendable = st
        .store
        .as_ref()
        .map(|s| s.utxos.iter().filter(|u| !u.pending_spend).count())
        .unwrap_or(0);
    if spendable < 2 {
        w.set_status("nothing to consolidate (need 2+ coins)".into());
        return;
    }
    let Some(addr) = st.ident.as_ref().map(|i| i.address.clone()) else { return };
    println!("cb: consolidate-open coins={spendable}");
    w.set_sweep_kind("consolidate".into());
    w.set_sweep_dest(addr.clone().into());
    w.set_sweep_dest_note("".into());
    let nb_name = st
        .ident
        .as_ref()
        .map(|i| st.notebook_display_name(i.index))
        .unwrap_or_else(|| "this notebook".into());
    w.set_sweep_to_label(format!("Consolidate within {nb_name} · {}", addr_short(&addr)).into());
    w.set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.set_sweep_rate_text(format!("{rate}").into());
    w.set_sweep_fund_external(false);
    w.set_sweep_inputs_expanded(false);
    // A fresh consolidate session — same reset rule as `set_sweep_dest`.
    st.reset_tx_lock_time_override();
    w.set_sweep_locktime_expanded(false);
    refresh_sweep_locktime_panel(w, st);
    w.set_status("".into());
    update_sweep_screen(w, st);
    w.set_screen(16);
}

/// A (possibly inactive) notebook's store (by receive index within the
/// active account), read from its file on disk; the ACTIVE notebook
/// prefers the live in-memory store.
fn notebook_store(st: &State, index: u32) -> Option<Store> {
    if st.ident.as_ref().map(|i| i.index) == Some(index) {
        if let Some(s) = &st.store {
            return Some(s.clone());
        }
    }
    let (_, _, fp8) = st.nb_addrs.iter().find(|(a, ..)| *a == index)?;
    Store::load(&st.store_path_for(fp8)).ok()
}

/// Sender-filter label rules, in priority order: "Self · <notebook>" when
/// the sender is one of the ACTIVE account's addresses (this notebook's
/// own notes, or directed notes from a sibling notebook),
/// "Self · account N" when it belongs to another of our accounts (rev-3
/// follow-up 3 — accounts are separate wallets, but the sender is still
/// us), the contact name when known, else the short address form.
fn sender_label(st: &State, key: &str) -> String {
    if let Some((index, ..)) = st.nb_addrs.iter().find(|(_, a, _)| a == key) {
        return format!("Self · {}", st.notebook_display_name(*index));
    }
    if let Some((acct, _)) = st.xacct_addrs.iter().find(|(_, a)| a == key) {
        return format!("Self · account {acct}");
    }
    if let Some(c) = st.contacts.iter().find(|c| c.address == key && !c.name.is_empty()) {
        return c.name.clone();
    }
    addr_short(key)
}

/// Build the notebook-list rows (screen 17) from the index plus each
/// notebook's store on disk. Snippet and unread respect that notebook's
/// sender filter, so the row preview matches what opening it reveals.
fn update_notebook_list(w: &AppWindow, st: &State) {
    let Some(ix) = &st.notebooks else { return };
    w.set_can_create_notebook(
        st.material
            .as_deref()
            .map(|m| is_multi_notebook(m, st.network))
            .unwrap_or(false),
    );
    let mut active_rows: Vec<NotebookItem> = Vec::new();
    let mut archived_rows: Vec<NotebookItem> = Vec::new();
    for meta in ix.books(st.account) {
        let Some((_, address, _)) = st.nb_addrs.iter().find(|(a, ..)| *a == meta.index) else {
            continue;
        };
        let store = notebook_store(st, meta.index);
        let (snippet, meta_line, unread) = match &store {
            Some(s) => {
                let visible: Vec<&app_core::store::NoteRecord> = s.visible_notes().collect();
                let snippet = visible
                    .last()
                    .map(|n| {
                        n.text
                            .as_deref()
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                            .unwrap_or("(encrypted)")
                            .to_string()
                    })
                    .unwrap_or_else(|| "No notes yet".into());
                let meta_line = format!(
                    "{} · {} sats · {} note{}",
                    addr_short(address),
                    commas(s.balance()),
                    visible.len(),
                    if visible.len() == 1 { "" } else { "s" }
                );
                (snippet, meta_line, s.unread_visible_count())
            }
            None => ("No notes yet".into(), format!("{} · not scanned yet", addr_short(address)), 0),
        };
        let row = NotebookItem {
            index: meta.index as i32,
            name: st.notebook_display_name(meta.index).into(),
            snippet: snippet.into(),
            meta: meta_line.into(),
            unread: match unread {
                0 => "".into(),
                1 => "1 new".into(),
                n => format!("{n} new").into(),
            },
            active: st.ident.as_ref().map(|i| i.index) == Some(meta.index),
        };
        if meta.archived {
            archived_rows.push(row);
        } else {
            active_rows.push(row);
        }
    }
    println!("cb: notebooks list n={} archived={}", active_rows.len(), archived_rows.len());
    w.set_notebooks(VecModel::from_slice(&active_rows));
    w.set_archived_notebooks(VecModel::from_slice(&archived_rows));
    w.set_archived_toggle_label(
        if archived_rows.is_empty() {
            String::new()
        } else {
            format!("Archived ({})", archived_rows.len())
        }
        .into(),
    );
}

/// Populate the Settings screen's identity/network/note-size fields from
/// current state. Called by `update_home` (fresh whenever a notebook home
/// renders) AND by `on_settings_open` — so Settings is correct even when the
/// user reaches it WITHOUT first visiting a notebook's home. Onboarding now
/// lands on the notebook LIST (Sal 2026-07-21), not a home; before this,
/// `settings-hierarchical` (which gates the "Change account…" row) and the
/// note-size field were only ever set by `update_home`, so a fresh
/// hierarchical import that never opened a home showed no "Change account…"
/// row and a stale chunk value.
/// One line under the locktime pills spelling out what the current policy
/// would actually put on the wire — "chain height" is only meaningful if
/// the user knows which height we last scanned to.
fn locktime_caption(
    policy: app_core::notes_core::tx::LockTimePolicy,
    tip: Option<u64>,
) -> String {
    use app_core::notes_core::tx::LockTimePolicy;
    match policy {
        LockTimePolicy::Tip => match tip.filter(|h| *h > 0) {
            Some(h) => format!(
                "New transactions get locktime {h}, the height of your last scan."
            ),
            None => "Nothing scanned yet, so locktime stays 0 until the first sync.".to_string(),
        },
        LockTimePolicy::Zero => {
            "New transactions get locktime 0 — simplest, but stands out from most wallets."
                .to_string()
        }
        LockTimePolicy::Custom { height } => format!("New transactions get locktime {height}."),
    }
}

/// Parse a locktime mode pill + custom-height text into a `LockTimePolicy`,
/// the same validation `on_set_locktime` (device Settings) always used —
/// factored out so the compose (screen 6) and sweep/consolidate (screen
/// 16) override panels share IDENTICAL parsing/validation, not a second
/// hand-copied version. `None` = invalid (a custom height that doesn't
/// parse, or is `>= 500_000_000` — read by consensus as a UNIX timestamp,
/// never what someone typing a block height means).
fn parse_locktime_mode(mode: &str, height: &str) -> Option<app_core::notes_core::tx::LockTimePolicy> {
    use app_core::notes_core::tx::LockTimePolicy;
    match mode {
        "zero" => Some(LockTimePolicy::Zero),
        "custom" => match height.trim().parse::<u32>() {
            Ok(h) if h < 500_000_000 => Some(LockTimePolicy::Custom { height: h }),
            _ => None,
        },
        _ => Some(LockTimePolicy::Tip),
    }
}

/// The compose (screen 6) and sweep/consolidate (screen 16) locktime
/// panels' four display values for a given policy: the mode pill, the
/// custom-height field text (ALWAYS the currently-effective resolved
/// height, even outside Custom mode — mirrors `on_set_locktime`'s own
/// `locktime_text` convention, so tapping Custom starts from a sensible
/// seed instead of a blank field), the effective caption
/// (`locktime_caption` — the ONE wording source, shared with Settings),
/// and the future-tip warning (empty = none). This is the safety content
/// of the whole feature: our inputs signal RBF (nSequence 0xfffffffd), so
/// nLockTime is ENFORCED — a height above the tip makes the tx non-final
/// and the node rejects it outright.
fn locktime_panel_values(
    policy: app_core::notes_core::tx::LockTimePolicy,
    tip: Option<u64>,
) -> (String, String, String, String) {
    use app_core::notes_core::tx::LockTimePolicy;
    let tip32 = tip.and_then(|t| u32::try_from(t).ok());
    let resolved = policy.resolve(tip32);
    let mode = policy.as_str().to_string();
    let height_text = resolved.to_string();
    let effective = locktime_caption(policy, tip);
    let warn = match policy {
        LockTimePolicy::Custom { height } if tip32.is_some_and(|t| height > t) => format!(
            "Height {height} is above the current chain tip ({}) — this transaction won't be final, and the node will reject it until block {height}.",
            tip32.unwrap()
        ),
        _ => String::new(),
    };
    (mode, height_text, effective, warn)
}

/// Repaint the compose screen's locktime panel from `st`'s current
/// effective policy (override if the panel set one this session, else the
/// device default) — called on every fresh compose session AND after
/// every `on_set_compose_locktime` tap, so the panel always reflects
/// exactly what the next Sign would build with.
fn refresh_compose_locktime_panel(w: &AppWindow, st: &State) {
    let policy = st.tx_lock_time_override.unwrap_or(st.lock_time_policy);
    let tip = st.store.as_ref().map(|s| s.tip_height);
    let (mode, height, effective, warn) = locktime_panel_values(policy, tip);
    w.set_compose_locktime_mode(mode.into());
    w.set_compose_locktime_height(height.into());
    w.set_compose_locktime_effective(effective.into());
    w.set_compose_locktime_warn(warn.into());
}

/// Same as [`refresh_compose_locktime_panel`], for the sweep/consolidate
/// (screen 16) panel.
fn refresh_sweep_locktime_panel(w: &AppWindow, st: &State) {
    let policy = st.tx_lock_time_override.unwrap_or(st.lock_time_policy);
    let tip = st.store.as_ref().map(|s| s.tip_height);
    let (mode, height, effective, warn) = locktime_panel_values(policy, tip);
    w.set_sweep_locktime_mode(mode.into());
    w.set_sweep_locktime_height(height.into());
    w.set_sweep_locktime_effective(effective.into());
    w.set_sweep_locktime_warn(warn.into());
}

fn update_settings_identity(w: &AppWindow, st: &State) {
    let policy = st.lock_time_policy;
    w.set_locktime_mode(policy.as_str().into());
    w.set_locktime_text(st.lock_time().to_string().into());
    w.set_locktime_effective(
        locktime_caption(policy, st.store.as_ref().map(|s| s.tip_height)).into(),
    );
    w.set_settings_network(st.network.as_str().into());
    // Runs on every activate, including the import paths that never paint
    // home — see `update_identity_flags`.
    update_identity_flags(w, st);
    // Audit M2: surface a key-protection downgrade instead of letting it pass
    // silently. Recomputed here because this runs after every activate /
    // identity change, which is exactly when the answer can change.
    w.set_key_protection_degraded(st.ident.is_some() && keychain::protection_degraded());
    w.set_settings_hierarchical(
        st.material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false),
    );
    if let Some(i) = &st.ident {
        let (active_n, archived_n) = st
            .notebooks
            .as_ref()
            .map(|ix| (ix.active(st.account).count(), ix.archived_count(st.account)))
            .unwrap_or((0, 0));
        let acct_part = if st
            .material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false)
        {
            format!(" · account {}", st.account)
        } else {
            String::new()
        };
        w.set_settings_identity(
            format!(
                "{}{} · {}{acct_part} · {} notebook{}{}",
                i.kind,
                if i.is_watch() { " · watch-only" } else { "" },
                st.network.as_str(),
                active_n,
                if active_n == 1 { "" } else { "s" },
                if archived_n > 0 { format!(" ({archived_n} archived)") } else { String::new() }
            )
            .into(),
        );
    }
    if let Some(store) = &st.store {
        w.set_chunk_text(store.chunk_size.to_string().into());
    }
}

/// Identity-derived UI flags, refreshed on EVERY path that activates an
/// identity — not only the ones that paint home.
///
/// These lived in `update_home` alone, which meant they went stale after a
/// hierarchical seed import: `go_home_or_list` only calls `update_home` when
/// the notebook is already listed, and multi-notebook material deliberately
/// is not listed at import time, so the import landed on the notebook LIST
/// with both flags at their `false` defaults. Visible fallout: Settings hid
/// "Public keys" until the user opened a notebook once, and — worse — a
/// watch-only ranged xpub (also multi-notebook) left `watch-only` false, so
/// the UI offered "Private keys" and the compose surfaces for an identity
/// that has no private key. The Rust callbacks gate on `AppIdentity::full()`
/// so nothing could actually be signed, but the affordances should not have
/// been there. Boot was always fine — it calls `update_home` before landing.
fn update_identity_flags(w: &AppWindow, st: &State) {
    let Some(ident) = &st.ident else { return };
    w.set_watch_only(ident.is_watch());
    // Single-key imports (wif/hex) have no account-level public material —
    // no xpub/descriptor to export — so hide the "Public keys" entry rather
    // than route to a dead-end hint (mirrors hiding Private for watch-only).
    w.set_reveal_can_public(!matches!(ident.kind, "wif" | "hex"));
}

fn update_home(w: &AppWindow, st: &State) {
    let Some(ident) = &st.ident else { return };
    let Some(store) = &st.store else { return };
    let watch = ident.is_watch();
    update_identity_flags(w, st);
    w.set_notebook_title(st.notebook_display_name(ident.index).into());
    w.set_address(ident.address.as_str().into());
    if let Some(img) = qr::qr_image(&ident.address.to_uppercase()) {
        w.set_address_qr(img);
    }
    w.set_balance_line(
        format!("{} sats · block {}", commas(store.balance()), commas(store.tip_height as u64))
            .into(),
    );
    // Sender filter: the checklist model + the "hidden" pill, then the
    // notes list itself filtered through the persisted exclusion set.
    let senders: Vec<SenderItem> = store
        .senders()
        .into_iter()
        .map(|(key, count)| SenderItem {
            label: sender_label(st, &key).into(),
            sub: format!("{count} note{}", if count == 1 { "" } else { "s" }).into(),
            excluded: store.is_excluded(&key),
            key: key.into(),
        })
        .collect();
    let hidden = senders.iter().filter(|s| s.excluded).count();
    w.set_senders(VecModel::from_slice(&senders));
    w.set_hidden_senders_label(
        match hidden {
            0 => String::new(),
            1 => "1 sender hidden".into(),
            n => format!("{n} senders hidden"),
        }
        .into(),
    );
    let address = ident.address.clone();
    let net = st.network;
    let mut items: Vec<NoteItem> = store
        .notes
        .iter()
        .rev()
        .filter(|n| !store.is_excluded(&store.sender_key(n)))
        .map(|n| {
            let badge = match n.status {
                NoteStatus::Pending => "pending",
                NoteStatus::Confirmed => "confirmed",
                NoteStatus::Orphaned => "orphaned",
            };
            let kind = match (n.received, n.directed, n.private) {
                (true, _, true) => "received private",
                (true, _, false) => "received",
                (false, true, true) => "sent private",
                (false, true, false) => "sent",
                (false, false, true) => "private",
                (false, false, false) => "public",
            };
            NoteItem {
                id: n.note_id.clone().into(),
                title: n
                    .text
                    .as_deref()
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .unwrap_or(if watch && n.private {
                        "(private — key not on this device)"
                    } else {
                        "(not decryptable)"
                    })
                    .into(),
                badge: badge.into(),
                meta: format!(
                    "{kind}{}",
                    n.height.map(|h| format!(" · block {h}")).unwrap_or_default()
                )
                .into(),
                web_url: note_web_url(net, &address, &n.note_id).into(),
                private: n.private,
            }
        })
        .collect();
    items.sort_by_key(|i| i.badge == "confirmed");
    w.set_notes(VecModel::from_slice(&items));
    refresh_contacts(w, st);
    update_settings_identity(w, st);
    load_backend_settings(w, st);
    update_wallet_coins(w, st);
    update_spending_ui(w, st);
}

/// The wallet-wide coins viewer (screen 10 + the Settings Coins card):
/// every ACTIVE notebook's spendable UTXOs, each tagged with its
/// notebook, plus the cross-wallet summary — data as of each notebook's
/// last scan (the ↻ on the coins screen rescans them all). Taproot
/// change-chain coins (`st.change_coins`, unit 3 — see
/// `../PLAN-chain-notes-app-taproot-change.md`) are folded into the SAME
/// list, each tagged "change" instead of a notebook name (Sal's decision:
/// one unified balance, not a separate segment) — they count toward the
/// total coin count and spendable sats but NOT toward the "M notebooks"
/// count below (they don't belong to any one notebook). The wallet Sweep
/// consumes them (unit 6) — this list is display-only for that; compose /
/// pay-from and watch-only still don't consume them (later units).
fn update_wallet_coins(w: &AppWindow, st: &State) {
    let mut coins: Vec<CoinItem> = Vec::new();
    let mut spendable: u64 = 0;
    let mut notebooks = 0usize;
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            let name = st.notebook_display_name(m.index);
            let mut any = false;
            for u in store.utxos.iter().filter(|u| !u.pending_spend) {
                coins.push(CoinItem {
                    outpoint: format!("{}:{}", u.txid, u.vout).into(),
                    value: u.value.to_string().into(),
                    status: if u.height.is_some() { "confirmed" } else { "unconfirmed" }.into(),
                    notebook: name.clone().into(),
                });
                spendable += u.value;
                any = true;
            }
            if any {
                notebooks += 1;
            }
        }
    }
    for c in &st.change_coins {
        coins.push(CoinItem {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            status: if c.confirmed { "confirmed" } else { "unconfirmed" }.into(),
            notebook: "change".into(),
        });
        spendable += c.value;
    }
    let n = coins.len();
    w.set_coins(VecModel::from_slice(&coins));
    // The aggregate (both pools) belongs ONLY on the Settings Coins card,
    // which has no segments of its own. The Coins SCREEN's notebook segment
    // and the notebook-consolidate confirm keep the notebook-only line —
    // Sal 2026-07-17: "spending: 2 coins" on a segment that shows no
    // spending coins is misleading (the spending segment is one tap away).
    let spending_state = if st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false) {
        if !st.spending_scanned {
            Some(app_core::mixed::SpendingSummaryState::NotScanned)
        } else {
            let sats: u64 = st.spending_coins.iter().map(|c| c.value).sum();
            Some(app_core::mixed::SpendingSummaryState::Scanned { n: st.spending_coins.len(), sats })
        }
    } else {
        None
    };
    w.set_coins_summary(app_core::mixed::coins_summary_line(n, spendable, notebooks, None).into());
    w.set_coins_summary_settings(
        app_core::mixed::coins_summary_line(n, spendable, notebooks, spending_state).into(),
    );
}

/// Apply one (already network-fetched) bundle to a NON-active notebook's
/// store file on disk — the per-notebook body of a wallet-wide rescan for
/// every notebook except the one currently open (see
/// `wallet_stores_refresh_async`/`apply_wallet_stores_refresh_results`,
/// and the doc comment on the old synchronous `refresh_wallet_stores` this
/// replaced). `material` is parsed once by the caller for the whole batch.
/// Best-effort: any failure (realize/apply) is silently skipped, exactly
/// like the old loop's `continue`. `spending_window_spks` (spending-self-
/// notes fix, Unit A): the caller derives it ONCE per wallet-wide scan
/// (`spending_window_spks_for`) and threads it through unchanged — the
/// spending wallet is account-level (shared across every notebook), so one
/// derivation covers this whole batch; an empty slice is a strict no-op.
fn apply_bundle_to_notebook_file(
    st: &State,
    material: &app_core::identity::KeyMaterial,
    notebook_spks: &[Vec<u8>],
    spending_window_spks: &[Vec<u8>],
    index: u32,
    bundle: &app_core::notes_core::bundle::SyncBundle,
) -> bool {
    let Ok(ident) = realize(material, st.network, st.account, index) else { return false };
    let mut store =
        notebook_store(st, index).unwrap_or_else(|| Store::new(&ident.output_x(), st.network));
    let applied = match ident.full() {
        Some(id) => store.apply_bundle(bundle, id, st.network, notebook_spks, spending_window_spks),
        None => store.apply_bundle_watch(
            bundle,
            &ident.output_x(),
            st.network,
            notebook_spks,
            spending_window_spks,
        ),
    };
    if applied.is_ok() {
        if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == index) {
            save_store_file(&store, &st.store_path_for(fp8));
        }
        true
    } else {
        false
    }
}

/// One finished background scan, waiting to be applied on the UI thread.
/// `address` guards staleness: if the user switched notebooks while the
/// worker ran, the result is dropped (apply_bundle would refuse anyway —
/// this just keeps the failure silent and correct).
struct RefreshResult {
    address: String,
    /// `None` = the `/address/:a` stats pre-check short-circuited: nothing
    /// moved since the store's stamped fingerprint, so no bundle (or
    /// pending/dropped checks) was ever fetched — the apply half just
    /// stamps fresh fees and reports "up to date" (429 politeness,
    /// 2026-07-20).
    bundle: Option<Result<app_core::notes_core::bundle::SyncBundle, String>>,
    /// Fresh `/address/:a` stats to stamp into the store after a successful
    /// full apply — `None` when the pre-check endpoint failed or is
    /// unsupported (regtest server.py), which never blocks the scan itself.
    new_stats: Option<AddrStats>,
    /// (txid, confirmed?) for the pending sweep/consolidate records that
    /// existed at snapshot time — fetched on the worker so
    /// resolve_spend_statuses never blocks the UI thread.
    statuses: Vec<(String, Option<bool>)>,
    /// Task #14 (dropped-pending detection): every PENDING record's
    /// (notes AND sweep/consolidate) CURRENT-txid lookup result, gathered
    /// on the worker thread alongside `statuses` — see
    /// [`gather_dropped_checks`] / [`fetch_dropped_checks`].
    dropped_lookup: HashMap<String, TxLookupStatus>,
    /// Populated only for entries whose lookup came back `NotFound` —
    /// keyed by the record's first spent input (txid, vout).
    dropped_unspent: HashMap<(String, u32), bool>,
}

static REFRESH_RESULTS: std::sync::Mutex<Vec<RefreshResult>> = std::sync::Mutex::new(Vec::new());

/// Task #14: one PENDING record's dropped-check inputs, snapshotted on the
/// UI thread (cheap field reads) before handing off to a worker that does
/// the actual HTTP round trips. `current_txid` is the record's LATEST txid
/// (an RBF bump supersedes the original — only the current attempt going
/// missing counts as "dropped"); `first_input` is what
/// `ChainClient::outpoint_unspent` checks.
struct DroppedCheck {
    current_txid: String,
    first_input: (String, u32),
}

/// Build a `ChainClient` against `base`, picking the Esplora or Bitcoin
/// Core RPC backend by URL scheme (`app_core::chain::AnyTransport`, the
/// backend seam of `../PLAN-chain-notes-app-core-rpc.md`). `creds` is
/// resolved by the caller — via [`core_rpc_creds_for`] on the UI thread for
/// a synchronous call, or snapshotted onto a worker thread before it spawns
/// (same convention every other per-request State read already follows
/// here) — so this function itself never touches the Keychain or `State`.
/// Every `base` an Esplora identity stores is unchanged: `creds` is simply
/// unused by `AnyTransport::new` for a non-`bitcoind+` base. Returns `Err`
/// only for a malformed `bitcoind+` URL — callers surface it exactly like
/// any other chain error (never `unwrap`/`expect`).
fn open_client(
    base: &str,
    network: Network,
    creds: Option<(String, String)>,
) -> Result<ChainClient<AnyTransport>, app_core::Error> {
    Ok(ChainClient::new(AnyTransport::new(base, creds)?, network))
}

/// [`open_client`] plus Bitcoin Core ranged-watch configuration (U7 —
/// `../PLAN-chain-notes-app-core-rpc.md` §2.2's "ranged descriptor import"
/// finally gets a caller; previously `CoreRpcTransport::watch_descriptors`
/// had none anywhere in this crate, so the app always paid for one
/// genesis-rescan `importdescriptors` PER ADDRESS instead of one per
/// descriptor family). `descriptors` is `State.core_rpc_watch` — computed
/// ONCE per (identity, account, network) by `activate()`, cloned onto the
/// caller's stack (or into a worker-thread closure, same convention as
/// `base`/`network`/`creds`) BEFORE calling this, never re-derived here.
///
/// For an Esplora base this is byte-identical to `open_client` — the
/// `AnyTransport::Esplora` arm below never touches `descriptors` at all,
/// so the Esplora path (`HttpTransport`, pacing, 429 retry, error
/// classification) is untouched by construction, not merely by
/// convention. For a Bitcoin Core base with at least one descriptor
/// configured, this calls `CoreRpcTransport::watch_descriptors` on the
/// freshly-built transport before handing it back, so every subsequent
/// `/address/...` lookup through it prefers the ranged path
/// (`CoreRpcTransport::ranged_lookup_or_widen`) over the per-address
/// `addr()` fallback. A `watch_descriptors` failure (a flaky node, a
/// malformed descriptor) is logged and swallowed rather than failing the
/// whole operation: configuring the fast path is an optimization, and the
/// per-address fallback remains fully correct on its own — exactly the
/// same "additive, never a correctness requirement" relationship the U4
/// doc comments already describe.
///
/// NOT every `open_client` call site needs this — only ones that go on to
/// look up one of the identity's OWN addresses (`build_bundle`,
/// `scan_funding` against the identity's own spending source,
/// `address_probe`/`address_used`). Broadcast-only calls
/// (`client.broadcast`), `fetch_tx_io`/`fetch_tx_hex`/`fetch_tx_status`
/// (keyed by txid, not address), and `preflight`/`fee_rates`/`btc_usd`/
/// `tip_height` never touch `/address/...` at all (see `Transport for
/// CoreRpcTransport::get_text`), so configuring descriptors ahead of one
/// of those would be pure overhead — those call sites keep using
/// `open_client` directly. Third-party funding-wallet scans
/// (`State.funding_wallets`) are a DIFFERENT descriptor than this
/// identity's own and are out of scope here too — they keep using the
/// per-address fallback, unchanged.
fn open_client_watched(
    base: &str,
    network: Network,
    creds: Option<(String, String)>,
    descriptors: &[app_core::chain::WatchDescriptor],
) -> Result<ChainClient<AnyTransport>, app_core::Error> {
    let client = open_client(base, network, creds)?;
    if !descriptors.is_empty() {
        if let AnyTransport::Core(t) = &client.transport {
            if let Err(_e) = t.watch_descriptors(descriptors.to_vec()) {
                #[cfg(debug_assertions)]
                eprintln!("cb: core-rpc watch-descriptors err={_e}");
            }
        }
    }
    Ok(client)
}

/// Pure form of `State::core_rpc_should_persist`: default true (an absent
/// entry — every pre-U10 config, and every network nobody has touched the
/// switch for) else whatever was explicitly stored. A free function so the
/// default rule is testable without constructing a `State` (plan §2.4 /
/// U10).
fn core_rpc_persist_default_true(save_creds: &HashMap<String, bool>, network_key: &str) -> bool {
    save_creds.get(network_key).copied().unwrap_or(true)
}

/// Parse the "Save credentials" per-network preference map out of a loaded
/// config.json `Value` — mirrors the boot loader's `str_map` closure for
/// `node_urls`/`explorers` but for booleans, factored into a free function
/// so the config round-trip is unit-testable (plan §2.4 / U10). An absent
/// or malformed key yields an empty map, matching `core_rpc_persist_default_true`'s
/// default-true-when-absent behavior for every entry.
fn parse_core_rpc_save_creds(config: &serde_json::Value) -> HashMap<String, bool> {
    config
        .get("core_rpc_save_creds")
        .and_then(|v| v.as_object())
        .map(|o| o.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect())
        .unwrap_or_default()
}

/// Pure decision: resolve Bitcoin Core RPC credentials for a `base` given
/// the "Save credentials" switch state and both possible sources —
/// extracted from [`core_rpc_creds_for`] so the switch logic is testable
/// without a live Keychain (plan §2.4 / U10). A non-`bitcoind+` base always
/// resolves to `None`, regardless of either input (Esplora never touches
/// either source). Otherwise: `persist == true` returns whatever the
/// Keychain lookup found (today's unconditional behavior, byte-identical
/// for every user who never touches the new switch); `persist == false`
/// returns the in-session slot instead — the Keychain is not consulted at
/// all in that branch, by construction of the caller only doing the lookup
/// when `persist` is true (see `core_rpc_creds_for`).
fn resolve_core_rpc_creds(
    base: &str,
    persist: bool,
    keychain_creds: Option<(String, String)>,
    session_creds: Option<(String, String)>,
) -> Option<(String, String)> {
    if !base.starts_with("bitcoind+") {
        return None;
    }
    if persist { keychain_creds } else { session_creds }
}

/// Source Bitcoin Core RPC credentials for a `bitcoind+` base, honoring the
/// per-network "Save credentials" switch (`State::core_rpc_should_persist`,
/// plan §2.4 / U10). ON (the default — every pre-U10 install and every
/// network nobody has touched the switch for) reads the Keychain lazily,
/// exactly as before: this runs on every call, i.e. on every network
/// request against a Core backend, NOT once at boot or once at
/// Settings-open — deliberately, so caching the credential in `State`
/// itself never becomes tempting (the mistake that cost two shipped builds
/// on the identity item, builds 42/44). A plain, no-ACL keychain read has
/// no prompt to block on, so re-reading per request costs a little I/O and
/// nothing else. OFF reads the session-only slot on `State` instead and
/// the Keychain is never touched. Never called for an Esplora base (this
/// function's first check short-circuits before either source is
/// consulted). A Keychain error (never expected — this item carries no
/// ACL) degrades to no creds rather than failing the request outright; an
/// auth-required node then answers 401, which the caller already surfaces
/// as an ordinary network error — never a panic, never a credential in a
/// log line either way.
fn core_rpc_creds_for(st: &State, base: &str, network: Network) -> Option<(String, String)> {
    if !base.starts_with("bitcoind+") {
        return None;
    }
    let persist = st.core_rpc_should_persist(network);
    let keychain_creds =
        if persist { keychain::load_rpc_creds(network.as_str()).ok().flatten() } else { None };
    let session_creds = if !persist {
        st.core_rpc_session_creds.get(network.as_str()).map(|(u, p)| (u.clone(), p.to_string()))
    } else {
        None
    };
    resolve_core_rpc_creds(base, persist, keychain_creds, session_creds)
}

/// Where a freshly typed/pasted RPC credential is written, given the
/// current "Save credentials" switch state (plan §2.4 / U10) — shared by
/// `on_set_node_core_creds` and `on_set_node_custom`'s inline-userinfo
/// path so a pasted `user:pass@host` can't become a persisted credential
/// behind the user's back just because it arrived via a different field.
/// `store`/`delete` are the Keychain operations, injected so this is
/// testable without a live Keychain: for `persist == false` neither is
/// ever called — the credential goes straight into `session_creds`
/// instead, and clearing both fields removes the session entry the same
/// way it deletes the Keychain item on the `persist == true` side.
fn route_core_rpc_creds(
    persist: bool,
    network_key: &str,
    user: &str,
    pass: &str,
    session_creds: &mut HashMap<String, (String, Zeroizing<String>)>,
    store: impl FnOnce(&str, &str) -> Result<(), String>,
    delete: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if persist {
        if user.is_empty() && pass.is_empty() { delete() } else { store(user, pass) }
    } else {
        if user.is_empty() && pass.is_empty() {
            session_creds.remove(network_key);
        } else {
            session_creds
                .insert(network_key.to_string(), (user.to_string(), Zeroizing::new(pass.to_string())));
        }
        Ok(())
    }
}

/// Core logic for flipping the "Save credentials" switch for one network —
/// factored out of the `on_set_node_core_save_creds` UI callback so the
/// ON→OFF deletion (design invariant: leaving a stale secret behind after
/// the user says "don't save" is worse than not having the feature) is
/// testable without a live Keychain. `delete`/`store` are injected exactly
/// like [`route_core_rpc_creds`]. Turning OFF unconditionally deletes
/// whatever the Keychain holds for this network and returns the fields
/// currently on screen so the caller can seed the session slot with them
/// (continuity — the user doesn't lose what they just typed, only where
/// it lives); turning ON persists those same fields if either is non-empty
/// and returns `None` (nothing left to hold in session). Returns the
/// delete/store `Err` untouched so the caller can revert the UI toggle
/// rather than claim success.
fn apply_core_rpc_persist_toggle(
    enabled: bool,
    current_user: &str,
    current_pass: &str,
    delete: impl FnOnce() -> Result<(), String>,
    store: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<Option<(String, Zeroizing<String>)>, String> {
    if enabled {
        if !current_user.is_empty() || !current_pass.is_empty() {
            store(current_user, current_pass)?;
        }
        Ok(None)
    } else {
        delete()?;
        if current_user.is_empty() && current_pass.is_empty() {
            Ok(None)
        } else {
            Ok(Some((current_user.to_string(), Zeroizing::new(current_pass.to_string()))))
        }
    }
}

/// Strip an inline `user:pass@` userinfo out of a node URL before it can
/// reach `config.json`, a `cb:` log line, or the Settings text field (plan
/// §2.4 — "the stored node URL must contain NO credentials"). Handles both
/// `bitcoind+http(s)://user:pass@host:port` (the Sparrow-style paste this
/// app's Custom field should tolerate) and a plain `http(s)://` Esplora URL
/// (unusual, but stripping it is still correct — this app never sends an
/// Esplora request with basic auth). Returns the creds-free URL plus the
/// parsed `(user, pass)` if any were present.
fn split_url_userinfo(url: &str) -> (String, Option<(String, String)>) {
    let Some(scheme_end) = url.find("://") else { return (url.to_string(), None) };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let Some(at) = rest.find('@') else { return (url.to_string(), None) };
    // An '@' that belongs to a PATH segment (after the authority) is not
    // userinfo — bail rather than mis-parse.
    if rest[..at].contains('/') {
        return (url.to_string(), None);
    }
    let (userinfo, hostpart) = rest.split_at(at);
    let hostpart = &hostpart[1..]; // drop the '@' itself
    let creds = userinfo.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()));
    (format!("{scheme}{hostpart}"), creds)
}

/// U11 defense-in-depth: `on_set_node_custom`'s inline-userinfo stripping
/// only ran on a URL typed/pasted THIS session — a `config.json` already
/// on disk (hand-edited, migrated from an older build, or written before
/// that stripping shipped) can still carry `bitcoind+http://user:pass@
/// host:port` verbatim, and would otherwise be loaded, used, and displayed
/// in the Settings field with the credential in plain sight. Applies
/// [`split_url_userinfo`] to every entry of a just-loaded `node_urls` map,
/// rewriting it in place to the creds-free form, and returns the
/// `(network, user, pass)` triples found — in the SAME shape
/// `on_set_node_custom` routes through `route_core_rpc_creds`, so the
/// caller can treat a migrated credential exactly like a freshly typed
/// one. Pure / host-testable; does not touch the Keychain (the boot path
/// must make zero Keychain calls — see `flush_core_rpc_migration`).
fn migrate_inline_node_creds(node_urls: &mut HashMap<String, String>) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for (net, url) in node_urls.iter_mut() {
        let (clean, creds) = split_url_userinfo(url);
        if let Some((user, pass)) = creds {
            found.push((net.clone(), user, pass));
            *url = clean;
        }
    }
    found
}

/// The Keychain-touching follow-through to [`migrate_inline_node_creds`]:
/// route every network in `core_rpc_migrate_pending` to the Keychain (if
/// that network's "Save credentials" switch is on) or leave it in the
/// session-only slot (if it's off) — exactly like `on_set_node_custom`'s
/// inline-creds branch, reusing the same [`route_core_rpc_creds`]. Called
/// from `refresh_node_health`, which only ever runs from a Settings-screen
/// UI callback — NEVER the launch path, so a migrated credential's
/// Keychain write happens well after the first frame, never during boot
/// (the same "defer to a lazy point" rule U6/U10 already follow for their
/// own Keychain calls). A no-op (drains nothing) once the pending set is
/// empty, so repeat calls from every `refresh_node_health` invocation cost
/// nothing.
fn flush_core_rpc_migration(s: &mut State) {
    if s.core_rpc_migrate_pending.is_empty() {
        return;
    }
    let pending: Vec<String> = s.core_rpc_migrate_pending.drain().collect();
    for net in pending {
        let Some((user, pass)) =
            s.core_rpc_session_creds.get(&net).map(|(u, p)| (u.clone(), p.to_string()))
        else {
            continue;
        };
        let persist = core_rpc_persist_default_true(&s.core_rpc_save_creds, &net);
        let net_for_store = net.clone();
        let result = route_core_rpc_creds(
            persist,
            &net,
            &user,
            &pass,
            &mut s.core_rpc_session_creds,
            |u, p| keychain::store_rpc_creds(&net_for_store, u, p),
            || Ok(()), // never reached: user/pass are non-empty by construction
        );
        match result {
            Ok(()) => {
                // route_core_rpc_creds only touches session_creds on the
                // persist==false branch — a successful persist==true store
                // leaves our load-time stash sitting in memory uselessly
                // (never read once persisted — see `core_rpc_creds_for`),
                // so drop it explicitly, same as `on_set_node_core_save_creds`
                // does on its own ON transition.
                if persist {
                    s.core_rpc_session_creds.remove(&net);
                }
                println!("cb: core-rpc-migrate net={net} persist={persist} ok");
            }
            Err(e) => println!("cb: core-rpc-migrate net={net} persist={persist} err={e}"),
        }
    }
}

#[cfg(test)]
mod core_rpc_settings_tests {
    use super::{
        apply_core_rpc_persist_toggle, compose_core_url, core_rpc_default_port,
        core_rpc_persist_default_true, display_core_url, fill_node, format_node_status,
        migrate_inline_node_creds, parse_core_rpc_save_creds, resolve_core_rpc_creds,
        route_core_rpc_creds, split_url_userinfo, Network, State,
    };
    use app_core::chain::node_presets;
    use app_core::chain::NodeStatus;
    use std::cell::Cell;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    #[test]
    fn strips_inline_userinfo_from_core_url() {
        let (url, creds) = split_url_userinfo("bitcoind+http://alice:s3cr3t@192.168.1.10:8332");
        assert_eq!(url, "bitcoind+http://192.168.1.10:8332");
        assert_eq!(creds, Some(("alice".to_string(), "s3cr3t".to_string())));
    }

    #[test]
    fn leaves_a_plain_url_untouched() {
        let (url, creds) = split_url_userinfo("bitcoind+http://192.168.1.10:8332");
        assert_eq!(url, "bitcoind+http://192.168.1.10:8332");
        assert_eq!(creds, None);
    }

    #[test]
    fn leaves_esplora_urls_untouched() {
        let (url, creds) = split_url_userinfo("https://mempool.example/api");
        assert_eq!(url, "https://mempool.example/api");
        assert_eq!(creds, None);
    }

    #[test]
    fn does_not_confuse_a_path_at_sign_for_userinfo() {
        // No userinfo here — the '@' (if any) would sit after a '/', which
        // this function must not treat as an authority separator.
        let (url, creds) = split_url_userinfo("http://127.0.0.1:3002/api@weird");
        assert_eq!(url, "http://127.0.0.1:3002/api@weird");
        assert_eq!(creds, None);
    }

    #[test]
    fn empty_and_malformed_inputs_pass_through() {
        assert_eq!(split_url_userinfo(""), (String::new(), None));
        assert_eq!(split_url_userinfo("not-a-url"), ("not-a-url".to_string(), None));
    }

    // ---- U10: "Save credentials" switch ----

    #[test]
    fn persist_default_true_when_absent() {
        let map: HashMap<String, bool> = HashMap::new();
        assert!(core_rpc_persist_default_true(&map, "testnet4"));
    }

    #[test]
    fn persist_default_respects_explicit_value() {
        let mut map = HashMap::new();
        map.insert("testnet4".to_string(), false);
        map.insert("mainnet".to_string(), true);
        assert!(!core_rpc_persist_default_true(&map, "testnet4"));
        assert!(core_rpc_persist_default_true(&map, "mainnet"));
        // A network never mentioned still defaults true.
        assert!(core_rpc_persist_default_true(&map, "signet"));
    }

    #[test]
    fn resolve_creds_persist_on_uses_keychain_source() {
        let keychain = Some(("alice".to_string(), "s3cr3t".to_string()));
        let session = Some(("bob".to_string(), "wrongsource".to_string()));
        let got = resolve_core_rpc_creds("bitcoind+http://10.0.0.1:8332", true, keychain, session);
        assert_eq!(got, Some(("alice".to_string(), "s3cr3t".to_string())));
    }

    #[test]
    fn resolve_creds_persist_off_uses_session_source() {
        let keychain = Some(("alice".to_string(), "s3cr3t".to_string()));
        let session = Some(("bob".to_string(), "sess-pass".to_string()));
        let got = resolve_core_rpc_creds("bitcoind+http://10.0.0.1:8332", false, keychain, session);
        assert_eq!(got, Some(("bob".to_string(), "sess-pass".to_string())));
    }

    #[test]
    fn resolve_creds_esplora_base_short_circuits_regardless_of_switch() {
        // Neither source is consulted for a non-`bitcoind+` base — proves
        // Esplora never touches either the Keychain-shaped input or the
        // session-shaped input, whichever the switch would otherwise pick.
        let some_creds = Some(("alice".to_string(), "s3cr3t".to_string()));
        assert_eq!(
            resolve_core_rpc_creds(
                "https://mempool.example/api",
                true,
                some_creds.clone(),
                some_creds.clone()
            ),
            None
        );
        assert_eq!(
            resolve_core_rpc_creds("https://mempool.example/api", false, some_creds.clone(), some_creds),
            None
        );
    }

    #[test]
    fn route_creds_persist_on_calls_keychain_store_not_session() {
        let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
        let stored: Cell<Option<(String, String)>> = Cell::new(None);
        let deleted = Cell::new(false);
        let result = route_core_rpc_creds(
            true,
            "testnet4",
            "alice",
            "s3cr3t",
            &mut session,
            |u, p| {
                stored.set(Some((u.to_string(), p.to_string())));
                Ok(())
            },
            || {
                deleted.set(true);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(stored.into_inner(), Some(("alice".to_string(), "s3cr3t".to_string())));
        assert!(!deleted.get());
        assert!(session.is_empty(), "persist-on must never touch the session slot");
    }

    #[test]
    fn route_creds_persist_on_clearing_both_fields_deletes() {
        let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
        let stored = Cell::new(false);
        let deleted = Cell::new(false);
        let result = route_core_rpc_creds(
            true,
            "testnet4",
            "",
            "",
            &mut session,
            |_, _| {
                stored.set(true);
                Ok(())
            },
            || {
                deleted.set(true);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(deleted.get());
        assert!(!stored.get());
    }

    #[test]
    fn route_creds_persist_off_never_touches_keychain() {
        let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
        let touched = Cell::new(false);
        let result = route_core_rpc_creds(
            false,
            "testnet4",
            "alice",
            "s3cr3t",
            &mut session,
            |_, _| {
                touched.set(true);
                Ok(())
            },
            || {
                touched.set(true);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(!touched.get(), "persist-off must never call a Keychain op");
        let entry = session.get("testnet4").expect("session slot populated");
        assert_eq!(entry.0, "alice");
        assert_eq!(entry.1.as_str(), "s3cr3t");
    }

    #[test]
    fn route_creds_persist_off_clearing_both_fields_clears_session_only() {
        let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
        session.insert("testnet4".to_string(), ("alice".to_string(), Zeroizing::new("s3cr3t".to_string())));
        let touched = Cell::new(false);
        let result = route_core_rpc_creds(
            false,
            "testnet4",
            "",
            "",
            &mut session,
            |_, _| {
                touched.set(true);
                Ok(())
            },
            || {
                touched.set(true);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(!touched.get());
        assert!(session.get("testnet4").is_none());
    }

    /// The load-bearing invariant: turning the switch OFF must
    /// unconditionally delete whatever the Keychain holds — this is what a
    /// mutation test should catch first. Also proves `store` is never
    /// called on the OFF path.
    #[test]
    fn toggle_off_always_deletes_the_stored_keychain_item() {
        let deleted = Cell::new(false);
        let stored = Cell::new(false);
        let result = apply_core_rpc_persist_toggle(
            false,
            "alice",
            "s3cr3t",
            || {
                deleted.set(true);
                Ok(())
            },
            |_, _| {
                stored.set(true);
                Ok(())
            },
        );
        assert!(deleted.get(), "OFF must delete the stored Keychain item");
        assert!(!stored.get());
        match result {
            Ok(Some((u, p))) => {
                assert_eq!(u, "alice");
                assert_eq!(p.as_str(), "s3cr3t");
            }
            other => panic!("expected the on-screen fields handed back for the session slot, got {other:?}"),
        }
    }

    #[test]
    fn toggle_off_with_blank_fields_still_deletes_and_leaves_session_empty() {
        // Blank on-screen fields don't imply "nothing to delete" — a
        // previously saved credential from an earlier session could still
        // be sitting in the Keychain (this app never pre-populates the
        // fields from anywhere but Settings-open), so deletion must fire
        // unconditionally on every ON→OFF transition.
        let deleted = Cell::new(false);
        let result = apply_core_rpc_persist_toggle(
            false,
            "",
            "",
            || {
                deleted.set(true);
                Ok(())
            },
            |_, _| Ok(()),
        );
        assert!(deleted.get());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn toggle_off_propagates_a_keychain_delete_error() {
        let result = apply_core_rpc_persist_toggle(
            false,
            "alice",
            "s3cr3t",
            || Err("keychain busy".to_string()),
            |_, _| Ok(()),
        );
        assert_eq!(result, Err("keychain busy".to_string()));
    }

    #[test]
    fn toggle_on_persists_the_on_screen_fields_and_clears_session() {
        let stored: Cell<Option<(String, String)>> = Cell::new(None);
        let deleted = Cell::new(false);
        let result = apply_core_rpc_persist_toggle(
            true,
            "alice",
            "s3cr3t",
            || {
                deleted.set(true);
                Ok(())
            },
            |u, p| {
                stored.set(Some((u.to_string(), p.to_string())));
                Ok(())
            },
        );
        assert!(!deleted.get());
        assert_eq!(stored.into_inner(), Some(("alice".to_string(), "s3cr3t".to_string())));
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn toggle_on_with_nothing_typed_stores_nothing() {
        let stored = Cell::new(false);
        let result = apply_core_rpc_persist_toggle(
            true,
            "",
            "",
            || Ok(()),
            |_, _| {
                stored.set(true);
                Ok(())
            },
        );
        assert!(!stored.get());
        assert_eq!(result.unwrap(), None);
    }

    /// `parse_core_rpc_save_creds` round trip in isolation — a hand-built
    /// `Value`, not the real `State::config_payload()`. This is READ-side
    /// coverage only (the boot-time parse); the actual WRITE side is
    /// covered by `config_payload_never_carries_session_credentials`
    /// below, which drives the production method instead of mirroring its
    /// shape.
    #[test]
    fn save_creds_preference_round_trips_through_config_json_never_carrying_secrets() {
        let mut before: HashMap<String, bool> = HashMap::new();
        before.insert("testnet4".to_string(), false);
        before.insert("mainnet".to_string(), true);
        let json = serde_json::json!({ "core_rpc_save_creds": before.clone() });
        let text = json.to_string();
        assert!(!text.contains("s3cr3t"));
        assert!(!text.contains("core_rpc_session_creds"));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        let after = parse_core_rpc_save_creds(&parsed);
        assert_eq!(after, before);
    }

    #[test]
    fn save_creds_preference_absent_key_parses_to_empty_map() {
        let parsed: serde_json::Value = serde_json::json!({ "network": "testnet4" });
        assert!(parse_core_rpc_save_creds(&parsed).is_empty());
    }

    /// The load-bearing regression test: drives the REAL
    /// `State::config_payload()` (what `save_config` actually serializes,
    /// after this review's extraction) with a distinctive username AND
    /// password sitting in `core_rpc_session_creds` — the exact plaintext
    /// a leak would carry — and asserts neither appears anywhere in the
    /// output, while the boolean preference map and the other expected
    /// keys still do. A hand-built mirror of the payload shape (as the
    /// prior version of this test was) cannot catch `save_config` drifting
    /// to leak a new field; this asserts on bytes the production method
    /// itself produced.
    #[test]
    fn config_payload_never_carries_session_credentials() {
        let mut save_creds: HashMap<String, bool> = HashMap::new();
        save_creds.insert("testnet4".to_string(), false);
        let mut session_creds: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
        session_creds.insert(
            "testnet4".to_string(),
            (
                "SENTINEL_USER_do_not_leak".to_string(),
                Zeroizing::new("SENTINEL_PASS_do_not_leak".to_string()),
            ),
        );
        let state = State::test_stub(
            Network::Testnet4,
            HashMap::new(),
            HashMap::new(),
            save_creds,
            session_creds,
        );
        let text = state.config_payload().to_string();
        assert!(!text.contains("SENTINEL_USER_do_not_leak"), "leaked the session username: {text}");
        assert!(!text.contains("SENTINEL_PASS_do_not_leak"), "leaked the session password: {text}");
        assert!(!text.contains("core_rpc_session_creds"), "leaked the session-creds field name: {text}");
        // The boolean preference map DOES round-trip (it's a preference,
        // not a secret) — and a couple of the other expected keys, so this
        // test would also fail loudly if `config_payload` lost fields
        // rather than gained one.
        assert!(text.contains("core_rpc_save_creds"));
        assert!(text.contains("testnet4"));
        assert!(text.contains("\"network\":\"testnet4\""));
    }

    // ---- U11: node-health caption copy (defect 2) ----

    /// The exact nonsense the review caught: `prune_height` of `Some(0)`
    /// used to render "pruned below block 0 — notes/history before it
    /// can't be recovered", which claims something is unrecoverable when
    /// NOTHING has actually been pruned yet. Zero must read as informational
    /// (no warn tint), not the strong warning.
    #[test]
    fn prune_height_zero_is_not_alarming() {
        let status = NodeStatus { pruned: true, prune_height: Some(0), txindex: true, ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(!warn, "prune height 0 must not set the warn tint: {text}");
        assert!(!text.contains("can't be recovered"), "prune height 0 must not claim data is lost: {text}");
        assert!(text.contains("nothing pruned"), "expected an honest not-yet-pruned note: {text}");
    }

    /// Same honesty rule for the ABSENT case (`prune_height: None` while
    /// `pruned` is true) — bitcoind only populates `pruneheight` once it has
    /// pruned at least once, so `None` means the same "nothing pruned yet"
    /// state as `Some(0)`, never "unknown, assume the worst."
    #[test]
    fn prune_height_absent_is_not_alarming() {
        let status = NodeStatus { pruned: true, prune_height: None, txindex: true, ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(!warn, "absent prune height must not set the warn tint: {text}");
        assert!(!text.contains("can't be recovered"), "absent prune height must not claim data is lost: {text}");
    }

    /// A REAL nonzero prune height keeps the strong wording and the warn
    /// tint — the fix must narrow the false-positive case, not silence the
    /// real one.
    #[test]
    fn prune_height_nonzero_still_warns() {
        let status = NodeStatus { pruned: true, prune_height: Some(500), txindex: true, ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(warn, "a real prune height must still warn: {text}");
        assert!(text.contains("pruned below block 500"), "expected the real height named: {text}");
        assert!(text.contains("can't be recovered"), "expected the strong wording for a real prune: {text}");
    }

    /// The exact scenario a locally-running pruned bitcoind hits moments
    /// after `-prune` is turned on: pruned (height 0, not yet alarming) AND
    /// no txindex (a real warning) in the SAME status. The overall `warn`
    /// flag must still be true (txindex alone earns it), the join must not
    /// leave a dangling `· ` separator, and the non-alarming prune note must
    /// still be present alongside the real txindex warning.
    #[test]
    fn pruned_zero_plus_no_txindex_warns_from_txindex_only() {
        let status = NodeStatus { pruned: true, prune_height: Some(0), txindex: false, ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(warn, "missing txindex alone must still warn: {text}");
        assert!(text.contains("nothing pruned"));
        assert!(text.contains("no txindex"));
        assert!(!text.trim_end().ends_with('·'), "no dangling separator: {text:?}");
        assert!(!text.contains("  "), "no doubled-up spacing from an empty joined part: {text:?}");
    }

    /// A fully healthy node — the "previously invisible" one-line case
    /// (defect 1's UI symptom): no parts pushed at all, so the fallback
    /// "connected · tip N" line is used, and it must never warn.
    #[test]
    fn healthy_node_reports_connected_and_never_warns() {
        let status = NodeStatus { tip_height: 123_456, txindex: true, ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(!warn);
        assert_eq!(text, "connected · tip 123,456");
    }

    /// A rescanning wallet must never look like a quiet/empty one — still
    /// warns.
    #[test]
    fn wallet_scanning_warns() {
        let status = NodeStatus { txindex: true, wallet_scanning: Some(true), ..Default::default() };
        let (text, warn) = format_node_status(&status);
        assert!(warn, "{text}");
        assert!(text.contains("rescanning"));
    }

    // ---- U11: strip inline creds from a LOADED config.json (defect 3) ----

    #[test]
    fn migrate_strips_inline_creds_from_a_loaded_node_url() {
        let mut node_urls = HashMap::new();
        node_urls.insert(
            "mainnet".to_string(),
            "bitcoind+http://alice:s3cr3t@203.0.113.5:8332".to_string(),
        );
        let found = migrate_inline_node_creds(&mut node_urls);
        assert_eq!(found, vec![("mainnet".to_string(), "alice".to_string(), "s3cr3t".to_string())]);
        assert_eq!(node_urls.get("mainnet").map(String::as_str), Some("bitcoind+http://203.0.113.5:8332"));
    }

    #[test]
    fn migrate_leaves_a_clean_loaded_url_untouched() {
        let mut node_urls = HashMap::new();
        node_urls.insert("testnet4".to_string(), "bitcoind+http://10.0.0.5:8332".to_string());
        let found = migrate_inline_node_creds(&mut node_urls);
        assert!(found.is_empty());
        assert_eq!(node_urls.get("testnet4").map(String::as_str), Some("bitcoind+http://10.0.0.5:8332"));
    }

    #[test]
    fn migrate_handles_multiple_networks_independently() {
        let mut node_urls = HashMap::new();
        node_urls.insert(
            "mainnet".to_string(),
            "bitcoind+http://alice:s3cr3t@203.0.113.5:8332".to_string(),
        );
        node_urls.insert("testnet4".to_string(), "https://mempool.example/api".to_string());
        node_urls.insert(
            "signet".to_string(),
            "bitcoind+http://bob:hunter2@198.51.100.9:8332".to_string(),
        );
        let mut found = migrate_inline_node_creds(&mut node_urls);
        found.sort();
        assert_eq!(
            found,
            vec![
                ("mainnet".to_string(), "alice".to_string(), "s3cr3t".to_string()),
                ("signet".to_string(), "bob".to_string(), "hunter2".to_string()),
            ]
        );
        assert_eq!(node_urls.get("mainnet").map(String::as_str), Some("bitcoind+http://203.0.113.5:8332"));
        assert_eq!(node_urls.get("testnet4").map(String::as_str), Some("https://mempool.example/api"));
        assert_eq!(node_urls.get("signet").map(String::as_str), Some("bitcoind+http://198.51.100.9:8332"));
    }

    #[test]
    fn migrate_on_an_empty_map_is_a_noop() {
        let mut node_urls: HashMap<String, String> = HashMap::new();
        assert!(migrate_inline_node_creds(&mut node_urls).is_empty());
        assert!(node_urls.is_empty());
    }

    // ---- U12: node picker — "Bitcoin Core" row, prefix-free UI ----

    #[test]
    fn confirmed_default_rpc_ports_per_network() {
        // Straight from the installed bitcoind v30.2.0's own
        // `-help-debug` text (verified 2026-07-29):
        //   -rpcport=<port> … (default: 8332, testnet3: 18332,
        //   testnet4: 48332, signet: 38332, regtest: 18443)
        // This app has no Testnet3 variant, so only the other four apply.
        assert_eq!(core_rpc_default_port(Network::Mainnet), 8332);
        assert_eq!(core_rpc_default_port(Network::Testnet4), 48332);
        assert_eq!(core_rpc_default_port(Network::Signet), 38332);
        assert_eq!(core_rpc_default_port(Network::Regtest), 18443);
    }

    #[test]
    fn compose_core_url_normalization_table() {
        // (input, network, expected stored URL, expected inline creds)
        let cases: &[(&str, Network, &str, Option<(&str, &str)>)] = &[
            // bare host -> default scheme + default port for the network
            ("192.168.1.10", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
            ("umbrel.local", Network::Testnet4, "bitcoind+http://umbrel.local:48332", None),
            ("node.example", Network::Signet, "bitcoind+http://node.example:38332", None),
            ("127.0.0.1", Network::Regtest, "bitcoind+http://127.0.0.1:18443", None),
            // host:port -> default scheme, given port honored verbatim
            ("192.168.1.10:8332", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
            ("umbrel.local:9998", Network::Testnet4, "bitcoind+http://umbrel.local:9998", None),
            // explicit http:// / https:// -> scheme honored, port defaults
            // or is honored the same way
            ("http://192.168.1.10", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
            (
                "https://node.example:8332",
                Network::Mainnet,
                "bitcoind+https://node.example:8332",
                None,
            ),
            ("https://umbrel.local", Network::Signet, "bitcoind+https://umbrel.local:38332", None),
            // whitespace tolerated
            ("  192.168.1.10:8332  ", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
            // pasted `bitcoind+…` (backward compat / Sparrow-style paste)
            // re-normalizes exactly like the bare forms above
            (
                "bitcoind+http://192.168.1.10:8332",
                Network::Mainnet,
                "bitcoind+http://192.168.1.10:8332",
                None,
            ),
            (
                "bitcoind+https://node.example",
                Network::Signet,
                "bitcoind+https://node.example:38332",
                None,
            ),
            (
                "bitcoind+http://alice:s3cr3t@192.168.1.10:8332",
                Network::Mainnet,
                "bitcoind+http://192.168.1.10:8332",
                Some(("alice", "s3cr3t")),
            ),
            // inline creds on a bare paste (no bitcoind+, no scheme)
            (
                "alice:s3cr3t@192.168.1.10:8332",
                Network::Mainnet,
                "bitcoind+http://192.168.1.10:8332",
                Some(("alice", "s3cr3t")),
            ),
        ];
        for (input, net, expect_url, expect_creds) in cases {
            let (url, creds) = compose_core_url(input, *net)
                .unwrap_or_else(|e| panic!("expected {input:?} to parse, got err {e:?}"));
            assert_eq!(url, *expect_url, "input={input:?}");
            assert_eq!(
                creds,
                expect_creds.map(|(u, p)| (u.to_string(), p.to_string())),
                "input={input:?}"
            );
        }
    }

    #[test]
    fn compose_core_url_rejects_malformed_input() {
        let bad: &[&str] = &[
            "",
            "   ",
            "bitcoind+",
            "192.168.1.10:not-a-port",
            "192.168.1.10:99999999",
            "ftp://192.168.1.10:8332",
            "192.168.1.10:8332/wallet/foo", // path not allowed on this field
            "http://",
            "http://:8332", // empty host
        ];
        for input in bad {
            assert!(
                compose_core_url(input, Network::Mainnet).is_err(),
                "expected {input:?} to be rejected"
            );
        }
    }

    #[test]
    fn compose_core_url_error_messages_are_useful() {
        let err = compose_core_url("ftp://host:21", Network::Mainnet).unwrap_err();
        assert!(err.contains("scheme"), "message should mention the bad scheme: {err}");
        let err = compose_core_url("", Network::Mainnet).unwrap_err();
        assert!(err.contains("host"), "message should ask for a host: {err}");
    }

    #[test]
    fn display_core_url_elides_default_http_scheme_but_keeps_https() {
        assert_eq!(display_core_url("bitcoind+http://192.168.1.10:8332"), "192.168.1.10:8332");
        assert_eq!(
            display_core_url("bitcoind+https://node.example:8332"),
            "https://node.example:8332"
        );
    }

    #[test]
    fn compose_then_display_round_trips_to_the_same_text() {
        // What gets shown after a successful commit must, if resubmitted
        // unchanged, reproduce the exact same stored URL — an elided
        // scheme must never silently flip http<->https on a second save.
        for (typed, net) in [
            ("192.168.1.10:8332", Network::Mainnet),
            ("umbrel.local", Network::Testnet4),
            ("https://node.example:8332", Network::Mainnet),
            ("https://umbrel.local", Network::Signet),
        ] {
            let (stored1, _) = compose_core_url(typed, net).unwrap();
            let shown = display_core_url(&stored1);
            let (stored2, _) = compose_core_url(&shown, net).unwrap();
            assert_eq!(stored1, stored2, "typed={typed:?} shown={shown:?}");
        }
    }

    #[test]
    fn fill_node_round_trip_core_base_selects_core_row_no_prefix_no_creds() {
        let net = Network::Mainnet;
        let presets = node_presets(net);
        let (opts, idx, esplora_text, core_text) =
            fill_node(presets.clone(), Some("bitcoind+http://192.168.1.10:8332"));
        // Row order: <presets…>, "Bitcoin Core", "Custom…" — Core is
        // second-to-last regardless of how many presets a network has.
        assert_eq!(opts[opts.len() - 2], "Bitcoin Core");
        assert_eq!(opts[opts.len() - 1], "Custom…");
        assert_eq!(idx as usize, presets.len()); // the "Bitcoin Core" row
        assert_eq!(esplora_text, "");
        assert_eq!(core_text, "192.168.1.10:8332"); // no prefix, no creds
    }

    #[test]
    fn fill_node_round_trip_preset_esplora_base_selects_that_preset() {
        let net = Network::Mainnet;
        let presets = node_presets(net);
        // Blockstream is a real preset on mainnet with an explicit URL.
        let (label, url) =
            presets.iter().find(|(_, u)| u.is_some()).expect("mainnet has an explicit preset");
        let (opts, idx, esplora_text, core_text) = fill_node(presets.clone(), *url);
        assert_eq!(opts[idx as usize], *label);
        assert_eq!(esplora_text, "");
        assert_eq!(core_text, "");
    }

    #[test]
    fn fill_node_round_trip_custom_esplora_base_selects_custom_row() {
        let net = Network::Mainnet;
        let presets = node_presets(net);
        let (opts, idx, esplora_text, core_text) =
            fill_node(presets.clone(), Some("https://my-own-node.example/api"));
        assert_eq!(opts[idx as usize], "Custom…");
        assert_eq!(idx as usize, presets.len() + 1);
        assert_eq!(esplora_text, "https://my-own-node.example/api");
        assert_eq!(core_text, "");
    }

    #[test]
    fn fill_node_regtest_has_exactly_core_then_custom() {
        // node_presets(Regtest) is empty — the dropdown must still resolve
        // to exactly "Bitcoin Core", "Custom…" with correct index math.
        let net = Network::Regtest;
        let presets = node_presets(net);
        assert!(presets.is_empty());
        let (opts, idx, _, core_text) =
            fill_node(presets.clone(), Some("bitcoind+http://127.0.0.1:18443"));
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0], "Bitcoin Core");
        assert_eq!(opts[1], "Custom…");
        assert_eq!(idx, 0);
        assert_eq!(core_text, "127.0.0.1:18443");

        // No configured value at all (default network base, None) selects
        // Custom on regtest — there is no Esplora preset for it to match.
        let (opts2, idx2, esplora_text2, core_text2) = fill_node(presets, None);
        assert_eq!(opts2.len(), 2);
        assert_eq!(idx2, 1); // "Custom…"
        assert_eq!(esplora_text2, "");
        assert_eq!(core_text2, "");
    }

    #[test]
    fn credentials_typed_into_node_address_field_never_reach_the_stored_url() {
        // The node-address field's own composer must never let a
        // credential survive into the value that gets written to
        // config.json — same invariant `split_url_userinfo` enforces for
        // the Custom field's paste path, proven here end-to-end through
        // `compose_core_url` for every accepted input shape that could
        // carry one.
        for input in [
            "alice:s3cr3t@192.168.1.10:8332",
            "http://alice:s3cr3t@192.168.1.10:8332",
            "https://alice:s3cr3t@192.168.1.10",
            "bitcoind+http://alice:s3cr3t@192.168.1.10:8332",
        ] {
            let (url, creds) = compose_core_url(input, Network::Mainnet).unwrap();
            assert!(!url.contains("s3cr3t"), "stored url leaked a credential: {url}");
            assert!(!url.contains('@'), "stored url carries userinfo syntax: {url}");
            assert_eq!(creds, Some(("alice".to_string(), "s3cr3t".to_string())));
            // And the round-trip display of that stored URL is equally
            // creds-free (belt and suspenders — display never re-derives
            // creds from anywhere, but prove it never echoes the input).
            assert!(!display_core_url(&url).contains("s3cr3t"));
        }
    }
}

/// Snapshot every PENDING record (sweep/consolidate txs AND notes) in
/// `store` into the (current-txid, first-input) pairs a worker thread needs
/// — shared by both the async and synchronous refresh paths so they exhibit
/// identical dropped-detection behavior.
fn gather_dropped_checks(store: &Store) -> Vec<DroppedCheck> {
    let tx_checks = store.txs.iter().filter(|t| t.status == NoteStatus::Pending).filter_map(|t| {
        let current_txid = t.txids.last()?.clone();
        let first = t.inputs.first()?;
        Some(DroppedCheck { current_txid, first_input: (first.txid.clone(), first.vout) })
    });
    let note_checks = store.notes.iter().filter(|n| n.status == NoteStatus::Pending).filter_map(|n| {
        let current_txid = n.txids.last()?.clone();
        let first = n.spent.first()?;
        Some(DroppedCheck { current_txid, first_input: (first.txid.clone(), first.vout) })
    });
    tx_checks.chain(note_checks).collect()
}

/// The worker-thread half of task #14: run `checks` (see
/// [`gather_dropped_checks`]) against a live `client`, returning the two
/// maps `RefreshResult` carries — `tx_lookup_status` once per DISTINCT
/// current txid, `outpoint_unspent` only for the ones that came back
/// `NotFound` (the common "still pending"/"confirmed" cases never pay for
/// the extra round trip).
fn fetch_dropped_checks(
    client: &ChainClient<AnyTransport>,
    address: &str,
    checks: &[DroppedCheck],
) -> (HashMap<String, TxLookupStatus>, HashMap<(String, u32), bool>) {
    let mut lookup = HashMap::new();
    let mut unspent = HashMap::new();
    for c in checks {
        let status = *lookup
            .entry(c.current_txid.clone())
            .or_insert_with(|| client.tx_lookup_status(&c.current_txid));
        if status == TxLookupStatus::NotFound {
            unspent.entry(c.first_input.clone()).or_insert_with(|| {
                client
                    .outpoint_unspent(address, &c.first_input.0, c.first_input.1)
                    .unwrap_or(false)
            });
        }
    }
    (lookup, unspent)
}

/// The UI-thread half: apply the two maps `fetch_dropped_checks` gathered
/// against `store`'s pending txs AND notes, logging `cb: tx-dropped
/// txid=<t>` once per NEW transition into dropped (task #14's log
/// contract).
fn apply_dropped_checks(
    store: &mut Store,
    lookup: &HashMap<String, TxLookupStatus>,
    unspent: &HashMap<(String, u32), bool>,
) {
    let lookup_fn = |txid: &str| lookup.get(txid).copied().unwrap_or(TxLookupStatus::Unknown);
    let unspent_fn = |_addr: &str, txid: &str, vout: u32| {
        unspent.get(&(txid.to_string(), vout)).copied()
    };
    let mut newly = store.resolve_dropped_tx(lookup_fn, unspent_fn);
    newly.extend(store.resolve_dropped_notes(lookup_fn, unspent_fn));
    for txid in newly {
        println!("cb: tx-dropped txid={txid}");
    }
}

/// Which ↻ tap kicked off a [`wallet_stores_refresh_async`] scan — drives
/// the final `cb: refresh-coins|refresh-notebooks notebooks=<n>` log label
/// and each tap's own post-scan UI work in
/// `apply_wallet_stores_refresh_results`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WalletStoresPurpose {
    Coins,
    Notebooks,
}

impl WalletStoresPurpose {
    fn label(self) -> &'static str {
        match self {
            WalletStoresPurpose::Coins => "refresh-coins",
            WalletStoresPurpose::Notebooks => "refresh-notebooks",
        }
    }
}

/// One active notebook's bundle fetch, gathered on the worker thread —
/// part of a [`WalletStoresRefreshResult`].
struct NotebookBundleResult {
    index: u32,
    bundle: Result<app_core::notes_core::bundle::SyncBundle, String>,
}

/// A finished wallet-wide rescan (every ACTIVE notebook, kicked off by the
/// Coins screen's or notebook-list's ↻), waiting to be applied on the UI
/// thread — see `wallet_stores_refresh_async`/
/// `apply_wallet_stores_refresh_results`. Coarse staleness guard: (fp8,
/// network, account) — an identity/account switch mid-scan drops the whole
/// result, same pattern as [`SpendingRefreshResult`]. `current_address`
/// additionally guards just the snapshot-time-active notebook's slice: a
/// mere notebook switch within the SAME account (fp8/network/account
/// unchanged) must never apply a stale bundle onto whatever notebook is
/// live in `State.store` now.
struct WalletStoresRefreshResult {
    purpose: WalletStoresPurpose,
    fp8: String,
    network: Network,
    account: u32,
    current_index: Option<u32>,
    current_address: Option<String>,
    /// (txid, confirmed?)/dropped-check results for the snapshot-time
    /// active notebook only — same shape as [`RefreshResult`]'s fields,
    /// gathered so applying its slice matches `refresh()`/
    /// `apply_refresh_results` exactly.
    current_statuses: Vec<(String, Option<bool>)>,
    current_dropped_lookup: HashMap<String, TxLookupStatus>,
    current_dropped_unspent: HashMap<(String, u32), bool>,
    /// Every active notebook's bundle fetch, including the snapshot-time
    /// active one.
    results: Vec<NotebookBundleResult>,
    /// Taproot change-chain gap walk (unit 3, `../PLAN-chain-notes-app-taproot-change.md`) —
    /// `scan_change_chain` gap 1, account-level (folded into the SAME
    /// (fp8, network, account) staleness guard the notebook results use
    /// above, so no separate guard is needed on apply). `Err` on a
    /// transport/parse failure; empty `Ok` for watch/WIF/hex material
    /// (no change chain to walk) or when no material was cached this
    /// session.
    change: Result<Vec<ChangeCoin>, String>,
}

static WALLET_STORES_REFRESH_RESULTS: std::sync::Mutex<Vec<WalletStoresRefreshResult>> =
    std::sync::Mutex::new(Vec::new());

/// Kick off a wallet-wide rescan — every ACTIVE notebook's bundle — for the
/// Coins screen's and notebook-list's ↻ (TODO(watchdog) fix, 2026-07-20:
/// these two used to call the old synchronous `refresh_wallet_stores` +
/// `refresh` directly on the UI thread, which could freeze the app on a
/// slow/hanging node — the same 0x8BADF00D class the auto-refresh timer
/// used to hit before it moved to `refresh_async`). Same shape as
/// `refresh_async`: snapshot everything the worker needs (base url, every
/// active notebook's address, the snapshot-time-active notebook's
/// pending-tx/dropped-check inputs), fetch every bundle on a worker
/// thread, and apply through [`WALLET_STORES_REFRESH_RESULTS`] + the
/// `apply-pending-wallet-stores-refresh` trampoline — never touching the
/// UI thread with network I/O. A second tap while one is already in flight
/// is ignored (simpler than overlapping store-file writes) rather than
/// queued; see [`WalletStoresRefreshResult`]'s doc comment for the
/// staleness guards applied when the result lands.
///
/// Goes through the [`SCAN_LANE`] queue (2026-07-21) keyed
/// `wstores/<fp8>/<network>/<account>`, behind the existing
/// `scan_gate.wallet_stores_busy()` early-return above (kept as-is).
/// Gate-flag + status only set when [`scan_lane_submit`] returns `true`.
fn wallet_stores_refresh_async(w: &AppWindow, st: &mut State, purpose: WalletStoresPurpose) {
    let label = purpose.label();
    if st.scan_gate.wallet_stores_busy() {
        println!("cb: {label} busy");
        return;
    }
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let Some(fp8) = st.notebooks_fp8.clone() else { return };
    let network = st.network;
    let account = st.account;
    let current_index = st.ident.as_ref().map(|i| i.index);
    let current_address = st.ident.as_ref().map(|i| i.address.clone());
    // Every ACTIVE notebook's (index, address) — mirrors the old
    // `refresh_wallet_stores`'s `ix.active(account)` walk, plus a fallback
    // push for the active notebook in the unlikely case it's missing from
    // `nb_addrs` (never observed, but `refresh()` never depended on that
    // invariant either — cheap to guard here too).
    let mut all: Vec<(u32, String)> = st
        .notebooks
        .as_ref()
        .map(|ix| {
            ix.active(account)
                .filter_map(|m| {
                    st.nb_addrs.iter().find(|(a, ..)| *a == m.index).map(|(i, addr, _)| (*i, addr.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(idx) = current_index {
        if !all.iter().any(|(i, _)| *i == idx) {
            if let Some(addr) = &current_address {
                all.push((idx, addr.clone()));
            }
        }
    }
    let pending_txids: Vec<String> = st
        .store
        .as_ref()
        .unwrap()
        .txs
        .iter()
        .filter(|t| t.status == NoteStatus::Pending)
        .flat_map(|t| t.txids.iter().cloned())
        .collect();
    let dropped_checks = gather_dropped_checks(st.store.as_ref().unwrap());
    // Taproot change-chain scan (unit 3): cloned here (worker-thread parse,
    // same convention `spending_scan_async` uses for its own material
    // clone) so the gap walk runs alongside the notebook rescans instead of
    // needing a separate kick. `None` (no cached material this session)
    // yields an empty result with no chain call — matches
    // `scan_change_chain`'s own "nothing to walk" shape for watch/WIF/hex.
    let material_for_change = st.material.clone();
    // Unit 6: a WATCH identity has no material `realize_change` can use
    // (it errors on Xpub) — its chain-1 change chain lives in the SAME
    // `tr(.../<0;1>/*)` descriptor `watch_source()` already exposes for
    // sweep/consolidate, so scan it via `scan_change_chain_watch` instead.
    let is_watch = st.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
    let watch_src_for_change = st.ident.as_ref().and_then(|i| i.watch_source()).cloned();
    let key = format!("wstores/{fp8}/{}/{account}", network.as_str());
    let creds = core_rpc_creds_for(st, &base, network);
    let core_watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    let job = move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let client = match open_client_watched(&base, network, creds, &core_watch) {
            Ok(c) => c,
            Err(e) => {
                // A malformed node URL fails the whole scan — every notebook's
                // bundle fetch reports the same error, matching an entirely
                // offline backend rather than inventing a new error path.
                let msg = e.to_string();
                let results: Vec<NotebookBundleResult> = all
                    .into_iter()
                    .map(|(index, _)| NotebookBundleResult { index, bundle: Err(msg.clone()) })
                    .collect();
                let current_statuses = pending_txids.iter().map(|t| (t.clone(), None)).collect();
                drop(material_for_change); // Zeroizing, same as the success path.
                WALLET_STORES_REFRESH_RESULTS
                    .lock()
                    .expect("wallet stores refresh mutex")
                    .push(WalletStoresRefreshResult {
                        purpose,
                        fp8,
                        network,
                        account,
                        current_index,
                        current_address,
                        current_statuses,
                        current_dropped_lookup: HashMap::new(),
                        current_dropped_unspent: HashMap::new(),
                        results,
                        change: Err(msg),
                    });
                let _ =
                    weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_stores_refresh());
                return;
            }
        };
        let results: Vec<NotebookBundleResult> = all
            .into_iter()
            .map(|(index, address)| NotebookBundleResult {
                index,
                bundle: client.build_bundle(&address, None).map_err(|e| format!("{e}")),
            })
            .collect();
        let current_statuses =
            pending_txids.iter().map(|t| (t.clone(), client.fetch_tx_status(t))).collect();
        let (current_dropped_lookup, current_dropped_unspent) = fetch_dropped_checks(
            &client,
            current_address.as_deref().unwrap_or_default(),
            &dropped_checks,
        );
        let change = if is_watch {
            // Unit 6: watch-only walks the descriptor's own chain-1 range —
            // no material to parse, no material to zeroize.
            match &watch_src_for_change {
                Some(src) => scan_change_chain_watch(&client, src, 1).map_err(|e| format!("{e}")),
                None => Ok(Vec::new()),
            }
        } else {
            match material_for_change.as_deref().map(|m| parse_key_material(m, network)) {
                Some(Ok(material)) => scan_change_chain(&client, &material, network, account, 1)
                    .map_err(|e| format!("{e}")),
                Some(Err(e)) => Err(e.to_string()),
                None => Ok(Vec::new()),
            }
        };
        drop(material_for_change); // Zeroizing — wiped as soon as the scan is done
        WALLET_STORES_REFRESH_RESULTS
            .lock()
            .expect("wallet stores refresh mutex")
            .push(WalletStoresRefreshResult {
                purpose,
                fp8,
                network,
                account,
                current_index,
                current_address,
                current_statuses,
                current_dropped_lookup,
                current_dropped_unspent,
                results,
                change,
            });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_stores_refresh());
    };
    if scan_lane_submit(key, job) {
        st.scan_gate.set_wallet_stores(true);
        update_scan_gate(w, st);
        w.set_status("syncing…".into());
    }
}

/// One finished notebook gap-discovery walk (worker thread), waiting to be
/// applied on the UI thread. The identity/network/account snapshot guards
/// staleness — switching identities mid-probe drops the result.
struct DiscoveryResult {
    fp8: String,
    network: Network,
    account: u32,
    found: Vec<u32>,
}

static DISCOVERY_RESULTS: std::sync::Mutex<Vec<DiscoveryResult>> = std::sync::Mutex::new(Vec::new());

/// Result of the deferred auto-unlock, handed from its worker thread to the
/// UI thread via the `apply-pending-unlock` trampoline (same shape as
/// REFRESH_RESULTS / DISCOVERY_RESULTS).
static UNLOCK_RESULT: std::sync::Mutex<Option<Result<Option<String>, String>>> =
    std::sync::Mutex::new(None);

/// A finished rebroadcast raw-hex fetch (`on_act_retry`'s sub-case (b): a
/// chain-recovered/watch record with no locally cached hex) — waiting to
/// enter the universal confirm screen on the UI thread. Mirrors
/// `SpendingRefreshResult`'s staleness pattern, anchored on the identity
/// address (switching identity mid-fetch drops the result rather than
/// misapplying it).
struct RebroadcastFetchResult {
    ref_id: String,
    is_note: bool,
    identity_addr: String,
    result: Result<String, String>,
}
static REBROADCAST_FETCH_RESULTS: std::sync::Mutex<Vec<RebroadcastFetchResult>> =
    std::sync::Mutex::new(Vec::new());

/// The UI-thread half of `on_act_retry`'s sub-case (b): clear the transient
/// fetch guard, drop a stale result, and either enter the confirm screen
/// (fetch succeeded) or report the failure — same shape as
/// `apply_spending_refresh_results`.
fn apply_pending_rebroadcast_fetch_results(w: &AppWindow, st: &mut State) {
    let results: Vec<RebroadcastFetchResult> =
        REBROADCAST_FETCH_RESULTS.lock().expect("rebroadcast fetch results mutex").drain(..).collect();
    for r in results {
        st.act_pending_ref = None;
        if st.ident.as_ref().map(|i| i.address.as_str()) != Some(r.identity_addr.as_str()) {
            println!("cb: rebroadcast-fetch stale-drop");
            continue;
        }
        match r.result {
            Ok(raw) if !raw.is_empty() => enter_rebroadcast_confirm(w, st, r.ref_id, r.is_note, raw),
            Ok(_) => {
                println!("cb: act-retry ref={} err=nothing-to-rebroadcast", r.ref_id);
                w.set_status("nothing to rebroadcast".into());
            }
            Err(e) => {
                println!("cb: act-retry ref={} err={e}", r.ref_id);
                w.set_status(format!("couldn't rebroadcast: {}", friendly_net_err(&e)).into());
            }
        }
    }
    update_activity(w, st);
}

/// A finished Activity Rebroadcast (`on_act_retry`) broadcast POST, waiting
/// to be applied on the UI thread — clears `State.act_pending_ref` and
/// shows the toast (2026-07-16: rebroadcast used to give no feedback at
/// all, "like nothing happened", per Sal).
struct ActRetryResult {
    ref_id: String,
    result: Result<String, String>,
}
static ACT_RETRY_RESULTS: std::sync::Mutex<Vec<ActRetryResult>> = std::sync::Mutex::new(Vec::new());

fn apply_act_retry_results(w: &AppWindow, st: &mut State) {
    let results: Vec<ActRetryResult> =
        ACT_RETRY_RESULTS.lock().expect("act-retry results mutex").drain(..).collect();
    for r in results {
        st.act_pending_ref = None;
        match r.result {
            Ok(txid) => {
                println!("cb: act-retry ref={} txid={txid} ok", r.ref_id);
                w.set_status(format!("rebroadcast {}…", &txid[..12.min(txid.len())]).into());
                show_toast(w, &format!("Rebroadcast ok · {}", &txid[..8.min(txid.len())]));
            }
            Err(e) => {
                println!("cb: act-retry ref={} err={e}", r.ref_id);
                let base = st.base_url().unwrap_or_default();
                w.set_status(
                    format!("rebroadcast failed: {}", friendly_broadcast_err(&e, &base)).into(),
                );
                show_toast(w, "Rebroadcast failed");
            }
        }
    }
    update_activity(w, st);
}

/// A finished Activity Speed-up (`on_act_bump_confirm`) broadcast POST. The
/// re-sign (bump_*_build at stage A, record_bumped_* + save at the
/// Broadcast tap) already ran synchronously and
/// saved the store BEFORE this — same "record already saved" shape as the
/// notebook compose path — so a broadcast failure here needs no navigation
/// (the bump dialog already closed onto the Activity screen); only status +
/// toast + a refresh.
struct ActBumpResult {
    ref_id: String,
    txid: String,
    fee: u64,
    new_rate: f64,
    result: Result<String, String>,
}
static ACT_BUMP_RESULTS: std::sync::Mutex<Vec<ActBumpResult>> = std::sync::Mutex::new(Vec::new());

fn apply_act_bump_results(w: &AppWindow, st: &mut State) {
    let results: Vec<ActBumpResult> =
        ACT_BUMP_RESULTS.lock().expect("act-bump results mutex").drain(..).collect();
    for r in results {
        st.act_pending_ref = None;
        match r.result {
            Ok(bt) => {
                println!(
                    "cb: act-bump ref={} txid={} fee={} rate={:.1} ok",
                    r.ref_id, r.txid, r.fee, r.new_rate
                );
                w.set_status(format!("sped up: {}…", &bt[..12.min(bt.len())]).into());
                show_toast(w, &format!("Sped up · {}", &bt[..8.min(bt.len())]));
            }
            Err(e) => {
                println!("cb: act-bump ref={} broadcast err={e}", r.ref_id);
                let base = st.base_url().unwrap_or_default();
                w.set_status(
                    format!("signed but broadcast failed: {}", friendly_broadcast_err(&e, &base))
                        .into(),
                );
                show_toast(w, "Speed-up broadcast failed");
            }
        }
    }
    update_activity(w, st);
    update_home(w, st);
}

// ---- CHANGE 4: async wallet-tx broadcast (2026-07-17) ----
//
// consolidate / sweep / wallet-consolidate / psbt-broadcast all build+sign
// synchronously (fast, no network) exactly as before; only the
// `client.broadcast()` POST moves to a worker thread — the part that used
// to visibly freeze the confirm button on a slow connection. Each flow's
// `apply_*_result` replays its EXACT pre-existing Ok/Err bookkeeping, once,
// from the worker's result, via the shared `apply-pending-wallet-tx`
// trampoline (`apply_pending_wallet_tx_results` drains every queue) — same
// shape as `apply_compose_results`. `State.wallet_tx_busy` is the shared
// re-entrancy guard; every entry point returns early when it's set.

/// Non-`result` half of [`SweepBroadcastResult`] — built on the UI thread
/// before spawning (owns everything the apply side needs), moved into the
/// worker, then wrapped with the real broadcast result and pushed. `Clone`
/// so it can also ride in `PendingPayload::Sweep` (universal confirm
/// screen, funding-unification follow-up 2026-07-17).
#[derive(Clone)]
struct SweepSnapshot {
    /// The active notebook's address at spawn time — if it no longer
    /// matches on the apply side (identity/account/notebook switched
    /// mid-flight), the tx is already on-chain but its bookkeeping is
    /// dropped (logged `stale-drop`) rather than misapplied to the WRONG
    /// store; the next refresh's UTXO scan still reconciles balances.
    identity_addr: String,
    dest: String,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    vsize: u64,
    raw_hex: String,
    /// Per-notebook lock list: (notebook index, [(txid display-hex, vout)]).
    notebook_locks: Vec<(u32, Vec<(String, u32)>)>,
    all_inputs: Vec<app_core::store::TxInput>,
    /// Empty for a MIXED sweep (`TxRecord.mixed_inputs` — CHANGE 2): no
    /// per-input owner scheme covers both input kinds, so a mixed record
    /// can't be bumped either.
    input_indexes: Vec<u32>,
    mixed: bool,
    /// CHANGE 2: spending-wallet coins that rode as inputs — pruned from
    /// the runtime cache and re-scanned on success.
    spending_spent: Vec<(String, u32)>,
    /// Sweeping notebook funds INTO the spending wallet's next receive
    /// address (`on_spending_sweep_here`) — marked used on success.
    pending_spending_sweep_index: Option<u32>,
    notebooks_n: usize,
    /// Taproot CHANGE-chain coins (`m/86'/…/1/{index}`) that rode as
    /// inputs — pruned from `State.change_coins` on success (unit 6, see
    /// `../PLAN-chain-notes-app-taproot-change.md`), same treatment as
    /// `spending_spent` above: the next wallet-stores refresh re-scans
    /// chain 1 and would otherwise re-offer an already-spent coin.
    change_spent: Vec<(String, u32)>,
}

struct SweepBroadcastResult {
    snap: SweepSnapshot,
    result: Result<String, String>,
}
static SWEEP_BROADCAST_RESULTS: std::sync::Mutex<Vec<SweepBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_sweep_broadcast_result(w: &AppWindow, st: &mut State, r: SweepBroadcastResult) {
    let snap = r.snap;
    if st.ident.as_ref().map(|i| i.address.as_str()) != Some(snap.identity_addr.as_str()) {
        println!("cb: sweep stale-drop");
        return;
    }
    match r.result {
        Ok(txid) => {
            for (index, coins) in &snap.notebook_locks {
                let active = st.ident.as_ref().map(|i| i.index) == Some(*index);
                let mark = |store: &mut Store| {
                    for (txid_hex, vout) in coins {
                        if let Some(l) =
                            store.utxos.iter_mut().find(|l| &l.txid == txid_hex && l.vout == *vout)
                        {
                            l.pending_spend = true;
                        }
                    }
                };
                if active {
                    if let Some(store) = st.store.as_mut() {
                        mark(store);
                    }
                } else if let Some(mut store) = notebook_store(st, *index) {
                    mark(&mut store);
                    if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                        save_store_file(&store, &st.store_path_for(fp8));
                    }
                }
            }
            if let Some(store) = st.store.as_mut() {
                store.record_tx(
                    "sweep",
                    txid.clone(),
                    snap.value,
                    snap.fee,
                    snap.vsize,
                    snap.raw_hex.clone(),
                    snap.dest.clone(),
                    snap.all_inputs.clone(),
                    snap.dest_spk_hex.clone(),
                    now(),
                );
                if let Some(rec) = store.txs.last_mut() {
                    rec.input_indexes = snap.input_indexes.clone();
                    rec.mixed_inputs = snap.mixed;
                }
            }
            if let Some(idx) = snap.pending_spending_sweep_index {
                st.pending_spending_sweep_index = None;
                if let (Some(src), Some(store)) = (st.spending_source.clone(), st.store.as_mut()) {
                    if let Ok(addr) = src.derive(0, idx) {
                        store.spending_mark_used(SpendingAddr {
                            chain: 0,
                            index: idx,
                            address: addr.address,
                            script_pubkey_hex: hex::encode(&addr.spk),
                        });
                    }
                }
                st.save_spending();
            }
            let spending_n = snap.spending_spent.len();
            if spending_n > 0 {
                st.spending_coins.retain(|c| {
                    !snap.spending_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
                update_spending_ui(w, st);
                spending_refresh_async(w, st);
            }
            // Taproot CHANGE-chain coins (unit 6): same treatment as the
            // spending-wallet coins above — pruned from the runtime cache
            // so they're not re-offered before the next wallet-stores
            // refresh re-scans chain 1 and finds them gone.
            let change_n = snap.change_spent.len();
            if change_n > 0 {
                st.change_coins.retain(|c| {
                    !snap.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
            }
            st.save_store();
            println!(
                "cb: sweep txid={txid} value={} fee={} notebooks={}{}{}",
                snap.value,
                snap.fee,
                snap.notebooks_n,
                if spending_n > 0 { format!(" spending={spending_n}") } else { String::new() },
                if change_n > 0 { format!(" change={change_n}") } else { String::new() }
            );
            w.set_status(
                format!(
                    "swept the wallet — {} sats to {}…",
                    commas(snap.value),
                    &snap.dest[..14.min(snap.dest.len())]
                )
                .into(),
            );
            update_notebook_list(w, st);
            w.set_screen(17); // wallet-level flow → the list
        }
        Err(e) => {
            println!("cb: sweep broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.set_status(
                format!("sweep broadcast failed: {}", friendly_broadcast_err(&e, &base)).into(),
            );
        }
    }
}

/// Non-`result` half of a single-notebook consolidate broadcast (screen 16,
/// kind "consolidate") — same shape as [`SweepSnapshot`], one store instead
/// of many. `Clone` for `PendingPayload::Consolidate`.
#[derive(Clone)]
struct ConsolidateSnapshot {
    identity_addr: String,
    value: u64,
    fee: u64,
    vsize: u64,
    raw_hex: String,
    dest_spk_hex: String,
    inputs: Vec<app_core::store::TxInput>,
}
struct ConsolidateBroadcastResult {
    snap: ConsolidateSnapshot,
    result: Result<String, String>,
}
static CONSOLIDATE_BROADCAST_RESULTS: std::sync::Mutex<Vec<ConsolidateBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_consolidate_broadcast_result(w: &AppWindow, st: &mut State, r: ConsolidateBroadcastResult) {
    let snap = r.snap;
    if st.ident.as_ref().map(|i| i.address.as_str()) != Some(snap.identity_addr.as_str()) {
        println!("cb: consolidate stale-drop");
        return;
    }
    match r.result {
        Ok(txid) => {
            if let Some(store) = st.store.as_mut() {
                for u in &mut store.utxos {
                    u.pending_spend = true;
                }
                store.record_tx(
                    "consolidate",
                    txid.clone(),
                    snap.value,
                    snap.fee,
                    snap.vsize,
                    snap.raw_hex.clone(),
                    "self".into(),
                    snap.inputs.clone(),
                    snap.dest_spk_hex.clone(),
                    now(),
                );
            }
            st.save_store();
            println!("cb: consolidate txid={txid} value={} fee={}", snap.value, snap.fee);
            w.set_status(format!("consolidating: {}…", &txid[..12.min(txid.len())]).into());
            w.set_screen(4); // done — home, like the PSBT flow
            update_home(w, st);
        }
        Err(e) => {
            println!("cb: consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.set_status(
                format!("consolidate broadcast failed: {}", friendly_broadcast_err(&e, &base))
                    .into(),
            );
        }
    }
}

/// Non-`result` half of a wallet-consolidate broadcast (Settings/Coins →
/// "Consolidate wallet…", keyed non-watch path) — spans potentially several
/// SOURCE notebook stores plus a DESTINATION store, so its staleness anchor
/// is the identity/network/account triple (`fp8`), same guard shape as
/// [`SpendingRefreshResult`], not a single notebook address. `Clone` for
/// `PendingPayload::WConsol`.
#[derive(Clone)]
struct WConsolSnapshot {
    fp8: String,
    network: Network,
    account: u32,
    dest_index: u32,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    vsize: u64,
    raw_hex: String,
    /// (source notebook index, [(txid display-hex, vout)]) — mirrors
    /// `SweepSnapshot.notebook_locks`.
    source_locks: Vec<(u32, Vec<(String, u32)>)>,
    all_inputs: Vec<app_core::store::TxInput>,
    input_indexes: Vec<u32>,
    sources_n: usize,
}
struct WConsolBroadcastResult {
    snap: WConsolSnapshot,
    result: Result<String, String>,
}
static WCONSOL_BROADCAST_RESULTS: std::sync::Mutex<Vec<WConsolBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_wconsol_broadcast_result(w: &AppWindow, st: &mut State, r: WConsolBroadcastResult) {
    let snap = r.snap;
    if st.notebooks_fp8.as_deref() != Some(snap.fp8.as_str())
        || st.network != snap.network
        || st.account != snap.account
    {
        println!("cb: wallet-consolidate stale-drop");
        return;
    }
    match r.result {
        Ok(txid) => {
            let material_str = st.material.as_ref().map(|z| String::from(z.as_str()));
            let dest_ident_ok = material_str
                .as_deref()
                .and_then(|m| parse_key_material(m, snap.network).ok())
                .and_then(|material| realize(&material, snap.network, snap.account, snap.dest_index).ok());
            if let Some(dest_ident) = dest_ident_ok {
                let mut dstore = notebook_store(st, snap.dest_index)
                    .unwrap_or_else(|| Store::new(&dest_ident.output_x(), snap.network));
                dstore.record_tx(
                    "consolidate",
                    txid.clone(),
                    snap.value,
                    snap.fee,
                    snap.vsize,
                    snap.raw_hex.clone(),
                    "self".into(),
                    snap.all_inputs.clone(),
                    snap.dest_spk_hex.clone(),
                    now(),
                );
                if let Some(rec) = dstore.txs.last_mut() {
                    rec.input_indexes = snap.input_indexes.clone();
                }
                // Sources' inputs lock (the dest store handles its own below).
                for (index, coins) in &snap.source_locks {
                    if *index == snap.dest_index {
                        for (txid_hex, vout) in coins {
                            if let Some(l) =
                                dstore.utxos.iter_mut().find(|l| &l.txid == txid_hex && l.vout == *vout)
                            {
                                l.pending_spend = true;
                            }
                        }
                    }
                }
                dstore.utxos.push(app_core::store::LedgerUtxo {
                    txid: txid.clone(),
                    vout: 0,
                    value: snap.value,
                    height: None,
                    pending_spend: false,
                });
                if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == snap.dest_index) {
                    save_store_file(&dstore, &st.store_path_for(fp8));
                }
            }
            for (index, coins) in &snap.source_locks {
                if *index == snap.dest_index {
                    continue; // handled with the destination store above
                }
                let Some(mut store) = notebook_store(st, *index) else { continue };
                for (txid_hex, vout) in coins {
                    if let Some(l) = store.utxos.iter_mut().find(|l| &l.txid == txid_hex && l.vout == *vout) {
                        l.pending_spend = true;
                    }
                }
                if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                    save_store_file(&store, &st.store_path_for(fp8));
                }
            }
            // Reload the active store from disk (it may be source and/or
            // dest), then land on the list — the wallet-level money flow's
            // home.
            if let Some(m) = material_str {
                let _ = activate(st, &m, false);
            }
            update_notebook_list(w, st);
            println!(
                "cb: wallet-consolidate txid={txid} coins={} notebooks={} value={} fee={}",
                snap.all_inputs.len(),
                snap.sources_n,
                snap.value,
                snap.fee
            );
            w.set_status(
                format!(
                    "consolidated — {} sats now at {}",
                    commas(snap.value),
                    st.notebook_display_name(snap.dest_index)
                )
                .into(),
            );
            w.set_screen(17);
        }
        Err(e) => {
            println!("cb: wallet-consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

/// Non-`result` half of a psbt-broadcast (screen 14 "Broadcast" — the
/// watch/external-sign flow's finalize+broadcast button, also used by
/// plain external-funding compose with no watch bookkeeping at all).
/// `finalize_extract` runs synchronously (local, fast) BEFORE spawning, so
/// `txid`/`raw`/`vsize` are already final — only the broadcast POST itself
/// is async. `identity_addr` is the staleness anchor; on a mismatch the
/// pending `watch_note`/`watch_spend` bookkeeping is dropped too (cleared,
/// not left to misapply against a switched-to identity next time).
struct PsbtBroadcastSnapshot {
    identity_addr: String,
    txid: String,
    raw: String,
    vsize: usize,
}
struct PsbtBroadcastResult {
    snap: PsbtBroadcastSnapshot,
    result: Result<String, String>,
}
static PSBT_BROADCAST_RESULTS: std::sync::Mutex<Vec<PsbtBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_psbt_broadcast_result(w: &AppWindow, st: &mut State, r: PsbtBroadcastResult) {
    let snap = r.snap;
    if st.ident.as_ref().map(|i| i.address.as_str()) != Some(snap.identity_addr.as_str()) {
        println!("cb: fund-broadcast stale-drop");
        st.watch_note = None;
        st.watch_spend = None;
        return;
    }
    match r.result {
        Ok(_got) => {
            let raw = snap.raw.as_str();
            let txid = snap.txid.as_str();
            let vsize = snap.vsize;
            // Wallet-level money flows (watch sweep/consolidate) land on
            // the notebook LIST — the wallet's home — like their keyed
            // twins; notes and bumps keep landing on the active notebook.
            let mut wallet_flow = false;
            if let Some(wn) = st.watch_note.take() {
                // Watch-mode compose (or a keyed mixed-source compose that
                // included an external wallet — funding-unification UI
                // rework, `wn.is_watch == false`): the note enters the
                // store as Pending exactly like a keyed compose (inputs
                // locked, change spendable, raw hex kept for rebroadcast).
                record_watch_note(st, &wn, txid, raw, vsize as u64);
                println!(
                    "cb: compose id={} txid={txid} fee={} vsize={vsize} to={} private={} gift={} watch={} broadcast=ok",
                    hex::encode(wn.note_id),
                    wn.fee,
                    wn.recipient.as_deref().unwrap_or("self"),
                    wn.private,
                    wn.gift,
                    if wn.is_watch { 1 } else { 0 }
                );
            } else if let Some(ws) = st.watch_spend.take() {
                // Watch-mode spend: record it so Activity gets the
                // pending→confirmed lifecycle, and lock the coins.
                let change_n = ws.change_spent.len();
                record_watch_spend(st, &ws, txid, raw, vsize as u64);
                println!(
                    "cb: watch-{} txid={txid} fee={} ok{}",
                    ws.kind,
                    ws.fee,
                    if change_n > 0 { format!(" change={change_n}") } else { String::new() }
                );
                wallet_flow = ws.bump_ref.is_none() && (ws.kind == "sweep" || ws.kind == "consolidate");
            } else {
                println!("cb: fund-broadcast txid={txid} ok");
            }
            w.set_status(format!("broadcast {}…", &txid[..12.min(txid.len())]).into());
            st.funding_coins.clear();
            st.built_psbt = None;
            st.signed_psbt = None;
            st.ur_frames.clear();
            w.set_compose_text("".into());
            w.set_fund_external(false);
            w.set_psbt_signed(false);
            if wallet_flow {
                refresh(w, st); // active store first — the list rows read disk + memory
                update_notebook_list(w, st);
                w.set_screen(17);
            } else {
                w.set_screen(4);
                refresh(w, st);
            }
        }
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

/// Non-`result` half of a spending-wallet consolidate broadcast (CHANGE 3,
/// Coins screen spending segment "Consolidate spending coins…") — merges
/// EVERY spending coin into one, at the next fresh spending receive
/// address, signed in-app (no external wallet). Staleness anchor is the
/// identity/network/account triple, like [`WConsolSnapshot`] (the spending
/// section lives at the account level, not a single notebook). `Clone` for
/// `PendingPayload::SpendingConsolidate`.
#[derive(Clone)]
struct SpendingConsolidateSnapshot {
    fp8: String,
    network: Network,
    account: u32,
    /// The receive index consolidated INTO — marked used on success.
    dest_index: u32,
    dest_addr: String,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    vsize: u64,
    raw_hex: String,
    /// Every spending coin that rode as an input (outpoint + value) —
    /// pruned from the runtime cache on success.
    spent: Vec<(String, u32, u64)>,
}
struct SpendingConsolidateResult {
    snap: SpendingConsolidateSnapshot,
    result: Result<String, String>,
}
static SPENDING_CONSOLIDATE_RESULTS: std::sync::Mutex<Vec<SpendingConsolidateResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_spending_consolidate_result(w: &AppWindow, st: &mut State, r: SpendingConsolidateResult) {
    let snap = r.snap;
    if st.notebooks_fp8.as_deref() != Some(snap.fp8.as_str())
        || st.network != snap.network
        || st.account != snap.account
    {
        println!("cb: spending-consolidate stale-drop");
        return;
    }
    match r.result {
        Ok(txid) => {
            // Fresh-address discipline: the destination is now used.
            if let Some(store) = st.store.as_mut() {
                store.spending_mark_used(SpendingAddr {
                    chain: 0,
                    index: snap.dest_index,
                    address: snap.dest_addr.clone(),
                    script_pubkey_hex: snap.dest_spk_hex.clone(),
                });
            }
            st.save_spending();
            // Prune every spent coin, then immediately track the new one so
            // the segment shows it without waiting for the rescan below.
            st.spending_coins.retain(|c| {
                !snap.spent.iter().any(|(t, v, _)| t == &c.txid && *v == c.vout)
            });
            st.spending_coins.push(FundingUtxo {
                txid: txid.clone(),
                vout: 0,
                value: snap.value,
                address: snap.dest_addr.clone(),
                chain: 0,
                index: snap.dest_index,
                confirmed: false,
            });
            if let Some(store) = st.store.as_mut() {
                let inputs: Vec<app_core::store::TxInput> = snap
                    .spent
                    .iter()
                    .map(|(t, v, val)| app_core::store::TxInput { txid: t.clone(), vout: *v, value: *val })
                    .collect();
                store.record_tx(
                    "consolidate",
                    txid.clone(),
                    snap.value,
                    snap.fee,
                    snap.vsize,
                    snap.raw_hex.clone(),
                    snap.dest_addr.clone(),
                    inputs,
                    snap.dest_spk_hex.clone(),
                    now(),
                );
                // All-P2WPKH inputs — same non-bumpable marker as a mixed
                // notebook+spending sweep (CHANGE 2 / TxRecord.mixed_inputs):
                // the taproot bump path can't re-sign these either.
                if let Some(rec) = store.txs.last_mut() {
                    rec.mixed_inputs = true;
                }
            }
            st.save_store();
            update_spending_ui(w, st);
            spending_refresh_async(w, st); // authoritative reconciliation
            println!(
                "cb: spending-consolidate txid={txid} coins={} value={} fee={}",
                snap.spent.len(),
                snap.value,
                snap.fee
            );
            // Coins-management op, like notebook consolidate — stays on the
            // Coins screen (spending segment), not a money-flow "go home".
            show_toast(w, &format!("Consolidated · {}…", &txid[..8.min(txid.len())]));
            update_wallet_coins(w, st);
        }
        Err(e) => {
            println!("cb: spending-consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.set_status(
                format!("consolidate failed: {}", friendly_broadcast_err(&e, &base)).into(),
            );
            show_toast(w, "Broadcast failed");
        }
    }
}

/// Drains the CHANGE-4 wallet-tx result queues and applies each on the UI
/// thread — the shared `apply-pending-wallet-tx` trampoline target. Also
/// clears the shared busy flag.
fn apply_pending_wallet_tx_results(w: &AppWindow, st: &mut State) {
    let sweep: Vec<SweepBroadcastResult> =
        SWEEP_BROADCAST_RESULTS.lock().expect("sweep broadcast results mutex").drain(..).collect();
    let consolidate: Vec<ConsolidateBroadcastResult> = CONSOLIDATE_BROADCAST_RESULTS
        .lock()
        .expect("consolidate broadcast results mutex")
        .drain(..)
        .collect();
    let wconsol: Vec<WConsolBroadcastResult> =
        WCONSOL_BROADCAST_RESULTS.lock().expect("wconsol broadcast results mutex").drain(..).collect();
    let psbt: Vec<PsbtBroadcastResult> =
        PSBT_BROADCAST_RESULTS.lock().expect("psbt broadcast results mutex").drain(..).collect();
    let spending_consolidate: Vec<SpendingConsolidateResult> = SPENDING_CONSOLIDATE_RESULTS
        .lock()
        .expect("spending consolidate results mutex")
        .drain(..)
        .collect();
    if sweep.is_empty()
        && consolidate.is_empty()
        && wconsol.is_empty()
        && psbt.is_empty()
        && spending_consolidate.is_empty()
    {
        return;
    }
    st.wallet_tx_busy = false;
    w.set_wallet_tx_busy(false);
    for r in sweep {
        apply_sweep_broadcast_result(w, st, r);
    }
    for r in consolidate {
        apply_consolidate_broadcast_result(w, st, r);
    }
    for r in wconsol {
        apply_wconsol_broadcast_result(w, st, r);
    }
    for r in psbt {
        apply_psbt_broadcast_result(w, st, r);
    }
    for r in spending_consolidate {
        apply_spending_consolidate_result(w, st, r);
    }
}

// ---- Async compose send (2026-07-16) ----
//
// Each of the three compose send paths (notebook / spending / mixed) builds
// + signs synchronously (fast, no network) exactly as before, then hands
// ONLY the `client.broadcast()` POST to a worker thread — the part that
// used to visibly freeze the Sign button on a slow connection. The UI-
// thread `apply_*_compose_result` functions replay each path's EXACT
// pre-existing Ok/Err bookkeeping, now run once from the worker's result via
// the shared `apply-pending-compose` trampoline (`apply_compose_results`
// drains all three). The external/watch/fund-external route is untouched —
// it already hands off to the sign screen instead of broadcasting itself.

/// Notebook path (`on_compose_send`): `compose_and_record` already wrote the
/// note Pending + locked its inputs BEFORE broadcast was attempted (existing
/// invariant), so a broadcast failure is never a build/sign failure —
/// staying on compose would risk a double-compose. Land on Activity instead
/// (Rebroadcast is right there for the already-saved record).
struct NotebookComposeResult {
    note_id: String,
    fee: u64,
    vsize: usize,
    to: Option<String>,
    private: bool,
    result: Result<String, String>,
}
static NOTEBOOK_COMPOSE_RESULTS: std::sync::Mutex<Vec<NotebookComposeResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_notebook_compose_result(w: &AppWindow, st: &mut State, r: NotebookComposeResult) {
    match r.result {
        Ok(txid) => {
            println!(
                "cb: compose id={} txid={txid} fee={} vsize={} to={} private={} broadcast=ok",
                r.note_id, r.fee, r.vsize, r.to.as_deref().unwrap_or("self"), r.private
            );
            w.set_status(format!("broadcast {}…", &txid[..12.min(txid.len())]).into());
            w.set_compose_text("".into());
            w.set_change_address("".into());
            w.set_change_expanded(false);
            w.set_spend_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.set_change_choice("".into());
            w.set_screen(4);
            refresh_async(w, st);
        }
        Err(e) => {
            println!("cb: compose broadcast err={e}");
            w.set_return_screen(4);
            update_activity(w, st);
            let base = st.base_url().unwrap_or_default();
            w.set_status(
                format!(
                    "broadcast failed: {} — note saved, retry from here",
                    friendly_broadcast_err(&e, &base)
                )
                .into(),
            );
            show_toast(w, "Broadcast failed — note saved. Retry from this list.");
            w.set_screen(11);
        }
    }
}

/// Spending-wallet path (`on_spending_compose_send`): unlike the notebook
/// path, nothing is recorded until broadcast actually succeeds — a failure
/// leaves the draft exactly as it was, so staying on compose to retry is
/// safe (no double-compose risk, nothing was locked).
struct SpendingComposeResult {
    note_id: [u8; 4],
    text: String,
    private: bool,
    to: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`.
    recipients: Vec<String>,
    gift: u64,
    raw: String,
    txid: String,
    vsize: usize,
    built_fee: u64,
    built_change: u64,
    spent_outpoints: Vec<(String, u32)>,
    change_index: u32,
    change_raw: String,
    source: FundingSource,
    result: Result<String, String>,
}
static SPENDING_COMPOSE_RESULTS: std::sync::Mutex<Vec<SpendingComposeResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_spending_compose_result(w: &AppWindow, st: &mut State, r: SpendingComposeResult) {
    match r.result {
        Ok(_echo) => {
            // Drop the coins this tx just spent from the runtime cache
            // immediately (finding 1: an immediate second compose must
            // never see an already-spent UTXO).
            st.spending_coins.retain(|c| {
                !r.spent_outpoints.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
            });
            update_spending_ui(w, st);
            spending_refresh_async(w, st);
            if r.built_change > 0 {
                if let Ok(change_addr) = r.source.derive(1, r.change_index) {
                    if let Some(store) = st.store.as_mut() {
                        store.spending_mark_used(SpendingAddr {
                            chain: 1,
                            index: r.change_index,
                            address: change_addr.address,
                            script_pubkey_hex: hex::encode(&change_addr.spk),
                        });
                    }
                    st.save_spending();
                }
            }
            if let Some(store) = st.store.as_mut() {
                store.record_signed(
                    app_core::store::NoteRecord {
                        note_id: hex::encode(r.note_id),
                        status: NoteStatus::Pending,
                        text: Some(r.text.clone()),
                        private: r.private,
                        directed: r.to.is_some(),
                        received: false,
                        sender: None,
                        recipient: r.to.clone(),
                        recipients: r.recipients.clone(),
                        txids: vec![r.txid.clone()],
                        height: None,
                        blocktime: None,
                        created_at: Some(now()),
                        spent: Vec::new(), // spending-wallet inputs only — no notebook coin locked
                        raw_hex: Some(r.raw.clone()),
                        fee: Some(r.built_fee),
                        vsize: Some(r.vsize as u64),
                        change_to: (!r.change_raw.is_empty()).then(|| r.change_raw.clone()),
                        gift_amount: r.to.as_ref().map(|_| r.gift),
                        funded_by: Some("spending".into()),
                        dropped: false,
                    },
                    None,
                );
            }
            // Touch every recipient — see `record_composed_note`'s same
            // rule on the notebook path. Redundant with the chip-add
            // flow's pick-time touch (idempotent), not the only place.
            // Device-level now (iCloud-contacts feature) — not on `store`.
            if r.recipients.is_empty() {
                if let Some(addr) = &r.to {
                    st.touch_contact(addr);
                }
            } else {
                for addr in &r.recipients {
                    st.touch_contact(addr);
                }
            }
            st.save_store();
            st.save_contacts();
            println!(
                "cb: compose id={} txid={} fee={} vsize={} to={} private={} funded=spending{} broadcast=ok",
                hex::encode(r.note_id), r.txid, r.built_fee, r.vsize,
                r.to.as_deref().unwrap_or("self"), r.private,
                if r.recipients.len() > 1 { format!(" recipients={}", r.recipients.len()) } else { String::new() }
            );
            w.set_status(format!("broadcast {}…", &r.txid[..12.min(r.txid.len())]).into());
            w.set_compose_text("".into());
            w.set_change_address("".into());
            w.set_change_expanded(false);
            w.set_spend_expanded(false);
            w.set_payfrom_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.set_change_choice("".into());
            w.set_screen(4);
            refresh_async(w, st);
        }
        // Universal confirm screen (2026-07-17): nothing was recorded, so
        // this is still safe to retry — but the retry point is compose
        // (screen 6, draft intact), not the confirm screen the user is
        // currently on (its Broadcast button is now inert: stage B already
        // dropped `pending_broadcast` for every non-psbt kind once it fired).
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
            w.set_screen(6);
        }
    }
}

/// Mixed-source path (`on_compose_send_mixed`): same "nothing recorded until
/// broadcast succeeds" shape as spending — a failure is safe to retry from
/// compose.
struct MixedComposeResult {
    note_id: [u8; 4],
    text: String,
    private: bool,
    to: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`.
    recipients: Vec<String>,
    gift: u64,
    raw: String,
    txid: String,
    vsize: usize,
    built_fee: u64,
    built_change: u64,
    change_default: app_core::mixed::ChangeDefault,
    notebook_spent: Vec<app_core::store::OutPointRef>,
    spent_spending: Vec<(String, u32)>,
    /// Taproot CHANGE-chain coins ridden as inputs (unit 5) — pruned from
    /// `State.change_coins` on success, same treatment as `spent_spending`.
    change_spent: Vec<(String, u32)>,
    payloads_len: usize,
    recipient_count: usize,
    change_index: u32,
    spending_source: Option<FundingSource>,
    result: Result<String, String>,
}
static MIXED_COMPOSE_RESULTS: std::sync::Mutex<Vec<MixedComposeResult>> =
    std::sync::Mutex::new(Vec::new());

fn apply_mixed_compose_result(w: &AppWindow, st: &mut State, r: MixedComposeResult) {
    match r.result {
        Ok(_echo) => {
            // Input-anchored skip (2026-07-18 dust-skip rework; extended to
            // Change by taproot-change unit 5): the dust-to-self output —
            // and therefore its BEFORE-change vout slot — only exists when
            // NO notebook OR change-chain coin funded this tx (same
            // `has_self_input` condition `assemble_mixed_note_psbt` used
            // for real); a notebook/change coin can still participate while
            // change defaults elsewhere-or-Notebook (the safe fallback), so
            // this must be derived from `notebook_spent`/`change_spent`,
            // never assumed.
            let dust_included = r.notebook_spent.is_empty() && r.change_spent.is_empty();
            if let Some(store) = st.store.as_mut() {
                let change_utxo = (r.built_change > 0
                    && r.change_default == app_core::mixed::ChangeDefault::Notebook)
                    .then(|| app_core::store::LedgerUtxo {
                        txid: r.txid.clone(),
                        vout: (r.payloads_len + r.recipient_count + usize::from(dust_included)) as u32,
                        value: r.built_change,
                        height: None,
                        pending_spend: false,
                    });
                store.record_signed(
                    app_core::store::NoteRecord {
                        note_id: hex::encode(r.note_id),
                        status: NoteStatus::Pending,
                        text: Some(r.text.clone()),
                        private: r.private,
                        directed: r.to.is_some(),
                        received: false,
                        sender: None,
                        recipient: r.to.clone(),
                        recipients: r.recipients.clone(),
                        txids: vec![r.txid.clone()],
                        height: None,
                        blocktime: None,
                        created_at: Some(now()),
                        spent: r.notebook_spent.clone(),
                        raw_hex: Some(r.raw.clone()),
                        fee: Some(r.built_fee),
                        vsize: Some(r.vsize as u64),
                        change_to: None,
                        gift_amount: r.to.as_ref().map(|_| r.gift),
                        funded_by: Some("mixed".into()),
                        dropped: false,
                    },
                    change_utxo,
                );
            }
            // Touch every recipient — see `record_composed_note`'s same
            // rule on the notebook path. Device-level now (iCloud-contacts
            // feature) — not on `store`.
            if r.recipients.is_empty() {
                if let Some(addr) = &r.to {
                    st.touch_contact(addr);
                }
            } else {
                for addr in &r.recipients {
                    st.touch_contact(addr);
                }
            }
            st.save_store();
            st.save_contacts();
            if !r.spent_spending.is_empty() {
                st.spending_coins.retain(|c| {
                    !r.spent_spending.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
                update_spending_ui(w, st);
            }
            // Taproot CHANGE-chain coins (unit 5): same treatment as the
            // spending-wallet coins above — pruned from the runtime cache so
            // they're not re-offered before the next wallet-stores refresh
            // re-scans chain 1 and finds them gone.
            let change_n = r.change_spent.len();
            if change_n > 0 {
                st.change_coins.retain(|c| {
                    !r.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
            }
            if r.change_default == app_core::mixed::ChangeDefault::Spending {
                if let Some(src) = r.spending_source.clone() {
                    if let Ok(change_addr) = src.derive(1, r.change_index) {
                        if let Some(store) = st.store.as_mut() {
                            store.spending_mark_used(SpendingAddr {
                                chain: 1,
                                index: r.change_index,
                                address: change_addr.address,
                                script_pubkey_hex: hex::encode(&change_addr.spk),
                            });
                        }
                        st.save_spending();
                    }
                }
                spending_refresh_async(w, st);
            } else if !r.spent_spending.is_empty() {
                spending_refresh_async(w, st);
            }
            println!(
                "cb: compose id={} txid={} fee={} vsize={} to={} private={} funded=mixed{}{} broadcast=ok",
                hex::encode(r.note_id), r.txid, r.built_fee, r.vsize,
                r.to.as_deref().unwrap_or("self"), r.private,
                if change_n > 0 { format!(" change={change_n}") } else { String::new() },
                if r.recipients.len() > 1 { format!(" recipients={}", r.recipients.len()) } else { String::new() }
            );
            w.set_status(format!("broadcast {}…", &r.txid[..12.min(r.txid.len())]).into());
            w.set_compose_text("".into());
            w.set_change_address("".into());
            w.set_change_expanded(false);
            w.set_spend_expanded(false);
            w.set_payfrom_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.set_change_choice("".into());
            w.set_screen(4);
            refresh_async(w, st);
        }
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

/// Drains all three compose-result queues and applies each on the UI
/// thread — the shared `apply-pending-compose` trampoline target. Also
/// clears the busy/progress state common to every path.
fn apply_compose_results(w: &AppWindow, st: &mut State) {
    let nb: Vec<NotebookComposeResult> =
        NOTEBOOK_COMPOSE_RESULTS.lock().expect("notebook compose results mutex").drain(..).collect();
    let sp: Vec<SpendingComposeResult> =
        SPENDING_COMPOSE_RESULTS.lock().expect("spending compose results mutex").drain(..).collect();
    let mx: Vec<MixedComposeResult> =
        MIXED_COMPOSE_RESULTS.lock().expect("mixed compose results mutex").drain(..).collect();
    if nb.is_empty() && sp.is_empty() && mx.is_empty() {
        return;
    }
    st.compose_busy = false;
    w.set_compose_sending(false);
    w.set_compose_stage("".into());
    // Universal confirm screen (2026-07-17): every compose broadcast now
    // fires from screen 26, gated on wallet_tx_busy, not compose_busy — see
    // `on_confirm_broadcast`. Unset it here alongside the (now largely
    // vestigial) compose flags so a failed spending/mixed attempt leaves
    // screen 26's Broadcast button tappable again.
    st.wallet_tx_busy = false;
    w.set_wallet_tx_busy(false);
    for r in nb {
        apply_notebook_compose_result(w, st, r);
    }
    for r in sp {
        apply_spending_compose_result(w, st, r);
    }
    for r in mx {
        apply_mixed_compose_result(w, st, r);
    }
}

/// Finished used/new address probes for the create-notebook picker (worker
/// thread). Applied to the picker rows on the UI thread; the (account, page)
/// snapshot guards staleness — paging or switching account/screen drops it.
struct PickerProbeResult {
    account: u32,
    page: u32,
    /// (receive index, pill "used"|"new", balance string) per probed row.
    rows: Vec<(u32, &'static str, String)>,
}

static PICKER_PROBE_RESULTS: std::sync::Mutex<Vec<PickerProbeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Finished Bitcoin Core preflight check (`PLAN-chain-notes-app-core-rpc.md`
/// §2.2/§2.3/U4, surfaced §3/U6). `network`+`base` are the snapshot the
/// worker started against — `on_apply_pending_node_health` drops a stale
/// result (network switched, or the node URL changed) rather than paint it
/// over a config the user has since moved on from.
struct NodeHealthResult {
    network: Network,
    base: String,
    text: SharedString,
    warn: bool,
}

static NODE_HEALTH_RESULTS: std::sync::Mutex<Vec<NodeHealthResult>> =
    std::sync::Mutex::new(Vec::new());

/// Kick off receive-chain notebook gap discovery on a worker thread when
/// activate() flagged a fresh index file (seed re-import; rev-3
/// follow-up 2). Needs a configured node — with none the flag stays
/// pending, so setting a node later (any refresh) retries. Results land
/// through [`DISCOVERY_RESULTS`] + the `apply-pending-discovery`
/// trampoline; callers are all post-first-frame (iOS launch rule).
///
/// Goes through the [`SCAN_LANE`] queue (2026-07-21) keyed
/// `discovery/<fp8>/<account>` — no gate counter here (discovery has
/// none), so this is just a submit: `discovery_pending` only clears when
/// [`scan_lane_submit`] returns `true` (admitted to run or queued); a
/// coalesced submission leaves the flag set so the NEXT natural kick
/// (another refresh) retries — matching the pre-queue "no node configured
/// → stays pending" behavior above.
fn maybe_start_discovery(w: &AppWindow, st: &mut State) {
    if !st.discovery_pending {
        return;
    }
    let Some(base) = st.base_url() else { return };
    let Some(material_str) = st.material.clone() else { return };
    let Some(fp8) = st.notebooks_fp8.clone() else { return };
    let network = st.network;
    let account = st.account;
    // Network-efficiency (build-39): snapshot the account's already-known
    // active notebook indexes on the UI thread — the worker below skips
    // probing these entirely (the "notebook-0 double-scan" fix; a fresh
    // seed re-import's notebook 0 was just scanned by refresh_async).
    let known: Vec<u32> =
        st.notebooks.as_ref().map(|ix| ix.active(account).map(|m| m.index).collect()).unwrap_or_default();
    let key = format!("discovery/{fp8}/{account}");
    let creds = core_rpc_creds_for(st, &base, network);
    let core_watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    let job = move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let found = parse_key_material(&material_str, network)
            .map(|material| {
                // A malformed node URL degrades exactly like any other
                // transport error here — best-effort, empty result.
                match open_client_watched(&base, network, creds, &core_watch) {
                    Ok(client) => {
                        // gap=1 (Sal 2026-07-23): notebooks are used
                        // sequentially from index 0, so stop at the first
                        // unused receive index. Misses only a FUNDED notebook
                        // stranded behind a skipped-empty one (recover by
                        // manually creating a notebook at that index); an
                        // unfunded notebook has no on-chain trace to discover
                        // anyway.
                        app_core::chain::discover_indexes(
                            &client, &material, network, account, &known, 1,
                        )
                    }
                    Err(_) => Vec::new(),
                }
            })
            .unwrap_or_default();
        drop(material_str); // Zeroizing — wiped as soon as the walk is done
        DISCOVERY_RESULTS
            .lock()
            .expect("discovery results mutex")
            .push(DiscoveryResult { fp8, network, account, found });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_discovery());
    };
    if scan_lane_submit(key, job) {
        st.discovery_pending = false;
    }
}

/// [`refresh`] with the network half on a worker thread (Sal 2026-07-11:
/// opening a notebook took 3-4 s on the phone because the tap handler
/// scanned synchronously — the screen never painted until it finished).
/// The screen paints immediately with "syncing…", the worker fetches the
/// bundle + pending-tx statuses, and the result comes back through
/// [`REFRESH_RESULTS`] + the `apply-pending-refresh` trampoline callback
/// (the UI thread applies it with full State access, exactly like the
/// synchronous refresh did).
///
/// Goes through the [`SCAN_LANE`] operation queue (2026-07-21) keyed
/// `nbscan/<address>`: the gate-counter increment + "syncing…" status
/// only fire when [`scan_lane_submit`] returns `true` (job admitted to
/// run or queued) — a coalesced submission (same address already
/// queued) skips both, since no scan will actually run on its behalf and
/// the executor's own `cb: netq coalesced …` line already logged it.
/// Building the job closure first and submitting before touching any
/// counter is safe because we're on the UI thread and the eventual
/// result apply only ever runs as a LATER event-loop callback — the
/// increment always precedes whatever decrement it pairs with.
fn refresh_async(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    maybe_start_discovery(w, st);
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let address = st.ident.as_ref().unwrap().address.clone();
    let network = st.network;
    let pending_txids: Vec<String> = st
        .store
        .as_ref()
        .unwrap()
        .txs
        .iter()
        .filter(|t| t.status == NoteStatus::Pending)
        .flat_map(|t| t.txids.iter().cloned())
        .collect();
    let dropped_checks = gather_dropped_checks(st.store.as_ref().unwrap());
    let prev_stats = st.store.as_ref().unwrap().addr_stats.clone();
    let key = format!("nbscan/{address}");
    let creds = core_rpc_creds_for(st, &base, network);
    let core_watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    let job = move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let client = match open_client_watched(&base, network, creds, &core_watch) {
            Ok(c) => c,
            Err(e) => {
                REFRESH_RESULTS.lock().expect("refresh results mutex").push(RefreshResult {
                    address,
                    bundle: Some(Err(e.to_string())),
                    new_stats: None,
                    statuses: Vec::new(),
                    dropped_lookup: HashMap::new(),
                    dropped_unspent: HashMap::new(),
                });
                let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_refresh());
                return;
            }
        };
        // 429 politeness (2026-07-20): ONE cheap `/address/:a` fingerprint
        // first — if nothing moved since the last applied scan (chain AND
        // mempool stats identical, so a pending tx confirming/dropping
        // always registers), skip the whole txs/utxo/pending/dropped fetch
        // burst. A stats error (regtest server.py has no bare /address
        // endpoint) falls through to the full scan — the pre-check is an
        // optimization, never a gate.
        let new_stats = client.address_stats(&address).ok();
        if prev_stats.is_some() && new_stats == prev_stats {
            // Network-efficiency (2026-07-23): fees used to refresh here
            // (one request) so compose estimates never went stale behind
            // the short-circuit — but fees/USD are only READ by the
            // fee-showing screens now, which fetch them lazily themselves
            // (`refresh_fees_price`), so the short-circuit fetches nothing
            // at all.
            REFRESH_RESULTS.lock().expect("refresh results mutex").push(RefreshResult {
                address,
                bundle: None,
                new_stats: None,
                statuses: Vec::new(),
                dropped_lookup: HashMap::new(),
                dropped_unspent: HashMap::new(),
            });
            let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_refresh());
            return;
        }
        let bundle = client.build_bundle(&address, None).map_err(|e| format!("{e}"));
        let statuses = pending_txids
            .iter()
            .map(|t| (t.clone(), client.fetch_tx_status(t)))
            .collect();
        let (dropped_lookup, dropped_unspent) = fetch_dropped_checks(&client, &address, &dropped_checks);
        REFRESH_RESULTS.lock().expect("refresh results mutex").push(RefreshResult {
            address,
            bundle: Some(bundle),
            new_stats,
            statuses,
            dropped_lookup,
            dropped_unspent,
        });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_refresh());
    };
    if scan_lane_submit(key, job) {
        w.set_status("syncing…".into());
        st.scan_gate.admit_notebook();
        update_scan_gate(w, st);
    }
}

/// Apply one already-fetched bundle to the CURRENTLY ACTIVE notebook's live
/// `State.store` — the shared core of [`apply_refresh_results`] (a single
/// open-notebook scan) and [`apply_wallet_stores_refresh_results`]'s
/// snapshot-time-active slice (a wallet-wide scan). Fees/usd, apply_bundle,
/// resolved pending-spend statuses, dropped-pending detection, save, the
/// `cb: refresh …` log line, and `update_home` — exactly what the
/// synchronous [`refresh`] does for the active notebook. Callers are
/// responsible for their own staleness guard before calling this (it
/// assumes `st.ident`/`st.store` are the right ones for `bundle`).
fn apply_active_bundle(
    w: &AppWindow,
    st: &mut State,
    bundle: Result<app_core::notes_core::bundle::SyncBundle, String>,
    statuses: &[(String, Option<bool>)],
    dropped_lookup: &HashMap<String, TxLookupStatus>,
    dropped_unspent: &HashMap<(String, u32), bool>,
    // Fresh `/address/:a` stats to stamp as the store's scan fingerprint on
    // a successful apply (429-politeness short-circuit, 2026-07-20).
    // `None` = leave the existing stamp alone (stats endpoint failed, or a
    // path that doesn't pre-check yet — the wallet-wide refresh).
    new_stats: Option<AddrStats>,
) {
    match bundle {
        Ok(bundle) => {
            // Neither st.fees nor st.usd is stamped from a scan
            // (network-efficiency, 2026-07-23): build_bundle no longer fetches
            // fee_rates OR btc_usd (both are default/None in the bundle now).
            // The fee-showing screens (compose/sweep/consolidate/bump) fetch
            // both lazily via `refresh_fees_price` (session-cached), and they
            // are the ONLY readers of st.fees/st.usd — so a scan touching
            // them would just clobber the lazily-fetched values.
            let keyed = st.ident.as_ref().unwrap().full().map(|i| i.clone_fields());
            let output_x = st.ident.as_ref().unwrap().output_x();
            let network = st.network;
            let notebook_spks = notebook_spks_for(st);
            // Spending-self-notes fix (Unit A): derived once for this apply
            // — a single-notebook scan, so no cross-notebook reuse needed
            // here (the wallet-wide caller derives it once itself; see
            // `apply_wallet_stores_refresh_results`).
            let spending_window_spks = spending_window_spks_for(st);
            let applied = match &keyed {
                Some(identity) => st.store.as_mut().unwrap().apply_bundle(
                    &bundle,
                    identity,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                ),
                None => st.store.as_mut().unwrap().apply_bundle_watch(
                    &bundle,
                    &output_x,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                ),
            };
            match applied {
                Ok(stats) => {
                    let n = st
                        .store
                        .as_mut()
                        .unwrap()
                        .resolve_spend_statuses(|t| {
                            statuses.iter().find(|(x, _)| x == t).and_then(|(_, s)| *s)
                        });
                    if n > 0 {
                        println!("cb: spend-confirmed n={n}");
                    }
                    apply_dropped_checks(st.store.as_mut().unwrap(), dropped_lookup, dropped_unspent);
                    if let Some(ns) = new_stats {
                        // Stamped only AFTER a successful apply, and the
                        // stats were fetched BEFORE the bundle — so a tx
                        // landing in between leaves a stale-low stamp and
                        // the next refresh does a full scan. Errs toward
                        // rescanning, never toward skipping real changes.
                        st.store.as_mut().unwrap().addr_stats = Some(ns);
                    }
                    if stats.reclassified > 0 {
                        // Unit B / RC2: a past too-narrow scan's stale
                        // received/"unknown" twin just got corrected —
                        // worth its own line (rare, so never spamming the
                        // common case with `reclassified=0`).
                        println!("cb: refresh reclassified n={}", stats.reclassified);
                    }
                    println!(
                        "cb: refresh notes={} new={} orphaned={} balance={} tip={}",
                        stats.notes_seen,
                        stats.notes_new,
                        stats.orphaned,
                        st.store.as_ref().unwrap().balance(),
                        st.store.as_ref().unwrap().tip_height
                    );
                    st.save_store();
                    w.set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.set_status("couldn't reach the network — tap refresh to retry".into());
        }
    }
    update_home(w, st);
}

/// The UI-thread half of [`refresh_async`]: identical bookkeeping to the
/// synchronous [`refresh`], fed from the worker's results.
fn apply_refresh_results(w: &AppWindow, st: &mut State) {
    let results: Vec<RefreshResult> =
        REFRESH_RESULTS.lock().expect("refresh results mutex").drain(..).collect();
    for r in results {
        // Every drained result releases its scan-gate slot — BEFORE the
        // staleness guard, or a stale-dropped scan would wedge the gate.
        st.scan_gate.drain_notebook();
        update_scan_gate(w, st);
        if st.ident.as_ref().map(|i| i.address.as_str()) != Some(r.address.as_str()) {
            println!("cb: refresh stale-drop address={}", &r.address[..12.min(r.address.len())]);
            continue;
        }
        let Some(bundle) = r.bundle else {
            // Stats pre-check short-circuit: nothing moved on-chain or in
            // the mempool since the stamped fingerprint — no bundle was
            // fetched, the store is already current. Fees/USD are no
            // longer fetched here at all (network-efficiency, 2026-07-23)
            // — the fee-showing screens fetch them lazily on open.
            println!("cb: refresh unchanged");
            w.set_status("up to date".into());
            update_home(w, st);
            continue;
        };
        apply_active_bundle(w, st, bundle, &r.statuses, &r.dropped_lookup, &r.dropped_unspent, r.new_stats);
        if w.get_screen() == 20 {
            update_funding_screen_ui(w, st);
            log_funding_refresh(st);
            // A landed notebook rescan must repaint the (now possibly
            // independently expanded) Notebook panel, not just the row's
            // summary balance — independent-expand rework, 2026-07-18.
            update_payfrom_panels(w, st);
        }
        if w.get_screen() == 6 {
            w.set_pay_from_balance(balance_text_for(st, w.get_pay_from().as_str()).into());
        }
    }
}

/// The UI-thread half of [`wallet_stores_refresh_async`]: applies the
/// snapshot-time-active notebook's slice via [`apply_active_bundle`] (same
/// as a single-notebook `refresh_async`) and every OTHER active notebook's
/// bundle via [`apply_bundle_to_notebook_file`] (disk-only, no live-view
/// side effects — matches the old synchronous `refresh_wallet_stores`).
/// The final `cb: refresh-coins|refresh-notebooks notebooks=<n>` count
/// always adds 1 for the snapshot-time-active notebook, matching the old
/// handlers' `scanned + 1` — unconditionally, even if its own fetch failed
/// (that failure already surfaced via `apply_active_bundle`'s status/err
/// line and the plain `cb: refresh err=…`).
fn apply_wallet_stores_refresh_results(w: &AppWindow, st: &mut State) {
    let results: Vec<WalletStoresRefreshResult> =
        WALLET_STORES_REFRESH_RESULTS.lock().expect("wallet stores refresh mutex").drain(..).collect();
    for r in results {
        st.scan_gate.set_wallet_stores(false);
        update_scan_gate(w, st);
        let label = r.purpose.label();
        if st.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
            || st.network != r.network
            || st.account != r.account
        {
            println!("cb: {label} stale-drop");
            w.set_status("".into());
            continue;
        }
        // Taproot change-chain coins (unit 3): folds into the SAME (fp8,
        // network, account) staleness guard above — no separate guard
        // needed. On error, leave `st.change_coins` at its last-known value
        // (same "don't clobber on failure" rule the spending scan uses)
        // rather than blanking a screen the user is actively looking at.
        match r.change {
            Ok(coins) => {
                println!("cb: change-coins n={}", coins.len());
                st.change_coins = coins;
                // Stamp the context so activate() knows these coins belong to
                // the CURRENT (fp8, network, account) and may survive a
                // same-context notebook switch (unit 7 fix).
                st.change_coins_ctx = Some((r.fp8.clone(), r.network, r.account));
            }
            Err(e) => println!("cb: change-scan err={e}"),
        }
        let material =
            st.material.as_deref().and_then(|m| parse_key_material(m, st.network).ok());
        let notebook_spks = notebook_spks_for(st);
        // Spending-self-notes fix (Unit A): derived ONCE for this whole
        // wallet-wide pass and reused across every notebook below — the
        // spending wallet is account-level, so re-deriving per notebook
        // would repeat the same ~2×upto secp derivations for nothing.
        let spending_window_spks = spending_window_spks_for(st);
        let now_active_addr = st.ident.as_ref().map(|i| i.address.clone());
        let mut scanned = 0usize;
        for nr in &r.results {
            // The snapshot-time-active notebook applies to the LIVE store
            // only if it's STILL the active one — a notebook switch mid-
            // scan (same account, so the coarse guard above passed) must
            // never misapply a stale bundle onto whatever's open now.
            let is_live_current = r.current_index == Some(nr.index)
                && r.current_address.is_some()
                && now_active_addr.as_deref() == r.current_address.as_deref();
            if is_live_current {
                apply_active_bundle(
                    w,
                    st,
                    nr.bundle.clone(),
                    &r.current_statuses,
                    &r.current_dropped_lookup,
                    &r.current_dropped_unspent,
                    // The wallet-wide refresh doesn't stats-pre-check (yet)
                    // — leave the store's fingerprint stamp alone.
                    None,
                );
            } else if let (Ok(bundle), Some(material)) = (&nr.bundle, &material) {
                if apply_bundle_to_notebook_file(
                    st,
                    material,
                    &notebook_spks,
                    &spending_window_spks,
                    nr.index,
                    bundle,
                ) {
                    scanned += 1;
                }
            }
        }
        scanned += 1; // the snapshot-time-active notebook, unconditionally
        println!("cb: {label} notebooks={scanned}");
        w.set_status("".into());
        // Repaint the Coins screen/card regardless of which ↻ kicked this
        // scan off — `update_wallet_coins` is a pure re-derive from `st`
        // (no side effects), and the change coins it now folds in just
        // landed above.
        update_wallet_coins(w, st);
        match r.purpose {
            WalletStoresPurpose::Coins => {
                if st.spending_capable
                    && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
                {
                    spending_refresh_async(w, st);
                }
                refresh_compose(w, st);
            }
            WalletStoresPurpose::Notebooks => update_notebook_list(w, st),
        }
    }
}

fn refresh(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    maybe_start_discovery(w, st);
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let creds = core_rpc_creds_for(st, &base, st.network);
    let client = match open_client_watched(&base, st.network, creds, &st.core_rpc_watch) {
        Ok(c) => c,
        Err(e) => {
            println!("cb: refresh err={e}");
            w.set_status("couldn't reach the network — tap refresh to retry".into());
            update_home(w, st);
            return;
        }
    };
    let address = st.ident.as_ref().unwrap().address.clone();
    let dropped_checks = gather_dropped_checks(st.store.as_ref().unwrap());
    match client.build_bundle(&address, None) {
        Ok(bundle) => {
            // st.fees/st.usd NOT stamped from a scan — see the matching
            // comment in `apply_active_bundle` (network-efficiency,
            // 2026-07-23); the fee-showing screens fetch both lazily.
            let keyed = st.ident.as_ref().unwrap().full().map(|i| i.clone_fields());
            let output_x = st.ident.as_ref().unwrap().output_x();
            let network = st.network;
            let notebook_spks = notebook_spks_for(st);
            // Spending-self-notes fix (Unit A) — see the matching comment
            // in `apply_active_bundle`.
            let spending_window_spks = spending_window_spks_for(st);
            let applied = match &keyed {
                Some(identity) => st.store.as_mut().unwrap().apply_bundle(
                    &bundle,
                    identity,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                ),
                None => st.store.as_mut().unwrap().apply_bundle_watch(
                    &bundle,
                    &output_x,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                ),
            };
            match applied {
                Ok(stats) => {
                    // Sweep/consolidate records settle on REAL confirmation
                    // (any of their txids in a block), asked of the node —
                    // mempool acceptance alone keeps them Pending so
                    // Speed-up/Rebroadcast stay available while RBF is.
                    let n = st
                        .store
                        .as_mut()
                        .unwrap()
                        .resolve_spend_statuses(|t| client.fetch_tx_status(t));
                    if n > 0 {
                        println!("cb: spend-confirmed n={n}");
                    }
                    let (dropped_lookup, dropped_unspent) =
                        fetch_dropped_checks(&client, &address, &dropped_checks);
                    apply_dropped_checks(st.store.as_mut().unwrap(), &dropped_lookup, &dropped_unspent);
                    if stats.reclassified > 0 {
                        println!("cb: refresh reclassified n={}", stats.reclassified);
                    }
                    println!(
                        "cb: refresh notes={} new={} orphaned={} balance={} tip={}",
                        stats.notes_seen,
                        stats.notes_new,
                        stats.orphaned,
                        st.store.as_ref().unwrap().balance(),
                        st.store.as_ref().unwrap().tip_height
                    );
                    st.save_store();
                    w.set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.set_status("couldn't reach the network — tap refresh to retry".into());
        }
    }
    update_home(w, st);
}

/// Network-efficiency (2026-07-23): `st.fees`/`st.usd` are read ONLY by the
/// fee-showing screens — compose (6), sweep/consolidate (16), pay-from
/// (20), and the Speed-up/bump dialogs — never by the notebook/spending
/// scan path, so they no longer ride along with every scan (see
/// `refresh_async`'s short-circuit branch and `chain::build_bundle`'s
/// dropped `btc_usd()` call). Call this at the START of every callback that
/// opens one of those screens; a call within ~60s of the last one is a free
/// cache hit (`fees_fetched_at`), so it's fine to call it more than
/// strictly needed. Synchronous, matching how these screen-open handlers
/// already run (no async worker/trampoline for a couple of GET requests —
/// same shape as the synchronous [`refresh`] above, which also has no
/// `NetOpGuard`). A failed/offline fetch just leaves `st.fees`/`st.usd`
/// whatever they were (the cost lines already `unwrap_or` a default rate /
/// hide the USD suffix) — never errors the screen.
fn refresh_fees_price(_w: &AppWindow, st: &mut State) {
    if let Some(t) = st.fees_fetched_at {
        if t.elapsed() < std::time::Duration::from_secs(60) {
            return;
        }
    }
    let Some(base) = st.base_url() else { return };
    let creds = core_rpc_creds_for(st, &base, st.network);
    let Ok(client) = open_client(&base, st.network, creds) else { return };
    let mut fetched = false;
    if let Ok(fees) = client.fee_rates() {
        st.fees = Some(fees);
        fetched = true;
    }
    if let Ok(usd) = client.btc_usd() {
        st.usd = usd;
        fetched = true;
    }
    // No repaint here — this is synchronous, and every call site runs it
    // BEFORE its own screen-paint call (refresh_compose/update_sweep_screen/
    // etc.), which reads the now-current st.fees/st.usd for free.
    if fetched {
        st.fees_fetched_at = Some(std::time::Instant::now());
    }
}

/// Automatic (non-deep) spending-wallet scan gap: the app hands out
/// spending addresses itself, sequentially, so its own usage has no gaps —
/// a small look-ahead past the last handed-out index is enough. See
/// [`SPENDING_GAP_DEEP`] for the manual fallback covering a seed that was
/// heavily used in ANOTHER BIP-84 wallet (gappy external usage a shallow
/// walk can't see).
const SPENDING_GAP_SHALLOW: u32 = 3;

/// Manual "Scan for existing funds…" deep scan gap — the same gap
/// `discover_indexes`/full notebook discovery use elsewhere in this file.
const SPENDING_GAP_DEEP: u32 = 20;

/// One finished spending-wallet scan (worker thread), waiting to be applied
/// on the UI thread. (fp8, network, account) guards staleness — switching
/// identity/network/account mid-scan drops the result, same pattern as
/// [`RefreshResult`]/[`DiscoveryResult`].
///
/// Network-efficiency merge (2026-07-23): ONE `scan_funding` call now
/// carries everything a separate `discover_spending` gap-walk USED to
/// report (which addresses have history — merged into `store.spending.used`
/// so the self-spk SET recognizes a spending-wallet-funded note as OWN on
/// the next rescan, via `FundingScan::used`/`next_receive_index`) alongside
/// the coins themselves (`FundingScan::utxos`, with values — what the
/// funded-note builder needs) and the next change index
/// (`next_change_index`) — see `ChainClient::scan_funding`'s doc comment.
/// This halves the automatic scan's request count outright, and the gap
/// dropping from 20 to 3 (see [`SPENDING_GAP_SHALLOW`]) cuts it further —
/// the tradeoff [`SPENDING_GAP_DEEP`]'s manual scan exists to cover.
struct SpendingRefreshResult {
    fp8: String,
    network: Network,
    account: u32,
    scan: Result<app_core::funding::FundingScan, String>,
}

static SPENDING_REFRESH_RESULTS: std::sync::Mutex<Vec<SpendingRefreshResult>> =
    std::sync::Mutex::new(Vec::new());

/// Kick off a spending-wallet coin scan on a worker thread (funding-
/// unification M3) — never block the UI thread with the chain call. A
/// no-op when the identity can't derive a spending wallet, or none is
/// configured (no node). Results land through [`SPENDING_REFRESH_RESULTS`]
/// + the `apply-pending-spending-refresh` trampoline, exactly like
/// [`refresh_async`].
///
/// Also goes through the [`SCAN_LANE`] queue (2026-07-21) keyed
/// `spscan/<fp8>/<network>/<account>` — a SECOND, general layer behind
/// the `scan_gate.spending_busy()` early-return above. That early-return
/// stays because it covers the wider enqueue→apply window (a scan that
/// already landed on the worker thread but hasn't finished applying on
/// the UI thread yet); the lane additionally serializes/coalesces at
/// admission time the same way every other scan class does. Gate-counter
/// increment + status only fire when [`scan_lane_submit`] returns `true`.
fn spending_refresh_async(w: &AppWindow, st: &mut State) {
    spending_scan_async(w, st, SPENDING_GAP_SHALLOW);
}

/// Manual "Scan for existing funds…" deep scan (network-efficiency
/// follow-up, 2026-07-23): the automatic scan above now walks a SHALLOW
/// gap-3 range (the app's own usage is sequential, so a small look-ahead
/// past the last handed-out index is enough) — but a seed that was heavily
/// used in ANOTHER BIP-84 wallet before this app ever touched it could have
/// funds sitting beyond that reach. This is the on-demand full gap-20
/// discovery pass for that case: same worker-thread / scan-lane / gate /
/// apply path as [`spending_refresh_async`], only the gap differs.
fn spending_scan_deep_async(w: &AppWindow, st: &mut State) {
    println!("cb: spending-scan-deep");
    spending_scan_async(w, st, SPENDING_GAP_DEEP);
}

fn spending_scan_async(w: &AppWindow, st: &mut State, gap: u32) {
    if !st.spending_capable {
        return;
    }
    // Never scan the spending wallet while it's DISABLED (Sal 2026-07-22). It's
    // opt-in (default OFF) and its coins are never shown when off, so scanning
    // it is pure waste — and on mainnet the gap-walk + coin scan against the
    // public esplora is a ~120-request burst that throttles and fails ("spending
    // wallet scan failed" on a fresh mainnet import). The enable toggle
    // (`on_set_spending`) flips `enabled` BEFORE its own kick, and every other
    // caller that should scan (sweep-open, spending ↻) already runs only when
    // enabled, so the enable→scan path is unaffected.
    if !st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false) {
        println!("cb: spending-refresh skipped=disabled");
        return;
    }
    // Coalesce (2026-07-21, first slice of the deferred operation queue):
    // the spending wallet is ONE tree per (identity, network, account) — a
    // second concurrent scan of it can only return the same view, and the
    // kick sources compound (↻ refreshes, sweep-open, compose CHANGE 5,
    // the wallet-stores apply): without this, a burst queued DOZENS of
    // identical ~80-request walks on a slow node and held the scan gate
    // closed for minutes. If a kick races an identity/account switch, the
    // in-flight scan stale-drops on apply and the next natural kick (boot
    // refresh, ↻, sweep-open) rescans the new context.
    if st.scan_gate.spending_busy() {
        println!("cb: spending-refresh coalesced");
        return;
    }
    let Some(material) = st.material.clone() else { return };
    let Some(base) = st.base_url() else { return };
    let network = st.network;
    let account = st.account;
    let Some(fp8) = st.notebooks_fp8.clone() else { return };
    let key = format!("spscan/{fp8}/{}/{account}", network.as_str());
    let creds = core_rpc_creds_for(st, &base, network);
    let core_watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    let job = move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let material_parsed = parse_key_material(&material, network);
        let source = material_parsed
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|m| app_core::spending::funding_source(m, network, account).map_err(|e| e.to_string()));
        let client = open_client_watched(&base, network, creds, &core_watch).map_err(|e| e.to_string());
        // ONE merged walk (network-efficiency, 2026-07-23): `scan_funding`
        // now reports used addresses (receive AND change — so OWN-detection
        // on rescan covers coins this app never explicitly "handed out",
        // e.g. an address funded before the app ever showed it) AND
        // spendable coins in the same pass — no separate `discover_spending`
        // gap-walk needed. `gap` is SPENDING_GAP_SHALLOW for the automatic
        // scan or SPENDING_GAP_DEEP for the manual deep scan.
        let scan = source.and_then(|src| {
            client.and_then(|c| c.scan_funding(&src, gap).map_err(|e| e.to_string()))
        });
        drop(material); // Zeroizing — wiped as soon as the scan is done
        SPENDING_REFRESH_RESULTS
            .lock()
            .expect("spending refresh mutex")
            .push(SpendingRefreshResult { fp8, network, account, scan });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_spending_refresh());
    };
    if scan_lane_submit(key, job) {
        w.set_status("scanning spending wallet…".into());
        st.scan_gate.admit_spending();
        update_scan_gate(w, st);
    }
}

/// Derive `spending_source` on demand from the session key material. The
/// descriptor needs no network scan — it was only ever populated by
/// [`apply_spending_refresh_results`], which made scan-independent flows
/// ("Sweep notebook funds here", spending consolidate — both only need the
/// descriptor + a store index) fail with "not scanned yet" when tapped
/// before a fresh session's first scan landed.
fn ensure_spending_source(st: &mut State) {
    if st.spending_source.is_some() || !st.spending_capable {
        return;
    }
    if let Some(material) = st.material.as_ref() {
        if let Ok(m) = parse_key_material(material.as_str(), st.network) {
            st.spending_source = app_core::spending::funding_source(&m, st.network, st.account).ok();
        }
    }
}

/// The UI-thread half of [`spending_refresh_async`]: cache the coins +
/// source, log the result, and repaint every screen that shows the
/// spending wallet (Settings card, compose picker, Coins segment).
fn apply_spending_refresh_results(w: &AppWindow, st: &mut State) {
    let results: Vec<SpendingRefreshResult> =
        SPENDING_REFRESH_RESULTS.lock().expect("spending refresh mutex").drain(..).collect();
    for r in results {
        // Release the scan-gate slot BEFORE the staleness guard — a
        // stale-dropped scan must not wedge the gate closed.
        st.scan_gate.drain_spending();
        update_scan_gate(w, st);
        if st.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
            || st.network != r.network
            || st.account != r.account
        {
            println!("cb: spending-refresh stale-drop");
            continue;
        }
        match r.scan {
            Ok(scan) => {
                // Discovery bookkeeping (used addresses + next indexes) comes
                // from the SAME merged scan now (network-efficiency merge,
                // 2026-07-23) — apply it before the coins, same order the old
                // separate discovery step ran in.
                if let Some(store) = st.store.as_mut() {
                    store.spending_apply_discovery(
                        scan.used.clone(),
                        scan.next_receive_index,
                        scan.next_change_index,
                    );
                }
                st.save_spending();
                st.spending_coins = scan.utxos;
                if let Some(material) = st.material.as_ref() {
                    if let Ok(m) = parse_key_material(material.as_str(), st.network) {
                        st.spending_source = app_core::spending::funding_source(&m, st.network, st.account).ok();
                    }
                }
                st.save_store();
                st.spending_scanned = true;
                let balance: u64 = st.spending_coins.iter().map(|c| c.value).sum();
                println!("cb: spending-refresh utxos={} balance={balance}", st.spending_coins.len());
                w.set_status("".into());
            }
            Err(e) => {
                println!("cb: spending-refresh err={e}");
                w.set_status(format!("spending wallet scan failed: {}", friendly_net_err(&e)).into());
            }
        }
        update_spending_ui(w, st);
        if w.get_screen() == 16 && w.get_sweep_kind() == "sweep" {
            // A wallet-sweep preview computed before the scan landed shows
            // notebook coins only (Sal 2026-07-17) — recompute it so the
            // spending coins join the inputs summary and fee preview.
            update_sweep_screen(w, st);
        }
        if w.get_screen() == 6 {
            // CHANGE 5: a user already sitting on compose when the scan
            // lands sees the default upgrade to "spending" too — but only
            // absent an explicit pick this session (payfrom_manual).
            if !st.payfrom_manual && w.get_pay_from() != "spending" {
                resolve_payfrom_default(w, st);
            }
            if w.get_pay_from() == "spending" {
                refresh_compose(w, st);
            }
        }
        if w.get_screen() == 20 {
            log_funding_refresh(st);
            // funding-unification UI rework: a landed scan must repaint the
            // Spending panel (independent-expand rework, 2026-07-18: it now
            // reads its own `sp-panel-coins`/`sp-panel-title`, not the
            // legacy singular `spend-coins`/`spend-title` — those stay
            // driven by whichever source is `payfrom_active_source`), or the
            // panel shows stale "0 coins" under a since-scanned wallet.
            refresh_compose(w, st);
            update_payfrom_panels(w, st);
        }
    }
}

/// Populate every spending-wallet-facing property: the Settings card
/// (capability/enabled/balance/next-receive QR), the compose picker's
/// subtitle, and the Coins screen's "spending" segment rows. Cheap local
/// derivation only — no chain call (callers that need fresh data call
/// [`spending_refresh_async`] first).
fn update_spending_ui(w: &AppWindow, st: &State) {
    w.set_spending_capable(st.spending_capable);
    let enabled = st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
    w.set_spending_enabled(enabled);
    if !st.spending_capable {
        w.set_spending_summary("".into());
        w.set_spending_balance_line("".into());
        w.set_spending_address("".into());
        w.set_spending_qr(slint::Image::default());
        let empty: Vec<SpendingCoinItem> = Vec::new();
        w.set_spending_coins_list(VecModel::from_slice(&empty));
        return;
    }
    let n = st.spending_coins.len();
    let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    if !st.spending_scanned {
        w.set_spending_summary(if enabled { "tap to scan…".to_string() } else { String::new() }.into());
        w.set_spending_balance_line("not scanned yet — tap refresh".into());
    } else {
        let line = format!("{} sats · {n} coin{}", commas(total), if n == 1 { "" } else { "s" });
        w.set_spending_summary(line.clone().into());
        w.set_spending_balance_line(line.into());
    }
    if let (Some(src), Some(store)) = (st.spending_source.as_ref(), st.store.as_ref()) {
        if let Ok(d) = src.derive(0, store.spending.next_receive) {
            w.set_spending_address(d.address.clone().into());
            w.set_spending_qr(qr::qr_image(&d.address.to_uppercase()).unwrap_or_default());
        }
    }
    let exb = st.explorer_base();
    let _ = exb; // per-coin explorer link not shown here — status is enough
    let rows: Vec<SpendingCoinItem> = st
        .spending_coins
        .iter()
        .map(|c| SpendingCoinItem {
            address: short_addr(&c.address).into(),
            value: c.value.to_string().into(),
            status: if c.confirmed { "confirmed" } else { "unconfirmed" }.into(),
        })
        .collect();
    w.set_spending_coins_list(VecModel::from_slice(&rows));
}

/// Estimated (chunks, vsize) for a note. `estimate_note_cost` assumes a
/// 34-byte taproot change output; when the change goes to a custom script
/// of `l` bytes, correct the vsize by `l - 34` (outputs aren't
/// witness-discounted, so 1 byte = 1 vB). None → self/taproot change.
/// Bitcoin standardness ceiling on a single transaction: `MAX_STANDARD_TX_WEIGHT`
/// (400_000 WU) / 4 = 100_000 vB. Nodes won't relay a bigger tx, so this — NOT
/// the per-output chunk-size setting — is the hard wall on how much one note can
/// carry. (A note is one tx of ≤255 OP_RETURN chunks.) The chunk setting only
/// decides how the body is sliced across outputs; at a small chunk size the
/// 255-chunk cap binds first, so raising it to Standard can rescue a note.
const MAX_STANDARD_TX_VSIZE: usize = 100_000;

fn note_est(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    note_est_at(store.chunk_size, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
}

/// `note_est` at an arbitrary chunk size — used to test whether a note that
/// doesn't fit at the current setting would fit at Standard.
fn note_est_at(
    chunk_size: usize,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    let (chunks, vsize) =
        estimate_note_cost(text_len, private, chunk_size, n_inputs, recipient_spk_len)?;
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((chunks, vsize))
}

/// Multi-recipient (2+ chips) analog of `note_est`: notes-core's
/// `estimate_note_cost` only takes a single optional recipient spk length,
/// and doesn't expose the intermediate payload-chunk LENGTHS it computes
/// internally (only a total count + a <=1-recipient vsize) — so this
/// reimplements that same chunking arithmetic from notes-core's own public
/// size constants (`envelope::HEADER_LEN`, `crypt::SEAL_OVERHEAD`,
/// `dm::WRAP_LEN`, matching `multi_body`'s framing exactly: `count(u8) ||
/// text` public, `count(u8) || count×WRAP_LEN || SEAL_OVERHEAD+text`
/// private) and feeds the result to `tx::estimate_vsize_multi`. This is a
/// PREVIEW convenience only — the universal confirm screen prices the
/// ACTUAL signed tx regardless, so an approximation here can never desync
/// what gets broadcast from what the user confirmed.
fn multi_note_est(
    text_len: usize,
    private: bool,
    chunk_size: usize,
    n_inputs: usize,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    use app_core::notes_core::{crypt, dm, envelope, tx, Error};
    let n = recipient_spk_lens.len();
    let body_len = if private { 1 + n * dm::WRAP_LEN + crypt::SEAL_OVERHEAD + text_len } else { 1 + text_len };
    if body_len == 0 {
        return Err(Error::Envelope("empty body"));
    }
    if chunk_size <= envelope::HEADER_LEN {
        return Err(Error::Envelope("max_payload smaller than header"));
    }
    let inner = chunk_size - envelope::HEADER_LEN;
    let total = body_len.div_ceil(inner);
    if total > u8::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let mut payload_lens = vec![chunk_size; total.saturating_sub(1)];
    let tail = body_len - (total - 1) * inner;
    payload_lens.push(envelope::HEADER_LEN + tail);
    let vsize = tx::estimate_vsize_multi(n_inputs.max(1), &payload_lens, recipient_spk_lens, true);
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((total, vsize))
}

/// Single call site for the compose preview's cost estimate: delegates to
/// the ordinary single-recipient `note_est` for 0 or 1 recipients (today's
/// exact byte-identical estimator) and to `multi_note_est` for 2+ — so
/// every existing caller (self-notes, ordinary directed notes) is
/// unaffected.
fn compose_est(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    if recipient_spk_lens.len() >= 2 {
        multi_note_est(text_len, private, store.chunk_size, n_inputs, recipient_spk_lens, change_spk_len)
    } else {
        note_est(store, text_len, private, n_inputs, recipient_spk_lens.first().copied(), change_spk_len)
    }
}

/// Whether the composed note can go out as one standard tx, and if not, whether
/// bumping the chunk size to Standard would rescue it.
enum FitCheck {
    /// Broadcastable at the current chunk-size setting.
    Ok,
    /// Over the limit now, but would fit at Standard (the user is on a smaller
    /// setting whose 255-chunk cap binds first) — offer to switch.
    FitsAtStandard,
    /// Over even at Standard: the ~100 kB per-tx network wall. No setting helps.
    HardWall,
}

fn fit_check(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> FitCheck {
    let fits = |chunk: usize| {
        note_est_at(chunk, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
            .map(|(_, vsize)| vsize <= MAX_STANDARD_TX_VSIZE)
            .unwrap_or(false) // Err = >255 chunks → treat as over-limit
    };
    if fits(store.chunk_size) {
        FitCheck::Ok
    } else if store.chunk_size < DEFAULT_CHUNK && fits(DEFAULT_CHUNK) {
        FitCheck::FitsAtStandard
    } else {
        FitCheck::HardWall
    }
}

/// Suggested coin selection over every SPENDABLE coin — unconfirmed
/// included (Sal 2026-07-25). The old rule auto-selected CONFIRMED coins
/// only, which left a freshly funded notebook (and, right after a note, its
/// own unconfirmed change) with an empty selection and a red
/// Required/Selected line, forcing a manual tap every time on a slow
/// network. Only `pending_spend` (locked by one of our own pending spends)
/// still excludes a coin — the same set the panel lists as spendable, so
/// the suggestion can now always cover what the panel shows. Every row
/// carries a confirmed/unconfirmed badge (`CoinPickRow`), so a chained-on
/// unconfirmed parent is visible, not silent. The spending-wallet panel has
/// always auto-selected regardless of confirmation
/// (`spending_compose_ui`) — this aligns the notebook path with it.
/// `consolidate` = pick
/// SMALLEST coins first (sweeps dust up into the change); otherwise LARGEST
/// first (fewest inputs, lowest fee). Stops once the note + fee is covered.
/// `recipient_spk_lens` replaces the old singular `spk_len` (additive,
/// 2026-07 multi-recipient): 0 entries = self-note, 1 = an ordinary
/// directed note (byte-identical to before via `compose_est`'s
/// delegation), 2+ = a multi-recipient note priced through
/// `multi_note_est`. `sent` is the TOTAL sats sent to every recipient
/// (gift × recipient count), not a single recipient's gift.
#[allow(clippy::too_many_arguments)]
fn suggested_coins(
    store: &Store,
    text_len: usize,
    private: bool,
    rate: f64,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
    sent: u64,
    consolidate: bool,
) -> Vec<(String, u32)> {
    let mut coins: Vec<&app_core::store::LedgerUtxo> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .collect();
    if consolidate {
        coins.sort_by(|a, b| a.value.cmp(&b.value)); // smallest first
    } else {
        coins.sort_by(|a, b| b.value.cmp(&a.value)); // largest first
    }
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for u in coins {
        chosen.push((u.txid.clone(), u.vout));
        total += u.value;
        if let Ok((_, vsize)) =
            compose_est(store, text_len.max(1), private, chosen.len(), recipient_spk_lens, change_spk_len)
        {
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total >= fee + sent {
                break;
            }
        }
    }
    chosen
}

/// Recompute the whole compose screen from state: coin list + selection,
/// spend total, live cost, change preview, change-address validation, and
/// the feasibility gate on the Sign button.
/// Apply a "Pay from" picker selection on compose (funding-unification
/// M3): "notebook" (today's path, default) or "spending" (the identity's
/// own BIP-84 wallet). External wallets go through [`activate_funding_wallet`]
/// instead (it sets `pay-from` to `"wallet:<id>"` itself, since picking one
/// also has to scan it). Kicks a background scan the first time "spending"
/// is chosen this session.
fn apply_pay_from(w: &AppWindow, st: &mut State, kind: &str) {
    match kind {
        "spending" => {
            w.set_pay_from("spending".into());
            w.set_pay_from_label("Spending wallet".into());
            w.set_fund_external(false);
            w.set_spend_from_wallet(true);
            if !st.spending_scanned {
                spending_refresh_async(w, st);
            }
        }
        _ => {
            w.set_pay_from("notebook".into());
            w.set_pay_from_label("Notebook".into());
            w.set_fund_external(false);
            w.set_spend_from_wallet(false);
        }
    }
    w.set_pay_from_balance(balance_text_for(st, kind).into());
}

/// Coins remembered under `source` in the cross-wallet selection memory
/// (funding-unification UI rework) — source key convention: "notebook" |
/// "spending" | "wallet:<id>".
fn mixed_coins_for(st: &State, source: &str) -> Vec<(String, u32)> {
    st.mixed_selected
        .iter()
        .filter(|(s, _, _)| s == source)
        .map(|(_, t, v)| (t.clone(), *v))
        .collect()
}

/// Replace `source`'s entries in the cross-wallet selection memory with
/// `coins` — keeps it in sync with the legacy single-source scratch state
/// (`selected_coins`) whenever the active source's selection changes.
fn mixed_sync_source(st: &mut State, source: &str, coins: &[(String, u32)]) {
    st.mixed_selected.retain(|(s, _, _)| s != source);
    for (t, v) in coins {
        st.mixed_selected.push((source.to_string(), t.clone(), *v));
    }
}

/// Everything [`app_core::mixed::assemble_mixed_note_psbt`] needs that comes
/// from the CURRENT cross-wallet selection + change choice — built by the
/// ONE args-builder ([`mixed_compose_args`]) shared by the compose preview
/// (`mixed_compose_ui`) and the send path (`on_compose_send_mixed` stage A),
/// so the two can structurally never disagree about what would be built
/// (Sal's TestFlight build-20 bug, 2026-07-18: the preview dry-ran the
/// spending-only builder — unconditional dust, spending-only weights —
/// while Sign built the anchored mixed shape).
struct MixedComposeArgs {
    coins: Vec<app_core::mixed::MixedCoin>,
    wallets_map: HashMap<String, FundingSource>,
    /// Chain-1 index → that leaf's own P2TR scriptPubKey, for every UNIQUE
    /// index among the selected `CoinSource::Change` coins (taproot-change
    /// unit 5) — the map `assemble_mixed_note_psbt_multi_ext` needs since
    /// the builder itself has no key material. Empty when no change coin
    /// is selected (every existing caller's shape, unaffected).
    change_spks: HashMap<u32, Vec<u8>>,
    change_default: app_core::mixed::ChangeDefault,
    change_override: Option<Vec<u8>>,
    change_index: u32,
}

/// Resolve the mixed-compose builder arguments from the live selection.
/// `Err` only for a "custom" change choice whose typed address doesn't
/// parse — the same (and only) validation failure `on_compose_send_mixed`'s
/// inline version had.
fn mixed_compose_args(w: &AppWindow, st: &State) -> Result<MixedComposeArgs, String> {
    let net = st.network;

    // Partition the cross-wallet selection into per-source coins.
    let notebook_sel = mixed_coins_for(st, "notebook");
    let spending_sel = mixed_coins_for(st, "spending");
    let wallet_key = st
        .mixed_selected
        .iter()
        .find_map(|(src, _, _)| src.strip_prefix("wallet:").map(|_| src.clone()));
    let wallet_sel = wallet_key.as_deref().map(|k| mixed_coins_for(st, k)).unwrap_or_default();

    let mut coins: Vec<app_core::mixed::MixedCoin> = Vec::new();
    if let Some(store) = st.store.as_ref() {
        for (txid, vout) in &notebook_sel {
            if let Some(u) =
                store.utxos.iter().find(|u| &u.txid == txid && u.vout == *vout && !u.pending_spend)
            {
                coins.push(app_core::mixed::MixedCoin {
                    source: app_core::mixed::CoinSource::Notebook,
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    chain: 0,
                    index: 0,
                });
            }
        }
    }
    for (txid, vout) in &spending_sel {
        if let Some(c) = st.spending_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
            coins.push(app_core::mixed::MixedCoin {
                source: app_core::mixed::CoinSource::Spending,
                txid: c.txid.clone(),
                vout: c.vout,
                value: c.value,
                chain: c.chain,
                index: c.index,
            });
        }
    }
    let mut wallets_map: HashMap<String, FundingSource> = HashMap::new();
    if let Some(wk) = wallet_key.as_deref() {
        if let (Some(id), Some(src)) = (wk.strip_prefix("wallet:"), st.funding.clone()) {
            for (txid, vout) in &wallet_sel {
                if let Some(c) = st.funding_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
                    coins.push(app_core::mixed::MixedCoin {
                        source: app_core::mixed::CoinSource::Wallet(id.to_string()),
                        txid: c.txid.clone(),
                        vout: c.vout,
                        value: c.value,
                        chain: c.chain,
                        index: c.index,
                    });
                }
            }
            wallets_map.insert(id.to_string(), src);
        }
    }

    // Taproot CHANGE-chain coins (unit 5, see
    // `../PLAN-chain-notes-app-taproot-change.md`): same account, chain 1
    // instead of the notebooks' chain 0 — `CoinSource::Change` carries the
    // chain-1 index (needed to derive the signing owner later); the
    // builder-side `change_spks` map is built here from the UNIQUE indexes
    // actually selected, via `realize_change` (the chain-1 sibling of
    // `realize`), mirroring `build_sweep_confirm`'s change-idents loop.
    let change_sel = mixed_coins_for(st, "change");
    let mut change_spks: HashMap<u32, Vec<u8>> = HashMap::new();
    if !change_sel.is_empty() {
        if let Some(material_str) = st.material.as_ref().map(|z| String::from(z.as_str())) {
            if let Ok(material) = parse_key_material(&material_str, net) {
                for (txid, vout) in &change_sel {
                    if let Some(c) = st.change_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
                        coins.push(app_core::mixed::MixedCoin {
                            source: app_core::mixed::CoinSource::Change,
                            txid: c.txid.clone(),
                            vout: c.vout,
                            value: c.value,
                            chain: 1,
                            index: c.index,
                        });
                        if let std::collections::hash_map::Entry::Vacant(e) = change_spks.entry(c.index) {
                            if let Ok(owner) = realize_change(&material, net, st.account, c.index) {
                                e.insert(p2tr_script_pubkey(&owner.output_x()));
                            }
                        }
                    }
                }
            }
        }
    }

    // Change: an explicit "custom" pick overrides; otherwise the resolved
    // default already reflected in `change-choice`.
    let choice = w.get_change_choice().to_string();
    let change_override = if choice == "custom" {
        let addr = normalize_addr(w.get_change_address().as_str());
        if addr.is_empty() {
            None
        } else {
            match Recipient::parse(net, &addr) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    return Err(format!("change address isn't a valid {} address", net.as_str()))
                }
            }
        }
    } else {
        None
    };
    let change_default = match choice.as_str() {
        "spending" => app_core::mixed::ChangeDefault::Spending,
        c if c.starts_with("wallet:") => {
            app_core::mixed::ChangeDefault::Wallet(c.trim_start_matches("wallet:").to_string())
        }
        _ => app_core::mixed::ChangeDefault::Notebook,
    };
    let change_index = st.store.as_ref().map(|s| s.spending.next_change).unwrap_or(0);

    Ok(MixedComposeArgs { coins, wallets_map, change_spks, change_default, change_override, change_index })
}

/// Build a source's OWN coin list + "N coins selected · X sats" caption for
/// the Pay-from screen's independently-expandable sections (2026-07-18
/// rework: every expanded section now renders its own data, so opening one
/// wallet never hides another's — see `nb_expanded`/`sp_expanded`/
/// `payfrom_expanded_source`). Deliberately separate from the legacy
/// singular `spend-coins`/`spend-title` (untouched — still driven by
/// whichever source is `payfrom_active_source` and feeds the live fee/
/// change preview via `refresh_compose`'s three branches). Selection
/// membership is read from the cross-wallet memory (`mixed_selected`) —
/// read-only, never mutates it. An external wallet's coins come from
/// `funding_coins` when it's the currently-active one, else the display-
/// only peek cache (`payfrom_wallet_coins`) populated by
/// `payfrom_scan_wallet_for_display` — empty (not yet scanned) shows as a
/// zero-coin panel, never a stale/wrong wallet's coins.
///
/// Taproot CHANGE-chain coins (unit 5, see
/// `../PLAN-chain-notes-app-taproot-change.md`): folded into the
/// `"notebook"` panel's row list — Sal's "one unified balance" rule, same
/// philosophy as the Coins screen (`update_wallet_coins`'s `notebook:
/// "change"` tag) — but their SELECTION membership is tracked under a
/// DISTINCT `"change"` key in `mixed_selected` (a change coin's signing
/// owner is per chain-1 INDEX, unlike the notebook's one fixed leaf, so
/// `mixed_compose_args` must be able to tell them apart), and each row
/// carries `tag: "change"` so `CoinListPanel` badges it.
fn payfrom_panel_coins(st: &State, source: &str) -> (Vec<SpendCoin>, String) {
    let net = st.network;
    let exb = st.explorer_base();
    let sel: std::collections::HashSet<(String, u32)> = mixed_coins_for(st, source).into_iter().collect();
    let row = |txid: &str, vout: u32, value: u64, confirmed: bool, selected: bool, tag: &str| SpendCoin {
        outpoint: format!("{txid}:{vout}").into(),
        value: value.to_string().into(),
        confirmed,
        selected,
        txid_short: txid[..8.min(txid.len())].to_string().into(),
        explorer: explorer_tx_url(exb.as_deref(), net, txid).into(),
        tag: tag.into(),
    };
    let mut coins: Vec<SpendCoin> = Vec::new();
    match source {
        "notebook" => {
            if let Some(store) = st.store.as_ref() {
                let mut spendable: Vec<&app_core::store::LedgerUtxo> =
                    store.utxos.iter().filter(|u| !u.pending_spend).collect();
                spendable.sort_by(|a, b| a.value.cmp(&b.value));
                for u in spendable {
                    let selected = sel.contains(&(u.txid.clone(), u.vout));
                    coins.push(row(&u.txid, u.vout, u.value, u.height.is_some(), selected, ""));
                }
            }
            // Fold in taproot CHANGE-chain coins (unit 5): SAME account,
            // chain 1 — tagged into the SAME panel per Sal's "one unified
            // balance" rule, but their selection lives under the DISTINCT
            // "change" key (see this function's doc comment above).
            let chg_sel: std::collections::HashSet<(String, u32)> =
                mixed_coins_for(st, "change").into_iter().collect();
            let mut change_sorted: Vec<&ChangeCoin> = st.change_coins.iter().collect();
            change_sorted.sort_by(|a, b| a.value.cmp(&b.value));
            for c in change_sorted {
                let selected = chg_sel.contains(&(c.txid.clone(), c.vout));
                coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, "change"));
            }
        }
        "spending" => {
            for c in &st.spending_coins {
                let selected = sel.contains(&(c.txid.clone(), c.vout));
                coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, ""));
            }
        }
        _ => {
            if let Some(id) = source.strip_prefix("wallet:") {
                let cached: Vec<FundingUtxo> = if st.active_funding_id.as_deref() == Some(id) {
                    st.funding_coins.clone()
                } else {
                    st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default()
                };
                for c in &cached {
                    let selected = sel.contains(&(c.txid.clone(), c.vout));
                    coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, ""));
                }
            }
        }
    }
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 =
        coins.iter().filter(|c| c.selected).filter_map(|c| c.value.parse::<u64>().ok()).sum();
    let plural = if sel_count == 1 { "" } else { "s" };
    let title = format!("{sel_count} coin{plural} selected · {} sats", commas(sel_total));
    (coins, title)
}

/// Refresh the Pay-from screen's per-section coin lists — Notebook and
/// Spending only (external wallets are handled per-row inside
/// `refresh_funding_list`, since they're a dynamic list). Pure read +
/// render, called after every state change that could affect what an
/// expanded section shows (open, header-tap expand, a coin toggle, a
/// landed scan) — cheap (bounded by UTXO count), never touches selection.
fn update_payfrom_panels(w: &AppWindow, st: &mut State) {
    let (nb_coins, nb_title) = payfrom_panel_coins(st, "notebook");
    w.set_nb_panel_coins(VecModel::from_slice(&nb_coins));
    w.set_nb_panel_title(nb_title.into());
    let (sp_coins, sp_title) = payfrom_panel_coins(st, "spending");
    w.set_sp_panel_coins(VecModel::from_slice(&sp_coins));
    w.set_sp_panel_title(sp_title.into());
}

/// Scan a saved wallet PURELY to populate its Pay-from screen coin list
/// (independent-expand rework, 2026-07-18) — the header-tap counterpart to
/// `activate_funding_wallet` that never makes the wallet the active/primary
/// funding source and never defaults its selection to "every coin" (that
/// default-to-all-on-expand was Sal's iPhone complaint #3). Only an actual
/// coin tap (`on_toggle_coin`, via `promote_wallet_active`) or a remembered
/// selection from earlier this session puts anything in `mixed_selected`.
/// A no-op once this wallet is either the live active one or already
/// peek-cached — re-expanding just shows what's already there.
fn payfrom_scan_wallet_for_display(w: &AppWindow, st: &mut State, id: &str) {
    if st.active_funding_id.as_deref() == Some(id) || st.payfrom_wallet_coins.contains_key(id) {
        return;
    }
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    let descriptor = st.funding_wallets[idx].descriptor.clone();
    let src = match FundingSource::parse(&descriptor, net) {
        Ok(src) => src,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    w.set_status("scanning funding wallet…".into());
    let creds = core_rpc_creds_for(st, &base, net);
    let client = match open_client(&base, net, creds) {
        Ok(c) => c,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    match client.scan_funding(&src, 20) {
        Ok(scan) => {
            st.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            st.funding_wallets[idx].coins = scan.utxos.len();
            st.funding_wallets[idx].scanned = true;
            st.funding_wallets[idx].next_change_index = scan.next_change_index;
            st.save_funding_wallets();
            let empty = scan.utxos.is_empty();
            st.payfrom_wallet_coins.insert(id.to_string(), scan.utxos);
            w.set_status(if empty { "wallet has no spendable coins yet".to_string() } else { String::new() }.into());
        }
        Err(e) => {
            w.set_status(format!("{e}").into());
        }
    }
}

/// Make a wallet the compose engine's active/primary pay-from source —
/// counterpart to `apply_pay_from`'s notebook/spending cases, called from
/// `on_toggle_coin` right after a coin tap (never from a mere expand).
/// Promotes the display-only peek cache (`payfrom_wallet_coins`) into the
/// SINGLE live `funding_coins`/`funding`/`active_funding_id` the rest of
/// the external-funding plumbing reads, unless this wallet is already the
/// live one (then its current scan is left untouched — never reverted to a
/// possibly-stale peek snapshot). Never auto-selects coins: by the time
/// this runs, the caller has already synced the just-toggled selection into
/// `mixed_selected`.
fn promote_wallet_active(w: &AppWindow, st: &mut State, id: &str) {
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    if st.active_funding_id.as_deref() != Some(id) {
        let descriptor = st.funding_wallets[idx].descriptor.clone();
        let src = match FundingSource::parse(&descriptor, net) {
            Ok(src) => src,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        st.funding_coins = st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default();
        st.funding_change_index = st.funding_wallets[idx].next_change_index;
        st.funding = Some(src);
        st.active_funding_id = Some(id.to_string());
    }
    let label = st.funding_wallets[idx].label.clone();
    let balance = st.funding_wallets[idx].balance;
    w.set_fund_external(true);
    w.set_spend_from_wallet(false);
    w.set_pay_from(format!("wallet:{id}").into());
    w.set_pay_from_label(label.clone().into());
    w.set_pay_from_balance(format!("{} sats", commas(balance)).into());
    println!("cb: pay-from wallet:{label}");
}

/// The ONE authoritative Pay-from verdict (Sal's iPhone bug cluster,
/// 2026-07-18: sufficiency was being evaluated per-wallet-PANEL — whichever
/// of `refresh_compose`'s three branches happened to be `payfrom_active_source`
/// at the time — instead of on the TRUE cross-wallet selection, so a
/// well-funded selection could render red, or the "Required" figure could go
/// blank, depending purely on which section was last tapped). Computed fresh
/// from `mixed_selected` (the cross-wallet memory — what actually gets
/// spent), NEVER from `payfrom_active_source` (a last-touched/visibility
/// concern, orthogonal to what's selected). Every consumer renders from
/// this: the summary card, the single insufficiency message, the compose
/// "Pay from" row (label + amount + tint), and the Sign gate
/// (`spend_enough`). Panel captions stay neutral always — see
/// `payfrom_panel_coins`, unchanged.
struct PayfromState {
    /// The exact fee-plus-outputs figure this selection's SHAPE needs, when
    /// one can be estimated numerically. `None` only for a lone external
    /// wallet, whose real cost is "whatever the wallet pays" — never an
    /// invented sats figure (unchanged design intent).
    required: Option<u64>,
    /// Always non-empty — "~N sats" for numeric shapes, a descriptive line
    /// ("funded by <wallet>") for the external-only shape.
    required_line: String,
    /// True cross-wallet total, regardless of which source is active/expanded.
    selected: u64,
    /// The single sufficiency verdict every consumer renders from.
    enough: bool,
    /// "Notebook" | "Spending wallet" | the external wallet's label | "N wallets".
    source_label: String,
    /// Machine-readable selection shape — drives the Sign-button DISPATCH
    /// inputs too (Sal's TestFlight-build-13 follow-up, 2026-07-18): see
    /// `sync_and_finalize_payfrom`'s alignment step.
    shape: PayfromShape,
}

/// Which single compose path (or the mixed one) the CURRENT cross-wallet
/// selection actually needs. `External` carries the full source key
/// ("wallet:<id>").
#[derive(Clone, PartialEq, Eq)]
enum PayfromShape {
    Empty,
    Notebook,
    Spending,
    External(String),
    Mixed,
}

/// Compute [`PayfromState`] for the CURRENT cross-wallet selection, using
/// whichever of the three real compose branches' math matches this
/// selection's shape (notebook-only / spending-only / external-only /
/// mixed) — the branches already compute the exact fee for their own shape;
/// this never invents a new estimator, it just stops letting the ANSWER
/// depend on which panel happens to be `payfrom_active_source`. The two
/// "funded" shapes (spending, mixed) reuse [`app_core::mixed::estimate_funded_fee`]
/// — the same weight/output math [`app_core::mixed::assemble_mixed_note_psbt`]
/// and `build_funding_psbt_amount` use internally, minus their insufficiency
/// gate (which would otherwise swallow the very fee figure a "you're short"
/// UI needs to show).
/// The Pay-from summary card's "Required" line, honest about a predicted
/// sub-dust fold (2026-07-18): `required` is always the NOMINAL figure
/// (what the shape actually needs at the chosen rate — never the eventual
/// byte-true fee, which includes the folded leftover on top), and a
/// `fold` prediction appends the leftover so the line never reads as an
/// inflated/expensive requirement. `"~0 sats"` when nothing is known yet
/// (unchanged from every branch's previous fallback).
fn fold_required_line(required: Option<u64>, fold: Option<(u64, u64)>) -> String {
    match (required, fold) {
        (Some(r), Some((_, folded))) => format!("~{} sats (+{} leftover, dust rule)", commas(r), commas(folded)),
        (Some(r), None) => format!("~{} sats", commas(r)),
        (None, _) => "~0 sats".to_string(),
    }
}

fn payfrom_state(w: &AppWindow, st: &State) -> PayfromState {
    let net = st.network;

    // ---- partition the TRUE cross-wallet selection — never the legacy
    // single-source `selected_coins` scratch, which only ever mirrors
    // whichever source is `payfrom_active_source`. ----
    let nb_sel = mixed_coins_for(st, "notebook");
    let nb_total: u64 = st
        .store
        .as_ref()
        .map(|store| {
            nb_sel
                .iter()
                .filter_map(|(t, v)| store.utxos.iter().find(|u| &u.txid == t && u.vout == *v).map(|u| u.value))
                .sum()
        })
        .unwrap_or(0);
    let sp_sel = mixed_coins_for(st, "spending");
    let sp_total: u64 = sp_sel
        .iter()
        .filter_map(|(t, v)| st.spending_coins.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value))
        .sum();
    // Taproot CHANGE-chain coins (unit 5, see
    // `../PLAN-chain-notes-app-taproot-change.md`): tracked under their own
    // "change" key in `mixed_selected` (see `payfrom_panel_coins`'s doc),
    // even though their rows render inside the "Notebook" panel.
    let chg_sel = mixed_coins_for(st, "change");
    let chg_total: u64 = chg_sel
        .iter()
        .filter_map(|(t, v)| st.change_coins.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value))
        .sum();
    let mut wallet_sources: Vec<String> = st
        .mixed_selected
        .iter()
        .filter(|(s, _, _)| s.starts_with("wallet:"))
        .map(|(s, _, _)| s.clone())
        .collect();
    wallet_sources.sort();
    wallet_sources.dedup();
    let ext_total: u64 = wallet_sources
        .iter()
        .map(|src| {
            let coins = mixed_coins_for(st, src);
            let id = src.strip_prefix("wallet:").unwrap_or("");
            let pool: Vec<FundingUtxo> = if st.active_funding_id.as_deref() == Some(id) {
                st.funding_coins.clone()
            } else {
                st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default()
            };
            coins.iter().filter_map(|(t, v)| pool.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value)).sum::<u64>()
        })
        .sum();

    let selected = nb_total + sp_total + ext_total + chg_total;
    // A change coin is always this identity's OWN coin — never a distinct
    // "group" the way an external wallet is — but it DOES need the mixed
    // builder (no single-source Sign button covers it), so it still counts
    // toward the group tally that decides whether a single-source branch
    // below applies (taproot-change unit 5).
    let groups =
        [nb_total > 0, sp_total > 0, ext_total > 0, chg_total > 0].into_iter().filter(|b| *b).count();

    // ---- shared compose context ----
    let text = w.get_compose_text().to_string();
    let text_for_est: String = if text.is_empty() { "x".to_string() } else { text.clone() };
    let private = w.get_compose_private();
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk length (uniform gift each) — empty
    // when self-note, one entry for an ordinary directed note (unchanged
    // estimate via `compose_est`'s delegation), 2+ for a real multi note.
    let recipient_spk_lens: Vec<usize> = match recipient.as_ref() {
        Some(r) => {
            let mut v = vec![r.spk.len()];
            v.extend(st.to_addresses_extra.iter().filter_map(|a| Recipient::parse(net, a).ok()).map(|x| x.spk.len()));
            v
        }
        None => Vec::new(),
    };
    // `gift` is already 0 for a self-note, so this is 0 there regardless
    // of the `.max(1)` below (empty `recipient_spk_lens`).
    let total_sent = gift * recipient_spk_lens.len().max(1) as u64;
    let change_raw = w.get_change_address().to_string();
    let change_trim = change_raw.trim();
    let custom_change = if change_trim.is_empty() { None } else { Recipient::parse(net, change_trim).ok() };
    // An explicitly-typed change address that DOESN'T parse is invalid —
    // gate Sign on it same as before (each branch used to bail out on this
    // independently; now it's one check).
    let change_valid = change_trim.is_empty() || custom_change.is_some();
    let custom_change_spk_len = custom_change.map(|r| r.spk.len());

    // Fee estimate for a "funded" shape (spending / mixed): reuses the real
    // sealer (`sealed_note_payloads`, the same primitive `build_funding_psbt_amount`/
    // `assemble_mixed_note_psbt` call internally) for accurate payload sizes,
    // then `estimate_funded_fee`/`estimate_funded_fee_no_change` for the
    // weight/fee math — WITHOUT their insufficiency gate, so a number
    // always comes back. Returns (fee_with_change, fee_no_change): the pair
    // `app_core::mixed::predict_fold` needs to tell whether THIS selection
    // would fold a sub-dust leftover into the fee (honest-fee-label,
    // 2026-07-18). `dust_to_self` mirrors `assemble_mixed_note_psbt`'s own
    // input-anchored skip (2026-07-18 dust-skip rework): callers pass
    // `false` when the selection includes a notebook coin, so the preview
    // stays byte-exact with the real build either way.
    let funded_fee_pair = |input_weights: &[bitcoin::transaction::InputWeightPrediction], change_spk_len: usize, dust_to_self: bool| -> Option<(u64, u64)> {
        let identity = st.ident.as_ref().and_then(|i| i.full())?.clone_fields();
        let chunk = st.store.as_ref().map(|s| s.chunk_size).unwrap_or(DEFAULT_CHUNK);
        // Multi-recipient: `recipient_spk_lens` (computed above) already
        // carries every chip's spk length — go through the multi sealer
        // when there are 2+ distinct recipients so the payload/chunk count
        // this estimate uses matches what the real multi build would emit
        // (a FLAG_MULTI body is a different size than a single-recipient
        // one for the same text).
        let payloads = if recipient_spk_lens.len() >= 2 {
            let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients =
                app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients).ok()?;
            let content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
            app_core::notes_core::bundle::sealed_note_payloads_multi(
                &identity, &text_for_est, private, &recipients, [0u8, 0, 0, 0], content_key, chunk,
            )
            .ok()?
            .0
        } else {
            app_core::notes_core::bundle::sealed_note_payloads(
                &identity, &text_for_est, private, recipient.as_ref(), [0u8, 0, 0, 0], chunk,
            )
            .ok()?
            .0
        };
        let fee_wc = app_core::mixed::estimate_funded_fee_multi(input_weights, &payloads, &recipient_spk_lens, change_spk_len, dust_to_self, rate);
        let fee_nc = app_core::mixed::estimate_funded_fee_no_change_multi(input_weights, &payloads, &recipient_spk_lens, dust_to_self, rate);
        Some((fee_wc, fee_nc))
    };

    let (required, required_line, source_label): (Option<u64>, String, String);
    let shape: PayfromShape;
    if groups == 0 {
        // Nothing selected in ANY source — estimate the minimal 1-input
        // self-funded shape (what auto-suggest will land on): never leave
        // the line blank just because the user hasn't picked a coin yet.
        // No fold prediction here — there's no real selection yet to fold
        // FROM (`in_value` would be 0), so this stays the plain estimate.
        let change_len = custom_change_spk_len.or(Some(34));
        let fee = st
            .store
            .as_ref()
            .and_then(|store| compose_est(store, text_for_est.len(), private, 1, &recipient_spk_lens, change_len).ok())
            .map(|(_, vsize)| (vsize as f64 * rate).ceil().max(0.0) as u64);
        required = fee.map(|f| f + total_sent);
        source_label = if st.payfrom_active_source == "spending" { "Spending wallet".to_string() } else { "Notebook".to_string() };
        required_line = required.map(|r| format!("~{} sats", commas(r))).unwrap_or_else(|| "~0 sats".to_string());
        shape = PayfromShape::Empty;
    } else if nb_total > 0 && groups == 1 {
        // Notebook-only — same self-funded estimator the plain compose path
        // already uses (no dust-to-self: change naturally returns to the
        // notebook, which already keeps the note discoverable). Sub-dust
        // fold prediction (honest-fee-label, 2026-07-18): `required` stays
        // the NOMINAL fee (what the no-change shape actually needs), and
        // the line notes the folded leftover separately so it never reads
        // as an inflated/expensive fee.
        let change_len = custom_change_spk_len.unwrap_or(34);
        let vsize = st
            .store
            .as_ref()
            .and_then(|store| {
                compose_est(store, text_for_est.len(), private, nb_sel.len().max(1), &recipient_spk_lens, Some(change_len)).ok()
            })
            .map(|(_, vsize)| vsize);
        let fee_wc = vsize.map(|v| (v as f64 * rate).ceil().max(0.0) as u64);
        let fold = vsize.and_then(|v| app_core::mixed::predict_notebook_fold(nb_total, total_sent, v, change_len, rate));
        let nominal = fold.map(|(n, _)| n).or(fee_wc);
        required = nominal.map(|f| f + total_sent);
        source_label = "Notebook".to_string();
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Notebook;
    } else if sp_total > 0 && groups == 1 {
        // Spending-only — same funded shape `spending_compose_ui` builds for
        // real (dust-to-self ALWAYS), just never gated on affordability.
        // Same fold treatment as the notebook branch above, via the funded
        // (with-change/no-change) estimator pair.
        let weights: Vec<_> = std::iter::repeat(bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX)
            .take(sp_sel.len().max(1))
            .collect();
        let change_len = custom_change_spk_len.unwrap_or(22); // BIP84 p2wpkh spk is always 22 bytes
        // Spending-only can never include a notebook coin (groups == 1,
        // nb_total == 0 by this branch's own guard) — dust-to-self always
        // rides, same as `assemble_funded_note_psbt`'s unconditional rule.
        let fees = funded_fee_pair(&weights, change_len, true);
        // `total_sent` (not `gift`) is the fixed non-fee output total when
        // 2+ recipients are chipped in — uniform gift × N (Sal, 2026-07-19).
        let fixed_out = total_sent + DUST_SATS; // recipients + the ALWAYS dust-to-self output
        let fold = fees.and_then(|(fee_wc, fee_nc)| app_core::mixed::predict_fold(sp_total, fixed_out, fee_wc, fee_nc, false));
        let nominal = fold.map(|(n, _)| n).or_else(|| fees.map(|(wc, _)| wc));
        required = nominal.map(|f| f + total_sent + DUST_SATS);
        source_label = "Spending wallet".to_string();
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Spending;
    } else if ext_total > 0 && groups == 1 {
        // External-only — cost is "whatever the wallet pays"; never invent a
        // numeric fee for it (unchanged design intent). Guarded on
        // `ext_total > 0` (taproot-change unit 5): a change-ONLY selection
        // is ALSO `groups == 1` (its own single group) but has no wallet
        // source at all — it must fall through to the Mixed branch below,
        // the only builder that knows `CoinSource::Change`.
        let id = wallet_sources.first().and_then(|s| s.strip_prefix("wallet:"));
        let label = id
            .and_then(|id| st.funding_wallets.iter().find(|fw| fw.id == id))
            .map(|fw| fw.label.clone())
            .unwrap_or_else(|| "External wallet".to_string());
        required = None;
        // Always non-empty (never blank just because no note text is typed
        // yet) — a funding wallet's role doesn't depend on that; "enough"
        // below still gates Sign on text being present.
        required_line = format!("funded by {label}");
        source_label = label;
        shape = PayfromShape::External(wallet_sources.first().cloned().unwrap_or_default());
    } else {
        // Mixed: 2+ source groups in ONE tx — the real mixed builder
        // (`assemble_mixed_note_psbt`) is the only correct sizer for this
        // shape (per-source input weights + the funded output shape), reused
        // here via `estimate_funded_fee` (same weights/outputs, no
        // insufficiency gate).
        let mut weights: Vec<bitcoin::transaction::InputWeightPrediction> = Vec::new();
        weights.extend(std::iter::repeat(bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH).take(nb_sel.len()));
        weights.extend(std::iter::repeat(bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX).take(sp_sel.len()));
        // Taproot CHANGE-chain coins (unit 5) are P2TR key-path, same
        // weight as a notebook coin.
        weights.extend(std::iter::repeat(bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH).take(chg_sel.len()));
        for src in &wallet_sources {
            let id = src.strip_prefix("wallet:").unwrap_or("");
            let taproot = st.funding_wallets.iter().find(|fw| fw.id == id).map(|fw| fw.kind == "taproot").unwrap_or(true);
            let iw = if taproot {
                bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
            } else {
                bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
            };
            weights.extend(std::iter::repeat(iw).take(mixed_coins_for(st, src).len()));
        }
        let spending_enabled = st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
        // `chg_total == 0` (taproot-change unit 5): a change coin is this
        // identity's OWN coin, so its presence disqualifies the "only an
        // external wallet participates" default just like a notebook coin
        // would — `resolve_change_default` then falls back to Notebook.
        let single_external = if wallet_sources.len() == 1 && nb_total == 0 && sp_total == 0 && chg_total == 0 {
            wallet_sources.first().and_then(|s| s.strip_prefix("wallet:"))
        } else {
            None
        };
        let default_change =
            app_core::mixed::resolve_change_default(spending_enabled, sp_total > 0, single_external);
        let change_len = custom_change_spk_len.unwrap_or(match &default_change {
            app_core::mixed::ChangeDefault::Spending => 22,
            app_core::mixed::ChangeDefault::Notebook => 34,
            app_core::mixed::ChangeDefault::Wallet(id) => st
                .funding_wallets
                .iter()
                .find(|fw| &fw.id == id)
                .map(|fw| if fw.kind == "taproot" { 34 } else { 22 })
                .unwrap_or(34),
        });
        // Input-anchored skip (2026-07-18 dust-skip rework; extended to
        // Change by taproot-change unit 5): a notebook OR change-chain coin
        // in this mixed selection means the tx is already input-anchored —
        // both are this identity's own coin — `assemble_mixed_note_psbt`
        // omits dust-to-self, so the preview must too, or the
        // Required/Leftover figures drift from the real build's fee.
        let has_self_input = nb_total > 0 || chg_total > 0;
        let dust_sats = if has_self_input { 0 } else { DUST_SATS };
        let fees = funded_fee_pair(&weights, change_len, !has_self_input);
        // `total_sent` (not `gift`) is the fixed non-fee output total when
        // 2+ recipients are chipped in — uniform gift × N (Sal, 2026-07-19).
        let fixed_out = total_sent + dust_sats; // recipients (if any) + dust-to-self, when present
        let fold = fees.and_then(|(fee_wc, fee_nc)| app_core::mixed::predict_fold(selected, fixed_out, fee_wc, fee_nc, false));
        let nominal = fold.map(|(n, _)| n).or_else(|| fees.map(|(wc, _)| wc));
        required = nominal.map(|f| f + total_sent + dust_sats);
        // A notebook and/or change-chain-only mix is still ONE wallet (two
        // chains of the same account, taproot-change unit 5) — "N wallets"
        // only describes a genuine cross-wallet mix (spending and/or an
        // external wallet participating).
        source_label =
            if sp_total == 0 && ext_total == 0 { "Notebook".to_string() } else { format!("{groups} wallets") };
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Mixed;
    }

    let enough = match required {
        Some(r) => change_valid && selected >= r,
        None => {
            // External-only: readiness, not a sats comparison — a watch
            // wallet's real cost isn't knowable up front (unchanged rule).
            let ready = st.funding.is_some() && !st.funding_coins.is_empty();
            change_valid && ready && ext_total > 0 && !text.is_empty()
        }
    };

    PayfromState { required, required_line, selected, enough, source_label, shape }
}

/// Recompute the mixed-source bookkeeping after `refresh_compose`'s active-
/// source branch runs: mirror its (possibly just auto-suggested) selection
/// into the cross-wallet memory, flag the linkage hint when the total
/// selection spans more than one wallet, and resolve the Change screen's
/// current destination label. Also the ONE place [`payfrom_state`] is
/// computed and fanned out to every consumer (summary card, insufficiency
/// message, compose row, Sign gate) — see its doc comment for why this
/// replaced each branch setting `spend_enough`/`payfrom_required_line`
/// independently (Sal's iPhone bug cluster, 2026-07-18).
fn sync_and_finalize_payfrom(w: &AppWindow, st: &mut State) {
    // Mirror the active source's scratch selection into the cross-wallet
    // memory — ONLY for notebook/spending, the two sources whose compose
    // branches actually maintain `selected_coins`. External wallets keep
    // their entries via `on_toggle_coin` + `funding_compose_ui`'s
    // default-all seeding; mirroring the (necessarily stale) scratch under
    // a "wallet:<id>" key would clobber the wallet's real selection with
    // another source's coin list (a latent 3f29024 hazard, closed in the
    // TestFlight-13 dispatch fix, 2026-07-18).
    let active = st.payfrom_active_source.clone();
    if active == "notebook" || active == "spending" {
        let coins = st.selected_coins.clone();
        mixed_sync_source(st, &active, &coins);
    }

    let pf = payfrom_state(w, st);
    // The note-size ceiling (`compose_oversize`, set by the notebook
    // branch's `fit_check`) is a hard broadcast-legality gate independent of
    // fund sufficiency — AND it in here rather than duplicating it into
    // every branch's own `enough` computation.
    let enough = pf.enough && !st.compose_oversize;
    w.set_spend_enough(enough);
    w.set_payfrom_required_line(pf.required_line.into());
    w.set_payfrom_selected_line(format!("{} sats", commas(pf.selected)).into());
    w.set_payfrom_source_label(pf.source_label.clone().into());
    // The linkage hint doubles as the Sign-button dispatch selector for the
    // mixed path — derived from the verdict's shape, same source of truth
    // as everything else here.
    w.set_mixed_linkage_hint(pf.shape == PayfromShape::Mixed);
    println!(
        "cb: payfrom state src={} required={} selected={} enough={}",
        pf.source_label,
        pf.required.map(|r| r.to_string()).unwrap_or_else(|| "?".to_string()),
        pf.selected,
        if enough { 1 } else { 0 },
    );

    // ---- Dispatch alignment (Sal's TestFlight-build-13 follow-up,
    // 2026-07-18): the Sign button in app.slint picks its send callback
    // from `mixed-linkage-hint` + `pay-from`/`fund-external`/
    // `spend-from-wallet`, which until now were LAST-TAPPED state — e.g.
    // deselecting the spending wallet's final coin (a tap ON the spending
    // source) left `pay-from` = "spending" while the actual selection was
    // notebook-only, so Sign invoked the spending branch, which bailed red
    // "no coins selected" despite a green globally-sufficient verdict.
    // Whenever the verdict's shape names ONE source, force the dispatch
    // inputs (and the active-source scratch the compose branches read) to
    // that source — payfrom_state is the single source of truth for which
    // send path runs, structurally. Empty/Mixed leave the flags alone
    // (Empty can't Sign — enough=0; Mixed dispatches via the hint,
    // ignoring `pay-from`). Re-runs `refresh_compose` once after a switch
    // so the preview lines come from the branch that will actually send;
    // `payfrom_aligning` guards the recursion (the inner pass finds the
    // flags agreeing and falls through).
    let desired: Option<String> = match &pf.shape {
        PayfromShape::Notebook => Some("notebook".to_string()),
        PayfromShape::Spending => Some("spending".to_string()),
        PayfromShape::External(key) => Some(key.clone()),
        PayfromShape::Empty | PayfromShape::Mixed => None,
    };
    if let Some(src) = desired {
        let flags_agree = w.get_pay_from().as_str() == src
            && st.payfrom_active_source == src
            && w.get_fund_external() == src.starts_with("wallet:")
            && w.get_spend_from_wallet() == (src == "spending");
        if !flags_agree && !st.payfrom_aligning {
            st.payfrom_aligning = true;
            println!("cb: payfrom align src={src}");
            st.payfrom_active_source = src.clone();
            if let Some(id) = src.strip_prefix("wallet:") {
                let id = id.to_string();
                promote_wallet_active(w, st, &id);
            } else {
                // Seed the scratch from the source's remembered selection so
                // the branch (and the send path) spends exactly what the
                // verdict counted — never a re-auto-suggest.
                st.selected_coins = mixed_coins_for(st, &src);
                st.coins_overridden = true;
                apply_pay_from(w, st, &src);
            }
            refresh_compose(w, st);
            st.payfrom_aligning = false;
            return;
        }
    }
    update_change_label(w, st);
}

/// Recompute the Change screen/nav-row's resolved destination — respects an
/// explicit `change_choice` pick made this session; otherwise applies
/// `app_core::mixed::resolve_change_default` (Sal's rule: spending wallet
/// enabled + participating wins, else a single participating external
/// wallet, else the notebook).
fn update_change_label(w: &AppWindow, st: &mut State) {
    let sources: std::collections::HashSet<&str> =
        st.mixed_selected.iter().map(|(s, _, _)| s.as_str()).collect();
    let spending_enabled =
        st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
    let spending_participates = sources.contains("spending") || st.payfrom_active_source == "spending";
    // Taproot-change unit 5: a "change" source key lands in this list too
    // (it's neither "notebook" nor "spending"), but `strip_prefix("wallet:")`
    // below always fails for it, so `only_external` correctly stays `None`
    // whenever change participates — resolve_change_default then falls back
    // to Notebook, same as a notebook coin would (both are this identity's
    // own coin; no code change needed here beyond this note).
    let non_notebook_spending: Vec<&str> =
        sources.iter().filter(|s| **s != "notebook" && **s != "spending").copied().collect();
    let only_external: Option<String> = if !sources.contains("notebook")
        && !sources.contains("spending")
        && non_notebook_spending.len() == 1
    {
        non_notebook_spending[0].strip_prefix("wallet:").map(String::from)
    } else {
        None
    };
    let default = app_core::mixed::resolve_change_default(
        spending_enabled,
        spending_participates,
        only_external.as_deref(),
    );

    let default_str = match &default {
        app_core::mixed::ChangeDefault::Spending => "spending".to_string(),
        app_core::mixed::ChangeDefault::Notebook => "notebook".to_string(),
        app_core::mixed::ChangeDefault::Wallet(id) => format!("wallet:{id}"),
    };
    w.set_change_default_choice(default_str.clone().into());
    let default_reason = match &default {
        app_core::mixed::ChangeDefault::Spending => "the spending wallet is paying".to_string(),
        app_core::mixed::ChangeDefault::Notebook => "no spending wallet enabled".to_string(),
        app_core::mixed::ChangeDefault::Wallet(id) => {
            let label = st
                .funding_wallets
                .iter()
                .find(|fw| &fw.id == id)
                .map(|fw| fw.label.clone())
                .unwrap_or_else(|| id.clone());
            format!("{label} is paying")
        }
    };
    w.set_change_default_reason(default_reason.into());
    let notebook_line = addr_short(&st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default());
    w.set_change_notebook_line(notebook_line.into());
    let spending_line = if st.spending_capable && spending_enabled {
        if let (Some(src), Some(store)) = (st.spending_source.as_ref(), st.store.as_ref()) {
            src.derive(1, store.spending.next_change)
                .ok()
                .map(|d| format!("{} · change #{}", addr_short(&d.address), store.spending.next_change))
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    w.set_change_spending_line(spending_line.into());
    // An explicit pick this session (including "custom") always wins; the
    // default only applies while `change_choice` is unset.
    let choice = if st.change_choice.is_empty() { default_str } else { st.change_choice.clone() };
    w.set_change_choice(choice.clone().into());

    let label = if choice == "spending" {
        "a fresh spending address".to_string()
    } else if choice == "notebook" {
        "your notebook address".to_string()
    } else if choice == "custom" {
        let addr = w.get_change_address().to_string();
        if addr.trim().is_empty() {
            "custom address".to_string()
        } else {
            format!("{}…", &addr[..14.min(addr.len())])
        }
    } else if let Some(id) = choice.strip_prefix("wallet:") {
        st.funding_wallets
            .iter()
            .find(|fw| fw.id == id)
            .map(|fw| format!("{} change", fw.label))
            .unwrap_or_else(|| "external wallet".to_string())
    } else {
        "your address".to_string()
    };
    w.set_change_dest_label(label.into());
}

/// Short "<n> sats" figure for the compose compact "Pay from" row and the
/// funding screen's Notebook row — deliberately terse (no coin count) so it
/// always elides cleanly at iPhone width. `kind` is a `pay-from` value:
/// "notebook" | "spending" | "wallet:<id>".
fn balance_text_for(st: &State, kind: &str) -> String {
    if let Some(id) = kind.strip_prefix("wallet:") {
        return st
            .funding_wallets
            .iter()
            .find(|fw| fw.id == id)
            .map(|fw| format!("{} sats", commas(fw.balance)))
            .unwrap_or_else(|| "watch-only".to_string());
    }
    if kind == "spending" {
        return if !st.spending_scanned {
            "scanning…".to_string()
        } else {
            let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
            format!("{} sats", commas(total))
        };
    }
    st.store.as_ref().map(|s| format!("{} sats", commas(s.balance()))).unwrap_or_default()
}

/// Populate the funding screen's Notebook row balance. Cheap local
/// derivation only — callers that need fresh chain data call
/// [`refresh_async`]/[`spending_refresh_async`] first (the funding-refresh
/// callback does both).
fn update_funding_screen_ui(w: &AppWindow, st: &State) {
    w.set_funding_notebook_balance(balance_text_for(st, "notebook").into());
}

/// `cb: funding-refresh` — logged whenever a background scan the funding
/// screen's ↻ kicked off lands while screen 20 is still open. Notebook and
/// spending scan on independent worker threads (same pattern as
/// `on_refresh_coins`), so this may print twice per tap (once per source
/// landing) — each time with the freshest values known so far.
fn log_funding_refresh(st: &State) {
    let notebook = st.store.as_ref().map(|s| s.balance()).unwrap_or(0);
    let spending = if st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false) {
        if st.spending_scanned {
            st.spending_coins.iter().map(|c| c.value).sum::<u64>().to_string()
        } else {
            "?".to_string()
        }
    } else {
        "off".to_string()
    };
    println!("cb: funding-refresh notebook={notebook} spending={spending}");
}

/// Fill the compose screen's structured cost-breakdown card (Sal's
/// build-17 follow-up, 2026-07-18: replace the single wrapped cost-line
/// string with key:value sections). Empty strings hide their row;
/// `fold_total` is `(folded_leftover, byte-true_total_fee)` when the
/// dust-rule fold prediction fired — it populates the "Leftover (dust
/// rule)" and "Total" rows (Total == Fee otherwise, so both stay hidden).
/// Clears `cost_line`: the plain accent text only renders while the card
/// is empty (error/status messaging goes through [`set_cost_status`]).
fn set_cost_card(
    w: &AppWindow,
    size: String,
    fee: String,
    gift: String,
    dust: String,
    fold_total: Option<(u64, u64)>,
) {
    w.set_cost_line("".into());
    w.set_cost_size(size.into());
    w.set_cost_fee(fee.into());
    w.set_cost_gift(gift.into());
    w.set_cost_dust(dust.into());
    match fold_total {
        Some((folded, total)) => {
            w.set_cost_fold(format!("+{} sats", commas(folded)).into());
            w.set_cost_total(format!("~{} sats", commas(total)).into());
        }
        None => {
            w.set_cost_fold("".into());
            w.set_cost_total("".into());
        }
    }
}

/// ERROR/status text under the rate box ("Too large to broadcast…",
/// "~N sats fee minimum", "funded from the external wallet"): plain
/// accent `cost_line` text, structured card hidden — these render exactly
/// as they did before the card existed.
fn set_cost_status(w: &AppWindow, text: String) {
    w.set_cost_size("".into());
    w.set_cost_fee("".into());
    w.set_cost_gift("".into());
    w.set_cost_dust("".into());
    w.set_cost_fold("".into());
    w.set_cost_total("".into());
    w.set_cost_line(text.into());
}

fn refresh_compose(w: &AppWindow, st: &mut State) {
    // Keep the locktime panel's caption/warning fresh against the current
    // tip even if the store's scan advances while compose stays open (the
    // panel's mode/height reflect `st`, not the other way around, so
    // recomputing here is always idempotent with whatever the user picked).
    refresh_compose_locktime_panel(w, st);
    let net = st.network;
    let text = w.get_compose_text().to_string();
    let private = w.get_compose_private();
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    // Keep the compact "Pay from" row's balance current regardless of which
    // branch below runs (notebook / spending / external).
    w.set_pay_from_balance(balance_text_for(st, w.get_pay_from().as_str()).into());
    // MIXED selection (TestFlight build-20 fix, 2026-07-18): a selection
    // spanning 2+ wallets dispatches Sign to `on_compose_send_mixed`
    // (`assemble_mixed_note_psbt`), so its preview must dry-run THAT
    // builder — routing by the last-active single-source flags rendered a
    // different builder's card (spending's unconditional dust-to-self +
    // spending-only input weights vs the anchored mixed build the confirm
    // screen then truthfully decoded). Mirror the active source's scratch
    // selection first (the same idempotent first step
    // `sync_and_finalize_payfrom` performs) so the shape check sees the
    // current selection, and refresh the resolved change default so the
    // dry-run prices the same change destination Sign will use. Watch
    // identities can't mix (no full key) — they fall through unchanged.
    {
        let active = st.payfrom_active_source.clone();
        if active == "notebook" || active == "spending" {
            let coins = st.selected_coins.clone();
            mixed_sync_source(st, &active, &coins);
        }
    }
    if st.ident.as_ref().and_then(|i| i.full()).is_some()
        && payfrom_state(w, st).shape == PayfromShape::Mixed
    {
        update_change_label(w, st);
        mixed_compose_ui(w, st, &text);
        sync_and_finalize_payfrom(w, st);
        return;
    }
    // External-funding mode: the coin panel shows the funding wallet's coins,
    // not the self-funded store coins. Handled on its own isolated path.
    if w.get_fund_external() {
        funding_compose_ui(w, st, &text);
        sync_and_finalize_payfrom(w, st);
        return;
    }
    // Internal spending-wallet mode (funding-unification M3): same idea,
    // but the source is the identity's OWN BIP-84 wallet, signed in-app.
    if w.get_spend_from_wallet() {
        spending_compose_ui(w, st, &text);
        sync_and_finalize_payfrom(w, st);
        return;
    }
    let spk_len = st
        .to_address
        .as_deref()
        .and_then(|a| Recipient::parse(net, a).ok())
        .map(|r| r.spk.len());
    // Multi-recipient: every chip's spk length (uniform gift each) — empty
    // for a self-note, one entry for an ordinary directed note (byte-
    // identical estimate via `compose_est`'s <=1 delegation), 2+ for a
    // real multi-recipient note.
    let recipient_spk_lens: Vec<usize> = match spk_len {
        Some(l) => {
            let mut v = vec![l];
            v.extend(st.to_addresses_extra.iter().filter_map(|a| Recipient::parse(net, a).ok()).map(|r| r.spk.len()));
            v
        }
        None => Vec::new(),
    };
    let n_recipients = recipient_spk_lens.len();
    // Directed notes send a "gift" to EACH recipient (>= dust); self-notes send 0.
    let gift = w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS);
    let sent = if spk_len.is_some() { gift * n_recipients.max(1) as u64 } else { 0 };

    // Change-address destination label + validation. A valid custom change
    // address also yields its scriptPubKey length so the fee/change preview
    // sizes the real change output (not the assumed taproot one).
    let change_raw = w.get_change_address().to_string();
    let change_trim = change_raw.trim();
    let (change_dest, change_err, change_spk_len) = if change_trim.is_empty() {
        ("your address".to_string(), String::new(), None)
    } else {
        match Recipient::parse(net, change_trim) {
            Ok(r) => (
                format!("{}…", &change_trim[..14.min(change_trim.len())]),
                String::new(),
                Some(r.spk.len()),
            ),
            Err(_) => (
                "⚠ invalid".to_string(),
                format!("Not a valid {} address.", net.as_str()),
                None,
            ),
        }
    };
    w.set_change_error(change_err.clone().into());

    // Pay-from screen summary card / Sign gate: computed ONCE, centrally, by
    // `payfrom_state` inside `sync_and_finalize_payfrom` below — from the
    // TRUE cross-wallet selection, not from whichever branch happens to run
    // here. This function still computes its own `cost_line`/`change_amount`
    // preview text (compose-screen display, unrelated to the Pay-from
    // cluster) but no longer sets `spend_enough`/`payfrom_required_line`
    // itself (Sal's iPhone bug cluster, 2026-07-18).
    let consolidate = st.consolidate_coins;
    let Some(store) = &st.store else { return };
    // Auto-suggest a selection until the user overrides it.
    if !st.coins_overridden {
        st.selected_coins = suggested_coins(
            store,
            text.len(),
            private,
            rate,
            &recipient_spk_lens,
            change_spk_len,
            sent,
            consolidate,
        );
    }
    let store = st.store.as_ref().unwrap();
    let exb = st.explorer_base();
    let sel: std::collections::HashSet<(String, u32)> = st.selected_coins.iter().cloned().collect();

    let mut coins: Vec<SpendCoin> = Vec::new();
    let (mut sel_total, mut sel_count) = (0u64, 0usize);
    // Spendable coins, sorted by amount low → high.
    let mut spendable: Vec<&app_core::store::LedgerUtxo> =
        store.utxos.iter().filter(|u| !u.pending_spend).collect();
    spendable.sort_by(|a, b| a.value.cmp(&b.value));
    for u in spendable {
        let selected = sel.contains(&(u.txid.clone(), u.vout));
        if selected {
            sel_total += u.value;
            sel_count += 1;
        }
        coins.push(SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
            tag: "".into(),
        });
    }
    w.set_spend_coins(VecModel::from_slice(&coins));
    let plural = if sel_count == 1 { "" } else { "s" };
    w.set_spend_title(format!("Spending {sel_count} coin{plural} · {sel_total} sats").into());

    if text.is_empty() {
        // The rate box + cost line are always visible now (fee-tier
        // redesign, 2026-07-16) — with no text yet, show the minimum
        // one-chunk estimate (text_len=1, the shortest possible note) so
        // the line still reads as a real (labeled) estimate instead of
        // going blank.
        let n = sel_count.max(1);
        let est_fee = compose_est(store, 1, private, n, &recipient_spk_lens, change_spk_len)
            .ok()
            .map(|(_, vsize)| (vsize as f64 * rate).ceil().max(0.0) as u64);
        let min_line = est_fee
            .map(|fee| format!("~{} sats fee minimum", commas(fee)))
            .unwrap_or_default();
        set_cost_status(w, min_line);
        w.set_change_amount(format!("Change to {change_dest}").into());
        st.compose_oversize = false;
        sync_and_finalize_payfrom(w, st);
        return;
    }
    let n = sel_count.max(1);
    let est = compose_est(store, text.len(), private, n, &recipient_spk_lens, change_spk_len);
    // fit_check stays the single-recipient shape on purpose: the >255-
    // chunk/100kB-vsize ceiling it guards is dominated by the TEXT/chunk
    // count, which multi-recipient outputs don't change (recipients add a
    // fixed handful of vB each — `est` above already prices them exactly;
    // this only decides whether the oversize dialog shows, so an N-
    // recipient note stays governed by the same body-size wall as N=1).
    let fit = fit_check(store, text.len(), private, n, spk_len, change_spk_len);
    let over = !matches!(fit, FitCheck::Ok);
    match est {
        Ok((chunks, vsize)) if !over => {
            let change_len = change_spk_len.unwrap_or(34);
            // Sub-dust fold prediction (honest-fee-label, 2026-07-18): when
            // the leftover after this selection's fee can't clear the dust
            // minimum, the real builder folds it into the fee instead of a
            // change output — mirror that HERE so the preview shows the
            // vsize/fee the tx will ACTUALLY have (the no-change shape), not
            // the with-change one that won't be built.
            let fold = app_core::mixed::predict_notebook_fold(sel_total, sent, vsize, change_len, rate);
            let (vsize, fee, change) = match fold {
                Some((nominal, _)) => {
                    (app_core::mixed::notebook_vsize_no_change(vsize, change_len), nominal, 0)
                }
                None => {
                    let fee = (vsize as f64 * rate).ceil() as u64;
                    (vsize, fee, sel_total.saturating_sub(fee + sent))
                }
            };
            let usd = st
                .usd
                .map(|p| format!(" (~${:.2})", fee as f64 * p / 1e8))
                .unwrap_or_default();
            let fold_amount = fold.map(|(_, folded)| folded).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            // "+330 sats" for one recipient (unchanged copy); "N × G = T
            // sats" for a multi-recipient note (uniform gift × N — Sal,
            // 2026-07-19) — shared formatter, see `gift_row`.
            let gift_line = gift_row(n_recipients, gift, sent);
            set_cost_card(
                w,
                format!("{chunks} chunk{} · ~{vsize} vB", if chunks == 1 { "" } else { "s" }),
                format!("~{} sats{usd}", commas(fee)),
                gift_line,
                String::new(), // no dust-to-self on the self-funded notebook shape
                fold.map(|(nominal, folded)| (folded, nominal + folded)),
            );
            w.set_change_amount(format!("Change to {change_dest} · ~{change} sats").into());
        }
        // Over the per-tx broadcast ceiling: vsize > 100 kB (Ok arm) or the
        // body needs > 255 chunks (Err arm). Sign is gated off via
        // `compose_oversize` (ANDed into `spend_enough` centrally below) —
        // the dialog below offers the fix.
        Ok((chunks, vsize)) => {
            set_cost_status(
                w,
                format!("{chunks} chunk(s) · ~{vsize} vB — too large to broadcast"),
            );
        }
        Err(_) => {
            set_cost_status(w, "Too large to broadcast (> 255 chunks)".to_string());
        }
    }

    // Edge-trigger the "too large" dialog: pop once when the draft first
    // crosses the ceiling, not on every keystroke while it stays over.
    if over && !st.compose_oversize {
        match fit {
            FitCheck::FitsAtStandard => {
                w.set_oversize_offer_bump(true);
                w.set_oversize_message(
                    "This note doesn't fit at your current chunk size. \
                     Switch to Standard (a single large chunk) to fit it in one transaction?"
                        .into(),
                );
                w.set_show_oversize_modal(true);
            }
            FitCheck::HardWall => {
                w.set_oversize_offer_bump(false);
                w.set_oversize_message(
                    "This note is too large to broadcast. A single Bitcoin transaction \
                     can't exceed ~100 kB (the network relay limit), whatever the chunk \
                     size. Shorten the note, or split it across several notes. \
                     Multi-transaction notes are planned for a future release."
                        .into(),
                );
                w.set_show_oversize_modal(true);
            }
            FitCheck::Ok => {}
        }
    }
    st.compose_oversize = over;
    sync_and_finalize_payfrom(w, st);
}

trait CloneFields {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity;
}
impl CloneFields for app_core::notes_core::bundle::Identity {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity {
        app_core::notes_core::bundle::Identity {
            internal_x: self.internal_x,
            output_x: self.output_x,
            tweaked_seckey: self.tweaked_seckey,
            enc_key: self.enc_key,
        }
    }
}

/// External-funding variant of the compose coin panel: show the funding
/// wallet's scanned coins and a source summary, instead of the self-funded
/// store coins. Coin selection (funding-unification UI rework) defaults to
/// every scanned coin until the user overrides it — same tap-to-toggle
/// pattern the notebook/spending panels use, tracked in the cross-wallet
/// selection memory keyed "wallet:<id>" so a mixed compose can spend only
/// SOME of an external wallet's coins.
fn funding_compose_ui(w: &AppWindow, st: &mut State, text: &str) {
    let net = st.network;
    let total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
    let n = st.funding_coins.len();
    let ready = st.funding.is_some() && n > 0;
    w.set_funding_ready(ready);

    // Summary card = which wallet + how much (its first receive address is a
    // recognisable handle for a multi-address wallet).
    match &st.funding {
        Some(src) => {
            let addr0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
            w.set_funding_summary(
                format!("{} · {} · {n} coin{} · {total} sats", src.kind.label(), short_addr(&addr0), if n == 1 { "" } else { "s" }).into(),
            );
        }
        None => w.set_funding_summary("Set a funding wallet".into()),
    }

    let source_key = st
        .active_funding_id
        .as_deref()
        .map(|id| format!("wallet:{id}"))
        .unwrap_or_default();
    let remembered = mixed_coins_for(st, &source_key);
    let sel: std::collections::HashSet<(String, u32)> = if remembered.is_empty() {
        // First time this wallet is shown this session: default to every
        // scanned coin (matches the pre-rework behavior byte-for-byte) and
        // remember that as the baseline.
        let all: Vec<(String, u32)> = st.funding_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect();
        if !all.is_empty() && !source_key.is_empty() {
            mixed_sync_source(st, &source_key, &all);
        }
        all.into_iter().collect()
    } else {
        remembered.into_iter().collect()
    };

    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .funding_coins
        .iter()
        .map(|c| SpendCoin {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            confirmed: c.confirmed,
            selected: sel.contains(&(c.txid.clone(), c.vout)),
            txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
            tag: "".into(),
        })
        .collect();
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 = st
        .funding_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .map(|c| c.value)
        .sum();
    w.set_spend_coins(VecModel::from_slice(&coins));
    w.set_spend_title(
        format!("Funding {sel_count}/{n} coin{} · {} sats", if n == 1 { "" } else { "s" }, commas(sel_total)).into(),
    );
    set_cost_status(w, if text.is_empty() { String::new() } else { "funded from the external wallet".to_string() });
    // `spend_enough`/`payfrom_required_line` are no longer set here — see
    // `payfrom_state`'s external-only branch (same readiness rule: a funding
    // wallet's real cost isn't knowable up front, so no numeric fee).

    // Change: blank = the funding wallet's own change; a valid custom address
    // overrides it. Same validation/label pattern as the self-funded path.
    let change_trim = w.get_change_address().trim().to_string();
    if change_trim.is_empty() {
        w.set_change_amount("Change to funding wallet".into());
        w.set_change_error("".into());
    } else if Recipient::parse(net, &normalize_addr(&change_trim)).is_ok() {
        w.set_change_amount(format!("Change to {}…", &change_trim[..14.min(change_trim.len())]).into());
        w.set_change_error("".into());
    } else {
        w.set_change_amount("Change: ⚠ invalid".into());
        w.set_change_error(format!("Not a valid {} address.", net.as_str()).into());
    }
}

/// Internal-spending-wallet variant of the compose coin panel (funding-
/// unification M3, coin control added funding-unification/M4): shows the
/// identity's OWN BIP-84 spending-wallet coins with the SAME tap-to-toggle
/// coin control as the notebook path (`selected_coins`/`coins_overridden`,
/// shared with [`refresh_compose`]'s notebook branch — default is every
/// scanned coin until the user overrides it) and a LIVE cost/change preview
/// from a dry-run of the exact same funded-note assembly the broadcast path
/// uses (`psbt_build::build_funding_psbt_amount`), spending only the
/// SELECTED coins, so the preview and the real build can never disagree.
fn spending_compose_ui(w: &AppWindow, st: &mut State, text: &str) {
    let net = st.network;
    // `spend_enough`/`payfrom_required_line` are no longer set anywhere in
    // this function — `payfrom_state` (called centrally in
    // `sync_and_finalize_payfrom` right after this returns) now computes
    // both from the TRUE cross-wallet selection, using the same funded-shape
    // math this function's `build_funding_psbt_amount` dry-run uses, minus
    // its insufficiency gate (Sal's iPhone bug cluster, 2026-07-18).
    let n = st.spending_coins.len();
    if !st.coins_overridden {
        st.selected_coins = st.spending_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect();
    }
    let sel: std::collections::HashSet<(String, u32)> = st.selected_coins.iter().cloned().collect();
    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .spending_coins
        .iter()
        .map(|c| SpendCoin {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            confirmed: c.confirmed,
            selected: sel.contains(&(c.txid.clone(), c.vout)),
            txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
            tag: "".into(),
        })
        .collect();
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 = st
        .spending_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .map(|c| c.value)
        .sum();
    w.set_spend_coins(VecModel::from_slice(&coins));
    w.set_spend_title(
        format!(
            "Spending wallet · {sel_count}/{n} coin{} · {} sats",
            if n == 1 { "" } else { "s" },
            commas(sel_total)
        )
        .into(),
    );

    // Change destination: blank = a fresh spending-wallet address; a valid
    // custom address overrides it — same pattern as the other two panels.
    let change_trim = w.get_change_address().trim().to_string();
    let change_override_spk = if change_trim.is_empty() {
        w.set_change_error("".into());
        None
    } else {
        match Recipient::parse(net, &normalize_addr(&change_trim)) {
            Ok(r) => {
                w.set_change_error("".into());
                Some(r.spk)
            }
            Err(_) => {
                w.set_change_amount("Change: ⚠ invalid".into());
                w.set_change_error(format!("Not a valid {} address.", net.as_str()).into());
                return;
            }
        }
    };

    if n == 0 {
        set_cost_status(w, String::new());
        w.set_change_amount("Spending wallet has no coins yet — fund its receive address in Settings.".into());
        return;
    }
    if sel_count == 0 {
        set_cost_status(w, String::new());
        w.set_change_amount("No coins selected — select at least one below.".into());
        return;
    }
    if text.is_empty() {
        set_cost_status(w, String::new());
        w.set_change_amount(
            if change_override_spk.is_some() {
                format!("Change to {}…", &change_trim[..14.min(change_trim.len())])
            } else {
                "Change to a fresh spending-wallet address".to_string()
            }
            .into(),
        );
        return;
    }
    let (Some(source), Some(store), Some(identity)) = (
        st.spending_source.as_ref(),
        st.store.as_ref(),
        st.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()),
    ) else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk (uniform gift each) — mirrors the
    // notebook path's preview (`refresh_compose`'s `recipient_spk_lens`).
    let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
    let recipients = app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients)
        .unwrap_or_default();
    let n_recipients = recipients.len();
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    let change_index = store.spending.next_change;
    let has_custom_change = change_override_spk.is_some();
    // Spend exactly the coins selected in the coin-control list below —
    // mirrors the notebook path's `compose_*_exact`.
    let selected_coins: Vec<app_core::funding::FundingUtxo> = st
        .spending_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .cloned()
        .collect();
    let plan = FundingPlan {
        source,
        coins: &selected_coins,
        change_index,
        fee_rate: rate,
        change_override: change_override_spk,
    };
    let np = NoteParams {
        identity: &identity,
        text,
        private: w.get_compose_private(),
        recipient: recipient.as_ref(),
        note_id: [0, 0, 0, 0], // preview only — the real send draws a fresh id
        max_op_return_bytes: store.chunk_size,
        network: net,
    };
    let build_result = if n_recipients >= 2 {
        app_core::psbt_build::build_funding_psbt_multi(&plan, &np, &recipients, gift, st.effective_lock_time())
    } else {
        app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift, st.effective_lock_time())
    };
    match build_result {
        Ok(built) => {
            // Sub-dust fold prediction (honest-fee-label, 2026-07-18):
            // `built.change == 0` means the REAL build already chose the
            // no-change shape — split its fee into the nominal figure
            // (what that shape actually costs at the chosen rate) and the
            // sub-dust leftover folded in on top, so the line never reads
            // as an inflated/expensive fee.
            let fold = if built.change == 0 {
                let weights: Vec<_> = std::iter::repeat(bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX)
                    .take(selected_coins.len().max(1))
                    .collect();
                let payload_and_lens = if n_recipients >= 2 {
                    let mut content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
                    app_core::notes_core::bundle::sealed_note_payloads_multi(
                        &identity, text, w.get_compose_private(), &recipients, [0u8, 0, 0, 0], content_key,
                        store.chunk_size,
                    )
                    .ok()
                    .map(|(p, spks)| (p, spks.iter().map(|s| s.len()).collect::<Vec<usize>>()))
                    .inspect(|_| content_key.zeroize())
                } else {
                    app_core::notes_core::bundle::sealed_note_payloads(
                        &identity, text, w.get_compose_private(), recipient.as_ref(), [0u8, 0, 0, 0],
                        store.chunk_size,
                    )
                    .ok()
                    .map(|(p, spk)| {
                        let lens = spk.map(|s| vec![s.len()]).unwrap_or_default();
                        (p, lens)
                    })
                };
                payload_and_lens.map(|(payloads, recipient_spk_lens)| {
                    // Spending-only path: never a notebook coin, so
                    // dust-to-self is always present (matches
                    // `build_funding_psbt_amount`'s unconditional rule).
                    let nominal = app_core::mixed::estimate_funded_fee_no_change_multi(
                        &weights,
                        &payloads,
                        &recipient_spk_lens,
                        true,
                        rate,
                    );
                    (nominal, built.fee.saturating_sub(nominal))
                })
                .filter(|(_, folded)| *folded > 0)
            } else {
                None
            };
            let fold_amount = fold.map(|(_, f)| f).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            let fee_shown = fold.map(|(nominal, _)| nominal).unwrap_or(built.fee);
            let usd = st.usd.map(|p| format!(" (~${:.2})", fee_shown as f64 * p / 1e8)).unwrap_or_default();
            set_cost_card(
                w,
                String::new(), // funded shape: no chunk/vsize estimate on this path
                format!("~{} sats{usd}", commas(fee_shown)),
                gift_row(n_recipients, gift, built.sent_to_recipient),
                // Row hidden when the built tx carries no dust-to-self —
                // always present on THIS (spending-only) shape today, but
                // conditional so the card can never claim an output the
                // build doesn't contain (TestFlight build-20 audit).
                if built.dust_to_self > 0 { format!("+{} sats", commas(built.dust_to_self)) } else { String::new() },
                // Total = the byte-true fee the tx pays (nominal + leftover).
                fold.map(|(_, folded)| (folded, built.fee)),
            );
            w.set_change_amount(
                if has_custom_change {
                    format!(
                        "Change to {}… · ~{} sats",
                        &change_trim[..14.min(change_trim.len())],
                        commas(built.change)
                    )
                } else {
                    format!("Change to a fresh spending-wallet address · ~{} sats", commas(built.change))
                }
                .into(),
            );
        }
        Err(e) => {
            set_cost_status(w, String::new());
            w.set_change_amount(format!("{e}").into());
        }
    }
}

/// MIXED-selection compose preview (TestFlight build-20 fix, 2026-07-18):
/// when the cross-wallet selection spans 2+ sources, Sign dispatches to
/// `on_compose_send_mixed` (`assemble_mixed_note_psbt`) — so the cost card
/// must dry-run THAT builder with THE SAME arguments ([`mixed_compose_args`],
/// the shared seam) instead of whichever single-source branch happened to be
/// `payfrom_active_source` (Sal's report: a spending-active mixed selection
/// rendered spending_compose_ui's card — unconditional dust-to-self,
/// spending-only inputs — while the confirm screen showed the anchored mixed
/// build with no dust output and a different fee). Rendering mirrors
/// `spending_compose_ui`'s Ok arm: fee/fold via the anchored-aware
/// estimators, dust row from `built.dust_to_self` (hidden when 0), Total =
/// byte-true fee. Logs `cb: compose-est shape=mixed dust=<n> fee=<n>` per
/// distinct value (same guard style as the fold line) — the e2e pins that
/// fee to the confirm screen's `fee=` for the same compose.
fn mixed_compose_ui(w: &AppWindow, st: &mut State, text: &str) {
    let net = st.network;
    let args = match mixed_compose_args(w, st) {
        Ok(a) => a,
        Err(_) => {
            // Same invalid-custom-change rendering the other branches use.
            set_cost_status(w, String::new());
            w.set_change_amount("Change: ⚠ invalid".into());
            w.set_change_error(format!("Not a valid {} address.", net.as_str()).into());
            return;
        }
    };
    w.set_change_error("".into());
    let change_dest = if args.change_override.is_some() {
        let t = w.get_change_address().trim().to_string();
        format!("{}…", &t[..14.min(t.len())])
    } else {
        match &args.change_default {
            app_core::mixed::ChangeDefault::Spending => "a fresh spending-wallet address".to_string(),
            app_core::mixed::ChangeDefault::Notebook => "your notebook address".to_string(),
            app_core::mixed::ChangeDefault::Wallet(_) => "the funding wallet".to_string(),
        }
    };
    if text.is_empty() {
        set_cost_status(w, String::new());
        w.set_change_amount(format!("Change to {change_dest}").into());
        return;
    }
    let Some(identity) = st.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk (uniform gift each) — mirrors
    // `on_compose_send_mixed`'s send path.
    let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
    let recipients = app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients)
        .unwrap_or_default();
    let n_recipients = recipients.len();
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    let chunk = st.store.as_ref().map(|s| s.chunk_size).unwrap_or(DEFAULT_CHUNK);
    // Preview note id is all-zero, like every other preview dry-run —
    // payload LENGTHS (all the fee math consumes) don't depend on the id.
    let sealed = if n_recipients >= 2 {
        let content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
        app_core::notes_core::bundle::sealed_note_payloads_multi(
            &identity, text, w.get_compose_private(), &recipients, [0u8, 0, 0, 0], content_key, chunk,
        )
    } else {
        app_core::notes_core::bundle::sealed_note_payloads(
            &identity, text, w.get_compose_private(), recipient.as_ref(), [0u8, 0, 0, 0], chunk,
        )
        .map(|(p, spk)| (p, spk.into_iter().collect::<Vec<Vec<u8>>>()))
    };
    let Ok((payloads, recipient_spks)) = sealed else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient_spk_lens: Vec<usize> = recipient_spks.iter().map(|s| s.len()).collect();
    let recipients_out: Vec<(Vec<u8>, u64)> = recipient_spks.into_iter().map(|spk| (spk, gift)).collect();
    match app_core::mixed::assemble_mixed_note_psbt_multi_ext(
        &args.coins,
        p2tr_script_pubkey(&identity.output_x),
        st.spending_source.as_ref(),
        &args.wallets_map,
        &args.change_spks,
        &payloads,
        &recipients_out,
        &args.change_default,
        args.change_override.clone(),
        args.change_index,
        rate,
        st.effective_lock_time(),
    ) {
        Ok(built) => {
            // Sub-dust fold prediction — `built.change == 0` means the REAL
            // build already chose the no-change shape; split its fee into
            // the nominal figure and the folded leftover, exactly like the
            // spending branch, but with per-coin input weights and the
            // anchored-aware dust flag (`built.dust_to_self > 0`).
            let fold = if built.change == 0 {
                let weights: Vec<bitcoin::transaction::InputWeightPrediction> = args
                    .coins
                    .iter()
                    .map(|c| match &c.source {
                        app_core::mixed::CoinSource::Notebook => {
                            bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
                        }
                        app_core::mixed::CoinSource::Spending => {
                            bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
                        }
                        app_core::mixed::CoinSource::Wallet(id) => match args.wallets_map.get(id).map(|s| s.kind) {
                            Some(app_core::funding::FundingKind::Wpkh) => {
                                bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
                            }
                            _ => bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
                        },
                        app_core::mixed::CoinSource::Change => {
                            bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
                        }
                    })
                    .collect();
                let nominal = app_core::mixed::estimate_funded_fee_no_change_multi(
                    &weights,
                    &payloads,
                    &recipient_spk_lens,
                    built.dust_to_self > 0,
                    rate,
                );
                Some((nominal, built.fee.saturating_sub(nominal))).filter(|(_, folded)| *folded > 0)
            } else {
                None
            };
            let fold_amount = fold.map(|(_, f)| f).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            // The preview==confirm pin: `fee` here is the byte-true total
            // fee the built tx pays — the confirm screen's `fee=` decodes
            // the same figure from the raw tx, and the e2e asserts equality.
            if st.mixed_est_shown != Some((built.dust_to_self, built.fee)) {
                println!("cb: compose-est shape=mixed dust={} fee={}", built.dust_to_self, built.fee);
                st.mixed_est_shown = Some((built.dust_to_self, built.fee));
            }
            let fee_shown = fold.map(|(nominal, _)| nominal).unwrap_or(built.fee);
            let usd = st.usd.map(|p| format!(" (~${:.2})", fee_shown as f64 * p / 1e8)).unwrap_or_default();
            set_cost_card(
                w,
                String::new(), // funded shape: no chunk/vsize estimate on this path
                format!("~{} sats{usd}", commas(fee_shown)),
                gift_row(n_recipients, gift, built.sent_to_recipient),
                // Anchored (a notebook coin spends) → no dust output → row hidden.
                if built.dust_to_self > 0 { format!("+{} sats", commas(built.dust_to_self)) } else { String::new() },
                fold.map(|(_, folded)| (folded, built.fee)),
            );
            w.set_change_amount(format!("Change to {change_dest} · ~{} sats", commas(built.change)).into());
        }
        Err(e) => {
            set_cost_status(w, String::new());
            w.set_change_amount(format!("{e}").into());
        }
    }
}

/// A per-frame preview closure for [`camera::capture_frames`] — pushes each
/// downscaled frame to the shared `camera-frame` image so the scan overlay
/// shows a live view (QR detection, not the preview, is what's throttled).
fn scan_preview(weak: slint::Weak<AppWindow>) -> impl FnMut(&[u8], u32, u32) {
    move |rgba: &[u8], pw: u32, ph: u32| {
        let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(pw, ph);
        buf.make_mut_bytes().copy_from_slice(rgba);
        let _ = weak.upgrade_in_event_loop(move |w| w.set_camera_frame(slint::Image::from_rgba8(buf)));
    }
}

/// Show the shared scan overlay and clear the cancel flag (call on the UI thread
/// before spawning the capture thread).
fn begin_scan(weak: &slint::Weak<AppWindow>, cancel: &Arc<AtomicBool>, hint: &str) {
    cancel.store(false, Ordering::Relaxed);
    if let Some(w) = weak.upgrade() {
        w.set_scan_hint(hint.into());
        w.set_scan_progress(0.0);
        w.set_scanning(true);
    }
}

/// Populate the saved-wallet manager list (screen 15).
fn refresh_funding_list(w: &AppWindow, st: &State) {
    let active = st.active_funding_id.clone();
    // Independent-expand rework (2026-07-18): each row carries its OWN
    // coins/title (from the shared `payfrom_panel_coins` helper — screen
    // 20's per-row panels bind directly to `fw.coins`, no more singular
    // `spend-coins`) and whether IT is the one open in the external-wallet
    // accordion slot (`payfrom_expanded_source`; Notebook/Spending have
    // their own independent booleans and never touch this).
    let rows: Vec<FundingWalletRow> = st
        .funding_wallets
        .iter()
        .map(|fw| {
            let meta = if fw.scanned {
                format!("{} · {} sats · {} coin{}", fw.kind, fw.balance, fw.coins, if fw.coins == 1 { "" } else { "s" })
            } else {
                format!("{} · tap to scan for funds", fw.kind)
            };
            let change_addr = fw
                .source(st.network)
                .ok()
                .and_then(|src| src.derive(1, fw.next_change_index).ok())
                .map(|d| addr_short(&d.address))
                .unwrap_or_default();
            let source_key = format!("wallet:{}", fw.id);
            let (coins, coin_title) = payfrom_panel_coins(st, &source_key);
            FundingWalletRow {
                id: fw.id.clone().into(),
                label: fw.label.clone().into(),
                meta: meta.into(),
                active: active.as_deref() == Some(fw.id.as_str()),
                change_addr: change_addr.into(),
                coins: VecModel::from_slice(&coins),
                coin_title: coin_title.into(),
                expanded: st.payfrom_expanded_source == source_key,
            }
        })
        .collect();
    w.set_funding_wallets(VecModel::from_slice(&rows));
}

/// Make a saved wallet the active funding source: scan it, cache its balance,
/// and return to compose in external-funding mode. Used by the screen-15
/// wallet list, the add-descriptor flow (12), and the sweep screen (16) —
/// NOT the Pay-from screen (20) anymore: independent-expand rework
/// (2026-07-18) split that header tap into `payfrom_scan_wallet_for_display`
/// (view only) + `promote_wallet_active` (on an actual coin tap), so
/// `stay_on_payfrom` below is effectively always false now — kept rather
/// than removed since this function's other callers still rely on the rest
/// of its behavior unchanged.
fn activate_funding_wallet(w: &AppWindow, st: &mut State, id: &str) {
    // funding-unification UI rework: tapping a wallet row on the Pay-from
    // screen (20) selects + expands it IN PLACE — it must not navigate away
    // like the screen-15/16 entry points do.
    let stay_on_payfrom = w.get_screen() == 20;
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    let descriptor = st.funding_wallets[idx].descriptor.clone();
    let src = match FundingSource::parse(&descriptor, net) {
        Ok(src) => src,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    w.set_status("scanning funding wallet…".into());
    let creds = core_rpc_creds_for(st, &base, net);
    let client = match open_client(&base, net, creds) {
        Ok(c) => c,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    match client.scan_funding(&src, 20) {
        Ok(scan) => {
            st.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            st.funding_wallets[idx].coins = scan.utxos.len();
            st.funding_wallets[idx].scanned = true;
            st.funding_wallets[idx].next_change_index = scan.next_change_index;
            st.save_funding_wallets();
            let empty = scan.utxos.is_empty();
            st.funding_coins = scan.utxos;
            st.funding_change_index = scan.next_change_index;
            st.funding = Some(src);
            st.active_funding_id = Some(id.to_string());
            // Seed the single-source scratch selection from this wallet's
            // coins (or its remembered cross-wallet selection), so
            // `sync_and_finalize_payfrom` mirrors the wallet into
            // `mixed_selected` — without this the change-default resolver
            // never saw an external wallet participating and kept
            // defaulting to the notebook (Sal's rule: external funding
            // defaults change to THAT wallet's change address).
            let remembered = mixed_coins_for(st, &format!("wallet:{id}"));
            st.selected_coins = if remembered.is_empty() {
                st.funding_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect()
            } else {
                remembered
            };
            w.set_status(if empty { "wallet has no spendable coins yet".to_string() } else { String::new() }.into());
            if stay_on_payfrom {
                w.set_fund_external(true);
                w.set_spend_from_wallet(false);
                let label = st.funding_wallets[idx].label.clone();
                w.set_pay_from(format!("wallet:{id}").into());
                w.set_pay_from_label(label.clone().into());
                w.set_pay_from_balance(format!("{} sats", commas(st.funding_wallets[idx].balance)).into());
                println!("cb: pay-from wallet:{label}");
                refresh_compose(w, st);
            } else if w.get_funding_return() == 16 {
                // Came from the sweep screen — return there, funding armed.
                w.set_sweep_fund_external(true);
                w.set_screen(16);
                update_sweep_screen(w, st);
            } else {
                w.set_fund_external(true);
                w.set_spend_from_wallet(false);
                let label = st.funding_wallets[idx].label.clone();
                w.set_pay_from(format!("wallet:{id}").into());
                w.set_pay_from_label(label.clone().into());
                w.set_pay_from_balance(format!("{} sats", commas(st.funding_wallets[idx].balance)).into());
                println!("cb: pay-from wallet:{label}");
                w.set_spend_expanded(true);
                w.set_screen(6);
                refresh_compose(w, st);
            }
        }
        Err(e) => {
            println!("cb: funding-wallet scan err={e}");
            w.set_status(format!("scan failed: {}", friendly_net_err(&e.to_string())).into());
        }
    }
}

/// If `text` is a UR account/descriptor export (BCR crypto-account etc.),
/// decode it, save every supported descriptor as a funding wallet, and show the
/// manager list. Returns true if the input was a UR (handled — possibly with an
/// error message); false to fall through to plain descriptor handling.
fn try_import_ur_account(w: &AppWindow, st: &mut State, text: &str) -> bool {
    let t = text.trim();
    if !t.to_lowercase().starts_with("ur:") {
        return false;
    }
    let net = st.network;
    let (ty, bytes) = match app_core::ur::decode_ur_string(t) {
        Ok(x) => x,
        Err(e) => {
            w.set_status(format!("UR: {e}").into());
            return true;
        }
    };
    if ty == "crypto-psbt" {
        w.set_status("that's a transaction QR, not a wallet".into());
        return true;
    }
    match app_core::ur_account::descriptors_from_ur(&ty, &bytes, net) {
        Ok(descs) if !descs.is_empty() => {
            let ds: Vec<String> = descs.iter().map(|d| d.descriptor.clone()).collect();
            let added = save_funding_descriptors(w, st, &ds);
            w.set_status(format!("imported {added} account(s) from {ty}").into());
            true
        }
        Ok(_) => {
            w.set_status("no taproot/segwit accounts in that export".into());
            true
        }
        Err(e) => {
            w.set_status(format!("{e}").into());
            true
        }
    }
}

/// Shorten a bech32 address for display: `bcrt1p2caqg…6hrewe`.
fn short_addr(a: &str) -> String {
    if a.len() > 20 {
        format!("{}…{}", &a[..10], &a[a.len() - 6..])
    } else {
        a.to_string()
    }
}

/// Pull an output descriptor out of pasted text or a wallet-export file:
/// a bare descriptor/xpub passes through; otherwise find an embedded
/// `tr(...)`/`wpkh(...)` token (handles Sparrow-style JSON + text exports).
fn extract_descriptor(text: &str) -> String {
    let t = text.trim();
    for pat in ["tr(", "wpkh("] {
        if let Some(i) = t.find(pat) {
            let rest = &t[i..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            return rest[..end].to_string();
        }
    }
    t.to_string()
}

/// Pull EVERY `tr()`/`wpkh()` descriptor out of pasted text or a wallet-export
/// file — a single export can list several script types. Falls back to the
/// whole trimmed input as one candidate when no `tr(`/`wpkh(` token is present.
fn extract_all_descriptors(text: &str) -> Vec<String> {
    let t = text.trim();
    let mut found: Vec<String> = Vec::new();
    for pat in ["tr(", "wpkh("] {
        let mut from = 0;
        while let Some(rel) = t[from..].find(pat) {
            let start = from + rel;
            let rest = &t[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            let desc = rest[..end].to_string();
            if !found.contains(&desc) {
                found.push(desc);
            }
            from = start + end.max(1);
        }
    }
    if found.is_empty() {
        vec![t.to_string()]
    } else {
        found
    }
}

/// Create + persist a funding wallet for each descriptor (dedup by id), refresh
/// the manager list, and show it. Returns how many NEW wallets were added.
/// Shared by UR account import and multi-descriptor wallet files — the user
/// then picks which one to use from the list.
fn save_funding_descriptors(w: &AppWindow, st: &mut State, descriptors: &[String]) -> usize {
    let net = st.network;
    let mut added = 0;
    for d in descriptors {
        if let Ok(fw) = FundingWallet::create(d, "", net) {
            if !st.funding_wallets.iter().any(|x| x.id == fw.id) {
                st.funding_wallets.push(fw);
                added += 1;
            }
        }
    }
    if added > 0 {
        st.save_funding_wallets();
    }
    refresh_funding_list(w, st);
    w.set_screen(15);
    added
}

/// Load the device-level saved funding wallets (empty if the file is absent).
fn load_funding_wallets(dir: &std::path::Path) -> Vec<FundingWallet> {
    std::fs::read_to_string(dir.join("funding-wallets.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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
fn load_or_migrate_contacts(data_dir: &std::path::Path) -> app_core::contacts::ContactState {
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

/// Import a signed PSBT (from file bytes, a base64/hex string, or a UR string),
/// validate it against the tx we built, render the Sparrow-style confirmation,
/// and advance to the review screen.
fn load_signed_psbt(w: &AppWindow, st: &mut State, data: &[u8]) {
    let psbt: Result<bitcoin::Psbt, String> = if data.starts_with(b"psbt\xff") {
        bitcoin::Psbt::deserialize(data).map_err(|e| e.to_string())
    } else {
        let text = String::from_utf8_lossy(data);
        let t = text.trim();
        if t.to_lowercase().starts_with("ur:") {
            let mut dec = app_core::ur::PsbtUrDecoder::new();
            match dec.receive(t) {
                Ok(true) => dec
                    .psbt_bytes()
                    .map_err(|e| e.to_string())
                    .and_then(|b| bitcoin::Psbt::deserialize(&b).map_err(|e| e.to_string())),
                Ok(false) => Err("multi-frame UR — import the .psbt file instead".into()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            parse_psbt(t).map_err(|e| e.to_string())
        }
    };
    match psbt {
        Ok(p) => set_confirm_from_psbt(w, st, p),
        Err(e) => w.set_status(format!("import: {e}").into()),
    }
}

// ---- Universal confirm screen (26) — infrastructure shared by every
// broadcast path (funding-unification follow-up, 2026-07-17). See
// `app_core::confirm` for the byte-truth summarizer this all feeds; the
// philosophy is the same here: every fact on screen 26 is decoded from the
// SIGNED raw tx about to hit the wire, never from the app's own intent.

/// Every scriptPubKey this account controls: every ACTIVE notebook's own
/// address (not just the current one — a directed self-note from a sibling
/// notebook must still classify as "self", same rule `xacct_addrs`/
/// `sender_label` already follow) plus every spending-wallet address
/// handed out so far (`Store::spending_self_spks`). Feeds
/// `ConfirmCtx.self_spks`/`spending_spks` for every compose path; PSBT-path
/// callers reuse it too. A change output going to an address not yet
/// recorded as "used" (the spending wallet's NEXT receive/change index, or
/// a freshly discovered one) must be added by the caller on top of this —
/// see the spending/mixed compose call sites below.
fn confirm_self_spks(st: &State) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut self_spks: Vec<Vec<u8>> = Vec::new();
    if let (Some(ix), Some(material_str)) = (&st.notebooks, st.material.as_deref()) {
        if let Ok(material) = parse_key_material(material_str, st.network) {
            for m in ix.active(st.account) {
                if let Ok(ident) = realize(&material, st.network, st.account, m.index) {
                    self_spks.push(p2tr_script_pubkey(&ident.output_x()));
                }
            }
        }
    }
    let spending_spks = st.store.as_ref().map(|s| s.spending_self_spks()).unwrap_or_default();
    self_spks.extend(spending_spks.iter().cloned());
    (self_spks, spending_spks)
}

/// The DISPLAY-OWNER anchor set (notes-core rev 6e36a23) for the CURRENT
/// identity's account — every ACTIVE notebook's own spk, in index order,
/// fed to `Store::apply_bundle`/`apply_bundle_watch` alongside a scan.
/// Mirrors `confirm_self_spks`'s notebook enumeration exactly (same
/// `ix.active(account)` + `realize` walk via `active_notebook_spks`) but
/// omits the spending wallet's addresses, which must never be in this
/// set. Empty when there's no material/notebooks index yet (non-
/// hierarchical key material, or before the first notebook loads) —
/// `Store::apply_bundle*` treat an empty slice as a strict no-op.
fn notebook_spks_for(st: &State) -> Vec<Vec<u8>> {
    match (&st.notebooks, st.material.as_deref()) {
        (Some(ix), Some(material_str)) => parse_key_material(material_str, st.network)
            .map(|material| active_notebook_spks(&material, st.network, st.account, ix))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Spending-self-notes fix window sizing (PLAN-chain-notes-app-spending-
/// self-notes.md, Unit A / RC1 — LOCKED decision 4): self-extending, no
/// magic cap. `WINDOW_MIN` is the floor for a fresh/lightly-used spending
/// wallet; `WINDOW_BUFFER` covers addresses handed out but not yet recorded
/// as `used` by THIS device (a scan that hasn't landed, or a disk-loaded
/// non-active store). Derivation is pure secp math (no network) — "generous"
/// is nearly free, computed ONCE per scan/apply pass (see call sites) and
/// reused across every notebook, never re-derived per notebook.
const SPENDING_WINDOW_MIN: u32 = 100;
const SPENDING_WINDOW_BUFFER: u32 = 50;

/// The derived spending-address classification window (Unit A / RC1): both
/// chains' scriptPubKeys for indexes `0..max(SPENDING_WINDOW_MIN,
/// discovered_next_index + SPENDING_WINDOW_BUFFER)`, where
/// `discovered_next_index` is the account's spending section's
/// `next_receive`/`next_change` high-water mark
/// (`NotebookIndex::spending_for`, history-based and already correct — see
/// the PLAN's RC1 analysis). Fed to `Store::apply_bundle`/
/// `apply_bundle_watch` as `extra_spending_spks` alongside a scan, UNIONED
/// with (never replacing) the store's own recorded-`used` snapshot — this
/// is what fixes a spending-wallet-funded self-note classifying as
/// "Unknown" after a fresh install or on a disk-loaded non-active store,
/// where that snapshot is empty or stale.
///
/// Empty for watch-only or non-hierarchical material (`spending::
/// window_spks` mirrors `can_derive_spending`, so a watch identity — which
/// has no spending wallet — degrades to today's byte-identical behavior)
/// or when there's no notebooks index / material loaded yet.
fn spending_window_spks_for(st: &State) -> Vec<Vec<u8>> {
    let (Some(ix), Some(material_str)) = (&st.notebooks, st.material.as_deref()) else {
        return Vec::new();
    };
    let Ok(material) = parse_key_material(material_str, st.network) else {
        return Vec::new();
    };
    let section = ix.spending_for(st.account);
    let discovered_next_index = section.next_receive.max(section.next_change);
    let upto = SPENDING_WINDOW_MIN.max(discovered_next_index.saturating_add(SPENDING_WINDOW_BUFFER));
    app_core::spending::window_spks(&material, st.network, st.account, upto).unwrap_or_default()
}

/// The confirm screen's one-liner caption for any note-composing tx:
/// "Public note · testnet4" / "Private note · testnet4" / "Directed note ·
/// testnet4". Directed takes priority in the label — a directed note's own
/// privacy is already visible on its NOTE card and recipient row.
fn note_context(directed: bool, private: bool, network: Network) -> String {
    let kind = if directed { "Directed note" } else if private { "Private note" } else { "Public note" };
    format!("{kind} · {}", network.as_str())
}

/// The tx builders fold sub-dust change into the fee (notes-core rule: a
/// leftover below the 330-sat dust minimum can't be an output, and the
/// builder never burns MORE than dust — larger leftovers force a change
/// output). Without this note the confirm screen shows a fee visibly above
/// rate×vsize with no explanation — Sal hit exactly that on testnet4
/// (single 330-sat coin → whole coin to fee) and asked if dust was
/// forgotten. The byte-truth fee row (e.g. "330 sats · 3.2 sat/vB") stays
/// untouched elsewhere on the screen — this banner is what keeps that
/// figure from reading as an inflated/expensive fee: it splits it into the
/// real network fee at the user's chosen rate (`nominal = ceil(vsize×rate)`)
/// and the sub-dust leftover riding along on top (Sal 2026-07-18: "every
/// fee label must split honestly ... so it's not misleading as being
/// expensive to use this app"). Appends to the warn banner AFTER
/// show_confirm populated it; only when the confirm screen actually
/// navigated.
fn note_subdust_fold_warn(w: &AppWindow, change: u64, fee: u64, vsize: u64, rate: f64) {
    if change != 0 || w.get_screen() != 26 {
        return;
    }
    let nominal = (vsize as f64 * rate).ceil() as u64;
    let folded = fee.saturating_sub(nominal);
    if folded == 0 {
        return;
    }
    println!("cb: confirm subdust-fold folded={folded}");
    let msg = format!(
        "network fee ~{} sats at your rate · +{} sats leftover below the {} sat dust minimum (too small to form a change output)",
        commas(nominal),
        commas(folded),
        DUST_SATS
    );
    let existing = w.get_confirm_warn().to_string();
    w.set_confirm_warn(if existing.is_empty() { msg.into() } else { format!("{existing}; {msg}").into() });
}

/// `ConfirmCtx.prevouts` for a notebook compose's spent coins — every input
/// is this notebook's own single address (coin control only ever selects
/// among this notebook's own UTXOs, so one address covers every entry).
/// `spent` is `NoteTx.spent_outpoints` — internal (non-reversed) txid
/// bytes, matching `compose::record_composed_note`'s own reversal.
fn notebook_prevouts(
    store: &Store,
    address: &str,
    name: &str,
    spent: &[([u8; 32], u32)],
) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    spent
        .iter()
        .map(|(txid, vout)| {
            let mut d = *txid;
            d.reverse();
            let txid_hex = hex::encode(d);
            let value =
                store.utxos.iter().find(|u| u.txid == txid_hex && u.vout == *vout).map(|u| u.value).unwrap_or(0);
            (
                format!("{txid_hex}:{vout}"),
                app_core::confirm::PrevoutInfo {
                    value,
                    address: Some(address.to_string()),
                    source: format!("Notebook · {name}"),
                },
            )
        })
        .collect()
}

/// `ConfirmCtx.prevouts` from already-known inputs whose value is already
/// in hand (gathered while building a sweep/consolidate tx, unlike
/// `notebook_prevouts`'s compose-path shape which must look values up) —
/// every entry gets the SAME address + source label. Multi-source flows
/// (wallet sweep, wconsol) build the map entry-by-entry themselves instead
/// (each input needs its OWN owning notebook's label).
fn labeled_prevouts(
    inputs: &[app_core::store::TxInput],
    address: Option<&str>,
    source: &str,
) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    inputs
        .iter()
        .map(|inp| {
            (
                format!("{}:{}", inp.txid, inp.vout),
                app_core::confirm::PrevoutInfo {
                    value: inp.value,
                    address: address.map(str::to_string),
                    source: source.to_string(),
                },
            )
        })
        .collect()
}

/// `ConfirmCtx.prevouts` for a STORED pending record's inputs — used by
/// Speed-up and Rebroadcast, where the tx was already built earlier (not
/// freshly composed this session, so there's no fresh coin list in hand).
/// A note spend is always this notebook's own single address (coin
/// control only ever spends one notebook's own UTXOs). A sweep/consolidate
/// record resolves each input's owning notebook from
/// `TxRecord.input_indexes`/`input_accounts` where available (multi-key
/// wallet ops); an input with no resolvable owner (a mixed notebook+
/// spending-wallet record has none at all — see `TxRecord.mixed_inputs`)
/// gets an empty source/no address — honest partial disclosure, never a
/// fabricated one; the confirm module renders that as "source unknown".
fn stored_record_prevouts(
    st: &State,
    ref_id: &str,
    is_note: bool,
) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    let Some(store) = st.store.as_ref() else { return HashMap::new() };
    if is_note {
        let Some(rec) = store.notes.iter().find(|n| n.note_id == ref_id) else { return HashMap::new() };
        let name = st.notebook_display_name(st.ident.as_ref().map(|i| i.index).unwrap_or(0));
        let addr = st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        return rec
            .spent
            .iter()
            .map(|op| {
                let value = store
                    .utxos
                    .iter()
                    .find(|u| u.txid == op.txid && u.vout == op.vout)
                    .map(|u| u.value)
                    .unwrap_or(0);
                (
                    format!("{}:{}", op.txid, op.vout),
                    app_core::confirm::PrevoutInfo {
                        value,
                        address: Some(addr.clone()),
                        source: format!("Notebook · {name}"),
                    },
                )
            })
            .collect();
    }
    let Some(rec) = store.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id)) else {
        return HashMap::new();
    };
    let material = st.material.as_deref().and_then(|m| parse_key_material(m, st.network).ok());
    rec.inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            let owner = if !rec.input_indexes.is_empty() {
                rec.input_indexes.get(i).map(|idx| (st.account, *idx))
            } else if !rec.input_accounts.is_empty() {
                rec.input_accounts.get(i).map(|acct| (*acct, 0u32))
            } else {
                None
            };
            let info = match (owner, material.as_ref()) {
                (Some((acct, idx)), Some(m)) => match realize(m, st.network, acct, idx) {
                    Ok(ident) => app_core::confirm::PrevoutInfo {
                        value: inp.value,
                        address: Some(ident.address.clone()),
                        source: if acct == st.account {
                            format!("Notebook · {}", st.notebook_display_name(idx))
                        } else {
                            format!("Notebook · account {acct}")
                        },
                    },
                    Err(_) => {
                        app_core::confirm::PrevoutInfo { value: inp.value, address: None, source: String::new() }
                    }
                },
                _ => app_core::confirm::PrevoutInfo { value: inp.value, address: None, source: String::new() },
            };
            (format!("{}:{}", inp.txid, inp.vout), info)
        })
        .collect()
}

/// `ConfirmCtx.expected_change` for a note's Speed-up/Rebroadcast: a note
/// composed with a custom (non-self) change address persists it on the
/// record (`NoteRecord.change_to`) specifically so RBF/rebroadcast keep
/// classifying it correctly — without this, a bumped/rebroadcast note's
/// custom-change output would wrongly read "other" (foreign) and trip the
/// paranoid warning on every legitimate replacement. Sweep/consolidate
/// records have no custom-change concept, so `None` for those.
fn stored_record_expected_change(st: &State, ref_id: &str, is_note: bool) -> Option<String> {
    if !is_note {
        return None;
    }
    st.store.as_ref()?.notes.iter().find(|n| n.note_id == ref_id)?.change_to.clone()
}

/// Decode a raw signed tx's txid + vsize directly (no `ConfirmCtx` needed)
/// — used by the rebroadcast path, which has the raw hex in hand (cached
/// or freshly fetched) but no build-time `NoteTx`/`finalize_extract`
/// result to read them from. `None` on malformed hex; the caller falls
/// back to empty/zero, and `show_confirm`'s own decode will independently
/// (and honestly) fail too.
fn decode_txid_vsize(raw_hex: &str) -> Option<(String, usize)> {
    let bytes = hex::decode(raw_hex.trim()).ok()?;
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes).ok()?;
    Some((tx.compute_txid().to_string(), tx.vsize()))
}

/// Populate the universal confirm screen (26) from a signed raw tx +
/// [`app_core::confirm::ConfirmCtx`], and stash `pending` for the
/// Broadcast/Cancel taps. `summarize_signed_tx` decodes `pending.raw_hex`
/// itself (the paranoid byte-truth rule); `ctx` only supplies lookups. On a
/// decode error, sets `status` and does NOT navigate — the caller stays
/// wherever it was (compose/sign/etc).
fn show_confirm(w: &AppWindow, st: &mut State, pending: PendingBroadcast, ctx: app_core::confirm::ConfirmCtx) {
    let sum = match app_core::confirm::summarize_signed_tx(&pending.raw_hex, &ctx) {
        Ok(s) => s,
        Err(e) => {
            println!("cb: confirm summarize err={e}");
            w.set_status(format!("confirm: {e}").into());
            return;
        }
    };
    let to_rows = |rows: &[app_core::confirm::SummaryRow]| -> Vec<PsbtRow> {
        rows.iter()
            .map(|r| PsbtRow {
                title: r.title.clone().into(),
                subtitle: r.subtitle.clone().into(),
                amount: r.amount.clone().into(),
                kind: r.kind.clone().into(),
            })
            .collect()
    };
    w.set_confirm_inputs(VecModel::from_slice(&to_rows(&sum.inputs)));
    w.set_confirm_outputs(VecModel::from_slice(&to_rows(&sum.outputs)));
    w.set_confirm_note(ctx.note_preview.clone().unwrap_or_default().into());
    w.set_confirm_fee_line(sum.fee_line.clone().into());
    w.set_confirm_locktime_line(sum.lock_time_line.clone().into());
    w.set_confirm_warn(sum.warn.clone().unwrap_or_default().into());
    w.set_confirm_txid(sum.txid.clone().into());
    w.set_confirm_context(pending.context.clone().into());
    println!(
        "cb: confirm show kind={} txid={} fee={} vsize={} inputs={} outputs={} lock_time={} warn={}",
        pending.kind,
        sum.txid,
        sum.fee.map(|f| f.to_string()).unwrap_or_else(|| "?".to_string()),
        sum.vsize,
        sum.inputs.len(),
        sum.outputs.len(),
        sum.lock_time,
        i32::from(sum.warn.is_some()),
    );
    let return_screen = w.get_screen();
    w.set_status("".into());
    st.pending_broadcast = Some(PendingBroadcast { return_screen, ..pending });
    w.set_screen(26);
}

/// Stage A for a wallet-level sweep (screen 16, `sweep-kind == "sweep"`,
/// keyed self-paid — `on_sweep_send`'s tail): gathers every active
/// notebook's coins (+ the spending wallet's, mixed-sweep style) exactly
/// as the old `on_sweep` modal handler did, builds + signs the multi-key
/// tx, then hands off to the universal confirm screen instead of
/// broadcasting immediately. The sweep destination is passed as
/// `ConfirmCtx.recipient` (no name) so it classifies "recipient" even
/// when it happens to be a foreign address — the paranoid "other"
/// tripwire is reserved for an address NOBODY chose, so a legitimate
/// sweep doesn't cry wolf on every tap. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Sweep`) is the pre-existing
/// `SWEEP_BROADCAST_RESULTS` thread-spawn, moved verbatim.
fn build_sweep_confirm(w: &AppWindow, s: &mut State, dest: String, rate: f64) {
    let net = s.network;
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        return; // caller already routes watch identities to watch_spend_build
    }
    if s.base_url().is_none() {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    }
    let Ok(recipient) = Recipient::parse(net, &dest) else {
        w.set_status(format!("not a valid {} address", net.as_str()).into());
        return;
    };
    let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
        return;
    };
    let Ok(material) = parse_key_material(&material_str, net) else { return };
    let mut idents: Vec<(
        u32,
        app_core::notes_core::bundle::Identity,
        Vec<app_core::notes_core::tx::Utxo>,
        String,
    )> = Vec::new();
    if let Some(ix) = &s.notebooks {
        for m in ix.active(s.account) {
            let Some(store) = notebook_store(s, m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            let Ok(ident) = realize(&material, net, s.account, m.index) else { continue };
            let addr = ident.address.clone();
            let Some(full) = ident.full().map(|i| i.clone_fields()) else { continue };
            idents.push((m.index, full, coins, addr));
        }
    }
    // CHANGE 2: gather the spending wallet's coins too — UNLESS this
    // sweep's destination IS the spending wallet's own next receive
    // address (`on_spending_sweep_here`), where including them would
    // sweep the spending wallet into itself.
    let spending_coins_for_sweep: Vec<FundingUtxo> = if s.pending_spending_sweep_index.is_none()
        && s.spending_capable
        && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
    {
        s.spending_coins.clone()
    } else {
        Vec::new()
    };
    // Taproot CHANGE-chain coins (unit 6, see
    // `../PLAN-chain-notes-app-taproot-change.md`): same account, chain 1
    // instead of the notebooks' chain 0. Grouped by unique chain-1 index
    // (mirrors the `idents` loop above) so each owner's OWN tweaked key
    // signs exactly its own inputs — `realize_change` is the chain-1
    // sibling of `realize`, same `output_x`/`full()` accessors. Each
    // coin's display-hex `txid` is decoded + reversed into notes-core's
    // internal byte order, the same conversion `Store::available_utxos`
    // does for notebook coins.
    let mut change_idents: Vec<(
        u32,
        app_core::notes_core::bundle::Identity,
        Vec<app_core::notes_core::tx::Utxo>,
        Vec<app_core::chain::ChangeCoin>,
    )> = Vec::new();
    {
        let mut seen_idx: Vec<u32> = Vec::new();
        for c in &s.change_coins {
            if seen_idx.contains(&c.index) {
                continue;
            }
            seen_idx.push(c.index);
            let Ok(owner) = realize_change(&material, net, s.account, c.index) else { continue };
            let Some(full) = owner.full().map(|i| i.clone_fields()) else { continue };
            let raw: Vec<app_core::chain::ChangeCoin> =
                s.change_coins.iter().filter(|x| x.index == c.index).cloned().collect();
            let utxos: Vec<app_core::notes_core::tx::Utxo> = raw
                .iter()
                .filter_map(|x| {
                    let mut txid = [0u8; 32];
                    hex::decode_to_slice(&x.txid, &mut txid).ok()?;
                    txid.reverse();
                    Some(app_core::notes_core::tx::Utxo { txid, vout: x.vout, value: x.value })
                })
                .collect();
            if utxos.is_empty() {
                continue; // a coin whose txid failed to decode — should not happen; skip defensively
            }
            change_idents.push((c.index, full, utxos, raw));
        }
    }
    if idents.is_empty() && spending_coins_for_sweep.is_empty() && change_idents.is_empty() {
        w.set_status("nothing to sweep".into());
        return;
    }
    let mut all_inputs: Vec<app_core::store::TxInput> = Vec::new();
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    let notebook_locks: Vec<(u32, Vec<(String, u32)>)> = idents
        .iter()
        .map(|(index, _, coins, addr)| {
            let name = s.notebook_display_name(*index);
            let source = format!("Notebook · {name}");
            let locks: Vec<(String, u32)> = coins
                .iter()
                .map(|u| {
                    let mut t = u.txid;
                    t.reverse();
                    let txid_hex = hex::encode(t);
                    all_inputs.push(app_core::store::TxInput {
                        txid: txid_hex.clone(),
                        vout: u.vout,
                        value: u.value,
                    });
                    prevouts.insert(
                        format!("{txid_hex}:{}", u.vout),
                        app_core::confirm::PrevoutInfo {
                            value: u.value,
                            address: Some(addr.clone()),
                            source: source.clone(),
                        },
                    );
                    (txid_hex, u.vout)
                })
                .collect();
            (*index, locks)
        })
        .collect();
    // Fold in the change-chain owners' inputs (unit 6): same all_inputs/
    // prevouts bookkeeping as the notebook loop above, tagged "Change"
    // instead of "Notebook · <name>" (change coins don't belong to any one
    // notebook — see `update_wallet_coins`). No lock-list is needed here:
    // like the notebook path, coins are only removed from the runtime
    // cache in `apply_sweep_broadcast_result` AFTER a successful
    // broadcast (see `change_spent` below), matching the existing
    // pre-confirm timing exactly.
    for (_, _, _, raw) in &change_idents {
        for c in raw {
            all_inputs.push(app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value });
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Change".to_string(),
                },
            );
        }
    }
    let change_spent: Vec<(String, u32)> = change_idents
        .iter()
        .flat_map(|(_, _, _, raw)| raw.iter().map(|c| (c.txid.clone(), c.vout)))
        .collect();
    let dest_spk_hex = hex::encode(&recipient.spk);
    // `spending_included` decides which notes-core builder runs (whether
    // spending-wallet P2WPKH coins ride along) — independent of change
    // coins, which are taproot key-path just like notebook coins and slot
    // into EITHER builder's all-taproot source list unchanged.
    let spending_included = !spending_coins_for_sweep.is_empty();
    let has_change = !change_idents.is_empty();
    // Mixed record: no per-input owner scheme covers notebook, change-
    // chain, AND spending-wallet inputs together, so it can't be
    // RBF-bumped — see CHANGE 2 / TxRecord.mixed_inputs. Change coins
    // ALSO force non-bumpable even with no spending-wallet coins involved:
    // `TxRecord.input_indexes` only carries chain-0 receive-notebook
    // indexes, so a bump could never re-derive a chain-1 leaf from it —
    // marking it non-bumpable is the safe v1 (rebroadcast still works). A
    // pure-notebook sweep (no change, no spending) keeps its owners
    // (bumpable, unchanged).
    let mixed = spending_included || has_change;
    let input_indexes: Vec<u32> = if mixed {
        Vec::new()
    } else {
        idents.iter().flat_map(|(a, _, coins, _)| std::iter::repeat(*a).take(coins.len())).collect()
    };
    let spending_spent: Vec<(String, u32)> =
        spending_coins_for_sweep.iter().map(|c| (c.txid.clone(), c.vout)).collect();
    if mixed {
        for c in &spending_coins_for_sweep {
            all_inputs.push(app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value });
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Spending wallet".to_string(),
                },
            );
        }
    }
    let sweep: Result<app_core::notes_core::tx::NoteTx, String> = if spending_included {
        let mut notebook_sources: Vec<app_core::mixed::NotebookSweepSource> = idents
            .iter()
            .map(|(_, id, coins, _)| app_core::mixed::NotebookSweepSource {
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
                utxos: coins,
            })
            .collect();
        notebook_sources.extend(change_idents.iter().map(|(_, id, utxos, _)| {
            app_core::mixed::NotebookSweepSource {
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
                utxos,
            }
        }));
        app_core::mixed::build_wallet_sweep_mixed(
            &notebook_sources,
            Some((&material, net, s.account, &spending_coins_for_sweep)),
            recipient.spk.clone(),
            rate,
            s.effective_lock_time(),
        )
        .map_err(|e| format!("{e}"))
    } else {
        let mut sources: Vec<app_core::notes_core::tx::SweepSource> = idents
            .iter()
            .map(|(_, id, coins, _)| app_core::notes_core::tx::SweepSource {
                utxos: coins,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            })
            .collect();
        sources.extend(change_idents.iter().map(|(_, id, utxos, _)| {
            app_core::notes_core::tx::SweepSource {
                utxos,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            }
        }));
        app_core::notes_core::tx::build_sweep_tx_multi(
            &sources,
            recipient.spk.clone(),
            rate,
            s.effective_lock_time(),
            app_core::notes_core::keys::generate_aux_rand,
        )
        .map_err(|e| format!("{e}"))
    };
    match sweep {
        Ok(tx) => {
            let snap = SweepSnapshot {
                identity_addr: s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
                dest: dest.clone(),
                dest_spk_hex,
                value: tx.tx.outputs[0].value,
                fee: tx.fee,
                vsize: tx.vsize as u64,
                raw_hex: tx.raw_hex.clone(),
                notebook_locks,
                all_inputs,
                input_indexes,
                mixed,
                spending_spent,
                pending_spending_sweep_index: s.pending_spending_sweep_index,
                notebooks_n: idents.len(),
                change_spent,
            };
            let (self_spks, spending_spks) = confirm_self_spks(s);
            let ctx = app_core::confirm::ConfirmCtx {
                network: app_core::derive::btc_network(net),
                prevouts,
                self_spks,
                spending_spks,
                expected_change: None,
                recipient: Some(dest.clone()),
                recipient_name: None,
                recipients: Vec::new(),
                note_preview: None,
                tip_height: s.confirm_tip_height(),
            };
            let pending = PendingBroadcast {
                kind: "sweep",
                raw_hex: tx.raw_hex.clone(),
                txid: tx.txid_hex.clone(),
                vsize: tx.vsize,
                context: format!("Sweep to {}… · {}", &dest[..14.min(dest.len())], net.as_str()),
                return_screen: 16, // overwritten by show_confirm
                payload: PendingPayload::Sweep { snap },
            };
            show_confirm(w, s, pending, ctx);
        }
        Err(e) => w.set_status(format!("sweep: {e}").into()),
    }
}

/// Stage A for a single-notebook consolidate (screen 16, `sweep-kind ==
/// "consolidate"`, keyed self-paid — `on_sweep_send`'s tail): build + sign
/// exactly as the old `on_consolidate` modal handler did, then hand off to
/// the universal confirm screen instead of broadcasting. The destination
/// is our own address (already in `confirm_self_spks`'s set), so no
/// `ConfirmCtx.recipient` is needed. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Consolidate`) is the
/// pre-existing thread-spawn, moved verbatim.
fn build_consolidate_confirm(w: &AppWindow, s: &mut State, rate: f64) {
    let net = s.network;
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        return; // caller already routes watch identities to watch_spend_build
    }
    if s.base_url().is_none() {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    }
    let Some(self_addr) = s.ident.as_ref().map(|i| i.address.clone()) else { return };
    let Ok(me) = Recipient::parse(net, &self_addr) else { return };
    let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
        w.set_status("no identity".into());
        return;
    };
    let nb_index = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
    let name = s.notebook_display_name(nb_index);
    let Some(store) = s.store.as_mut() else { return };
    if store.available_utxos().len() < 2 {
        w.set_status("nothing to consolidate (need 2+ coins)".into());
        return;
    }
    let inputs = spendable_inputs(store);
    let dest_spk_hex = hex::encode(&me.spk);
    let tx = app_core::notes_core::tx::build_sweep_tx(
        &store.available_utxos(),
        &identity.output_x,
        me.spk.clone(),
        rate,
        s.effective_lock_time(),
        &identity.tweaked_seckey,
        app_core::notes_core::keys::generate_aux_rand,
    );
    match tx {
        Ok(tx) => {
            let snap = ConsolidateSnapshot {
                identity_addr: self_addr.clone(),
                value: tx.tx.outputs[0].value,
                fee: tx.fee,
                vsize: tx.vsize as u64,
                raw_hex: tx.raw_hex.clone(),
                dest_spk_hex,
                inputs: inputs.clone(),
            };
            let prevouts = labeled_prevouts(&inputs, Some(&self_addr), &format!("Notebook · {name}"));
            let (self_spks, spending_spks) = confirm_self_spks(s);
            let ctx = app_core::confirm::ConfirmCtx {
                network: app_core::derive::btc_network(net),
                prevouts,
                self_spks,
                spending_spks,
                expected_change: None,
                recipient: None,
                recipient_name: None,
                recipients: Vec::new(),
                note_preview: None,
                tip_height: s.confirm_tip_height(),
            };
            let pending = PendingBroadcast {
                kind: "consolidate",
                raw_hex: tx.raw_hex.clone(),
                txid: tx.txid_hex.clone(),
                vsize: tx.vsize,
                context: format!("Consolidate · {}", net.as_str()),
                return_screen: 16, // overwritten by show_confirm
                payload: PendingPayload::Consolidate { snap },
            };
            show_confirm(w, s, pending, ctx);
        }
        Err(e) => w.set_status(format!("consolidate: {e}").into()),
    }
}

/// Stage A for wallet-level consolidate (account picker "wconsol" mode —
/// picking a destination row IS the trigger now, no separate confirm
/// tap): keyed identities build + sign here and hand off to the universal
/// confirm screen; watch identities are UNCHANGED (external-sign PSBT,
/// screens 13/14, copied verbatim from the old `on_wallet_consolidate`).
/// The linkage-warning caption the old confirm modal carried
/// ("One transaction spends every notebook's coins…") moves onto
/// `PendingBroadcast.context`, appended after the base context. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::WConsol`) is the pre-existing
/// thread-spawn, moved verbatim.
///
/// Deliberately uses the plain DEVICE-DEFAULT `lock_time()` throughout,
/// never `effective_lock_time()`: this flow is reached from the account
/// picker (Settings → "Consolidate wallet…"), not compose (6) or
/// sweep/consolidate (16) — nothing resets the per-tx override before it
/// runs, so consulting it here could silently leak a stale override from
/// an earlier, unrelated compose/sweep session with no UI indication.
fn build_wconsol_confirm(w: &AppWindow, s: &mut State, wc: WConsol) {
    // The picker's own job is done the moment a destination is picked —
    // reset its mode now (regardless of watch/keyed outcome below), same
    // as the old `on_wallet_consolidate` modal handler did unconditionally
    // at its top, so a later "Change account…" open isn't left in
    // "wconsol" mode.
    w.set_account_pick_mode("switch".into());
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        // Watch: ONE external-sign PSBT over every source notebook's
        // coins — each input's key origin carries its own receive index,
        // so the signer recognizes them all in one pass. The cross-store
        // bookkeeping runs post-broadcast (record_watch_spend, dest_index
        // = the picked notebook). Unchanged from the old handler.
        let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else {
            return;
        };
        let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
            Ok(r) => r.spk,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let coins: Vec<WatchCoin> = wc
            .sources
            .iter()
            .flat_map(|(index, coins, _)| {
                coins.iter().map(move |u| {
                    let mut t = u.txid;
                    t.reverse();
                    WatchCoin { txid: hex::encode(t), vout: u.vout, value: u.value, chain: 0, index: *index }
                })
            })
            .collect();
        let inputs: Vec<app_core::store::TxInput> = coins
            .iter()
            .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
            .collect();
        let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), wc.rate, s.lock_time()) {
            Ok(built) => {
                let cost = format!(
                    "consolidate · {} sats · fee {} sats · {} input{} from {} notebook{} · sign with your external wallet",
                    built.sent_to_recipient,
                    built.fee,
                    coins.len(),
                    if coins.len() == 1 { "" } else { "s" },
                    wc.sources.len(),
                    if wc.sources.len() == 1 { "" } else { "s" }
                );
                s.watch_note = None;
                s.watch_spend = Some(WatchSpend {
                    kind: "consolidate",
                    dest: wc.dest_addr.clone(),
                    dest_spk_hex: hex::encode(&dest_spk),
                    value: built.sent_to_recipient,
                    fee: built.fee,
                    inputs,
                    input_indexes,
                    dest_index: Some(wc.dest_index),
                    bump_ref: None,
                    change_spent: Vec::new(), // wconsol sources are notebook coins only (chain 0)
                });
                println!(
                    "cb: wallet-consolidate build txid={} coins={} notebooks={} fee={}",
                    built.txid,
                    coins.len(),
                    wc.sources.len(),
                    built.fee
                );
                show_psbt_sign_screen(w, s, built, cost);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
        return;
    }
    let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
        return;
    };
    let Ok(material) = parse_key_material(&material_str, s.network) else { return };
    if s.base_url().is_none() {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    }
    // Realize every source's full identity; a failure aborts cleanly.
    let mut idents = Vec::new();
    for (index, coins, _) in &wc.sources {
        let ident = match realize(&material, s.network, s.account, *index) {
            Ok(i) => i,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let addr = ident.address.clone();
        let Some(full) = ident.full().map(|i| i.clone_fields()) else {
            w.set_status("wallet consolidate needs the full key".into());
            return;
        };
        idents.push((*index, full, coins.clone(), addr));
    }
    let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
        Ok(r) => r.spk,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let sources: Vec<app_core::notes_core::tx::SweepSource> = idents
        .iter()
        .map(|(_, id, coins, _)| app_core::notes_core::tx::SweepSource {
            utxos: coins,
            output_x: id.output_x,
            tweaked_seckey: &id.tweaked_seckey,
        })
        .collect();
    let built = match app_core::notes_core::tx::build_sweep_tx_multi(
        &sources,
        dest_spk.clone(),
        wc.rate,
        s.lock_time(),
        app_core::notes_core::keys::generate_aux_rand,
    ) {
        Ok(t) => t,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let mut all_inputs: Vec<app_core::store::TxInput> = Vec::new();
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    let source_locks: Vec<(u32, Vec<(String, u32)>)> = idents
        .iter()
        .map(|(index, _, coins, addr)| {
            let name = s.notebook_display_name(*index);
            let source = format!("Notebook · {name}");
            let locks: Vec<(String, u32)> = coins
                .iter()
                .map(|u| {
                    let mut t = u.txid;
                    t.reverse();
                    let txid_hex = hex::encode(t);
                    all_inputs.push(app_core::store::TxInput {
                        txid: txid_hex.clone(),
                        vout: u.vout,
                        value: u.value,
                    });
                    prevouts.insert(
                        format!("{txid_hex}:{}", u.vout),
                        app_core::confirm::PrevoutInfo {
                            value: u.value,
                            address: Some(addr.clone()),
                            source: source.clone(),
                        },
                    );
                    (txid_hex, u.vout)
                })
                .collect();
            (*index, locks)
        })
        .collect();
    let input_indexes: Vec<u32> =
        wc.sources.iter().flat_map(|(a, coins, _)| std::iter::repeat(*a).take(coins.len())).collect();
    let net = s.network;
    let snap = WConsolSnapshot {
        fp8: s.notebooks_fp8.clone().unwrap_or_default(),
        network: net,
        account: s.account,
        dest_index: wc.dest_index,
        dest_spk_hex: hex::encode(&dest_spk),
        value: built.tx.outputs[0].value,
        fee: built.fee,
        vsize: built.vsize as u64,
        raw_hex: built.raw_hex.clone(),
        source_locks,
        all_inputs,
        input_indexes,
        sources_n: wc.sources.len(),
    };
    let (mut self_spks, spending_spks) = confirm_self_spks(s);
    // The destination notebook may be freshly created (not yet an
    // "active" notebook `realize()` would find via `confirm_self_spks`)
    // — push its spk on top so it classifies "self", same rule a
    // compose's fresh change address follows.
    self_spks.push(dest_spk.clone());
    let ctx = app_core::confirm::ConfirmCtx {
        network: app_core::derive::btc_network(net),
        prevouts,
        self_spks,
        spending_spks,
        expected_change: None,
        recipient: None,
        recipient_name: None,
        recipients: Vec::new(),
        note_preview: None,
        tip_height: s.confirm_tip_height(),
    };
    let pending = PendingBroadcast {
        kind: "wconsol",
        raw_hex: built.raw_hex.clone(),
        txid: built.txid_hex.clone(),
        vsize: built.vsize,
        context: format!(
            "Consolidate wallet · {} — One transaction spends every notebook's coins — all their addresses become publicly linked on-chain.",
            net.as_str()
        ),
        return_screen: 9, // overwritten by show_confirm
        payload: PendingPayload::WConsol { snap },
    };
    show_confirm(w, s, pending, ctx);
}

/// Stage A for a Rebroadcast (`on_act_retry`), once the raw hex is in hand
/// (cached locally, or freshly fetched for a chain-recovered/watch record
/// with none cached — both sub-cases converge here): summarize + hand off
/// to the universal confirm screen. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Rebroadcast`) is the
/// pre-existing broadcast thread-spawn, moved verbatim.
fn enter_rebroadcast_confirm(w: &AppWindow, st: &mut State, ref_id: String, is_note: bool, raw_hex: String) {
    let net = st.network;
    let (txid, vsize) = decode_txid_vsize(&raw_hex).unwrap_or_default();
    let prevouts = stored_record_prevouts(st, &ref_id, is_note);
    let expected_change = stored_record_expected_change(st, &ref_id, is_note);
    let (self_spks, spending_spks) = confirm_self_spks(st);
    let ctx = app_core::confirm::ConfirmCtx {
        network: app_core::derive::btc_network(net),
        prevouts,
        self_spks,
        spending_spks,
        expected_change,
        recipient: None,
        recipient_name: None,
        recipients: Vec::new(),
        note_preview: None,
        tip_height: st.confirm_tip_height(),
    };
    let pending = PendingBroadcast {
        kind: "rebroadcast",
        raw_hex,
        txid,
        vsize,
        context: format!("Rebroadcast · {}", net.as_str()),
        return_screen: 11, // overwritten by show_confirm
        payload: PendingPayload::Rebroadcast { ref_id },
    };
    show_confirm(w, st, pending, ctx);
}

/// Put a freshly built unsigned PSBT on the sign screen (13): animated-UR
/// QR, cost line, save/copy state. Shared by external funding and the
/// watch-mode spend flows.
fn show_psbt_sign_screen(w: &AppWindow, st: &mut State, built: BuiltPsbt, cost_line: String) {
    let frames = app_core::ur::encode_psbt(&built.to_bytes(), 300);
    w.set_psbt_cost_line(cost_line.into());
    w.set_psbt_qr(qr::qr_image(&frames[0]).unwrap_or_default());
    w.set_psbt_frame_label(
        if frames.len() > 1 { format!("frame 1 / {}", frames.len()).into() } else { "".into() },
    );
    st.ur_frames = frames;
    st.built_psbt = Some(built);
    st.signed_psbt = None;
    w.set_psbt_signed(false);
    w.set_status("".into());
    w.set_screen(13);
}

/// Validate + summarize a signed PSBT into the confirmation screen.
/// Validate a signed PSBT, finalize it to raw broadcastable bytes, and hand
/// it to the universal confirm screen (kind "psbt" — external-wallet-funded
/// notes AND every watch-only spend share this path). `State.signed_psbt`/
/// `built_psbt`/`watch_note`/`watch_spend` are left exactly as before: they
/// already carry everything `on_psbt_broadcast`'s stage-B needs, untouched
/// by the confirm screen's navigation.
fn set_confirm_from_psbt(w: &AppWindow, st: &mut State, psbt: bitcoin::Psbt) {
    let Some(built) = st.built_psbt.as_ref() else {
        w.set_status("build a transaction first".into());
        return;
    };
    if let Err(e) = validate_signed(&psbt, &built.txid) {
        w.set_status(format!("{e}").into());
        return;
    }
    let Some(output_x) = st.ident.as_ref().map(|i| i.output_x()) else { return };
    // Watch spends label their destination as the recipient; the funding
    // flow labels the compose recipient + the funding wallet's change.
    let recipient_addr = match &st.watch_spend {
        Some(ws) => Some(ws.dest.clone()),
        None => st.to_address.clone(),
    };
    let change_addr = match &st.watch_spend {
        Some(_) => None,
        None => st
            .funding
            .as_ref()
            .and_then(|src| src.derive(1, st.funding_change_index).ok())
            .map(|d| d.address),
    };
    // Only used here to pull the (public) note text back out / detect
    // whether this tx carries a note at all — the OUTPUTS list itself now
    // comes from the raw-hex decode below, not this PSBT-level summary.
    let sum_ctx = SummaryContext {
        identity_output_x: output_x,
        network: st.network,
        recipient_addr: recipient_addr.as_deref(),
        change_addr: change_addr.as_deref(),
    };
    let sum = match summarize(&psbt, &sum_ctx) {
        Ok(s) => s,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let mut note_text = String::new();
    let mut has_note = false;
    for o in &sum.outputs {
        if let OutputRole::Note { text, .. } = &o.role {
            has_note = true;
            if let Some(t) = text {
                note_text = t.clone();
            }
        }
    }
    let note_preview = has_note.then(|| {
        if note_text.is_empty() { "Private note (encrypted)".to_string() } else { note_text.clone() }
    });
    // Sweep/consolidate/bump carry no OP_RETURN at all — label them from
    // `watch_spend` instead of the (note-shaped) public/private/directed
    // formula.
    let context = if has_note {
        note_context(recipient_addr.is_some(), note_text.is_empty(), st.network)
    } else {
        match &st.watch_spend {
            Some(ws) if ws.kind == "bump" => format!("Speed up · {}", st.network.as_str()),
            Some(ws) => {
                let label = match ws.kind {
                    "sweep" => "Sweep",
                    "consolidate" => "Consolidate",
                    other => other,
                };
                format!("{label} to {}", short_addr(&ws.dest))
            }
            None => format!("Transaction · {}", st.network.as_str()),
        }
    };

    // Prevout lookups straight from the PSBT's own witness_utxo — every
    // input here was funded externally (a watch identity's own coin,
    // signed off-device, or a separate funding wallet's coin), so there's
    // one source label for the whole tx: the active funding wallet's
    // label when known, else a generic "external signer".
    let source_label = active_funding_pill(st)
        .and_then(|s| s.strip_prefix("wallet:").map(str::to_string))
        .unwrap_or_else(|| "external signer".to_string());
    let btc_net = app_core::derive::btc_network(st.network);
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let wu = psbt.inputs.get(i).and_then(|pi| pi.witness_utxo.as_ref());
        let value = wu.map(|o| o.value.to_sat()).unwrap_or(0);
        let address = wu.and_then(|o| bitcoin::Address::from_script(&o.script_pubkey, btc_net).ok()).map(|a| a.to_string());
        prevouts.insert(
            format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout),
            app_core::confirm::PrevoutInfo { value, address, source: source_label.clone() },
        );
    }

    let (raw, txid, vsize) = match finalize_extract(psbt.clone()) {
        Ok(x) => x,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };

    let (self_spks, spending_spks) = confirm_self_spks(st);
    let recipient_name = recipient_addr.as_deref().and_then(|a| {
        st.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
    });
    let confirm_ctx = app_core::confirm::ConfirmCtx {
        network: btc_net,
        prevouts,
        self_spks,
        spending_spks,
        expected_change: change_addr,
        recipient: recipient_addr,
        recipient_name,
        recipients: Vec::new(),
        note_preview,
        tip_height: st.confirm_tip_height(),
    };

    st.signed_psbt = Some(psbt);
    w.set_psbt_signed(true);
    let pending = PendingBroadcast {
        kind: "psbt",
        raw_hex: raw,
        txid,
        vsize,
        context,
        return_screen: 14, // overwritten by show_confirm
        payload: PendingPayload::Psbt,
    };
    show_confirm(w, st, pending, confirm_ctx);
}

/// Read the platform safe-area insets (converting with the window's scale
/// factor) and push them into the UI. Cheap; called on a few startup ticks
/// and a slow rotation poll. No-op on desktop (insets are 0).
fn apply_safe_area(win: &AppWindow) {
    let scale = win.window().scale_factor();
    let (top, bottom) = platform::safe_area_insets(scale);
    if (win.get_safe_top() - top).abs() > 0.5 || (win.get_safe_bottom() - bottom).abs() > 0.5 {
        println!("cb: safe-area top={top:.1} bottom={bottom:.1} scale={scale:.2}");
    }
    win.set_safe_top(top);
    win.set_safe_bottom(bottom);
    // Reveal the UI once the inset is known — immediately on desktop (no
    // insets), or as soon as a mobile window reports a real top inset. Until
    // then a splash cover hides the content so it never visibly slides down
    // from under the status bar on cold start.
    if !platform::has_insets() || top > 0.0 {
        win.set_ready(true);
    }
}

/// Shared entry point. The desktop/iOS bin calls this from `fn main`;
/// the Android cdylib calls it from `android_main` after Slint's
/// android backend is initialized.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--spike") {
        let result = match args.get(2).map(String::as_str) {
            Some("keychain") => keychain::spike(),
            Some("keychain-auth") => keychain::spike_auth(),
            // Crash-safe two-phase write (H1). The plain one is
            // automation-safe; `-auth` prompts and is human-run.
            #[cfg(target_vendor = "apple")]
            Some("keychain-atomic") => keychain::spike_atomic(),
            #[cfg(target_vendor = "apple")]
            Some("keychain-atomic-auth") => keychain::spike_atomic_auth(),
            #[cfg(target_vendor = "apple")]
            Some("file-protection") => platform::spike_file_protection(),
            #[cfg(target_os = "macos")]
            Some("clipboard") => platform::spike_clipboard(),
            Some("camera") => {
                camera::spike(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15))
            }
            other => Err(format!("unknown spike {other:?}")),
        };
        if let Err(e) = result {
            eprintln!("cb: spike err={e}");
            std::process::exit(1);
        }
        return;
    }
    // Headless design preview: `--render <out-dir> <screen>[,<screen>...]`
    // renders each screen to a PNG via the software renderer (no window).
    // macOS-only dev tool (the software renderer isn't in the mobile builds).
    #[cfg(target_os = "macos")]
    {
        if args.get(1).map(String::as_str) == Some("--render") {
            let out_dir = args.get(2).cloned().unwrap_or_else(|| ".".into());
            let screens: Vec<i32> = args
                .get(3)
                .map(|s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect())
                .unwrap_or_else(|| vec![6, 12, 13, 26]);
            render_previews(480, 900, &screens, &out_dir);
            return;
        }
    }

    let data_dir = std::env::var("APP_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("Library/Application Support/ChainNotes")
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
    let window = AppWindow::new().expect("window");
    // iCloud UI is Apple-only; Android's keystore is device-bound.
    window.set_apple_platform(cfg!(target_vendor = "apple"));
    window.set_desktop_platform(cfg!(target_os = "macos"));
    window.set_biometric_name(
        if cfg!(target_os = "ios") {
            "Face ID"
        } else if cfg!(target_os = "android") {
            "biometrics"
        } else {
            "Touch ID"
        }
        .into(),
    );
    // Back-chevron optical nudge: Roboto's line box differs from the Apple
    // system font's, so Android gets its own calibrated value (see the
    // Metrics global in app.slint; Apple platforms keep the -1.25px default).
    #[cfg(target_os = "android")]
    window.global::<Metrics>().set_back_dy(1.5);

    // EditOps: UTF-8 byte-offset text helpers + platform clipboard for the
    // EditField/EditArea widgets (offsets come from TextInput's cursor API
    // and are always char boundaries; clamp defensively anyway).
    {
        fn clamp_boundary(t: &str, mut i: usize) -> usize {
            i = i.min(t.len());
            while i > 0 && !t.is_char_boundary(i) {
                i -= 1;
            }
            i
        }
        fn range(t: &str, s: i32, e: i32) -> (usize, usize) {
            let s = clamp_boundary(t, s.max(0) as usize);
            let e = clamp_boundary(t, e.max(0) as usize);
            (s.min(e), s.max(e))
        }
        let is_word = |c: char| c.is_alphanumeric() || c == '_';
        let ops = window.global::<EditOps>();
        ops.on_slice(|t, s, e| {
            let (s, e) = range(t.as_str(), s, e);
            t.as_str()[s..e].into()
        });
        ops.on_splice(|t, s, e, ins| {
            let (s, e) = range(t.as_str(), s, e);
            let mut out = String::with_capacity(t.len() + ins.len());
            out.push_str(&t.as_str()[..s]);
            out.push_str(ins.as_str());
            out.push_str(&t.as_str()[e..]);
            out.into()
        });
        ops.on_byte_len(|t| t.len() as i32);
        ops.on_word_start(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            // if the char at the offset isn't a word char, try the one before
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                return i as i32;
            }
            while let Some(c) = t[..i].chars().next_back() {
                if is_word(c) {
                    i -= c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_word_end(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                // not on a word: select the single char under the cursor (if any)
                if let Some(c) = t[i..].chars().next() {
                    return (i + c.len_utf8()) as i32;
                }
                return i as i32;
            }
            while let Some(c) = t[i..].chars().next() {
                if is_word(c) {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_clip_set(|t| {
            let ok = platform::set_clipboard_text(t.as_str());
            println!("cb: edit-clip-set bytes={} ok={ok}", t.len());
        });
        ops.on_clip_get(|| {
            let t = platform::clipboard_text().unwrap_or_default();
            println!("cb: edit-clip-get bytes={}", t.len());
            t.into()
        });
        #[cfg(any(target_os = "ios", target_os = "android"))]
        ops.set_touch(true);
        #[cfg(target_os = "ios")]
        ops.set_ios(true);
    }

    // Boot identity: APP_KEY env (dev/tests) or the keychain.
    //
    // **THE LAUNCH PATH NEVER UNLOCKS THE KEYCHAIN.** `load_secret_protected`
    // on a UserPresence item makes the OS put up Face ID and BLOCKS this
    // thread until the user answers — on the launch path that is a hung
    // launch, and iOS kills the app (black screen → `0x8badf00d`). It is the
    // same rule the post-first-frame network sync below already follows, and
    // it is invisible under Xcode/devicectl because those relax the watchdog:
    // only a home-screen tap shows it. Reported from TestFlight on build 42
    // ("something is blocking a smooth launch, then it asked for Face ID"),
    // though the call has been on this path since 2026-07-09 — it stayed
    // hidden while iCloud backup was on, since a synced item carries no ACL
    // and so never prompts.
    //
    // So boot only PROBES (attributes only, no prompt). What happens next:
    //   - no saved key            → onboarding, exactly as before
    //   - saved key, auto_unlock  → unlock AFTER the first frame (deferred)
    //   - saved key, not opted in → onboarding shows the "Restore saved key"
    //                               door; Face ID fires on that TAP, which is
    //                               user-initiated and can't trip a watchdog
    {
        let mut s = st.borrow_mut();
        let material = match std::env::var("APP_KEY") {
            Ok(k) => Some(k),
            Err(_) => {
                // NOT EVEN A PROBE ON THIS THREAD. `identity_exists` looked
                // safe — attributes only, never kSecReturnData — and was not:
                // SecItemCopyMatching evaluates an item's access control to
                // decide whether it MATCHES, so a UserPresence item drags in
                // LAContext and blocks on XPC. That killed build 44 at launch,
                // in the very code added to stop build 42 doing the same
                // thing. `item_exists` now forbids the auth UI so it answers
                // immediately, but the probe ALSO moved off this thread:
                // after being wrong twice about what blocks, the launch path
                // gets to make no keychain calls at all.
                println!("cb: boot auto-unlock={}", u8::from(s.auto_unlock));
                None
            }
        };
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    // APP_KEY boots (automation, dev) name their notebook via
                    // APP_ACCOUNT/APP_INDEX/config — that's an explicit
                    // choice, so it counts as deliberate notebook creation.
                    // Keychain boots never auto-create: the index is whatever
                    // onboarding and the user left behind.
                    if std::env::var("APP_KEY").is_ok() {
                        let index = s.nb_index;
                        ensure_notebook(&mut s, index);
                    }
                    // The notebook list is the main screen; the active
                    // notebook's home is one tap in.
                    update_home(&window, &s);
                    update_notebook_list(&window, &s);
                    window.set_screen(17);
                    // Initial sync AFTER the first frame. Blocking the launch
                    // path on network I/O gets the app killed by the iOS
                    // launch watchdog (black screen, then 0x8badf00d) when
                    // started from the home screen — devicectl/Xcode launches
                    // relax the watchdog, which masked this. A single-shot
                    // timer lets winit attach the scene and paint first; the
                    // sync itself stays synchronous, same as a manual ↻.
                    let w = window.as_weak();
                    let st_boot = st.clone();
                    slint::Timer::single_shot(std::time::Duration::from_millis(300), move || {
                        if let Some(win) = w.upgrade() {
                            let mut s = st_boot.borrow_mut();
                            refresh_async(&win, &mut s);
                            // CHANGE 5: boot is an activate()-then-refresh
                            // site too — without this, the spending cache
                            // stays empty until something else triggers a
                            // scan (Settings, or opening compose).
                            spending_refresh_async(&win, &mut s);
                        }
                    });
                }
                Err(e) => window.set_status(format!("stored key failed: {e}").into()),
            }
        } else if s.auto_unlock {
            // Opted in already, so don't ask again — but still AFTER the first
            // frame. "Automatic" must never mean "during launch": the Face ID
            // prompt blocks, and a user who looks away long enough would be
            // right back at the watchdog kill this whole change exists to fix.
            // OFF the main thread, and only after the first frame. Deferring
            // alone is NOT enough: the crash log for build 42 shows the
            // watchdog budget that ran out is `process-launch`, 20 s of WALL
            // CLOCK — so a main-thread Face ID prompt that the user is slow to
            // answer can still exhaust it even once the UI is up. On a worker
            // thread nothing the user does can block the main thread, so the
            // watchdog cannot fire no matter how long they take. (The system
            // presents the prompt itself; it needs nothing from us.) The
            // result comes back through UNLOCK_RESULT + `apply-pending-unlock`,
            // the same trampoline shape the async scans use.
            let w = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
                let weak = w.clone();
                std::thread::spawn(move || {
                    let r = keychain::load_secret_protected(
                        KEYCHAIN_ACCOUNT,
                        "unlock your Chain Notes identity",
                    );
                    *UNLOCK_RESULT.lock().expect("unlock result mutex") = Some(r);
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_unlock());
                });
            });
        } else {
            // Not opted in: we still need to know whether to offer the
            // "Restore saved key" door — but off the main thread and after the
            // first frame, same reasoning. The door just appears a moment
            // after onboarding paints.
            let w = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
                let weak = w.clone();
                std::thread::spawn(move || {
                    let found = keychain::identity_exists(KEYCHAIN_ACCOUNT);
                    println!("cb: probe saved-key={}", u8::from(found));
                    // Window-only: no State borrow crosses the thread.
                    let _ = weak.upgrade_in_event_loop(move |w| w.set_saved_key_present(found));
                });
            });
        }
    }

    // iCloud state: (a) whether iCloud is available at all (gates the "Back up
    // to iCloud" affordance + its default-on), (b) whether a synced backup
    // already exists (offers a restore door in onboarding). For an EXISTING
    // stored key the toggle reflects that key's real sync state; for a fresh
    // install it defaults ON when iCloud is available.
    {
        let mut s = st.borrow_mut();
        let synced = keychain::is_synced(KEYCHAIN_ACCOUNT);
        let icloud_avail = keychain::icloud_available();
        let has_key = s.material.is_some();
        s.icloud_backup = if has_key { synced } else { icloud_avail };
        window.set_icloud_backup(s.icloud_backup);
        window.set_icloud_enabled(icloud_avail); // iCloud usable for new backups
    }

    // First-run disclaimer gate: before anything else, a fresh install (or an
    // upgrade that predates the gate) must accept the terms. The key/notebook
    // state was already loaded above, so accepting just reveals the screen the
    // boot would otherwise have shown (list if a key exists, else onboarding).
    window.set_disclaimer_body(DISCLAIMER.into());
    if !st.borrow().terms_accepted {
        window.set_terms_accept_mode(true);
        window.set_screen(24);
    }

    // System back (Android): the ui-side nav-back() already navigated; this
    // just emits the log-contract line (screen = where back landed us). No
    // state borrow — nav-back may have gone through a state-borrowing
    // callback (go-home etc.) synchronously before this fires.
    window.on_back_logged(|handled, screen| {
        println!("cb: sys-back handled={handled} screen={screen}");
    });

    macro_rules! cb {
        ($name:ident, |$w:ident, $s:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let st = st.clone();
            let weak = window.as_weak();
            window.$name(move |$($arg : $ty),*| {
                let $w = weak.unwrap();
                let mut $s = st.borrow_mut();
                $body
            });
        }};
    }

    // Onboarding's "Restore saved key" door. This is the ONLY place a user
    // meets the Face ID prompt for the stored key on a cold start, and it is
    // reached by a tap — so it can block for as long as it likes.
    // Written out rather than via cb!: that macro takes a State borrow for the
    // whole body, and this body sits on a Face ID prompt that can last as long
    // as the user does. Borrow only AFTER the prompt returns.
    {
        let st_restore = st.clone();
        let weak = window.as_weak();
        window.on_restore_saved_key(move || {
            let w = weak.unwrap();
            println!("cb: restore-saved-key");
            if let Some(m) = read_saved_material(&w) {
                let mut s = st_restore.borrow_mut();
                activate_restored(&w, &mut s, m, true); // onboarding exit
            }
        });
    }

    cb!(on_door_import, |w, s| {
        println!("cb: door=import");
        w.set_import_feedback("".into());
        // Default the iCloud backup ON for the imported key when iCloud is
        // available (parity with create; the toggle stays user-overridable).
        let avail = keychain::icloud_available();
        s.icloud_backup = avail;
        w.set_icloud_backup(avail);
        w.set_icloud_enabled(avail);
        w.set_screen(1);
    });

    cb!(on_door_create, |w, s, words: i32| {
        println!("cb: door=create words={words}");
        match generate_mnemonic(words as usize) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    // TEST ONLY (env-gated): lets the UI e2e complete the
                    // backup quiz. Never set outside automation.
                    println!("cb-test: words={phrase}");
                }
                w.set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
                // New key on an online device → default the iCloud backup ON
                // when iCloud is available (the user can still turn it off).
                let avail = keychain::icloud_available();
                s.icloud_backup = avail;
                w.set_icloud_backup(avail);
                w.set_icloud_enabled(avail);
                w.set_screen(2);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    // "New words" (↻) on the backup screen: reroll a fresh mnemonic of the same
    // length, in case the user didn't like the ones shown.
    cb!(on_regenerate_words, |w, s| {
        let count = s
            .pending_mnemonic
            .as_ref()
            .map(|m| m.split(' ').count())
            .unwrap_or(12);
        let salt = w.get_entropy_salt().to_string();
        match generate_mnemonic_with_salt(count, &salt) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    println!("cb-test: words={phrase}");
                }
                println!("cb: regenerate-words count={count}");
                w.set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    // iCloud backup toggle (backup screen + Settings). Sets the sync mode; if a
    // key is already stored this session, re-stores it with the new mode.
    cb!(on_set_icloud_backup, |w, s, enabled: bool| {
        s.icloud_backup = enabled;
        println!("cb: set-icloud-backup {enabled}");
        if let Some(material) = s.material.clone() {
            match keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material.trim(), enabled) {
                Ok(()) => {
                    // Re-stored under a new sync mode — still a saved key.
                    s.saved_key_present = true;
                    w.set_saved_key_present(true);
                    w.set_status(
                        if enabled { "iCloud backup on" } else { "iCloud backup off" }.into(),
                    );
                }
                Err(e) => {
                    w.set_status(format!("iCloud: {e}").into());
                    s.icloud_backup = !enabled;
                    w.set_icloud_backup(!enabled);
                }
            }
        }
    });

    // Funding-unification M3: "Separate spending wallet" toggle. Persisted
    // per (identity, account) — M3.1: in the notebooks index, shared by
    // every notebook of the account — survives restarts, resets to off on
    // a fresh identity.
    cb!(on_set_spending_enabled, |w, s, on: bool| {
        println!("cb: set-spending enabled={on}");
        if let Some(store) = s.store.as_mut() {
            store.spending_set_enabled(on);
        }
        s.save_spending();
        update_spending_ui(&w, &s);
        if on && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
    });

    cb!(on_spending_refresh, |w, s| {
        spending_refresh_async(&w, &mut s);
    });

    // "Scan for existing funds…" manual deep scan (network-efficiency
    // follow-up): gap-20 full discovery for a seed used elsewhere with gaps
    // the shallow automatic scan wouldn't reach.
    cb!(on_spending_scan_deep, |w, s| {
        spending_scan_deep_async(&w, &mut s);
    });

    // (`on_restore_icloud` lived here until 2026-07-26. A synced key is a
    // saved key — the same `load_secret_protected` call behind the same
    // onboarding door — so the separate handler only duplicated the door and
    // left different state behind. See `activate_restored`.)

    cb!(on_backup_continue, |w, s| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let count = phrase.split(' ').count();
        let mut idx = [0u8; 3];
        let _ = getrandom_fill(&mut idx);
        let mut picks: Vec<usize> = idx.iter().map(|b| (*b as usize) % count).collect();
        picks.sort();
        picks.dedup();
        while picks.len() < 3 {
            picks.push((picks.last().copied().unwrap_or(0) + 3) % count);
            picks.sort();
            picks.dedup();
        }
        if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
            println!("cb-test: quiz={} {} {}", picks[0] + 1, picks[1] + 1, picks[2] + 1);
        }
        w.set_quiz_prompt(
            format!(
                "Type words #{}, #{} and #{} (space separated):",
                picks[0] + 1,
                picks[1] + 1,
                picks[2] + 1
            )
            .into(),
        );
        s.quiz_indices = picks;
        w.set_quiz_answer("".into());
        w.set_screen(3);
    });

    cb!(on_quiz_submit, |w, s, answer: SharedString| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = s.quiz_indices.iter().map(|i| words[*i]).collect();
        let got: Vec<String> =
            answer.split_whitespace().map(|x| x.to_lowercase()).collect();
        let ok = got == expect;
        println!("cb: quiz ok={ok}");
        if !ok {
            w.set_status("mismatch — check your written words and try again".into());
            return;
        }
        // A freshly created seed is a NEW identity — start at account 0, never
        // inheriting a persisted account from a previous identity (Sal
        // 2026-07-22; config.account survives an identity reset).
        s.account = 0;
        s.nb_index = 0;
        match activate(&mut s, &phrase, true) {
            Ok(()) => {
                s.pending_mnemonic = None;
                w.set_status("".into());
                // Onboarding unification (Sal 2026-07-21, superseding the
                // 2026-07-11 empty-list rule): creating a seed behaves
                // exactly like importing one — the account's notebook 0
                // (the FIRST receive address) is created, auto-named
                // "Notebook 1", and the notebook LIST opens. More
                // notebooks are added from the list later; unwanted ones
                // archive.
                ensure_first_onboarded_notebook(&mut s);
                update_notebook_list(&w, &s);
                w.set_screen(17);
                refresh_async(&w, &mut s);
                spending_refresh_async(&w, &mut s); // CHANGE 5
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_import_changed, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if t.is_empty() {
            w.set_import_feedback("".into());
            w.set_import_suggestions("".into());
            return;
        }
        // Word autocomplete for the mnemonic path.
        let last = t.split_whitespace().last().unwrap_or("");
        let sugg = if last.len() >= 2 && last.chars().all(|c| c.is_ascii_alphabetic()) {
            let prefix = last.to_lowercase();
            let matches = bip39::Language::English.words_by_prefix(&prefix);
            if matches.len() > 1 || (matches.len() == 1 && matches[0] != last) {
                format!("… {}", matches.iter().take(6).cloned().collect::<Vec<_>>().join(" · "))
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        w.set_import_suggestions(sugg.into());
        let (fb, ok) = match parse_key_material(&t, s.network) {
            Ok(m) if is_hierarchical(&t, s.network) => {
                (format!("{} OK — you'll choose an account next", m.kind()), true)
            }
            Ok(m) => match realize(&m, s.network, 0, 0) {
                Ok(p) => {
                    let a = &p.address;
                    let label = if m.is_watch() {
                        "account xpub OK — watch-only: public notes and balance, no signing"
                    } else {
                        "OK"
                    };
                    let kind_prefix = if m.is_watch() { String::new() } else { format!("{} ", m.kind()) };
                    (format!("{kind_prefix}{label} · {}…{}", &a[..12.min(a.len())], &a[a.len().saturating_sub(6)..]), true)
                }
                Err(e) => (format!("{e}"), false),
            },
            Err(e) => (format!("{e}"), false),
        };
        w.set_import_feedback_ok(ok);
        w.set_import_feedback(fb.into());
    });

    cb!(on_import_confirm, |w, s, text: SharedString| {
        // Sal 2026-07-22: a SEED (hierarchical: mnemonic/xprv) no longer
        // branches into the account picker — it activates account 0 directly,
        // auto-creates its first notebook, and lands on the notebook LIST.
        // Single-key imports (WIF/hex) are unchanged: activate() adds their one
        // intrinsic notebook and they land on its home.
        let hierarchical = parse_key_material(text.trim(), s.network).is_ok()
            && is_hierarchical(text.trim(), s.network);
        s.account = 0;
        s.nb_index = 0;
        match activate(&mut s, text.trim(), true) {
            Ok(()) => {
                println!("cb: import ok");
                w.set_import_text("".into());
                if hierarchical {
                    ensure_first_onboarded_notebook(&mut s);
                    update_notebook_list(&w, &s);
                    w.set_screen(17);
                    refresh_async(&w, &mut s);
                    spending_refresh_async(&w, &mut s);
                } else {
                    w.set_screen(4);
                    update_home(&w, &s);
                    refresh_async(&w, &mut s);
                }
            }
            Err(e) => {
                println!("cb: import err={e}");
                w.set_import_feedback_ok(false);
                w.set_import_feedback(format!("{e}").into());
            }
        }
    });

    // Shared cancel flag for every "Scan QR" path (set by the overlay's Cancel).
    let scan_cancel = Arc::new(AtomicBool::new(false));
    {
        let sc = scan_cancel.clone();
        let weak = window.as_weak();
        window.on_cancel_scan(move || {
            sc.store(true, Ordering::Relaxed);
            if let Some(w) = weak.upgrade() {
                w.set_scanning(false);
            }
        });
    }
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_import_scan(move || {
            println!("cb: import-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point your key or SeedQR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(payload)) => match app_core::seedqr::decode(&payload) {
                        Ok(m) => m.to_string(),
                        Err(_) => String::from_utf8_lossy(&payload).to_string(),
                    },
                    Ok(None) => String::new(),
                    Err(e) => {
                        println!("cb: import-scan err={e}");
                        String::new()
                    }
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if !text.is_empty() {
                        println!("cb: import-scan ok len={}", text.len());
                        w.set_import_text(text.clone().into());
                        w.invoke_import_changed(text.into());
                    } else {
                        w.set_import_feedback_ok(false);
                        w.set_import_feedback("scan: no QR seen".into());
                    }
                });
            });
        });
    }

    // Paste from the system clipboard — Slint's iOS text fields don't surface
    // the native paste menu, so this reads UIPasteboard directly. Deferred to
    // the event loop so import-changed re-runs without a State double-borrow.
    cb!(on_paste_import, |w, s| {
        let _ = &mut s;
        match platform::clipboard_text() {
            Some(text) => {
                let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                    w.set_import_text(text.clone().into());
                    w.invoke_import_changed(text.into());
                });
            }
            None => {
                w.set_import_feedback_ok(false);
                w.set_import_feedback("clipboard empty".into());
            }
        }
    });

    // Paste into the compose note (appends clipboard to the current text).
    cb!(on_paste_compose, |w, s| {
        let _ = &mut s;
        if let Some(text) = platform::clipboard_text() {
            let combined = format!("{}{}", w.get_compose_text(), text);
            let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                w.set_compose_text(combined.clone().into());
                w.invoke_compose_changed();
            });
        }
    });

    cb!(on_import_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    println!("cb: import-file len={}", text.trim().len());
                    w.set_import_text(text.trim().into());
                    w.invoke_import_changed(text.trim().into());
                }
                Err(e) => {
                    w.set_import_feedback_ok(false);
                    w.set_import_feedback(format!("file: {e}").into());
                }
            }
        }
    });

    cb!(on_refresh, |w, s| {
        refresh_async(&w, &mut s);
    });

    // Trampoline: a finished background scan invokes this from the event
    // loop; the UI thread applies it with full State access.
    cb!(on_apply_pending_refresh, |w, s| {
        apply_refresh_results(&w, &mut s);
    });

    // Trampoline: an async compose send (notebook/spending/mixed) finished
    // building+broadcasting on a worker thread.
    cb!(on_apply_pending_compose, |w, s| {
        apply_compose_results(&w, &mut s);
    });

    // Trampoline: an Activity Rebroadcast finished on a worker thread.
    cb!(on_apply_pending_act_retry, |w, s| {
        apply_act_retry_results(&w, &mut s);
    });

    // Trampoline: `on_act_retry`'s sub-case (b) raw-hex fetch (chain-
    // recovered/watch record, no local hex) landed on a worker thread.
    cb!(on_apply_pending_rebroadcast_fetch, |w, s| {
        apply_pending_rebroadcast_fetch_results(&w, &mut s);
    });

    // Trampoline: an Activity Speed-up (RBF) broadcast finished on a worker
    // thread (the re-sign itself stays synchronous — fast, no network; only
    // the broadcast POST is async).
    cb!(on_apply_pending_act_bump, |w, s| {
        apply_act_bump_results(&w, &mut s);
    });

    // Trampoline: an async consolidate/sweep/wallet-consolidate/psbt
    // broadcast (CHANGE 4) finished on a worker thread.
    cb!(on_apply_pending_wallet_tx, |w, s| {
        apply_pending_wallet_tx_results(&w, &mut s);
    });

    // Trampoline: a finished spending-wallet scan (funding-unification M3)
    // landed — same pattern as apply-pending-refresh.
    cb!(on_apply_pending_spending_refresh, |w, s| {
        apply_spending_refresh_results(&w, &mut s);
    });

    // Trampoline: a finished wallet-wide rescan (Coins screen / notebook-
    // list ↻, watchdog fix 2026-07-20) landed — same pattern as
    // apply-pending-refresh.
    cb!(on_apply_pending_wallet_stores_refresh, |w, s| {
        apply_wallet_stores_refresh_results(&w, &mut s);
    });

    // Trampoline: an iCloud KV notification (a contacts change synced in
    // from the user's OTHER device) landed — re-merge the freshly-synced
    // blob into the live device-level contacts list and refresh the
    // picker so the change appears without restarting the app.
    cb!(on_apply_pending_icloud_contacts, |w, s| {
        apply_icloud_contacts_merge(&w, &mut s);
    });

    // Trampoline: worker-thread used/new probes for the create-notebook
    // picker landed — fill in the pills/balances without having blocked the
    // tap. Guarded by account/page/screen so a stale probe (user paged or
    // left) is dropped.
    cb!(on_apply_pending_picker_probe, |w, s| {
        let results: Vec<PickerProbeResult> =
            PICKER_PROBE_RESULTS.lock().expect("picker probe mutex").drain(..).collect();
        for r in results {
            if s.account != r.account
                || w.get_account_page() != r.page as i32
                || w.get_screen() != 9
            {
                println!("cb: picker-probe stale-drop");
                continue;
            }
            let model = w.get_accounts();
            for i in 0..model.row_count() {
                if let Some(mut row) = model.row_data(i) {
                    if let Some((_, pill, bal)) =
                        r.rows.iter().find(|(idx, ..)| *idx == row.index as u32)
                    {
                        row.pill = (*pill).into();
                        row.balance = bal.clone().into();
                        model.set_row_data(i, row);
                    }
                }
            }
        }
    });

    // Trampoline: a finished Bitcoin Core preflight check (`refresh_node_health`).
    // Dropped when stale — the network or the configured node changed since
    // the check started (e.g. the user switched networks, or edited the
    // node URL again before the first check returned).
    cb!(on_apply_pending_node_health, |w, s| {
        let results: Vec<NodeHealthResult> =
            NODE_HEALTH_RESULTS.lock().expect("node health mutex").drain(..).collect();
        for r in results {
            if s.network != r.network || s.base_url().as_deref() != Some(r.base.as_str()) {
                println!("cb: node-health stale-drop");
                continue;
            }
            w.set_node_health_text(r.text);
            w.set_node_health_warn(r.warn);
        }
    });

    // Trampoline: a finished notebook gap-discovery walk (seed re-import).
    // Discovery is the sanctioned exception to deliberate notebook
    // creation — every found index has on-chain history, so recovering it
    // is what the user meant by importing the seed.
    // Deferred auto-unlock landed. Mirrors read_saved_material's error
    // handling, but on the UI thread with the result already in hand.
    cb!(on_apply_pending_unlock, |w, s| {
        let taken = UNLOCK_RESULT.lock().expect("unlock result mutex").take();
        match taken {
            // Boot path, not onboarding: never create a notebook here.
            Some(Ok(Some(m))) => activate_restored(&w, &mut s, m, false),
            Some(Ok(None)) => {
                println!("cb: unlock none");
                s.saved_key_present = false;
                w.set_saved_key_present(false);
            }
            // Both failure branches REVEAL the door. The auto-unlock branch
            // never runs the `identity_exists` probe (it went straight for the
            // key), so `saved_key_present` is still false here — and the status
            // line tells the user to "tap Restore" on a door that isn't
            // rendered. We know an item exists: that is why we tried to unlock
            // it. (Until 2026-07-26 the separate "Restore from iCloud" door
            // accidentally covered this, but only for a SYNCED key.)
            Some(Err(e)) if e == "cancelled" => {
                // Left on onboarding with the door there, so a mis-tapped or
                // timed-out prompt is one tap from retrying.
                println!("cb: unlock cancelled");
                s.saved_key_present = true;
                w.set_saved_key_present(true);
                w.set_status("unlock cancelled — tap Restore to try again".into());
            }
            Some(Err(e)) => {
                println!("cb: unlock err={e}");
                s.saved_key_present = true;
                w.set_saved_key_present(true);
                w.set_status(format!("keychain: {e}").into());
            }
            None => {}
        }
    });

    cb!(on_apply_pending_discovery, |w, s| {
        let results: Vec<DiscoveryResult> =
            DISCOVERY_RESULTS.lock().expect("discovery results mutex").drain(..).collect();
        for r in results {
            if s.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
                || s.network != r.network
                || s.account != r.account
            {
                println!("cb: notebook-discovery stale-drop");
                continue;
            }
            let mut added = 0;
            for index in &r.found {
                if s.notebooks.as_ref().and_then(|ix| ix.get(r.account, *index)).is_none() {
                    ensure_notebook(&mut s, *index);
                    added += 1;
                }
            }
            println!("cb: notebook-discovery found={} added={added}", r.found.len());
            if added > 0 {
                update_notebook_list(&w, &s);
            }
        }
    });

    cb!(on_open_note, |w, s, id: SharedString| {
        let Some(store) = &s.store else { return };
        if let Some(n) = store.notes.iter().find(|n| n.note_id.as_str() == id.as_str()) {
            println!("cb: open-note id={} status={:?}", n.note_id, n.status);
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let detail = format!(
                "{}\n\nid: {}\nkind: {}{}{}\ntxids: {}\nheight: {}\n{}{}",
                n.text.as_deref().unwrap_or(if watch && n.private {
                    "(private — the key that reads this note isn't on this device)"
                } else {
                    "(not decryptable)"
                }),
                n.note_id,
                if n.received { "received" } else { "own" },
                if n.directed { " · directed" } else { "" },
                if n.private { " · private" } else { " · public" },
                n.txids.join(", "),
                n.height.map(|h| h.to_string()).unwrap_or_else(|| "unconfirmed".into()),
                n.sender.as_deref().map(|a| format!("from: {a}\n")).unwrap_or_default(),
                // Multi-recipient note: list EVERY recipient (one per line,
                // output order); the singular field only names the first.
                if n.recipients.is_empty() {
                    n.recipient.as_deref().map(|a| format!("to: {a}\n")).unwrap_or_default()
                } else {
                    format!("to ({}): {}\n", n.recipients.len(), n.recipients.join("\n    "))
                },
            );
            w.set_note_detail(detail.into());
            w.set_note_view_id(n.note_id.clone().into());
            w.set_note_pending(n.status == NoteStatus::Pending && n.raw_hex.is_some());
            w.set_note_txid(n.txids.last().cloned().unwrap_or_default().into());
            // Reply-all set ({sender} ∪ recipients minus me) — meaningful
            // for both a received note (sender + other recipients) and an
            // OWN directed note (a shortcut to write the same people again;
            // Sal 2026-07-19). Self-notes have an empty set → no buttons.
            let my_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let full_set = n.reply_set(&my_addr);
            // Reply = the single counterparty: the sender of a received note,
            // or the sole recipient of an own single-recipient directed note.
            // An own multi-recipient note has no single counterparty — it
            // gets Reply all only.
            let reply_addr = if n.received {
                n.sender.clone().unwrap_or_default()
            } else if full_set.len() == 1 {
                full_set[0].clone()
            } else {
                String::new()
            };
            w.set_note_reply_address(reply_addr.into());
            let reply_rows: Vec<ContactItem> = full_set
                .iter()
                .map(|a| {
                    let name = s
                        .contacts
                        .iter()
                        .find(|c| &c.address == a && !c.name.is_empty())
                        .map(|c| c.name.clone())
                        .unwrap_or_default();
                    ContactItem { address: a.clone().into(), name: name.into(), synced: false, sync_status: 0 }
                })
                .collect();
            w.set_note_reply_set(VecModel::from_slice(&reply_rows));
            let web = match s.network {
                Network::Regtest => String::new(),
                net => {
                    let addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                    format!(
                        "https://objsal.github.io/chain-notes-companion/note.html?address={addr}&network={}&note={}",
                        net.as_str(),
                        n.note_id
                    )
                }
            };
            w.set_note_web_url(web.into());
            w.set_screen(5);
        }
    });

    cb!(on_open_note_web, |w, s| {
        let _ = &mut s;
        let url = w.get_note_web_url().to_string();
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web url={url}");
        let _ = platform::open_url(&url);
    });

    cb!(on_copy_text, |w, s, kind: SharedString, text: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_text(text.as_str());
        println!("cb: copy kind={kind} len={} ok={ok}", text.len());
        let msg = if ok {
            match kind.as_str() {
                "address" => "Address copied",
                "backup-words" => "Recovery phrase copied",
                "note-text" => "Note copied",
                "txid" => "Txid copied",
                _ => "Copied",
            }
        } else {
            "Copy failed"
        };
        show_toast(&w, msg);
    });

    cb!(on_set_fee_tier, |w, s, tier: i32| {
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        w.set_fee_tier(tier);
        // Custom (tier 3, also reached by editing the always-visible rate
        // box) keeps whatever the field already holds — Rust never
        // overwrites it while tier == 3 (same rule as sweep's
        // on_set_sweep_tier), so auto-selecting custom on edit can't fight
        // the user's typing.
        if tier != 3 {
            w.set_rate_text(format!("{rate}").into());
        }
        println!("cb: fee-tier {tier} rate={rate}");
        refresh_compose(&w, &mut s);
    });

    cb!(on_open_coins, |w, s| {
        println!("cb: open-coins");
        update_home(&w, &s);
        update_spending_ui(&w, &s);
        if w.get_coins_segment() == "spending" && s.spending_capable && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
        w.set_status("".into());
        w.set_screen(10);
    });

    // Coins screen "spending" segment: scan on first view (data otherwise
    // stays "as of the last scan", matching the notebook segment's rule).
    cb!(on_set_coins_segment, |w, s, seg: SharedString| {
        w.set_coins_segment(seg.clone());
        if seg.as_str() == "spending" && s.spending_capable && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
    });

    cb!(on_open_activity, |w, s| {
        println!("cb: open-activity");
        w.set_return_screen(if w.get_screen() == 17 { 17 } else { 4 });
        update_activity(&w, &s);
        w.set_status("".into());
        w.set_screen(11);
    });

    // Universal confirm screen (2026-07-17): stage A resolves the raw hex
    // (locally cached, or fetched) and hands off to screen 26 —
    // `act_pending_ref` is no longer set here for the broadcast itself
    // (moved to stage B, `on_confirm_broadcast`/`PendingPayload::
    // Rebroadcast`, mirroring `on_act_bump_confirm` below); it's only
    // touched transiently to guard sub-case (b)'s own network fetch
    // against a double-tap, cleared the moment the fetch result lands.
    cb!(on_act_retry, |w, s, ref_id: SharedString, is_note: bool| {
        if s.act_pending_ref.is_some() || s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        let (raw, last_txid) = if is_note {
            let n = s
                .store
                .as_ref()
                .and_then(|st| st.notes.iter().find(|n| n.note_id.as_str() == ref_id.as_str()));
            (n.and_then(|n| n.raw_hex.clone()), n.and_then(|n| n.txids.last().cloned()))
        } else {
            let t = s
                .store
                .as_ref()
                .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id.as_str())));
            (t.and_then(|t| t.raw_hex.clone()), t.and_then(|t| t.txids.last().cloned()))
        };
        let ref_id_s = ref_id.to_string();
        if let Some(r) = raw.filter(|r| !r.is_empty()) {
            // Case (a): raw hex cached locally — summarize + show_confirm
            // right now, no network round trip needed.
            enter_rebroadcast_confirm(&w, &mut s, ref_id_s, is_note, r);
            return;
        }
        // Case (b): chain-recovered record (watch mode, or any record with
        // no cached hex) — the node that already knows the tx is the
        // keyless rebroadcast source. Never block the UI thread on the
        // fetch; land on the confirm screen from the fetch-result
        // trampoline (mirrors `spending_refresh_async`).
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let net = s.network;
        let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let creds = core_rpc_creds_for(&s, &base, net);
        s.act_pending_ref = Some(ref_id_s.clone());
        update_activity(&w, &s);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let client = open_client(&base, net, creds).map_err(|e| e.to_string());
            let result = last_txid
                .ok_or_else(|| "nothing to rebroadcast".to_string())
                .and_then(|t| client.and_then(|c| c.fetch_tx_hex(&t).map_err(|e| format!("{e}"))));
            REBROADCAST_FETCH_RESULTS.lock().expect("rebroadcast fetch results mutex").push(
                RebroadcastFetchResult { ref_id: ref_id_s, is_note, identity_addr, result },
            );
            let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_rebroadcast_fetch());
        });
    });

    cb!(on_act_bump_open, |w, s, ref_id: SharedString, is_note: bool| {
        // The bump dialog prices off `st.fees.fastest` — lazily (re)fetch
        // before either branch below reads it (network-efficiency,
        // 2026-07-23). `watch_bump_open` also calls this — the 60s cache
        // makes the second call here-or-there free either way.
        refresh_fees_price(&w, &mut s);
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            watch_bump_open(&w, &mut s, ref_id.to_string(), is_note);
            return;
        }
        let Some(store) = &s.store else { return };
        // CHANGE 2 defense-in-depth: the UI already hides Speed-up for a
        // mixed record (`ActivityItem.bumpable`), but refuse here too
        // rather than trust the tap origin.
        if !is_note && store.txs.iter().any(|t| t.txids.iter().any(|x| x == ref_id.as_str()) && t.mixed_inputs) {
            w.set_status("this sweep mixed notebook + spending coins — it can't be sped up (rebroadcast still works)".into());
            return;
        }
        let Some((old_rate, fee, vsize)) = tx_rate(store, ref_id.as_str(), is_note) else {
            w.set_status("can't determine current fee rate".into());
            return;
        };
        // BIP-125: the replacement must add at least 1 sat/vB (incremental
        // relay) over the original, and pay a strictly higher total fee.
        let min_rate = old_rate + 1.0;
        let fast = s.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
        let recommended = fast.max(min_rate);
        println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1}");
        w.set_bump_ref(ref_id.clone());
        w.set_bump_is_note(is_note);
        w.set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
        w.set_bump_current(format!("Currently {old_rate:.1} sat/vB · {fee} sats fee").into());
        w.set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
        w.set_bump_error("".into());
        w.set_bump_rate(format!("{recommended:.1}").into());
        w.set_bump_new_fee(new_fee_line(recommended, vsize, fee).into());
        w.set_show_bump_dialog(true);
    });

    cb!(on_act_bump_rate_changed, |w, s, rate_s: SharedString| {
        let ref_id = w.get_bump_ref().to_string();
        let is_note = w.get_bump_is_note();
        if let Some(wb) =
            s.watch_bump.as_ref().filter(|wb| wb.ref_id == ref_id && wb.is_note == is_note)
        {
            match rate_s.trim().parse::<f64>() {
                Ok(r) if r > 0.0 => w.set_bump_new_fee(new_fee_line(r, wb.vsize, wb.old_fee).into()),
                _ => w.set_bump_new_fee("".into()),
            }
            return;
        }
        let Some((_, old_fee, vsize)) = s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note))
        else {
            return;
        };
        match rate_s.trim().parse::<f64>() {
            Ok(r) if r > 0.0 => w.set_bump_new_fee(new_fee_line(r, vsize, old_fee).into()),
            _ => w.set_bump_new_fee("".into()),
        }
    });

    // Universal confirm screen (2026-07-17): the dialog stays for rate
    // entry only — its primary button ("Sign…") now BUILDS + SIGNS the
    // replacement (stage A) and hands off to screen 26 instead of
    // broadcasting directly. `act_pending_ref` moves to stage B
    // (`on_confirm_broadcast`/`PendingPayload::Bump`, the actual
    // broadcast POST) — NOT set here, so it must never gate stage A;
    // `pending_broadcast`/`wallet_tx_busy` are the re-entrancy guard for
    // the build+navigate step instead.
    cb!(on_act_bump_confirm, |w, s| {
        if s.act_pending_ref.is_some() || s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        let ref_id = w.get_bump_ref().to_string();
        let is_note = w.get_bump_is_note();
        let Ok(new_rate) = w.get_bump_rate().trim().parse::<f64>() else {
            w.set_bump_error("enter a number".into());
            return;
        };
        let net = s.network;
        if s.base_url().is_none() {
            w.set_bump_error("no Bitcoin node — set one in Settings".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            watch_bump_confirm(&w, &mut s, new_rate);
            return;
        }
        // CHANGE 2 defense-in-depth (see on_act_bump_open).
        if !is_note
            && s.store.as_ref().map(|st| st.txs.iter().any(|t| t.txids.iter().any(|x| x == &ref_id) && t.mixed_inputs)).unwrap_or(false)
        {
            w.set_bump_error("this sweep mixed notebook + spending coins — it can't be sped up".into());
            return;
        }
        let min_rate = match s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note)) {
            Some((old_rate, _, _)) => old_rate + 1.0,
            None => {
                w.set_bump_error("transaction no longer pending".into());
                return;
            }
        };
        if new_rate + 1e-9 < min_rate {
            w.set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_bump_error("no identity".into());
            return;
        };
        // Multi-key records (wallet sweep/consolidate) carry per-input
        // owners — rev-3 records list notebook INDEXES within the active
        // account (`input_indexes`); legacy records list ACCOUNTS
        // (`input_accounts`, notebook 0 implied). Re-sign each input with
        // its owner's key.
        let (owner_ids, owners_are_indexes): (Vec<u32>, bool) = s
            .store
            .as_ref()
            .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == &ref_id)))
            .map(|t| {
                if !t.input_indexes.is_empty() {
                    (t.input_indexes.clone(), true)
                } else {
                    (t.input_accounts.clone(), false)
                }
            })
            .unwrap_or_default();
        let active_account = s.account;
        // PURE builds only (zero-trace cancel): the store is not touched
        // — no txid append, no fee/raw_hex update, no ledger swap, no
        // save — until the Broadcast tap runs `record_bumped_*` in stage
        // B. Cancel on screen 26 leaves the original pending tx exactly
        // as it was.
        let result: Result<BumpedBuild, app_core::Error> = if is_note {
            app_core::compose::bump_fee_build(
                s.store.as_ref().unwrap(),
                &identity,
                net,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Note)
        } else if !owner_ids.is_empty() {
            let mut distinct = owner_ids.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let idents: Result<Vec<(u32, app_core::notes_core::bundle::Identity)>, app_core::Error> =
                s.material
                    .as_deref()
                    .ok_or_else(|| app_core::Error::Store("no key material".into()))
                    .and_then(|m| {
                        parse_key_material(m, net)
                            .map_err(|e| app_core::Error::Store(format!("{e}")))
                    })
                    .and_then(|material| {
                        distinct
                            .iter()
                            .map(|a| {
                                let (acct, idx) = if owners_are_indexes {
                                    (active_account, *a)
                                } else {
                                    (*a, 0)
                                };
                                realize(&material, net, acct, idx)
                                    .map_err(|e| app_core::Error::Store(format!("{e}")))
                                    .and_then(|i| {
                                        i.full().map(|f| (*a, f.clone_fields())).ok_or_else(|| {
                                            app_core::Error::Store("watch key can't bump".into())
                                        })
                                    })
                            })
                            .collect()
                    });
            idents.and_then(|idents| {
                app_core::compose::bump_raw_tx_multi_build(
                    s.store.as_ref().unwrap(),
                    &idents,
                    &ref_id,
                    new_rate,
                    None, // device default — no override control on the bump dialog
                )
                .map(BumpedBuild::Tx)
            })
        } else {
            app_core::compose::bump_raw_tx_build(
                s.store.as_ref().unwrap(),
                &identity,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Tx)
        };
        match result {
            Ok(bumped) => {
                let (raw, txid, fee, vsize) = match &bumped {
                    BumpedBuild::Note(c) => {
                        (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee, c.tx.vsize)
                    }
                    BumpedBuild::Tx(tx) => {
                        (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee, tx.vsize)
                    }
                };
                // NOTHING is recorded or saved here — hand the signed
                // replacement to the universal confirm screen; stage B
                // (`on_confirm_broadcast`) applies `record_bumped_*` +
                // `save_store()` at the Broadcast tap, re-arms
                // `act_pending_ref` right before the POST, and spawns the
                // SAME worker pushing `ActBumpResult`.
                w.set_show_bump_dialog(false);
                let prevouts = stored_record_prevouts(&s, &ref_id, is_note);
                let expected_change = stored_record_expected_change(&s, &ref_id, is_note);
                let (self_spks, spending_spks) = confirm_self_spks(&s);
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: s.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "bump",
                    raw_hex: raw,
                    txid,
                    vsize,
                    context: format!("Speed-up · {}", net.as_str()),
                    return_screen: 11, // overwritten by show_confirm
                    payload: PendingPayload::Bump { ref_id: ref_id.clone(), fee, new_rate, bumped },
                };
                show_confirm(&w, &mut s, pending, ctx);
            }
            Err(e) => {
                println!("cb: act-bump ref={ref_id} err={e}");
                w.set_bump_error(format!("{e}").into());
            }
        }
    });

    cb!(on_act_explorer, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = platform::open_url(url.as_str());
    });

    cb!(on_open_source, |w, s| {
        let _ = (&w, &mut s);
        println!("cb: open-source");
        let _ = platform::open_url(SOURCE_URL);
    });

    cb!(on_open_note_web_url, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web-url");
        let _ = platform::open_url(url.as_str());
    });

    cb!(on_compose_open, |w, s| {
        println!("cb: compose-open");
        w.set_pick_mode("compose".into());
        pull_icloud_contacts_on_open(&w, &mut s);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    // Send-to picker header "Sync now" (sync-status UI, 2026-07-20).
    cb!(on_sync_contacts_now, |w, s| {
        sync_contacts_now(&w, &mut s);
    });

    cb!(on_sweep_open, |w, s| {
        println!("cb: sweep-open");
        // The send-to picker's sweep entry lands on screen 16 (fee tiers
        // shown) once a destination is picked — lazily (re)fetch here so
        // it's ready by then (network-efficiency, 2026-07-23).
        refresh_fees_price(&w, &mut s);
        s.pending_spending_sweep_index = None; // a fresh manual pick, not the spending-wallet shortcut
        // A wallet sweep's inputs include spending-wallet coins — ALWAYS kick
        // a fresh scan here (not just when never-scanned). A prior scan can be
        // stale: coins may have arrived since, or gap-discovery may not have
        // reached the funded index yet, which showed ONLY notebook coins in
        // the sweep preview until the user backed out and re-entered. The scan
        // runs while the user is on the picker; apply_spending_refresh_results
        // repaints screen 16 with the spending coins when it lands.
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
        {
            spending_refresh_async(&w, &mut s);
        }
        w.set_sweep_kind("sweep".into());
        w.set_pick_mode("sweep".into());
        pull_icloud_contacts_on_open(&w, &mut s);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    // Funding-unification M3: Settings spending-wallet card "Sweep notebook
    // funds here…" — routes through the EXISTING sweep flow (screen 7 →
    // 16), just pre-picking the destination = the spending wallet's next
    // receive address. `pending_spending_sweep_index` tells on_sweep's
    // success handler to mark that address used (fresh-address discipline).
    cb!(on_spending_sweep_here, |w, s| {
        ensure_spending_source(&mut s);
        let Some(src) = s.spending_source.clone() else {
            w.set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let Some(idx) = s.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(d) = src.derive(0, idx) else { return };
        s.pending_spending_sweep_index = Some(idx);
        w.set_sweep_kind("sweep".into());
        w.set_pick_mode("sweep".into());
        set_sweep_dest(&w, &mut s, d.address);
    });

    // CHANGE 3 (2026-07-17) / universal confirm screen follow-up: the
    // Coins screen's spending segment "Consolidate spending coins…"
    // button IS the trigger now (the confirm modal is gone) — build +
    // sign the all-P2WPKH merge directly (byte-exact mixed estimator, one
    // P2WPKH output at the next fresh spending receive address) and hand
    // off to the universal confirm screen. Stage B
    // (`on_confirm_broadcast`/`PendingPayload::SpendingConsolidate`) is
    // the pre-existing thread-spawn, moved verbatim.
    cb!(on_spending_consolidate_open, |w, s| {
        if s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        // The fee rate used to build this tx comes from `s.fees.hour`
        // below — lazily (re)fetch first (network-efficiency, 2026-07-23).
        refresh_fees_price(&w, &mut s);
        ensure_spending_source(&mut s);
        let Some(src) = s.spending_source.clone() else {
            w.set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let coins = s.spending_coins.clone();
        if coins.len() < 2 {
            w.set_status("nothing to consolidate (need 2+ spending coins)".into());
            return;
        }
        if s.base_url().is_none() {
            w.set_status("no Bitcoin node for this network — set one in Settings".into());
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        let net = s.network;
        let Ok(material) = parse_key_material(&material_str, net) else { return };
        let Some(next_receive) = s.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(dest) = src.derive(0, next_receive) else {
            w.set_status("couldn't derive the destination address".into());
            return;
        };
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        let account = s.account;
        // Deliberately the device default, not `effective_lock_time()`:
        // this is the Coins screen's direct "Consolidate spending coins…"
        // shortcut, not compose (6) or sweep/consolidate (16) — nothing
        // resets the per-tx override before it runs (see
        // `build_wconsol_confirm`'s doc comment for the same reasoning).
        let built = app_core::mixed::build_wallet_sweep_mixed(
            &[],
            Some((&material, net, account, &coins)),
            dest.spk.clone(),
            rate,
            s.lock_time(),
        );
        match built {
            Ok(tx) => {
                let spent: Vec<(String, u32, u64)> =
                    coins.iter().map(|c| (c.txid.clone(), c.vout, c.value)).collect();
                let snap = SpendingConsolidateSnapshot {
                    fp8: s.notebooks_fp8.clone().unwrap_or_default(),
                    network: net,
                    account,
                    dest_index: next_receive,
                    dest_addr: dest.address.clone(),
                    dest_spk_hex: hex::encode(&dest.spk),
                    value: tx.tx.outputs[0].value,
                    fee: tx.fee,
                    vsize: tx.vsize as u64,
                    raw_hex: tx.raw_hex.clone(),
                    spent,
                };
                let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
                for c in &coins {
                    prevouts.insert(
                        format!("{}:{}", c.txid, c.vout),
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(c.address.clone()),
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                let (mut self_spks, mut spending_spks) = confirm_self_spks(&s);
                // Fresh spending receive address, not yet "used" bookkeeping
                // — push its spk on top so it classifies "self".
                self_spks.push(dest.spk.clone());
                spending_spks.push(dest.spk.clone());
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: None,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: s.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "spending-consolidate",
                    raw_hex: tx.raw_hex.clone(),
                    txid: tx.txid_hex.clone(),
                    vsize: tx.vsize,
                    context: format!("Consolidate spending coins · {}", net.as_str()),
                    return_screen: 10, // overwritten by show_confirm
                    payload: PendingPayload::SpendingConsolidate { snap },
                };
                show_confirm(&w, &mut s, pending, ctx);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_consolidate_open, |w, s| {
        open_notebook_consolidate(&w, &mut s);
    });

    cb!(on_consolidate_wallet_open, |w, s| {
        // The destination-pick handler prices the tx off `s.fees.hour`
        // shortly after this opens the account picker — lazily (re)fetch
        // now so it's ready (network-efficiency, 2026-07-23).
        refresh_fees_price(&w, &mut s);
        // Keyed AND watch identities take the same wallet-level flow
        // (rev-3 follow-up 1): snapshot every active notebook's coins,
        // pick the destination notebook, confirm. Watch identities sign
        // the one resulting PSBT externally (screens 13/14).
        let Some(ix) = &s.notebooks else { return };
        let mut sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)> = Vec::new();
        let mut coins_total = 0usize;
        for m in ix.active(s.account) {
            let Some(store) = notebook_store(&s, m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            coins_total += coins.len();
            let value: u64 = coins.iter().map(|u| u.value).sum();
            sources.push((m.index, coins, value));
        }
        if coins_total < 2 {
            w.set_status("nothing to consolidate (need 2+ coins across the wallet)".into());
            return;
        }
        println!(
            "cb: wallet-consolidate open coins={coins_total} notebooks={}",
            sources.len()
        );
        s.wconsol = Some(WConsol {
            sources,
            dest_index: 0,
            dest_addr: String::new(),
            rate: 0.0,
            fee: 0,
            vsize: 0,
        });
        w.set_nb_create_name("".into());
        show_notebook_picker(&w, &s, 0, "wconsol");
    });

    cb!(on_set_sweep_tier, |w, s, tier: i32| {
        w.set_sweep_tier(tier);
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        if tier != 3 {
            w.set_sweep_rate_text(format!("{rate}").into());
        }
        println!("cb: sweep-tier {tier} rate={rate}");
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_sweep_rate_changed, |w, s| {
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_toggle_sweep_fund_external, |w, s, on: bool| {
        println!("cb: sweep-fund-external {on}");
        w.set_status("".into());
        if on && s.funding.is_none() {
            // No funding wallet active yet — pick one; Back returns here.
            w.set_funding_return(16);
            refresh_funding_list(&w, &s);
            w.set_screen(15);
            return;
        }
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_sweep_send, |w, s| {
        // Scan-freshness gate (belt to the UI button's braces — an e2e tap
        // or a race can land on a just-disabled button): never build a
        // sweep/consolidate off a coin cache a scan is about to replace.
        if w.get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=sweep");
            w.set_status("still syncing — one moment".into());
            return;
        }
        let dest = w.get_sweep_dest().to_string();
        let net = s.network;
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        let rate = resolve_sweep_rate(&w, &s);
        if rate <= 0.0 {
            w.set_status("enter a fee rate".into());
            return;
        }
        if w.get_sweep_fund_external() {
            // Fee from the funding wallet: the FULL balance rides to the
            // destination, funding change returns to the funding wallet.
            let Some(fund_src) = s.funding.clone() else {
                w.set_status("set a funding wallet first".into());
                return;
            };
            if s.funding_coins.is_empty() {
                w.set_status("funding wallet has no spendable coins".into());
                return;
            }
            // Watch identities sweep the whole WALLET (every active
            // notebook's coins, per-index key origins); a keyed identity
            // signs its own inputs with the one active key, so it stays on
            // the active store.
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let notes_coins: Vec<WatchCoin> = if watch {
                watch_wallet_coins(&s)
            } else {
                let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
                s.store
                    .as_ref()
                    .map(|store| {
                        store
                            .utxos
                            .iter()
                            .filter(|u| !u.pending_spend)
                            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            if notes_coins.is_empty() {
                w.set_status("nothing to sweep".into());
                return;
            }
            let inputs: Vec<app_core::store::TxInput> = notes_coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let input_indexes: Vec<u32> = notes_coins.iter().map(|c| c.index).collect();
            // Unit 6: the watch branch's `notes_coins` (from `watch_wallet_coins`)
            // may include chain-1 change coins riding in this fee-external-
            // funded sweep too — same non-bumpable + prune-on-success
            // treatment as the self-paid watch sweep.
            let change_spent: Vec<(String, u32)> =
                notes_coins.iter().filter(|c| c.chain == 1).map(|c| (c.txid.clone(), c.vout)).collect();
            let Some(ident) = s.ident.as_ref() else { return };
            let identity_spk = p2tr_script_pubkey(&ident.output_x());
            let identity_source = ident.watch_source().cloned();
            let fund_coins = s.funding_coins.clone();
            let plan = FundingPlan {
                source: &fund_src,
                coins: &fund_coins,
                change_index: s.funding_change_index,
                fee_rate: rate,
                change_override: None,
            };
            match build_funded_sweep_psbt(
                identity_spk,
                identity_source.as_ref(),
                &notes_coins,
                &plan,
                recipient.spk.clone(),
                s.effective_lock_time(),
            ) {
                Ok(mut built) => {
                    // Keyed identity: the app signs its own inputs here and
                    // now — only the funding wallet still needs to sign.
                    if let Some(id) = s.ident.as_ref().and_then(|i| i.full()) {
                        match sign_own_taproot_inputs(&mut built.psbt, &id.output_x, &id.tweaked_seckey) {
                            Ok(k) => println!("cb: sweep-own-signed inputs={k}"),
                            Err(e) => {
                                w.set_status(format!("{e}").into());
                                return;
                            }
                        }
                    }
                    let cost = format!(
                        "sweep · {} sats arrive in full · fee {} sats from the funding wallet",
                        built.sent_to_recipient, built.fee
                    );
                    s.watch_note = None;
                    s.watch_spend = Some(WatchSpend {
                        kind: if w.get_sweep_kind().as_str() == "consolidate" { "consolidate" } else { "sweep" },
                        dest: dest.clone(),
                        dest_spk_hex: hex::encode(&recipient.spk),
                        value: built.sent_to_recipient,
                        fee: built.fee,
                        inputs,
                        input_indexes,
                        dest_index: None,
                        bump_ref: None,
                        change_spent: change_spent.clone(),
                    });
                    println!(
                        "cb: sweep-build funded=1 txid={} fee={} notes_in={} fund_in={}{}",
                        built.txid,
                        built.fee,
                        notes_coins.len(),
                        fund_coins.len(),
                        if change_spent.is_empty() { String::new() } else { format!(" change={}", change_spent.len()) }
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let consolidate = w.get_sweep_kind().as_str() == "consolidate";
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            let kind = if consolidate { "consolidate" } else { "sweep" };
            watch_spend_build(&w, &mut s, kind, dest, recipient.spk.clone(), rate);
            return;
        }
        // Keyed, self-paid: build + sign now (stage A) and hand off to the
        // universal confirm screen — the (removed) sweep/consolidate
        // confirm modals used to gate this; Broadcast on screen 26 is the
        // only way out now (`on_confirm_broadcast`, kind "sweep"/
        // "consolidate").
        if s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        if consolidate {
            build_consolidate_confirm(&w, &mut s, rate);
        } else {
            build_sweep_confirm(&w, &mut s, dest, rate);
        }
    });

    cb!(on_pick_contact, |w, s, addr: SharedString| {
        // Sweep mode: the picker chooses the sweep DESTINATION, then opens
        // the compose-like sweep screen (16) instead of compose.
        if w.get_pick_mode().as_str() == "sweep" {
            let mut a = normalize_addr(addr.as_str());
            if a == "self" || a.is_empty() {
                w.set_status("pick a destination address".into());
                return;
            }
            if Recipient::parse(s.network, &a).is_err() {
                let lower = a.to_lowercase();
                if Recipient::parse(s.network, &lower).is_ok() {
                    a = lower;
                } else {
                    println!("cb: sweep-pick err=bad-address");
                    w.set_status(format!("not a valid {} address", s.network.as_str()).into());
                    return;
                }
            }
            // A manual pick here always replaces whatever destination was
            // set before (including the spending-wallet shortcut) — don't
            // mark a stale index used for an address the user didn't pick.
            s.pending_spending_sweep_index = None;
            set_sweep_dest(&w, &mut s, a);
            return;
        }
        // Multi-select: the picker was reopened via compose's "+ Add
        // recipient" — append instead of replacing the primary recipient.
        if s.picking_extra {
            add_recipient_chip(&w, &mut s, addr.as_str());
            return;
        }
        w.set_compose_return(7);
        pick_contact_core(&w, &mut s, addr.as_str());
    });

    cb!(on_reply_to_note, |w, s| {
        let addr = w.get_note_reply_address().to_string();
        if addr.is_empty() {
            return;
        }
        println!("cb: reply to={addr}");
        w.set_compose_return(5);
        pick_contact_core(&w, &mut s, &addr);
    });

    cb!(on_reply_all_to_note, |w, s| {
        let addrs: Vec<String> = w.get_note_reply_set().iter().map(|c| c.address.to_string()).collect();
        let Some((first, rest)) = addrs.split_first() else { return };
        println!("cb: reply-all to={} n={}", addrs.join(","), addrs.len());
        w.set_compose_return(5);
        // pick_contact_core resets the compose session (clearing any prior
        // to_addresses_extra) before we seed the rest as extra chips.
        pick_contact_core(&w, &mut s, first);
        s.to_addresses_extra = rest.to_vec();
        refresh_to_chips(&w, &s);
        refresh_compose(&w, &mut s);
    });

    cb!(on_add_recipient_open, |w, s| {
        // Multi-select stays notebook-funded-compose only (watch-only has
        // no multi-recipient PSBT builder yet — a later unit).
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            return;
        }
        let total = 1 + s.to_addresses_extra.len();
        if total >= 255 {
            w.set_status("recipient limit reached (255)".into());
            return;
        }
        println!("cb: add-recipient-open");
        s.picking_extra = true;
        w.set_picking_extra(true);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_pick_mode("compose".into());
        pull_icloud_contacts_on_open(&w, &mut s);
        w.set_screen(7);
    });

    cb!(on_remove_chip, |w, s, addr: SharedString| {
        let a = addr.to_string();
        s.to_addresses_extra.retain(|x| x != &a);
        println!("cb: remove-chip n={}", s.to_addresses_extra.len() + 1);
        refresh_to_chips(&w, &s);
        refresh_compose(&w, &mut s);
    });

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_contact_scan(move || {
            println!("cb: contact-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the recipient's address QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(p)) => String::from_utf8_lossy(&p).to_string(),
                    _ => String::new(),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if text.is_empty() {
                        w.set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: contact-scan ok");
                        let a = normalize_addr(&text);
                        // Prefill so a failed validation leaves it editable,
                        // then pick directly — a valid scan goes straight
                        // to Compose (the Prime picker behavior).
                        w.set_contact_input(a.clone().into());
                        w.invoke_pick_contact(a.into());
                    }
                });
            });
        });
    }

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_change_scan(move || {
            println!("cb: change-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the change-address QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(p)) => String::from_utf8_lossy(&p).to_string(),
                    _ => String::new(),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if text.is_empty() {
                        w.set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: change-scan ok");
                        w.set_change_address(normalize_addr(&text).into());
                        w.set_change_expanded(true);
                        w.invoke_compose_changed();
                    }
                });
            });
        });
    }

    // Scan a funding descriptor / xpub / account-UR QR → prefill + validate.
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_funding_scan(move || {
            println!("cb: funding-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the funding-wallet QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let pweak = weak.clone();
                // Reassemble an animated account UR across frames (a hardware
                // wallet's crypto-account export can span several QR frames); a
                // single non-UR descriptor/xpub QR completes on the first frame.
                let mut dec = app_core::ur::UrDecoder::new();
                let mut parts: Vec<String> = Vec::new();
                let mut single: Option<String> = None;
                let done = camera::capture_frames(45, &cancel, preview, |payload| {
                    let s = String::from_utf8_lossy(payload);
                    let t = s.trim();
                    if t.to_lowercase().starts_with("ur:") {
                        let complete = dec.receive(t).unwrap_or(false);
                        parts.push(t.to_string());
                        let p = dec.progress();
                        let _ = pweak.upgrade_in_event_loop(move |w| w.set_scan_progress(p));
                        complete
                    } else {
                        single = Some(t.to_string());
                        true
                    }
                });
                let result: Option<Result<String, String>> = match done {
                    Ok(true) => match single {
                        Some(d) => Some(Ok(d)),           // non-UR descriptor
                        None if !parts.is_empty() => Some(Err(parts.join(" "))), // UR frames
                        None => None,
                    },
                    _ => None,
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    match result {
                        Some(Err(ur)) => {
                            println!("cb: funding-scan ur (multi-frame)");
                            w.invoke_funding_import_ur(ur.into());
                        }
                        Some(Ok(desc)) => {
                            println!("cb: funding-scan ok");
                            let t: SharedString = extract_descriptor(&desc).into();
                            w.set_funding_descriptor(t.clone());
                            w.invoke_funding_changed(t);
                        }
                        None => w.set_status("scan: no complete QR seen".into()),
                    }
                });
            });
        });
    }

    // Scan a signed PSBT QR (single-frame crypto-psbt) → validate + confirm.
    // The decode/validate runs back on the UI thread via the psbt-loaded
    // callback (which has state access), so no Rc crosses the thread boundary.
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_psbt_import_scan(move || {
            println!("cb: psbt-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the signed-transaction QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let pweak = weak.clone();
                // Reassemble an animated crypto-psbt UR across frames (a hardware
                // wallet hands the signed PSBT back as a multi-part QR); a single
                // non-UR QR (hex/base64) completes on the first frame.
                let mut dec = app_core::ur::PsbtUrDecoder::new();
                let mut single: Option<String> = None;
                let done = camera::capture_frames(45, &cancel, preview, |payload| {
                    let s = String::from_utf8_lossy(payload);
                    let t = s.trim();
                    if t.to_lowercase().starts_with("ur:") {
                        let _ = dec.receive(t);
                        let p = dec.progress();
                        let _ = pweak.upgrade_in_event_loop(move |w| w.set_scan_progress(p));
                        dec.is_complete()
                    } else {
                        single = Some(t.to_string());
                        true
                    }
                });
                let result: Option<String> = match done {
                    Ok(true) => single.or_else(|| dec.psbt_bytes().ok().map(hex::encode)),
                    _ => None,
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    match result {
                        Some(text) => {
                            println!("cb: psbt-scan ok");
                            w.invoke_psbt_loaded(text.into());
                        }
                        None => w.set_status("scan: no complete PSBT seen".into()),
                    }
                });
            });
        });
    }

    cb!(on_start_rename, |w, s, addr: SharedString, name: SharedString, synced: bool| {
        let _ = &mut s;
        println!("cb: rename-start addr={addr}");
        w.set_status("".into());
        w.set_rename_address(addr);
        w.set_rename_input(name);
        w.set_rename_synced(synced);
    });

    cb!(on_save_rename, |w, s, name: SharedString| {
        let addr = w.get_rename_address().to_string();
        let synced = w.get_rename_synced();
        s.name_contact(&addr, name.trim(), synced);
        s.save_contacts();
        println!("cb: save-contact addr={addr} name-len={}", name.trim().len());
        w.set_status("".into());
        w.set_rename_address("".into());
        w.set_rename_input("".into());
        w.set_rename_synced(false);
        update_home(&w, &s);
    });

    cb!(on_cancel_rename, |w, s| {
        let _ = &mut s;
        w.set_rename_address("".into());
        w.set_rename_input("".into());
        w.set_rename_synced(false);
    });

    cb!(on_confirm_remove, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: confirm-remove addr={addr}");
        w.set_confirm_remove_name(name);
        w.set_confirm_remove_address(addr);
    });

    cb!(on_cancel_remove, |w, s| {
        let _ = &mut s;
        w.set_confirm_remove_address("".into());
    });

    cb!(on_remove_contact, |w, s, addr: SharedString| {
        s.remove_contact(addr.as_str());
        s.save_contacts();
        println!("cb: remove-contact addr={addr}");
        w.set_status("".into());
        w.set_confirm_remove_address("".into());
        if w.get_rename_address() == addr {
            w.set_rename_address("".into());
        }
        update_home(&w, &s);
    });

    cb!(on_compose_changed, |w, s| {
        refresh_compose(&w, &mut s);
    });

    // Independent-expand rework (2026-07-18): `source` is now passed
    // explicitly by the tapped panel itself (each of the 3 CoinListPanel
    // instances on screen 20 forwards its OWN "notebook"/"spending"/
    // "wallet:<id>" — see app.slint) rather than read from a single
    // "currently expanded" variable, since multiple sections can be
    // expanded at once now. The cross-wallet selection memory
    // (`mixed_selected`) is authoritative; notebook/spending also mirror
    // into the legacy `selected_coins` scratch so their existing fee/
    // change-preview math keeps reading it directly. A coin tap — and ONLY
    // a coin tap, never a header tap — also makes its wallet the compose
    // engine's active/primary pay-from source (Sal's rule: only an
    // explicit pick may do that).
    cb!(on_toggle_coin, |w, s, source: SharedString, outpoint: SharedString| {
        let source = source.to_string();
        let op = outpoint.as_str();
        if let Some((txid, vout)) = op.rsplit_once(':') {
            if let Ok(vout) = vout.parse::<u32>() {
                // Taproot CHANGE-chain coins (unit 5, see
                // `../PLAN-chain-notes-app-taproot-change.md`) render folded
                // into the "notebook" panel (`payfrom_panel_coins`), so the
                // slint call site always passes source="notebook" for their
                // rows too — resolve the TRUE source from the outpoint
                // itself (globally unique) rather than trusting the caller,
                // so a change coin is tracked under its own "change" key.
                let source = if s.change_coins.iter().any(|c| c.txid == txid && c.vout == vout) {
                    "change".to_string()
                } else {
                    source
                };
                let mut coins = mixed_coins_for(&s, &source);
                let key = (txid.to_string(), vout);
                if let Some(i) = coins.iter().position(|c| c == &key) {
                    coins.remove(i);
                } else {
                    coins.push(key);
                }
                mixed_sync_source(&mut s, &source, &coins);
                s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
                s.payfrom_active_source = source.clone();
                if source == "notebook" || source == "spending" {
                    s.selected_coins = coins.clone();
                    s.coins_overridden = true;
                    apply_pay_from(&w, &mut s, source.as_str());
                } else if let Some(id) = source.strip_prefix("wallet:") {
                    promote_wallet_active(&w, &mut s, id);
                }
                println!("cb: toggle-coin selected={}", coins.len());
                refresh_compose(&w, &mut s);
                update_payfrom_panels(&w, &mut s);
                refresh_funding_list(&w, &s);
            }
        }
    });

    cb!(on_set_coin_strategy, |w, s, strategy: i32| {
        // 0 = fewest coins (largest-first), 1 = consolidate (smallest-first).
        // Re-applies the suggestion (clears any manual override).
        s.consolidate_coins = strategy == 1;
        s.coins_overridden = false;
        w.set_coin_strategy(strategy);
        println!("cb: coin-strategy {}", if strategy == 1 { "consolidate" } else { "fewest" });
        refresh_compose(&w, &mut s);
    });

    // Watchdog fix (2026-07-20): both ↻ taps used to rescan every active
    // notebook synchronously on the UI thread — see
    // `wallet_stores_refresh_async`'s doc comment. The spending-wallet
    // kickoff + notebook-list rebuild now happen in
    // `apply_wallet_stores_refresh_results` once the scan actually lands.
    cb!(on_refresh_coins, |w, s| {
        wallet_stores_refresh_async(&w, &mut s, WalletStoresPurpose::Coins);
    });

    // Notebook-list (main screen) header ↻: rescan every active notebook and
    // rebuild the list so balances / note counts / unread badges are current.
    cb!(on_refresh_notebooks, |w, s| {
        wallet_stores_refresh_async(&w, &mut s, WalletStoresPurpose::Notebooks);
    });

    // First-run disclaimer accepted → persist + reveal the real first screen.
    cb!(on_accept_terms, |w, s| {
        s.terms_accepted = true;
        s.save_config();
        let target = if s.material.is_some() { 17 } else { 0 };
        w.set_terms_accept_mode(false);
        w.set_screen(target);
        println!("cb: accept-terms target={target}");
    });

    // About / Privacy / Help / Q&A — one info screen, content set per button.
    cb!(on_open_info, |w, s, kind: slint::SharedString| {
        let _ = &mut s;
        let (title, body): (&str, String) = match kind.as_str() {
            "about" => ("About", about_body()),
            "privacy" => ("Privacy", PRIVACY.to_string()),
            "help" => ("Help", HELP.to_string()),
            "faq" => ("Q & A", FAQ.to_string()),
            // Terms & disclaimer re-views through the SAME info screen (25) as
            // the others, so Settings sub-screens share one scroll-top UX. The
            // centered screen 24 is now purely the first-run accept gate.
            "terms" => ("Terms & disclaimer", DISCLAIMER.to_string()),
            _ => return,
        };
        w.set_info_title(title.into());
        w.set_info_body(body.as_str().into());
        w.set_screen(25);
        println!("cb: open-info {kind}");
    });

    // ---------- external funding (PSBT) ----------
    cb!(on_toggle_fund_external, |w, s, on: bool| {
        println!("cb: fund-external {on}");
        if !on {
            s.funding_coins.clear();
        }
        w.set_status("".into());
        refresh_compose(&w, &mut s);
        // Turning it on with no wallet active → go to the saved-wallets list.
        if on && s.funding.is_none() {
            w.set_funding_return(6);
            refresh_funding_list(&w, &s);
            w.set_screen(15);
        }
    });

    // Funding-unification M3: compose "Pay from" picker — "notebook" or
    // "spending". External wallets are picked via use-funding-wallet
    // directly (they need a scan first, same as before this milestone).
    cb!(on_set_pay_from, |w, s, kind: SharedString| {
        println!("cb: pay-from {kind}");
        s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
        apply_pay_from(&w, &mut s, kind.as_str());
        refresh_compose(&w, &mut s);
    });

    cb!(on_open_funding, |w, s| {
        println!("cb: open-funding");
        w.set_status("".into());
        refresh_funding_list(&w, &s);
        w.set_screen(15);
    });

    // funding-unification: compose's compact "Pay from" row → the dedicated
    // picker/coin-control/change-address screen (20). Independent-expand
    // rework (2026-07-18, Sal's iPhone feedback #3): on EVERY open, re-derive
    // which sections start expanded from what's actually selected right now
    // (never persisted across visits) — every source holding at least one
    // selected coin starts open so the user sees it, the rest start
    // collapsed. This is the ONLY place auto-selection-driven expansion
    // happens; a header tap thereafter only shows/hides (`on_payfrom_expand`).
    cb!(on_open_funding_screen, |w, s| {
        println!("cb: funding-open");
        // Screen 20 (pay-from) shows fee tiers via the compose cost line —
        // lazily (re)fetch (network-efficiency, 2026-07-23).
        refresh_fees_price(&w, &mut s);
        w.set_status("".into());
        s.nb_expanded = !mixed_coins_for(&s, "notebook").is_empty();
        s.sp_expanded = !mixed_coins_for(&s, "spending").is_empty();
        w.set_nb_expanded(s.nb_expanded);
        w.set_sp_expanded(s.sp_expanded);
        println!("cb: payfrom expand wallet=notebook expanded={}", s.nb_expanded);
        println!("cb: payfrom expand wallet=spending expanded={}", s.sp_expanded);
        let wallet_open = s
            .funding_wallets
            .iter()
            .find(|fw| !mixed_coins_for(&s, &format!("wallet:{}", fw.id)).is_empty())
            .map(|fw| format!("wallet:{}", fw.id))
            .unwrap_or_default();
        s.payfrom_expanded_source = wallet_open;
        w.set_payfrom_expanded_source(s.payfrom_expanded_source.clone().into());
        if !s.payfrom_expanded_source.is_empty() {
            println!("cb: payfrom expand wallet={} expanded=true", s.payfrom_expanded_source);
        }
        update_funding_screen_ui(&w, &s);
        update_payfrom_panels(&w, &mut s);
        refresh_funding_list(&w, &s);
        w.set_screen(20);
    });

    // Independent-expand rework (2026-07-18, Sal's iPhone feedback #1/#3): a
    // wallet-row tap ONLY toggles that section's visibility — it never
    // selects/deselects coins or changes which source is the compose
    // engine's active pay-from (that's `on_toggle_coin`'s job, triggered by
    // an actual coin tap, or the on-open auto-selection above). Notebook and
    // Spending expand/collapse fully independently of each other and of the
    // external-wallet row(s): opening one never hides another's selection.
    // External wallets stay an accordion AMONG THEMSELVES only — this app
    // only ever keeps ONE external wallet's coins scanned/cached live at a
    // time (`payfrom_wallet_coins`/`funding_coins`, a pre-existing scope
    // boundary) — but expanding one never touches Notebook/Spending.
    cb!(on_payfrom_expand, |w, s, source: SharedString| {
        let key = source.to_string();
        match key.as_str() {
            "notebook" => {
                s.nb_expanded = !s.nb_expanded;
                w.set_nb_expanded(s.nb_expanded);
                println!("cb: payfrom expand wallet=notebook expanded={}", s.nb_expanded);
            }
            "spending" => {
                s.sp_expanded = !s.sp_expanded;
                w.set_sp_expanded(s.sp_expanded);
                println!("cb: payfrom expand wallet=spending expanded={}", s.sp_expanded);
                if s.sp_expanded && !s.spending_scanned {
                    spending_refresh_async(&w, &mut s);
                }
            }
            _ => {
                let collapsing = s.payfrom_expanded_source == key;
                s.payfrom_expanded_source = if collapsing { String::new() } else { key.clone() };
                w.set_payfrom_expanded_source(s.payfrom_expanded_source.clone().into());
                println!("cb: payfrom expand wallet={key} expanded={}", !collapsing);
                if !collapsing {
                    if let Some(id) = key.strip_prefix("wallet:") {
                        payfrom_scan_wallet_for_display(&w, &mut s, id);
                    }
                }
            }
        }
        update_payfrom_panels(&w, &mut s);
        refresh_funding_list(&w, &s);
    });

    // Change now lives on its own screen (21), reached from a second
    // compose nav row below "Pay from" (funding-unification UI rework).
    cb!(on_change_open, |w, s| {
        w.set_status("".into());
        refresh_funding_list(&w, &s);
        update_change_label(&w, &mut s);
        // Logged AFTER resolution so `default=<choice>` reflects the
        // effective destination (an explicit pick if one was made this
        // session, else app-core's resolved default) — a screenshot-
        // independent way to assert change-default behavior in e2e.
        println!("cb: change-open default={}", w.get_change_choice());
        w.set_screen(21);
    });

    cb!(on_change_pick, |w, s, choice: SharedString| {
        println!("cb: change-pick {choice}");
        s.change_choice = choice.to_string();
        w.set_change_choice(choice.clone());
        if choice.as_str() != "custom" {
            w.set_change_address("".into());
            w.set_change_error("".into());
        }
        update_change_label(&w, &mut s);
        refresh_compose(&w, &mut s);
        if choice.as_str() != "custom" {
            w.set_screen(6);
        }
    });

    // Screen 20's header ↻: re-scan the notebook + (if enabled) the spending
    // wallet on worker threads, same async/trampoline pattern as
    // refresh_async/spending_refresh_async — never blocks the UI thread.
    // Each landing logs its own `cb: funding-refresh …` (see
    // apply_refresh_results / apply_spending_refresh_results).
    cb!(on_funding_refresh, |w, s| {
        refresh_async(&w, &mut s);
        if s.spending_capable && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false) {
            spending_refresh_async(&w, &mut s);
        }
    });

    cb!(on_add_funding_wallet, |w, s| {
        let _ = &mut s;
        w.set_status("".into());
        w.set_funding_descriptor("".into());
        w.set_funding_feedback("".into());
        w.set_funding_valid(false);
        w.set_screen(12);
    });

    cb!(on_use_funding_wallet, |w, s, id: SharedString| {
        activate_funding_wallet(&w, &mut s, id.as_str());
    });

    cb!(on_remove_funding_wallet, |w, s, id: SharedString| {
        println!("cb: remove-funding-wallet");
        s.funding_wallets.retain(|fw| fw.id != id.as_str());
        if s.active_funding_id.as_deref() == Some(id.as_str()) {
            s.active_funding_id = None;
            s.funding = None;
            s.funding_coins.clear();
        }
        s.save_funding_wallets();
        refresh_funding_list(&w, &s);
    });

    cb!(on_refresh_funding_wallet, |w, s, id: SharedString| {
        let net = s.network;
        let Some(idx) = s.funding_wallets.iter().position(|fw| fw.id == id.as_str()) else { return };
        let descriptor = s.funding_wallets[idx].descriptor.clone();
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let Ok(src) = FundingSource::parse(&descriptor, net) else { return };
        w.set_status("scanning…".into());
        let creds = core_rpc_creds_for(&s, &base, net);
        if let Ok(client) = open_client(&base, net, creds) {
            if let Ok(scan) = client.scan_funding(&src, 20) {
                s.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
                s.funding_wallets[idx].coins = scan.utxos.len();
                s.funding_wallets[idx].scanned = true;
                s.funding_wallets[idx].next_change_index = scan.next_change_index;
                s.save_funding_wallets();
            }
        }
        w.set_status("".into());
        refresh_funding_list(&w, &s);
    });

    cb!(on_fund_rename_start, |w, s, id: SharedString, label: SharedString| {
        let _ = &mut s;
        w.set_fund_rename_input(label);
        w.set_fund_rename_id(id);
    });

    cb!(on_fund_rename_save, |w, s, text: SharedString| {
        let id = w.get_fund_rename_id().to_string();
        let name = text.trim();
        if !name.is_empty() {
            if let Some(fw) = s.funding_wallets.iter_mut().find(|fw| fw.id == id) {
                fw.label = name.to_string();
            }
            s.save_funding_wallets();
        }
        w.set_fund_rename_id("".into());
        refresh_funding_list(&w, &s);
    });

    cb!(on_fund_rename_cancel, |w, s| {
        let _ = &mut s;
        w.set_fund_rename_id("".into());
    });

    cb!(on_funding_changed, |w, s, text: SharedString| {
        let net = s.network;
        let _ = &mut s;
        let t = text.trim();
        if t.is_empty() {
            w.set_funding_feedback("".into());
            w.set_funding_valid(false);
            return;
        }
        if t.to_lowercase().starts_with("ur:") {
            w.set_funding_feedback("Hardware-wallet export (UR) — press Save & use to import.".into());
            w.set_funding_valid(true);
            return;
        }
        match FundingSource::parse(&extract_descriptor(t), net) {
            Ok(src) => {
                let a0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
                w.set_funding_feedback(format!("{} wallet · first address\n{a0}", src.kind.label()).into());
                w.set_funding_valid(true);
            }
            Err(e) => {
                w.set_funding_feedback(format!("{e}").into());
                w.set_funding_valid(false);
            }
        }
    });

    cb!(on_funding_use, |w, s| {
        // A UR hardware-wallet export imports its account(s) into the list.
        if try_import_ur_account(&w, &mut s, &w.get_funding_descriptor()) {
            return;
        }
        // Otherwise: validate the descriptor, save to the list if new, activate.
        let input = extract_descriptor(&w.get_funding_descriptor());
        let net = s.network;
        let wallet = match FundingWallet::create(&input, "", net) {
            Ok(fw) => fw,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        if !s.funding_wallets.iter().any(|x| x.id == wallet.id) {
            s.funding_wallets.push(wallet.clone());
            s.save_funding_wallets();
        }
        activate_funding_wallet(&w, &mut s, &wallet.id);
    });

    cb!(on_funding_file, |w, s| {
        if let Some(path) =
            platform::pick_file(&[("Descriptor / wallet export", &["txt", "json", "desc", "ur"])])
        {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if try_import_ur_account(&w, &mut s, &content) {
                        return;
                    }
                    // A wallet-export file can list several script-type descriptors.
                    let descs = extract_all_descriptors(&content);
                    if descs.len() > 1 {
                        let added = save_funding_descriptors(&w, &mut s, &descs);
                        w.set_status(format!("imported {added} wallet(s) from file — pick one").into());
                    } else {
                        let d = descs.into_iter().next().unwrap_or_default();
                        w.set_funding_descriptor(d.clone().into());
                        w.invoke_funding_changed(d.into());
                    }
                }
                Err(e) => w.set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(on_funding_import_ur, |w, s, text: SharedString| {
        try_import_ur_account(&w, &mut s, text.as_str());
    });

    cb!(on_funding_clear, |w, s| {
        s.funding = None;
        s.funding_coins.clear();
        s.built_psbt = None;
        s.signed_psbt = None;
        w.set_funding_descriptor("".into());
        w.set_funding_feedback("".into());
        w.set_funding_valid(false);
        refresh_compose(&w, &mut s);
    });

    cb!(on_fund_build, |w, s| {
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        if s.funding.is_none() || s.funding_coins.is_empty() {
            w.set_status("set a funding wallet first".into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Change destination: blank field = the funding wallet's own change
        // address; a valid custom address overrides it.
        let change_raw = normalize_addr(w.get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let src = s.funding.clone().unwrap();
        let coins = s.funding_coins.clone();
        let change_index = s.funding_change_index;
        let r = app_core::notes_core::keys::generate_aux_rand()
            .map(|x| [x[0], x[1], x[2], x[3]])
            .unwrap_or([1, 2, 3, 4]);
        let plan =
            FundingPlan { source: &src, coins: &coins, change_index, fee_rate: rate, change_override };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch identity + funding wallet: PUBLIC note paid entirely by
            // the funding coins; both signatures happen externally. Frozen-
            // scan caveat: a rescan attributes an externally funded PUBLIC
            // note as received-from-funder — the local record keeps it own.
            if private {
                w.set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let output_x = s.ident.as_ref().map(|i| i.output_x()).unwrap_or_default();
            let gift = if recipient.is_some() {
                w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips — same
            // treatment as `on_compose_send`'s watch branch.
            let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(rc) => rc,
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|rc| (rc.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|rc| rc.address.clone()).collect() } else { Vec::new() };
            let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
            match app_core::psbt_build::build_watch_funded_note_psbt_multi(
                &output_x, &plan, &text, &recipients_out, r, chunk, s.effective_lock_time(),
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    s.watch_spend = None;
                    s.watch_note = Some(WatchNote {
                        note_id: r,
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: 0, // funding change isn't an own coin
                        spent: Vec::new(),
                        funded: active_funding_pill(&s),
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = coins.len();
                    let nr = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats · {n} funding input{} · sign with your external wallet{}",
                        built.fee,
                        if n == 1 { "" } else { "s" },
                        gift_cost_suffix(nr, gift),
                    );
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs} funded=1{}",
                        hex::encode(r),
                        built.txid,
                        built.fee,
                        if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            note_id: r,
            max_op_return_bytes: DEFAULT_CHUNK,
            network: net,
        };
        match build_funding_psbt(&plan, &np, s.effective_lock_time()) {
            Ok(built) => {
                let n = coins.len();
                let cost =
                    format!("fee {} sats · {n} input{}", built.fee, if n == 1 { "" } else { "s" });
                s.watch_spend = None; // this sign screen serves external funding
                s.watch_note = None;
                show_psbt_sign_screen(&w, &mut s, built, cost);
                println!("cb: fund-build ok");
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_psbt_save, |w, s| {
        let Some(built) = s.built_psbt.as_ref() else { return };
        let bytes = built.to_bytes();
        if let Some(path) = platform::save_file("note.psbt") {
            match std::fs::write(&path, &bytes) {
                Ok(()) => w.set_status("saved .psbt".into()),
                Err(e) => w.set_status(format!("save failed: {e}").into()),
            }
        }
    });

    cb!(on_psbt_copy, |w, s| {
        let b64 = s.built_psbt.as_ref().map(|b| b.to_base64()).unwrap_or_default();
        if b64.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_text(&b64);
        if !ok {
            w.set_status("copy failed".into());
        }
        show_toast(&w, if ok { "PSBT copied" } else { "Copy failed" });
    });

    cb!(on_psbt_goto_import, |w, s| {
        let _ = &mut s;
        w.set_status("".into());
        w.set_screen(14);
    });

    cb!(on_psbt_loaded, |w, s, text: SharedString| {
        load_signed_psbt(&w, &mut s, text.as_bytes());
    });

    cb!(on_psbt_import_file, |w, s| {
        if let Some(path) = platform::pick_file(&[("PSBT", &["psbt", "txt"])]) {
            match std::fs::read(&path) {
                Ok(bytes) => load_signed_psbt(&w, &mut s, &bytes),
                Err(e) => w.set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(on_psbt_broadcast, |w, s| {
        if s.wallet_tx_busy {
            return;
        }
        let Some(psbt) = s.signed_psbt.clone() else {
            w.set_status("no signed PSBT".into());
            return;
        };
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let net = s.network;
        let snap = PsbtBroadcastSnapshot {
            identity_addr: s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
            txid,
            raw: raw.clone(),
            vsize,
        };
        s.wallet_tx_busy = true;
        w.set_wallet_tx_busy(true);
        let creds = core_rpc_creds_for(&s, &base, net);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let result = open_client(&base, net, creds)
                .map_err(|e| e.to_string())
                .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
            PSBT_BROADCAST_RESULTS
                .lock()
                .expect("psbt broadcast results mutex")
                .push(PsbtBroadcastResult { snap, result });
            let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_tx());
        });
    });

    // ---- Universal confirm screen (26) — stage B ----
    //
    // Every broadcast path lands here now: stage A (each compose/sign
    // callback above) builds + signs synchronously and hands the result to
    // `show_confirm`, which stashes it as `State.pending_broadcast` and
    // navigates to screen 26. Tapping Broadcast there runs stage B: for
    // "psbt" that's the pre-existing `on_psbt_broadcast` handler above,
    // invoked verbatim (`invoke_psbt_broadcast`) — it already manages its
    // own `wallet_tx_busy` and reads `State.signed_psbt`/`watch_note`/
    // `watch_spend`, none of which the confirm screen touched. For the
    // three compose kinds, stage B is the exact record/spawn tail their
    // Stage-A callbacks used to run immediately after signing — moved here
    // so a Cancel tap (before Broadcast) never runs it at all.
    cb!(on_confirm_broadcast, |w, s| {
        if s.wallet_tx_busy {
            return;
        }
        let Some(pending) = s.pending_broadcast.clone() else { return };
        println!("cb: confirm broadcast kind={} txid={}", pending.kind, pending.txid);
        match pending.payload {
            PendingPayload::Psbt => {
                // Self-managed: reads State.signed_psbt directly, sets its
                // own wallet_tx_busy, pushes PSBT_BROADCAST_RESULTS. Leaving
                // `pending_broadcast` in place lets a failed POST be retried
                // by tapping Broadcast again (re-invokes this same path).
                // `on_psbt_broadcast` takes its own `st.borrow_mut()` — drop
                // ours first or the shared RefCell double-borrows and panics.
                drop(s);
                w.invoke_psbt_broadcast();
            }
            PendingPayload::Compose { composed, text, private, change_to, created_at, to } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A: exactly what
                // `compose_and_record` used to do before its own broadcast
                // call. Recording is one-shot, so drop `pending_broadcast`
                // now — a failed POST is retried from Activity's
                // Rebroadcast (existing `apply_notebook_compose_result`
                // behavior, unchanged), never by re-tapping this button.
                if let Some(store) = s.store.as_mut() {
                    app_core::compose::record_composed_note(
                        store,
                        &text,
                        private,
                        change_to.as_deref(),
                        created_at,
                        &composed,
                    );
                }
                s.save_store();
                // Device-level contacts (iCloud-contacts feature): touch
                // every recipient here too — `record_composed_note` still
                // touches the per-notebook `Store.contacts` internally (kept
                // for serde back-compat; no longer read anywhere), but the
                // recents list the picker actually shows now lives on
                // `State.contacts`.
                if composed.recipients.is_empty() {
                    if let Some(addr) = &to {
                        s.touch_contact(addr);
                    }
                } else {
                    for addr in &composed.recipients {
                        s.touch_contact(addr);
                    }
                }
                s.save_contacts();
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let note_id = composed.note_id.clone();
                let fee = composed.tx.fee;
                let vsize = composed.tx.vsize;
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    NOTEBOOK_COMPOSE_RESULTS.lock().expect("notebook compose results mutex").push(
                        NotebookComposeResult { note_id, fee, vsize, to, private, result },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_compose());
                });
            }
            PendingPayload::ComposeSpending {
                note_id,
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SPENDING_COMPOSE_RESULTS.lock().expect("spending compose results mutex").push(
                        SpendingComposeResult {
                            note_id,
                            text,
                            private,
                            to,
                            recipients,
                            gift,
                            raw,
                            txid,
                            vsize,
                            built_fee,
                            built_change,
                            spent_outpoints,
                            change_index,
                            change_raw,
                            source,
                            result,
                        },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_compose());
                });
            }
            PendingPayload::ComposeMixed {
                note_id,
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    MIXED_COMPOSE_RESULTS.lock().expect("mixed compose results mutex").push(
                        MixedComposeResult {
                            note_id,
                            text,
                            private,
                            to,
                            recipients,
                            gift,
                            raw,
                            txid,
                            vsize,
                            built_fee,
                            built_change,
                            change_default,
                            notebook_spent,
                            spent_spending,
                            change_spent,
                            payloads_len,
                            recipient_count,
                            change_index,
                            spending_source,
                            result,
                        },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_compose());
                });
            }
            // ---- sweep / consolidate / wconsol / spending-consolidate:
            // stage A already built + signed (see `build_sweep_confirm`
            // et al.); stage B synchronously returns to the ORIGIN screen
            // (`pending.return_screen`) — mirroring the removed confirm
            // modals, which closed in place while the broadcast ran in the
            // background — then spawns the pre-existing thread-spawn
            // verbatim, pushing into the SAME result queue their (UNTOUCHED)
            // `apply_*_broadcast_result` already drains via the shared
            // `apply-pending-wallet-tx` trampoline.
            PendingPayload::Sweep { snap } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SWEEP_BROADCAST_RESULTS
                        .lock()
                        .expect("sweep broadcast results mutex")
                        .push(SweepBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::Consolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    CONSOLIDATE_BROADCAST_RESULTS
                        .lock()
                        .expect("consolidate broadcast results mutex")
                        .push(ConsolidateBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::WConsol { snap } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = snap.network;
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    WCONSOL_BROADCAST_RESULTS
                        .lock()
                        .expect("wconsol broadcast results mutex")
                        .push(WConsolBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::SpendingConsolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SPENDING_CONSOLIDATE_RESULTS
                        .lock()
                        .expect("spending consolidate results mutex")
                        .push(SpendingConsolidateResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_wallet_tx());
                });
            }
            // ---- bump / rebroadcast: stage B re-arms `act_pending_ref`
            // (the Activity row's own busy guard — screen 26 briefly, then
            // back on the Activity screen while the POST runs) and spawns
            // the SAME broadcast worker their (UNTOUCHED) apply_act_*
            // functions already drain.
            PendingPayload::Bump { ref_id, fee, new_rate, bumped } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A (zero-trace
                // cancel fix): apply the exact mutation the one-shot
                // bump_* functions used to make — replacement txid append,
                // fee/vsize/raw_hex update, and (notes) the ledger change
                // swap — then save, exactly like the Compose arm. A failed
                // POST leaves a retryable record with the replacement hex
                // in hand (`apply_act_bump_results` behavior, unchanged).
                if let Some(store) = s.store.as_mut() {
                    match &bumped {
                        BumpedBuild::Note(c) => app_core::compose::record_bumped_note(store, c),
                        BumpedBuild::Tx(tx) => {
                            app_core::compose::record_bumped_tx(store, &ref_id, tx)
                        }
                    }
                }
                s.save_store();
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.act_pending_ref = Some(ref_id.clone());
                update_activity(&w, &s);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    ACT_BUMP_RESULTS
                        .lock()
                        .expect("act-bump results mutex")
                        .push(ActBumpResult { ref_id, txid, fee, new_rate, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_act_bump());
                });
            }
            PendingPayload::Rebroadcast { ref_id } => {
                let Some(base) = s.base_url() else {
                    w.set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.set_screen(pending.return_screen);
                s.act_pending_ref = Some(ref_id.clone());
                update_activity(&w, &s);
                let raw = pending.raw_hex.clone();
                let creds = core_rpc_creds_for(&s, &base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    ACT_RETRY_RESULTS
                        .lock()
                        .expect("act-retry results mutex")
                        .push(ActRetryResult { ref_id, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_act_retry());
                });
            }
        }
    });

    cb!(on_confirm_cancel, |w, s| {
        // Busy-guard: a broadcast already in flight can't be canceled out
        // from under itself (mirrors the Broadcast-tap guard above) — the
        // psbt kind in particular delegates to on_psbt_broadcast's own
        // wallet_tx_busy management, so this is the same flag either way.
        if s.wallet_tx_busy {
            return;
        }
        let kind = s.pending_broadcast.as_ref().map(|p| p.kind).unwrap_or("?");
        println!("cb: confirm cancel kind={kind}");
        let return_screen = s.pending_broadcast.take().map(|p| p.return_screen).unwrap_or(4);
        w.set_confirm_warn("".into());
        w.set_confirm_txid("".into());
        w.set_confirm_context("".into());
        w.set_confirm_note("".into());
        w.set_confirm_inputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.set_confirm_outputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.set_status("".into());
        if kind == "psbt" {
            // Zero-trace for the PSBT path means discarding the loaded
            // signed PSBT too — nothing was recorded, and re-showing a
            // stale confirm screen next load would be wrong. The unsigned
            // built PSBT / UR export (screen 13) is untouched, so backing
            // further out and re-exporting still works.
            s.signed_psbt = None;
            w.set_psbt_signed(false);
        }
        w.set_screen(return_screen);
    });

    cb!(on_compose_send, |w, s| {
        // Async sign+broadcast (2026-07-16): re-entrancy guard so a
        // double-tap on Sign can't double-broadcast.
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=compose");
            w.set_status("still syncing — one moment".into());
            return;
        }
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        // Optional custom change address (empty = back to self).
        let change_addr = normalize_addr(w.get_change_address().as_str());
        if !change_addr.is_empty() && Recipient::parse(s.network, &change_addr).is_err() {
            w.set_status(format!("change address isn't a valid {} address", s.network.as_str()).into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        if s.base_url().is_none() {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        if !w.get_spend_enough() {
            w.set_status("selected coins don't cover the note + fee".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch compose: PUBLIC note as an external-sign PSBT over the
            // selected coins; recorded on broadcast like a keyed compose.
            if private {
                w.set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
            let recipient = match to.as_deref() {
                Some(a) => match Recipient::parse(net, a) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        w.set_status(format!("{e}").into());
                        return;
                    }
                },
                None => None,
            };
            let gift = if recipient.is_some() {
                w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips, exactly
            // like the notebook path — a watch identity can't compose
            // PRIVATE notes at all (checked above), so no content-key/ECDH
            // concerns here; `public_multi_payloads`/`build_watch_note_psbt_
            // multi` hand-frame the same FLAG_MULTI body a keyed identity's
            // sealer would produce.
            let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(r) => r,
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|r| (r.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
            let Some(store) = s.store.as_ref() else { return };
            let sel: std::collections::HashSet<(String, u32)> =
                s.selected_coins.iter().cloned().collect();
            let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend && sel.contains(&(u.txid.clone(), u.vout)))
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                .collect();
            if coins.is_empty() {
                println!("cb: compose-send bail=no-coins src=watch");
                w.set_status("no coins selected".into());
                return;
            }
            let mut note_id = [0u8; 4];
            loop {
                let r = app_core::notes_core::keys::generate_aux_rand()
                    .map(|x| [x[0], x[1], x[2], x[3]])
                    .unwrap_or([1, 2, 3, 4]);
                note_id = r;
                if !store.note_id_taken(&note_id) {
                    break;
                }
            }
            let chunk = store.chunk_size;
            match build_watch_note_psbt_multi(
                &src, &coins, &text, &recipients_out, note_id, chunk, rate, s.effective_lock_time(),
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    s.watch_spend = None;
                    s.watch_note = Some(WatchNote {
                        note_id,
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: built.change,
                        spent: coins
                            .iter()
                            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
                            .collect(),
                        funded: None, // spends the notebook's own coins
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats{} · sign with your external wallet",
                        built.fee,
                        gift_cost_suffix(n, gift)
                    );
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs}{}",
                        hex::encode(note_id),
                        built.txid,
                        built.fee,
                        if n >= 2 { format!(" recipients={n}") } else { String::new() }
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        // Universal confirm screen (2026-07-17): stage A builds + signs
        // via the PURE `compose_note` (split out of `compose_and_record` —
        // see app-core/src/compose.rs) — no store mutation, so a Cancel on
        // screen 26 leaves zero trace. Stage B (`on_confirm_broadcast`)
        // calls `record_composed_note` + `save_store()` at the Broadcast
        // tap — exactly what `compose_and_record` used to do before its
        // own POST — then spawns the SAME broadcast worker below.
        let coins_vec = s.selected_coins.clone();
        let created_at = now();
        let gift_amount = to
            .as_ref()
            .map(|_| w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS));
        let change_to = (!change_addr.is_empty()).then(|| change_addr.clone());
        // Multi-recipient (notebook-funded compose only, see State::
        // to_addresses_extra): the compose screen's removable To-chips,
        // beyond the primary `to`. Empty for every other pay-from source
        // and for watch-only (the picker's "+ Add recipient" affordance is
        // hidden there) — so this stays the exact single-recipient flow,
        // byte-identical, for every path but this one.
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        let req = ComposeRequest {
            text: &text,
            private,
            recipient: to.as_deref(),
            extra_recipients: &extra_recipients,
            change_to: change_to.as_deref(),
            coins: (!coins_vec.is_empty()).then_some(coins_vec.as_slice()),
            fee_rate: rate,
            gift_amount,
            lock_time: s.lock_time_override_value(),
            now: created_at,
        };
        let Some(store) = s.store.as_ref() else {
            w.set_status("no store".into());
            return;
        };
        match app_core::compose::compose_note(store, &identity, net, &req) {
            Ok(composed) => {
                let name = s.notebook_display_name(s.nb_index);
                let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                let prevouts = notebook_prevouts(
                    s.store.as_ref().unwrap(),
                    &identity_addr,
                    &name,
                    &composed.tx.spent_outpoints,
                );
                let (self_spks, spending_spks) = confirm_self_spks(&s);
                let contact_name = |a: &str| -> Option<String> {
                    s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
                };
                let recipient_name = to.as_deref().and_then(contact_name);
                // Multi-recipient: `composed.recipients` is only populated
                // (2+ entries) for an actual multi-recipient note — every
                // other compose (self or ordinary single-recipient) keeps
                // this empty and relies on `recipient`/`recipient_name`
                // above, unchanged.
                let recipients: Vec<(String, Option<String>)> =
                    composed.recipients.iter().map(|a| (a.clone(), contact_name(a))).collect();
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: change_to.clone(),
                    recipient: to.clone(),
                    recipient_name,
                    recipients,
                    note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
                    tip_height: s.confirm_tip_height(),
                };
                let (fchange, ffee, fvsize) = (composed.tx.change, composed.tx.fee, composed.tx.vsize);
                let pending = PendingBroadcast {
                    kind: "compose",
                    raw_hex: composed.tx.raw_hex.clone(),
                    txid: composed.tx.txid_hex.clone(),
                    vsize: composed.tx.vsize,
                    context: note_context(to.is_some(), private, net),
                    return_screen: 6, // overwritten by show_confirm
                    payload: PendingPayload::Compose {
                        composed,
                        text: text.clone(),
                        private,
                        change_to,
                        created_at,
                        to: to.clone(),
                    },
                };
                show_confirm(&w, &mut s, pending, ctx);
                note_subdust_fold_warn(&w, fchange, ffee, fvsize as u64, rate);
            }
            Err(e) => {
                println!("cb: compose err={e}");
                w.set_status(format!("{e}").into());
            }
        }
    });

    // Funding-unification M3: the internal spending-wallet compose path —
    // build the SAME funded-note shape the external path uses
    // (`build_funding_psbt_amount`), sign every P2WPKH input in-process
    // (`sign_own_wpkh_inputs` — no PSBT export/import round trip), and
    // broadcast in one tap. Mirrors `examples/cli.rs`'s `note-spend-funded`
    // recipe exactly.
    cb!(on_spending_compose_send, |w, s| {
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=spending-compose");
            w.set_status("still syncing — one moment".into());
            return;
        }
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        let net = s.network;
        if s.base_url().is_none() {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them (`compose::compose_note`).
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let change_raw = normalize_addr(w.get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let Some(source) = s.spending_source.clone() else {
            w.set_status("spending wallet not scanned yet".into());
            return;
        };
        if s.spending_coins.is_empty() {
            w.set_status("spending wallet has no coins — fund it from Settings".into());
            return;
        }
        // Spend exactly the coins selected in the funding screen's coin
        // control — same `selected_coins`/`coins_overridden` state the
        // notebook path uses; unselected defaults to every scanned coin
        // (matches the live preview in `spending_compose_ui`).
        let spending_sel: std::collections::HashSet<(String, u32)> = if s.coins_overridden {
            s.selected_coins.iter().cloned().collect()
        } else {
            s.spending_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect()
        };
        let selected_spending_coins: Vec<app_core::funding::FundingUtxo> = s
            .spending_coins
            .iter()
            .filter(|c| spending_sel.contains(&(c.txid.clone(), c.vout)))
            .cloned()
            .collect();
        if selected_spending_coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=spending");
            w.set_status("no coins selected".into());
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            w.set_status("no identity".into());
            return;
        };
        let Ok(key_material) = parse_key_material(&material_str, net) else {
            w.set_status("identity parse failed".into());
            return;
        };
        let account = s.account;
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let Some(change_index) = s.store.as_ref().map(|st| st.spending.next_change) else { return };
        let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
        let gift = if recipient.is_some() {
            w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        let mut note_id = [1u8, 2, 3, 4];
        for _ in 0..8 {
            let r = app_core::notes_core::keys::generate_aux_rand()
                .map(|x| [x[0], x[1], x[2], x[3]])
                .unwrap_or(note_id);
            note_id = r;
            if !s.store.as_ref().map(|st| st.note_id_taken(&note_id)).unwrap_or(false) {
                break;
            }
        }
        let plan = FundingPlan {
            source: &source,
            coins: &selected_spending_coins,
            change_index,
            fee_rate: rate,
            change_override,
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            note_id,
            max_op_return_bytes: chunk,
            network: net,
        };
        let built = if recipients.len() >= 2 {
            app_core::psbt_build::build_funding_psbt_multi(&plan, &np, &recipients, gift, s.effective_lock_time())
        } else {
            app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift, s.effective_lock_time())
        };
        let built = match built {
            Ok(b) => b,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let mut psbt = built.psbt.clone();
        match app_core::psbt_build::sign_own_wpkh_inputs(
            &mut psbt,
            &key_material,
            net,
            account,
            &selected_spending_coins,
        ) {
            Ok(n) if n > 0 => {}
            Ok(_) => {
                w.set_status("no spending-wallet inputs signed".into());
                return;
            }
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        // Captured before `finalize_extract` consumes the PSBT — used below
        // to drop the just-spent coins from the runtime cache the moment the
        // broadcast succeeds (finding 1: a second compose in the same
        // session must never see an already-spent UTXO).
        let spent_outpoints: Vec<(String, u32)> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|inp| (inp.previous_output.txid.to_string(), inp.previous_output.vout))
            .collect();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        // Universal confirm screen (2026-07-17): nothing is recorded here —
        // that was already true before this refactor (unlike the notebook
        // path) — so stage A just hands the signed tx to the confirm
        // screen. Stage B (`on_confirm_broadcast`) is this exact
        // thread-spawn, moved verbatim to the Broadcast tap.
        let built_fee = built.fee;
        let built_change = built.change;
        let (mut self_spks, mut spending_spks) = confirm_self_spks(&s);
        // A custom change override leaves the wallet entirely (classified
        // via `expected_change`, not self); the default spending-wallet
        // change address is freshly derived and not yet "used" bookkeeping,
        // so it must be added on top of `confirm_self_spks`'s set.
        let expected_change = if !change_raw.is_empty() {
            Some(change_raw.clone())
        } else {
            if built_change > 0 {
                if let Ok(d) = source.derive(1, change_index) {
                    self_spks.push(d.spk.clone());
                    spending_spks.push(d.spk);
                }
            }
            None
        };
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &selected_spending_coins {
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Spending wallet".to_string(),
                },
            );
        }
        let recipient_name = to.as_deref().and_then(|a| {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: s.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-spending",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: 6, // overwritten by show_confirm
            payload: PendingPayload::ComposeSpending {
                note_id,
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            },
        };
        show_confirm(&w, &mut s, pending, ctx);
        note_subdust_fold_warn(&w, built_change, built_fee, vsize as u64, rate);
    });

    // Funding-unification UI rework (2026-07-16): the selection on the
    // Pay-from screen spans more than one wallet — assemble ONE mixed-
    // source PSBT (notebook + spending + at most one external wallet),
    // sign our own inputs in-app, and either broadcast directly (no
    // external coin involved) or route the partially-signed PSBT through
    // the existing external-sign screens 13/14 (the funded-sweep test in
    // app-core's psbt_build already proves that pattern: our own
    // signatures plus an external signer's, on one PSBT).
    cb!(on_compose_send_mixed, |w, s| {
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=mixed-compose");
            w.set_status("still syncing — one moment".into());
            return;
        }
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            w.set_status("watch-only identities can't mix sources".into());
            return;
        }
        let net = s.network;
        if s.base_url().is_none() {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        let gift = if recipient.is_some() {
            w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them.
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let notebook_spk = p2tr_script_pubkey(&identity.output_x);

        // Coins + wallets + change resolution come from the SAME args-builder
        // the compose preview (`mixed_compose_ui`) dry-runs — the shared seam
        // that makes preview and send structurally identical (TestFlight
        // build-20 fix, 2026-07-18).
        let MixedComposeArgs { coins, wallets_map, change_spks, change_default, change_override, change_index } =
            match mixed_compose_args(&w, &s) {
                Ok(a) => a,
                Err(e) => {
                    w.set_status(e.into());
                    return;
                }
            };

        if coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=mixed");
            w.set_status("no coins selected".into());
            return;
        }
        // A change-ONLY selection is single-source by `spans_multiple_wallets`'s
        // count (one distinct `CoinSource::Change`), but there IS no other
        // Sign button for it — taproot-change unit 5 — so it must still
        // route here rather than bounce with "use the Sign button on that
        // source instead".
        let has_change = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Change));
        if !has_change && !app_core::mixed::spans_multiple_wallets(&coins) {
            println!("cb: compose-send bail=single-source src=mixed");
            w.set_status("selection is single-source — use the Sign button on that source instead".into());
            return;
        }
        let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);

        let mut note_id = [2u8, 0, 1, 6];
        for _ in 0..8 {
            let r = app_core::notes_core::keys::generate_aux_rand()
                .map(|x| [x[0], x[1], x[2], x[3]])
                .unwrap_or(note_id);
            note_id = r;
            if !s.store.as_ref().map(|st| st.note_id_taken(&note_id)).unwrap_or(false) {
                break;
            }
        }

        // Fresh one-shot content key for a private multi-recipient body
        // (notes-core's hybrid seal) — OS TRNG, never persisted/logged,
        // zeroized immediately after use, same convention `compose_note`
        // (the notebook path) follows. Unused (and not drawn) for 0/1
        // recipients — `sealed_note_payloads_multi` ignores it there too.
        let payloads_and_spks = if recipients.len() >= 2 {
            let content_key = match app_core::compose::fresh_content_key() {
                Ok(k) => k,
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            };
            let mut content_key = content_key;
            let result = app_core::notes_core::bundle::sealed_note_payloads_multi(
                &identity, &text, private, &recipients, note_id, content_key, chunk,
            );
            content_key.zeroize();
            result.map_err(app_core::Error::from)
        } else {
            app_core::notes_core::bundle::sealed_note_payloads(
                &identity, &text, private, recipient.as_ref(), note_id, chunk,
            )
            .map(|(p, spk)| (p, spk.into_iter().collect::<Vec<Vec<u8>>>()))
            .map_err(app_core::Error::from)
        };
        let (payloads, recipient_spks) = match payloads_and_spks {
            Ok(p) => p,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let recipients_out: Vec<(Vec<u8>, u64)> = recipient_spks.into_iter().map(|spk| (spk, gift)).collect();

        let mut built = match app_core::mixed::assemble_mixed_note_psbt_multi_ext(
            &coins,
            notebook_spk,
            s.spending_source.as_ref(),
            &wallets_map,
            &change_spks,
            &payloads,
            &recipients_out,
            &change_default,
            change_override,
            change_index,
            rate,
            s.effective_lock_time(),
        ) {
            Ok(b) => b,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };

        // Sign our own inputs regardless of kind — a no-op (Ok(0)) for
        // whichever kind isn't present in this selection.
        if let Err(e) =
            app_core::psbt_build::sign_own_taproot_inputs(&mut built.psbt, &identity.output_x, &identity.tweaked_seckey)
        {
            w.set_status(format!("{e}").into());
            return;
        }
        // Taproot CHANGE-chain owners (unit 5): group the selected coins by
        // UNIQUE chain-1 index and sign each owner's inputs with its OWN
        // tweaked key — exactly unit 4's `build_sweep_confirm` change-idents
        // loop, at the PSBT level. `realize_change`'s `AppIdentity` (and its
        // `Zeroizing` leaf secret) drops — and zeroizes — at the end of each
        // loop iteration, never escaping this scope.
        if has_change {
            let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.set_status("identity parse failed".into());
                return;
            };
            let mut seen_idx: Vec<u32> = Vec::new();
            for c in coins.iter().filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change)) {
                if seen_idx.contains(&c.index) {
                    continue;
                }
                seen_idx.push(c.index);
                let owner = match realize_change(&key_material, net, s.account, c.index) {
                    Ok(o) => o,
                    Err(e) => {
                        w.set_status(format!("{e}").into());
                        return;
                    }
                };
                let Some(owner_identity) = owner.full() else {
                    w.set_status("change-chain identity has no key".into());
                    return;
                };
                if let Err(e) = app_core::psbt_build::sign_own_taproot_inputs(
                    &mut built.psbt, &owner_identity.output_x, &owner_identity.tweaked_seckey,
                ) {
                    w.set_status(format!("{e}").into());
                    return;
                }
            }
        }
        let spending_funding_utxos = app_core::mixed::spending_funding_utxos(&coins);
        if !spending_funding_utxos.is_empty() {
            let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.set_status("identity parse failed".into());
                return;
            };
            if let Err(e) = app_core::psbt_build::sign_own_wpkh_inputs(
                &mut built.psbt, &key_material, net, s.account, &spending_funding_utxos,
            ) {
                w.set_status(format!("{e}").into());
                return;
            }
        }

        let notebook_spent: Vec<app_core::store::OutPointRef> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Notebook))
            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
            .collect();
        // Taproot CHANGE-chain coins ridden as inputs (unit 5): NOT part of
        // `store.utxos` (they live in `State.change_coins`, a separate
        // per-account pool), so they're tracked as their own (txid, vout)
        // list — same shape+timing as `SweepSnapshot.change_spent` (unit 4):
        // pruned from `State.change_coins` only on broadcast SUCCESS.
        let change_spent: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let has_external = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Wallet(_)));
        // Input-anchored skip (2026-07-18 dust-skip rework; extended to
        // Change by taproot-change unit 5): mirrors
        // `assemble_mixed_note_psbt`'s own `has_self_input` condition
        // exactly, so a bumped/re-read `WatchNote`'s change-vout math
        // (`wn.dust_to_self`) stays byte-true to what the built tx actually
        // contains.
        let has_notebook_input = !notebook_spent.is_empty() || !change_spent.is_empty();

        if has_external {
            // Our own inputs are already signed above; export for the
            // external wallet to complete its own via screens 13/14.
            s.watch_spend = None;
            s.watch_note = Some(WatchNote {
                note_id,
                text: text.clone(),
                recipient: to.clone(),
                recipients: recipient_addrs.clone(),
                gift,
                chunks: payloads.len(),
                fee: built.fee,
                change: built.change,
                spent: notebook_spent,
                funded: Some("mixed".to_string()),
                is_watch: false,
                private,
                dust_to_self: !has_notebook_input,
                change_spent: change_spent.clone(),
            });
            let n = coins.len();
            let nr = recipients.len();
            let sources: std::collections::HashSet<&str> =
                s.mixed_selected.iter().map(|(src, _, _)| src.as_str()).collect();
            println!(
                "cb: compose-mixed build txid={} fee={} inputs={n} sources={} external=1{}",
                built.txid,
                built.fee,
                sources.len(),
                if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
            );
            // `today's copy` here never mentioned the gift at all (even for
            // a single recipient) — preserved for nr <= 1; nr >= 2 appends
            // the ×N total (Sal, 2026-07-19).
            let cost = format!(
                "mixed source · fee {} sats · {n} input{}{} · sign with your external wallet",
                built.fee,
                if n == 1 { "" } else { "s" },
                if nr >= 2 { gift_cost_suffix(nr, gift) } else { String::new() }
            );
            show_psbt_sign_screen(&w, &mut s, built, cost);
            return;
        }

        // No external coin: finalize + hand off to the universal confirm
        // screen. Nothing is recorded here — same "safe to retry from
        // compose on failure" shape as the spending path; stage B
        // (`on_confirm_broadcast`) is this exact thread-spawn, moved
        // verbatim to the Broadcast tap.
        let psbt = built.psbt.clone();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let spent_spending: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Spending))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let spending_source = s.spending_source.clone();
        let built_fee = built.fee;
        let built_change = built.change;
        let payloads_len = payloads.len();
        // `recipients` (the full parsed list, not the "empty means single"
        // `recipient_addrs`) already carries the exact recipient OUTPUT
        // count for every case (0 self-note / 1 ordinary / N multi).
        let recipient_count = recipients.len();

        let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let name = s.notebook_display_name(s.nb_index);
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &coins {
            let key = format!("{}:{}", c.txid, c.vout);
            match &c.source {
                app_core::mixed::CoinSource::Notebook => {
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(identity_addr.clone()),
                            source: format!("Notebook · {name}"),
                        },
                    );
                }
                app_core::mixed::CoinSource::Spending => {
                    let addr = s
                        .spending_coins
                        .iter()
                        .find(|sc| sc.txid == c.txid && sc.vout == c.vout)
                        .map(|sc| sc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: addr,
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                // Taproot CHANGE-chain coin (unit 5): same account, chain 1
                // — tagged "Change" (mirrors the sweep confirm's own
                // `source: "Change"` label from unit 4).
                app_core::mixed::CoinSource::Change => {
                    let addr = s
                        .change_coins
                        .iter()
                        .find(|cc| cc.txid == c.txid && cc.vout == c.vout)
                        .map(|cc| cc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo { value: c.value, address: addr, source: "Change".to_string() },
                    );
                }
                // Unreachable here: `has_external` (Wallet(_) coins present)
                // returned above via the external-sign screen instead.
                app_core::mixed::CoinSource::Wallet(_) => {}
            }
        }
        let (mut self_spks, mut spending_spks) = confirm_self_spks(&s);
        // A custom change override (screen 21 "custom") leaves the wallet
        // entirely; the default spending-wallet change address is freshly
        // derived and not yet "used" bookkeeping, so — like the spending
        // path — it must be added on top of `confirm_self_spks`'s set. A
        // notebook-default change needs no augmentation (already covered).
        let choice = w.get_change_choice().to_string();
        let expected_change = if choice == "custom" {
            Some(normalize_addr(w.get_change_address().as_str()))
        } else {
            if change_default == app_core::mixed::ChangeDefault::Spending && built_change > 0 {
                if let Some(src) = s.spending_source.as_ref() {
                    if let Ok(d) = src.derive(1, change_index) {
                        self_spks.push(d.spk.clone());
                        spending_spks.push(d.spk);
                    }
                }
            }
            None
        };
        let recipient_name = to.as_deref().and_then(|a| {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: s.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-mixed",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: 6, // overwritten by show_confirm
            payload: PendingPayload::ComposeMixed {
                note_id,
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            },
        };
        show_confirm(&w, &mut s, pending, ctx);
        note_subdust_fold_warn(&w, built_change, built_fee, vsize as u64, rate);
    });

    cb!(on_settings_open, |w, s| {
        w.set_return_screen(if w.get_screen() == 17 { 17 } else { 4 });
        println!("cb: settings-open");
        clear_reveal(&w, &mut s);
        w.set_status("".into());
        w.set_chunk_custom(false);
        load_backend_settings(&w, &s);
        refresh_node_health(&w, &mut s);
        // Settings shows identity/network/note-size fields that used to be set
        // only by update_home; onboarding now lands on the list (not a home),
        // so populate them here too or the "Change account…" row (gated on
        // settings-hierarchical) is missing on the first Settings visit.
        update_settings_identity(&w, &s);
        update_spending_ui(&w, &s);
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
            && !s.spending_scanned
        {
            spending_refresh_async(&w, &mut s);
        }
        // Fresh entry from the list starts at the top; returning from a Settings
        // sub-screen (via nav-back, which doesn't call this) keeps its position.
        w.set_settings_scroll_y(0.0);
        w.set_screen(8);
    });

    cb!(on_open_account_picker, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = s.account / 5;
        w.set_account_pick_mode("switch".into());
        show_account_picker(&w, &material, s.network, page, Some(s.account));
    });

    cb!(on_accounts_page, |w, s, delta: i32| {
        let page = (w.get_account_page() + delta).max(0) as u32;
        let mode = w.get_account_pick_mode();
        if mode == "notebook" || mode == "wconsol" {
            show_notebook_picker(&w, &s, page, mode.as_str());
            return;
        }
        let material = s
            .pending_import
            .as_ref()
            .or(s.material.as_ref())
            .map(|z| String::from(z.as_str()));
        let Some(material) = material else { return };
        let active = if s.pending_import.is_some() { None } else { Some(s.account) };
        show_account_picker(&w, &material, s.network, page, active);
    });

    cb!(on_pick_account, |w, s, idx: i32| {
        if w.get_account_pick_mode() == "wconsol" {
            if s.wallet_tx_busy || s.pending_broadcast.is_some() {
                return;
            }
            // Wallet consolidate: the pick is the DESTINATION — a notebook
            // address (receive index) of the active account. A non-
            // notebook address becomes a notebook (named inline) so the
            // gathered coin can never land somewhere invisible. Picking IS
            // the trigger now (the confirm modal is gone) — build + sign
            // (or, watch, build the external-sign PSBT) right here.
            let index = idx.max(0) as u32;
            let Some(mut wc) = s.wconsol.take() else { return };
            // An archived destination un-archives: the wallet's coin must
            // never land in a hidden notebook.
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).map(|m| m.archived)
                == Some(true)
            {
                let account = s.account;
                if let Some(ix) = s.notebooks.as_mut() {
                    ix.set_archived(account, index, false);
                    s.save_notebooks();
                    println!("cb: archive-notebook index={index} archived=false");
                }
            }
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_none() {
                // The picker has no name field in this mode, so the new
                // notebook takes the default name ("Notebook <index+1>")
                // until the user renames it from the list.
                ensure_notebook(&mut s, index);
            }
            let Some(addr) =
                s.nb_addrs.iter().find(|(a, ..)| *a == index).map(|(_, ad, _)| ad.clone())
            else {
                return;
            };
            let n: usize = wc.sources.iter().map(|(_, c, _)| c.len()).sum();
            let total: u64 = wc.sources.iter().map(|(_, _, v)| *v).sum();
            let vsize = app_core::notes_core::tx::estimate_sweep_vsize(n, 34);
            let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < DUST_SATS {
                w.set_status("not enough across the wallet to cover the fee".into());
                s.wconsol = None;
                return;
            }
            wc.dest_index = index;
            wc.dest_addr = addr;
            wc.rate = rate;
            wc.fee = fee;
            wc.vsize = vsize as u64;
            build_wconsol_confirm(&w, &mut s, wc);
            return;
        }
        if w.get_account_pick_mode() == "notebook" {
            // Create flow: the inline name field is already filled (or
            // left empty, taking the default "Notebook <index+1>") —
            // tapping an address creates right away.
            let index = idx.max(0) as u32;
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_some() {
                return; // row is disabled in the UI; never re-add
            }
            let name = w.get_nb_create_name().trim().to_string();
            println!("cb: create-notebook index={index}");
            let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                return;
            };
            s.nb_index = index;
            match activate(&mut s, &material, false) {
                Ok(()) => {
                    ensure_notebook(&mut s, index);
                    if !name.is_empty() {
                        let account = s.account;
                        if let Some(ix) = s.notebooks.as_mut() {
                            ix.rename(account, index, &name);
                            s.save_notebooks();
                            println!("cb: rename-notebook index={index}");
                        }
                    }
                    w.set_account_pick_mode("switch".into());
                    w.set_nb_create_name("".into());
                    w.set_status("".into());
                    update_notebook_list(&w, &s);
                    w.set_screen(17);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        // Sal 2026-07-22: this picker mode is now switch-only — imports
        // never set `pending_import` any more (removed in on_import_confirm),
        // so this always falls back to the current identity's material.
        let Some(material) = s
            .pending_import
            .take()
            .map(|z| String::from(z.as_str()))
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())))
        else {
            return;
        };
        s.account = idx.max(0) as u32;
        s.nb_index = 0;
        println!("cb: pick-account {}", s.account);
        match activate(&mut s, &material, false) {
            Ok(()) => {
                // Settings account switch: the account is a wallet — land on
                // ITS notebook list. A fresh/empty account (no notebooks at
                // all) auto-creates its first one so the switch never lands
                // on an empty list (Sal 2026-07-22); an account that already
                // has notebooks (even if all archived) is left untouched.
                let empty =
                    s.notebooks.as_ref().map(|ix| ix.active(s.account).count() == 0).unwrap_or(true);
                if empty {
                    ensure_first_onboarded_notebook(&mut s);
                }
                w.set_status("".into());
                update_notebook_list(&w, &s);
                w.set_screen(17);
                refresh_async(&w, &mut s);
                spending_refresh_async(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_account_cancel, |w, s| {
        if w.get_account_pick_mode() == "wconsol" {
            // Abandon wallet consolidate: back to settings, untouched.
            w.set_account_pick_mode("switch".into());
            w.set_nb_create_name("".into());
            s.wconsol = None;
            w.set_status("".into());
            w.set_screen(8);
            return;
        }
        if w.get_account_pick_mode() == "notebook" {
            // Abandon create → back to the notebook list, untouched.
            w.set_account_pick_mode("switch".into());
            w.set_nb_create_name("".into());
            w.set_status("".into());
            update_notebook_list(&w, &s);
            w.set_screen(17);
            return;
        }
        if s.pending_import.take().is_some() {
            w.set_screen(1); // abandon import → back to the import form
        } else {
            update_home(&w, &s);
            w.set_screen(8); // came from settings
        }
    });

    cb!(on_reset_identity, |w, s| {
        println!("cb: reset-identity");
        let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);
        // Privacy: local stores cache decrypted note text — delete them.
        if let Ok(entries) = std::fs::read_dir(&s.data_dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if (name.starts_with("store-") || name.starts_with("notebooks-"))
                    && name.ends_with(".json")
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        s.ident = None;
        s.store = None;
        s.material = None;
        s.account = 0;
        s.nb_index = 0;
        s.notebooks = None;
        s.notebooks_fp8 = None;
        s.nb_addrs.clear();
        s.xacct_addrs.clear();
        s.discovery_pending = false;
        s.to_address = None;
        s.to_addresses_extra.clear();
        s.picking_extra = false;
        w.set_picking_extra(false);
        s.icloud_backup = false;
        w.set_icloud_backup(false);
        // The key is gone, so there is nothing to restore and nothing to
        // auto-unlock — leaving either set would show a "Restore saved key"
        // door pointing at an item we just deleted.
        s.auto_unlock = false;
        s.saved_key_present = false;
        w.set_saved_key_present(false);
        s.save_config();
        w.set_show_reset_confirm(false);
        clear_reveal(&w, &mut s);
        w.set_status("".into());
        w.set_import_text("".into());
        w.set_screen(0);
    });

    cb!(on_reveal_hide, |w, s| {
        clear_reveal(&w, &mut s);
        println!("cb: hide-reveal");
    });

    cb!(on_set_network, |w, s, net: SharedString| {
        let Some(n) = Network::from_str_opt(net.as_str()) else { return };
        if n == s.network {
            return;
        }
        s.network = n;
        println!("cb: set-network {}", s.network.as_str());
        s.save_config();
        // Same key material, new network: re-derive + reload store.
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    update_home(&w, &s);
                    refresh_async(&w, &mut s);
                    spending_refresh_async(&w, &mut s); // CHANGE 5
                }
                Err(e) => w.set_status(format!("network switch: {e}").into()),
            }
        }
        w.set_settings_network(s.network.as_str().into());
    });

    cb!(on_set_chunk, |w, s, t: SharedString| {
        match t.trim().parse::<usize>() {
            Ok(n) if (20..=100_000).contains(&n) => {
                if let Some(store) = &mut s.store {
                    store.chunk_size = n;
                }
                s.save_store();
                s.chunk = Some(n); // device-level: every notebook, on activate
                s.save_config();
                println!("cb: set-chunk-size {n} ok");
                w.set_chunk_text(n.to_string().into());
                if n == 100_000 || n == 80 {
                    w.set_chunk_custom(false);
                }
                w.set_status("".into());
            }
            _ => {
                println!("cb: set-chunk-size err=range");
                w.set_status("chunk bytes must be 20..=100000".into());
            }
        }
    });

    cb!(on_set_locktime, |w, s, mode: SharedString, height: SharedString| {
        let policy = parse_locktime_mode(mode.as_str(), height.as_str());
        let Some(policy) = policy else {
            println!("cb: set-locktime err=range");
            w.set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.lock_time_policy = policy;
        if let Some(store) = &mut s.store {
            store.lock_time = policy; // device-level: every notebook, on activate
        }
        s.save_store();
        s.save_config();
        let effective = s.lock_time();
        println!("cb: set-locktime {} effective={effective} ok", policy.as_str());
        w.set_locktime_mode(policy.as_str().into());
        w.set_locktime_text(effective.to_string().into());
        w.set_locktime_effective(locktime_caption(policy, s.store.as_ref().map(|st| st.tip_height)).into());
        w.set_status("".into());
    });

    // Compose screen (6) locktime override panel — a per-tx override of
    // the device policy above, NOT a new setting: never written to
    // config.json/store, reset to the device default every time compose is
    // (re)opened (`pick_contact_core`). Shares `parse_locktime_mode`'s
    // validation and `locktime_caption`'s wording with Settings.
    cb!(on_set_compose_locktime, |w, s, mode: SharedString, height: SharedString| {
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: compose-locktime err=range");
            w.set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.tx_lock_time_override = Some(policy);
        let effective = s.effective_lock_time();
        println!("cb: compose-locktime {} effective={effective} ok", policy.as_str());
        refresh_compose_locktime_panel(&w, &s);
        w.set_status("".into());
    });

    // Sweep/consolidate screen (16) locktime override panel — same
    // contract as the compose one above, reset on `set_sweep_dest`/
    // `open_notebook_consolidate`.
    cb!(on_set_sweep_locktime, |w, s, mode: SharedString, height: SharedString| {
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: sweep-locktime err=range");
            w.set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.tx_lock_time_override = Some(policy);
        let effective = s.effective_lock_time();
        println!("cb: sweep-locktime {} effective={effective} ok", policy.as_str());
        refresh_sweep_locktime_panel(&w, &s);
        w.set_status("".into());
    });

    // Compose "too large" dialog: raise the chunk size to Standard and reprice
    // the draft in place. Only offered when the note actually fits at Standard.
    cb!(on_oversize_bump, |w, s| {
        if let Some(store) = &mut s.store {
            store.chunk_size = DEFAULT_CHUNK;
        }
        s.save_store();
        println!("cb: set-chunk-size {DEFAULT_CHUNK} ok (oversize-bump)");
        w.set_chunk_text(DEFAULT_CHUNK.to_string().into());
        w.set_chunk_custom(false);
        w.set_show_oversize_modal(false);
        refresh_compose(&w, &mut s);
    });

    // Bitcoin node dropdown: a preset row writes its base (None = network
    // default) to the device config for this network; the two trailing
    // UI-managed rows — "Bitcoin Core" then "Custom…" (U12) — just reveal
    // their own text field (the Slint side already moved node-index) and
    // write nothing yet; the value follows when the user submits it via
    // set-node-address / set-node-custom respectively.
    cb!(on_set_node_preset, |w, s, i: i32| {
        let net = s.network.as_str().to_string();
        let presets = node_presets(s.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { s.node_urls.insert(net, url.to_string()); }
                None => { s.node_urls.remove(&net); }
            }
            s.save_config();
            println!("cb: set-node-preset {}", presets[i].0);
        } else if i == presets.len() {
            println!("cb: set-node-preset core");
        } else {
            println!("cb: set-node-preset custom");
        }
        w.set_status("".into());
        // Every preset is Esplora — this both clears a previously-active
        // Core node's credential fields/health line and is a no-op (no
        // network call) whenever the picker was already on Esplora.
        refresh_node_health(&w, &mut s);
    });

    // Bitcoin Core node-address field (U12): normalizes whatever a person
    // typed (bare host, host:port, http(s)://…, or a pasted `bitcoind+…`)
    // into the stored `bitcoind+http(s)://host:port` form via
    // `compose_core_url` — the `bitcoind+` scheme prefix is a storage
    // detail now, never something the user has to type or see. Inline
    // credentials are stripped and routed exactly like `set-node-custom`'s
    // paste path (never stored in the URL). On success the field is
    // rewritten to the canonical `display_core_url` form so what's on
    // screen always matches what got stored; on a malformed input nothing
    // is written and the field is left as typed so the user can fix it.
    cb!(on_set_node_address, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        match compose_core_url(t.trim(), s.network) {
            Ok((v, inline_creds)) => {
                s.node_urls.insert(net.clone(), v.clone());
                s.save_config();
                println!("cb: set-node-address {v}");
                if let Some((user, pass)) = &inline_creds {
                    let persist = s.core_rpc_should_persist(s.network);
                    let result = route_core_rpc_creds(
                        persist,
                        &net,
                        user,
                        pass,
                        &mut s.core_rpc_session_creds,
                        |u, p| keychain::store_rpc_creds(&net, u, p),
                        || keychain::delete_rpc_creds(&net),
                    );
                    match result {
                        Ok(()) => println!(
                            "cb: set-node-address inline-creds redacted stored=ok persist={persist}"
                        ),
                        Err(e) => {
                            println!("cb: set-node-address inline-creds redacted stored=err ({e})")
                        }
                    }
                }
                w.set_node_address_text(display_core_url(&v).into());
                w.set_status("".into());
            }
            Err(msg) => {
                println!("cb: set-node-address err={msg}");
                w.set_status(format!("Bitcoin node address: {msg}").into());
            }
        }
        refresh_node_health(&w, &mut s);
    });

    cb!(on_set_node_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        // Strip any inline `user:pass@` userinfo BEFORE it ever reaches
        // config.json or this `cb:` log line (plan §2.4 — "the stored node
        // URL must contain NO credentials"). A pasted
        // `bitcoind+http://user:pass@host:8332` is routed exactly like the
        // credential fields below (`route_core_rpc_creds` — Keychain when
        // the "Save credentials" switch is on, the session-only slot when
        // it's off, so a pasted credential can't become a persisted one
        // behind the user's back); the value that gets
        // stored/logged/displayed is always the creds-free form.
        let (v, inline_creds) = split_url_userinfo(t.trim());
        if v.is_empty() {
            s.node_urls.remove(&net);
        } else {
            s.node_urls.insert(net.clone(), v.clone());
        }
        s.save_config();
        println!("cb: set-node-custom {}", if v.is_empty() { "default" } else { &v });
        if let Some((user, pass)) = &inline_creds {
            let persist = s.core_rpc_should_persist(s.network);
            let result = route_core_rpc_creds(
                persist,
                &net,
                user,
                pass,
                &mut s.core_rpc_session_creds,
                |u, p| keychain::store_rpc_creds(&net, u, p),
                || keychain::delete_rpc_creds(&net),
            );
            match result {
                Ok(()) => println!(
                    "cb: set-node-custom inline-creds redacted stored=ok persist={persist}"
                ),
                Err(e) => println!("cb: set-node-custom inline-creds redacted stored=err ({e})"),
            }
        }
        w.set_status("".into());
        refresh_node_health(&w, &mut s);
    });

    // Bitcoin Core RPC credentials (plan §2.4/U6, extended by U10's "Save
    // credentials" switch): persisted in the Keychain ONLY while the switch
    // is on for this network — `keychain::{store,load,delete}_rpc_creds`,
    // under a distinct account namespace from the identity key. Off routes
    // to the session-only slot instead (`route_core_rpc_creds`); the
    // Keychain is never touched in that branch. Never written to
    // config.json, never logged (length only). Clearing both fields
    // deletes/clears the stored or session credential instead of writing
    // an empty one.
    cb!(on_set_node_core_creds, |w, s, user: SharedString, pass: SharedString| {
        let net = s.network.as_str().to_string();
        let user = user.trim().to_string();
        let pass = pass.to_string();
        let persist = s.core_rpc_should_persist(s.network);
        let result = route_core_rpc_creds(
            persist,
            &net,
            &user,
            &pass,
            &mut s.core_rpc_session_creds,
            |u, p| keychain::store_rpc_creds(&net, u, p),
            || keychain::delete_rpc_creds(&net),
        );
        match &result {
            Ok(()) => println!(
                "cb: set-node-core-creds ok user_len={} pass_len={} persist={persist}",
                user.len(),
                pass.len()
            ),
            Err(e) => println!("cb: set-node-core-creds err={e}"),
        }
        w.set_status(if result.is_ok() { "".into() } else { "couldn't save RPC credentials".into() });
        refresh_node_health(&w, &mut s);
    });

    // "Save credentials" switch (plan §2.4 / U10): default ON, so nobody who
    // already saved credentials sees a change. Turning it OFF immediately
    // deletes any stored Keychain item for this network — leaving a stale
    // secret behind after the user says "don't save" would be worse than
    // not having the feature — and keeps today's on-screen fields in the
    // session-only slot instead, so the user doesn't lose what they just
    // typed. Turning it back ON persists whatever is in hand (session slot
    // or the on-screen fields) and clears the session copy. A failed
    // Keychain op reverts the on-screen toggle rather than claiming
    // success.
    cb!(on_set_node_core_save_creds, |w, s, enabled: bool| {
        let net = s.network.as_str().to_string();
        let net_key = net.clone();
        let user = w.get_node_core_user().to_string();
        let pass = w.get_node_core_pass().to_string();
        let result = apply_core_rpc_persist_toggle(
            enabled,
            &user,
            &pass,
            || keychain::delete_rpc_creds(&net),
            |u, p| keychain::store_rpc_creds(&net, u, p),
        );
        match result {
            Ok(session) => {
                s.core_rpc_save_creds.insert(net_key.clone(), enabled);
                match session {
                    Some(entry) => {
                        s.core_rpc_session_creds.insert(net_key, entry);
                    }
                    None => {
                        s.core_rpc_session_creds.remove(&net_key);
                    }
                }
                s.save_config();
                println!("cb: set-node-core-save-creds {enabled} ok");
            }
            Err(e) => {
                w.set_node_core_save_creds(!enabled);
                println!("cb: set-node-core-save-creds {enabled} err={e}");
            }
        }
        update_node_backend_ui(&w, &s);
        refresh_node_health(&w, &mut s);
    });

    cb!(on_set_explorer_preset, |w, s, i: i32| {
        let net = s.network.as_str().to_string();
        let presets = explorer_presets(s.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { s.explorers.insert(net, url.to_string()); }
                None => { s.explorers.remove(&net); }
            }
            s.save_config();
            update_activity(&w, &s); // refresh live Explorer links
            println!("cb: set-explorer-preset {}", presets[i].0);
        } else {
            println!("cb: set-explorer-preset custom");
        }
        w.set_status("".into());
    });

    cb!(on_set_explorer_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        let v = t.trim().to_string();
        if v.is_empty() {
            s.explorers.remove(&net);
        } else {
            s.explorers.insert(net, v.clone());
        }
        s.save_config();
        update_activity(&w, &s); // refresh live Explorer links
        println!("cb: set-explorer-custom {}", if v.is_empty() { "default" } else { &v });
        w.set_status("".into());
    });

    // ---- Public keys (screen 18): derived from the SESSION-CACHED
    // material only — never a fresh biometric. Watch-only identities show
    // whatever public material `export_formats` yields (their `material`
    // IS the xpub/descriptor string itself, so this works unchanged).
    cb!(on_reveal_public, |w, s| {
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        let Some(material) = material else {
            w.set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
            w.set_reveal_fingerprint("".into());
            w.set_reveal_public_hint(
                "No key material cached this session — open Private keys once (it re-authenticates), or restart the app."
                    .into(),
            );
            w.set_screen(18);
            println!("cb: reveal-public no-material");
            return;
        };
        match app_core::keyexport::export_formats(&material, s.network, s.account, s.nb_index) {
            Ok(f) => {
                let mut rows: Vec<RevealRow> = Vec::new();
                if let Some(v) = f.account_xpub.as_deref() {
                    rows.push(RevealRow {
                        label: "Account xpub".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                if let Some(v) = f.descriptor.as_deref() {
                    rows.push(RevealRow {
                        label: "Descriptor (tr)".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                let fp_line = match f.fingerprint.as_deref() {
                    Some(fp) => format!("{fp} · account {}", s.account),
                    None => format!("account {}", s.account),
                };
                println!("cb: reveal-public ok rows={}", rows.len());
                w.set_reveal_fingerprint(fp_line.into());
                w.set_reveal_public_rows(VecModel::from_slice(&rows));
                // A single hex/WIF key import has a leaf key but no account
                // node — legitimately nothing public to export. Explain the
                // empty screen instead of leaving it blank.
                w.set_reveal_public_hint(if rows.is_empty() {
                    "This key has no account-level public material — a single hex/WIF import can't yield a watch-only xpub or descriptor.".into()
                } else {
                    "".into()
                });
            }
            Err(e) => {
                w.set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
                w.set_reveal_public_hint(format!("Couldn't derive public keys: {e}").into());
                println!("cb: reveal-public err");
            }
        }
        w.set_screen(18);
    });

    // ---- Private keys (screen 19): ALWAYS a fresh biometric — never the
    // session cache. Only on success do we derive + navigate; failures
    // surface as a status message on Settings (screen stays 8). Every
    // format this identity supports is derived up front and cached in
    // `s.reveal_formats` so the picker (`private-select`) never re-prompts
    // — but nothing is shown until the user taps a pill (progressive
    // disclosure).
    cb!(on_reveal_private, |w, s| {
        match keychain::reveal_secret(KEYCHAIN_ACCOUNT, "reveal your keys") {
            Ok(Some(secret)) => {
                match app_core::keyexport::export_formats(&secret, s.network, s.account, s.nb_index)
                {
                    Ok(f) => {
                        let fp_line = match f.fingerprint.as_deref() {
                            Some(fp) => format!("{fp} · account {}", s.account),
                            None => format!("account {}", s.account),
                        };
                        w.set_reveal_fingerprint(fp_line.into());
                        w.set_reveal_has_recovery(f.mnemonic.is_some());
                        w.set_reveal_has_xprv(f.account_xprv.is_some());
                        w.set_reveal_has_hex(f.leaf_hex.is_some());
                        w.set_reveal_has_wif(f.leaf_wif.is_some());
                        // Nothing selected yet — the screen shows only the
                        // pills until one is tapped.
                        w.set_reveal_private_format("".into());
                        w.set_reveal_private_value("".into());
                        w.set_reveal_private_qr(slint::Image::default());
                        w.set_reveal_words_col1("".into());
                        w.set_reveal_words_col2("".into());
                        w.set_reveal_show_seedqr(false);
                        w.set_reveal_seedqr_image(slint::Image::default());
                        // Hex/WIF picker: the active account's notebooks,
                        // defaulting to the active notebook. Hidden in the UI
                        // for recovery/xprv, but harmless to populate always.
                        w.set_reveal_nb_rows(VecModel::from_slice(&private_nb_rows(&s)));
                        w.set_reveal_nb_index(s.nb_index as i32);
                        println!("cb: reveal-private ok");
                        s.reveal_formats = Some(f);
                        w.set_status("".into());
                        w.set_screen(19);
                    }
                    Err(e) => {
                        println!("cb: reveal-private err");
                        w.set_status(format!("export: {e}").into());
                    }
                }
            }
            Ok(None) => {
                println!("cb: reveal-private no-key");
                w.set_status("(no key in keychain — APP_KEY env session?)".into());
            }
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-private cancelled");
                w.set_status("authentication cancelled".into());
            }
            Err(e) => {
                println!("cb: reveal-private err");
                w.set_status(format!("keychain: {e}").into());
            }
        }
    });

    // Switch which single format is on screen (progressive disclosure —
    // only one value visible at a time). Reads the formats derived at
    // reveal-private time; never re-authenticates. Hex/WIF derive from
    // whichever notebook the picker currently has selected (not always
    // the active notebook) so switching back to a pill after picking a
    // different notebook shows the right value.
    cb!(on_private_select, |w, s, fmt: SharedString| {
        let fmt = fmt.as_str();
        if fmt == "hex" || fmt == "wif" {
            let Some(v) = derive_leaf_value(&s, &w, fmt) else { return };
            w.set_reveal_show_seedqr(false);
            w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
            w.set_reveal_private_value(v.into());
            w.set_reveal_private_format(fmt.into());
            println!("cb: private-select fmt={fmt}");
            return;
        }
        let Some(f) = s.reveal_formats.as_ref() else { return };
        w.set_reveal_show_seedqr(false);
        match fmt {
            "recovery" => {
                let Some(words) = f.mnemonic.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                let list: Vec<&str> = words.split_whitespace().collect();
                let half = list.len() / 2;
                let col = |range: std::ops::Range<usize>| -> String {
                    range
                        .map(|i| format!("{:2}. {}", i + 1, list[i]))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                w.set_reveal_words_col1(col(0..half).into());
                w.set_reveal_words_col2(col(half..list.len()).into());
                if let Ok(m) = bip39::Mnemonic::parse(&words) {
                    let digits = app_core::seedqr::encode_standard(&m);
                    w.set_reveal_seedqr_image(qr::qr_image(&digits).unwrap_or_default());
                }
                w.set_reveal_private_value(words.into());
                w.set_reveal_private_qr(slint::Image::default());
            }
            "xprv" => {
                let Some(v) = f.account_xprv.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
                w.set_reveal_private_value(v.into());
            }
            // hex/wif are handled above (picker-aware, returns early).
            _ => return,
        }
        w.set_reveal_private_format(fmt.into());
        println!("cb: private-select fmt={fmt}");
    });

    // Hex/WIF only: switch the picker's selected notebook and re-derive
    // its leaf key from the session-cached material — NO re-auth. A no-op
    // for recovery/xprv (the picker is hidden for those, and the shown
    // format is index-independent anyway).
    cb!(on_private_pick_notebook, |w, s, index: i32| {
        w.set_reveal_nb_index(index);
        println!("cb: private-pick-notebook index={index}");
        let fmt = w.get_reveal_private_format().to_string();
        if fmt != "hex" && fmt != "wif" {
            return;
        }
        let Some(v) = derive_leaf_value(&s, &w, &fmt) else { return };
        w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
        w.set_reveal_private_value(v.into());
    });

    cb!(on_copy_value, |w, s, value: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_text(value.as_str());
        println!("cb: copy-value len={}", value.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    // Spending material (audit M3) — concealed/local-only/expiring clipboard,
    // never the plain broadcast one. Length only, as ever; never the value.
    cb!(on_copy_secret, |w, s, value: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_secret(value.as_str());
        println!("cb: copy-secret len={}", value.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(on_go_home, |w, s| {
        clear_reveal(&w, &mut s);
        go_home_or_list(&w, &s);
    });

    cb!(on_open_notebooks, |w, s| {
        // Leaving the open notebook: everything that was on screen counts
        // as read, so the list badge only flags what arrived since.
        if let Some(store) = s.store.as_mut() {
            if store.mark_seen() > 0 {
                s.save_store();
            }
        }
        w.set_status("".into());
        update_notebook_list(&w, &s);
        w.set_screen(17);
    });

    cb!(on_open_notebook, |w, s, index: i32| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        s.nb_index = index.max(0) as u32;
        println!("cb: open-notebook index={}", s.nb_index);
        match activate(&mut s, &material, false) {
            Ok(()) => {
                update_home(&w, &s);
                w.set_screen(4); // paint first — the scan runs in the background
                refresh_async(&w, &mut s);
                spending_refresh_async(&w, &mut s); // CHANGE 5: was missing — Sal's finding
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_create_notebook, |w, s| {
        // Address-first, then name-first: "+ New notebook" opens the
        // account picker (used/new pills + balances) so recovering a used
        // address is a visible choice; the naming dialog follows the pick.
        // Nothing is derived or persisted until the dialog's Create.
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        if !is_multi_notebook(&material, s.network) {
            return; // button is hidden; a stray call must not add phantom rows
        }
        println!("cb: create-notebook picker open");
        w.set_nb_create_name("".into());
        show_notebook_picker(&w, &s, 0, "notebook");
    });

    cb!(on_nb_rename_start, |w, s, index: i32, _display: SharedString| {
        let _ = &mut s;
        // Prefill the RAW local name (the display name may be the address
        // short form, which must not become a name by accident).
        let raw = s
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(s.account, index.max(0) as u32))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        w.set_nb_rename_input(raw.into());
        w.set_nb_rename_index(index);
    });

    cb!(on_nb_rename_save, |w, s, name: SharedString| {
        let sel = w.get_nb_rename_index();
        if sel < 0 {
            return;
        }
        w.set_nb_rename_index(-1);
        w.set_nb_rename_input("".into());
        let index = sel as u32;
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.rename(account, index, name.as_str());
            s.save_notebooks();
            println!("cb: rename-notebook index={index}");
        }
        update_notebook_list(&w, &s);
        if s.ident.as_ref().map(|i| i.index) == Some(index) {
            w.set_notebook_title(s.notebook_display_name(index).into());
        }
    });

    cb!(on_nb_rename_cancel, |w, s| {
        let _ = &mut s;
        w.set_nb_rename_index(-1);
        w.set_nb_rename_input("".into());
    });

    cb!(on_nb_archive, |w, s, index: i32, archived: bool| {
        let index = index.max(0) as u32;
        if s.notebooks.is_none() {
            return;
        }
        if archived {
            // One guard only: funds never disappear from view silently —
            // sweep first. Archiving EVERY notebook is allowed (the list
            // shows its empty state); Restore brings any of them back.
            let balance = notebook_store(&s, index).map(|st2| st2.balance()).unwrap_or(0);
            if balance > 0 {
                w.set_status(
                    format!(
                        "this notebook holds {} sats — consolidate the wallet first (Coins)",
                        commas(balance)
                    )
                    .into(),
                );
                return;
            }
        }
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.set_archived(account, index, archived);
            s.save_notebooks();
            println!("cb: archive-notebook index={index} archived={archived}");
        }
        w.set_status("".into());
        update_notebook_list(&w, &s);
    });

    cb!(on_toggle_sender, |w, s, key: SharedString, excluded: bool| {
        let Some(store) = s.store.as_mut() else { return };
        store.set_excluded(key.as_str(), excluded);
        let hidden = store.excluded_senders.len();
        println!("cb: toggle-sender excluded={excluded} hidden={hidden}");
        s.save_store();
        update_home(&w, &s);
    });

    let auto_refresh = slint::Timer::default();
    {
        let st = st.clone();
        let weak = window.as_weak();
        auto_refresh.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(60),
            move || {
                if let Some(w) = weak.upgrade() {
                    if w.get_screen() == 4 {
                        let mut s = st.borrow_mut();
                        if s.ident.is_some() {
                            // MUST be the async refresh: slint timers keep
                            // firing while the app is BACKGROUNDED, and a
                            // blocking chain call here parks the main thread
                            // inside a timer callback — iOS's scene-update
                            // watchdog then kills the app (0x8BADF00D, the
                            // builds 3–9 "crashed in the background /
                            // after resuming" reports; root-caused from
                            // device .ips logs 2026-07-19).
                            println!("cb: auto-refresh");
                            refresh_async(&w, &mut s);
                        }
                    }
                }
            },
        );
    }

    // Design-preview harness: `CN_PREVIEW=<screen>` boots straight into a
    // funding screen with mock data so the UI can be screenshotted and
    // iterated without wiring or clicking through onboarding. Dev-only.
    if let Ok(scr) = std::env::var("CN_PREVIEW") {
        if let Ok(n) = scr.parse::<i32>() {
            preview_mock(&window);
            window.set_screen(n);
        }
    }

    // Apply safe-area insets (iOS status bar / Dynamic Island / home
    // indicator; Android status/nav bars). Applied on the very first
    // event-loop ticks (0/100/250 ms) so the layout is positioned correctly
    // from the first painted frame — no visible "slide down" on cold start —
    // with a couple of quick retries covering the window/insets not being
    // ready at tick 0. Then polled at a slow cadence for rotation. No-op on
    // desktop (returns 0,0). The timer is kept alive for the run's lifetime.
    for delay_ms in [0_u64, 16, 50, 100, 250] {
        let w = window.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(delay_ms), move || {
            if let Some(win) = w.upgrade() {
                apply_safe_area(&win);
            }
        });
    }
    // Fallback: reveal the UI after a short delay no matter what, so the splash
    // cover can never stick if the inset never reports a value.
    {
        let w = window.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
            if let Some(win) = w.upgrade() {
                win.set_ready(true);
            }
        });
    }
    let safe_area_timer = slint::Timer::default();
    {
        let w = window.as_weak();
        safe_area_timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(500),
            move || {
                if let Some(win) = w.upgrade() {
                    apply_safe_area(&win);
                }
            },
        );
    }

    // iCloud-contacts feature: live cross-device sync while this device is
    // already running (boot-time sync happened above, before the window
    // existed). A no-op registration off Apple platforms, or when the OS
    // has no entitlement/iCloud account (see icloud.rs) — the callback can
    // fire on any thread, so it only ever schedules the real work back onto
    // the UI thread via the same upgrade_in_event_loop trampoline every
    // other async result uses.
    {
        let weak = window.as_weak();
        icloud::start_observer(move || {
            let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_icloud_contacts());
        });
    }

    window.run().expect("event loop");
    let _ = safe_area_timer;
}

/// Populate every external-funding screen with representative mock data for
/// the `CN_PREVIEW` design harness.
fn preview_mock(w: &AppWindow) {
    w.set_directed(true);
    w.set_gift_sats("330".into());
    w.set_backup_words(
        " 1. legal      2. winner    3. thank\n 4. year       5. wave      6. sausage\n 7. worth      8. useful    9. dawn\n10. absorb    11. pledge   12. yellow\n"
            .into(),
    );
    w.set_fund_external(true);
    w.set_funding_ready(true);
    w.set_funding_summary("taproot · bcrt1p2caq…6hrewe · 2 coins · 220,000 sats".into());
    w.set_change_amount("Change to funding wallet".into());
    w.set_funding_descriptor("tr([a1b2c3d4/86h/1h/0h]tpub…/<0;1>/*)".into());
    w.set_funding_feedback(
        "Taproot wallet · fingerprint a1b2c3d4 · first address\nbcrt1p2caqg0ht8m7dykfrx2lnrcc85kxs09m3vgur9fl6emljxktnu7es6hrewe"
            .into(),
    );
    w.set_funding_valid(true);
    w.set_to_label("bcrt1pxs94vakt8gnq…rqmeyu58".into());
    w.set_compose_text("Happy birthday! Paid from cold storage.".into());
    w.set_rate_text("2".into());
    // Worst case on purpose: EVERY row of the structured cost card
    // populated, including the dust-rule fold split (Sal's build-17
    // follow-up — the card replaced the long wrapped cost-line string).
    set_cost_card(
        w,
        "1 chunk · ~180 vB".to_string(),
        "~360 sats (~$0.26)".to_string(),
        "+330 sats".to_string(),
        "+330 sats".to_string(),
        Some((227, 587)),
    );

    let coins = [
        SpendCoin { outpoint: "aa:0".into(), value: "200,000".into(), confirmed: true, selected: true, txid_short: "aaaa…aaaa".into(), explorer: "".into(), tag: "".into() },
        SpendCoin { outpoint: "bb:1".into(), value: "20,000".into(), confirmed: false, selected: false, txid_short: "bbbb…bbbb".into(), explorer: "".into(), tag: "".into() },
    ];
    w.set_spend_coins(VecModel::from_slice(&coins));
    w.set_spend_title("Spending 1 coin · 200,000 sats".into());
    w.set_spend_expanded(true);

    w.set_psbt_qr(qr::qr_image("UR:CRYPTO-PSBT/1-1/HKADCSJNCPFGAXHDMOCKPREVIEWFRAME").unwrap_or_default());
    w.set_psbt_cost_line("fee 360 sats · 1 input · 180 vB".into());
    w.set_psbt_frame_label("frame 1 / 1".into());

    w.set_psbt_signed(true);
    w.set_confirm_note("Happy birthday! Paid from cold storage.".into());
    w.set_confirm_fee_line("360 sats · 2.0 sat/vB".into());
    w.set_confirm_locktime_line("Locktime 146209 · block height".into());
    w.set_confirm_warn("".into());
    w.set_confirm_txid("aaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbbccccccccdddddddd".into());
    w.set_confirm_context("Directed note · regtest".into());
    let ins = [PsbtRow {
        title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc85kx…".into(),
        subtitle: "aaaaaaaa…aaaaaaaa : 0".into(),
        amount: "200,000".into(),
        kind: "input".into(),
    }];
    w.set_confirm_inputs(VecModel::from_slice(&ins));
    let outs = [
        PsbtRow { title: "".into(), subtitle: "OP_RETURN · PNTE note".into(), amount: "0".into(), kind: "note".into() },
        PsbtRow { title: "bcrt1pxs94vakt8gnqrwhuxdscwkx5e…".into(), subtitle: "directed recipient".into(), amount: "330".into(), kind: "recipient".into() },
        PsbtRow { title: "bcrt1p8wpt9v4frpf3tkn0srd97pks…".into(), subtitle: "your notebook (keeps the note yours)".into(), amount: "330".into(), kind: "self".into() },
        PsbtRow { title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc…".into(), subtitle: "change back to the funding wallet".into(), amount: "198,980".into(), kind: "change".into() },
    ];
    w.set_confirm_outputs(VecModel::from_slice(&outs));

    let wallets = [
        FundingWalletRow { id: "aa".into(), label: "Signer · bc1p5cyxnux…".into(), meta: "taproot · 220,000 sats · 2 coins".into(), active: true, change_addr: "bc1p3qkhfe…uhk7".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
        FundingWalletRow { id: "bb".into(), label: "Sparrow hot wallet".into(), meta: "segwit · 45,000 sats · 1 coin".into(), active: false, change_addr: "bc1qm34ls…dqfw".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
        FundingWalletRow { id: "cc".into(), label: "segwit · tb1qr8k2p9…".into(), meta: "segwit · tap to scan for funds".into(), active: false, change_addr: "".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
    ];
    w.set_funding_wallets(VecModel::from_slice(&wallets));
}

/// Render each screen to `<out_dir>/screen-<n>.png` via the software renderer,
/// with no on-screen window — for headless design iteration. macOS-only.
#[cfg(target_os = "macos")]
fn render_previews(w: u32, h: u32, screens: &[i32], out_dir: &str) {
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
    use std::rc::Rc;

    struct HeadlessPlatform {
        win: Rc<MinimalSoftwareWindow>,
    }
    impl slint::platform::Platform for HeadlessPlatform {
        fn create_window_adapter(
            &self,
        ) -> Result<Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
            Ok(self.win.clone())
        }
    }

    let win = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(HeadlessPlatform { win: win.clone() }))
        .expect("set_platform");
    let app = AppWindow::new().expect("window");
    win.set_size(slint::PhysicalSize::new(w, h));
    // No safe-area pass runs headless — lift the splash cover directly.
    app.set_ready(true);

    for &n in screens {
        preview_mock(&app);
        app.set_screen(n);
        slint::platform::update_timers_and_animations();
        win.request_redraw();
        let mut buf = vec![Rgb565Pixel(0); (w * h) as usize];
        win.draw_if_needed(|renderer| {
            renderer.render(&mut buf, w as usize);
        });
        // Rgb565 → RGB8.
        let mut rgb = Vec::with_capacity((w * h * 3) as usize);
        for px in &buf {
            let v = px.0;
            let r = ((v >> 11) & 0x1f) as u8;
            let g = ((v >> 5) & 0x3f) as u8;
            let b = (v & 0x1f) as u8;
            rgb.push((r << 3) | (r >> 2));
            rgb.push((g << 2) | (g >> 4));
            rgb.push((b << 3) | (b >> 2));
        }
        let path = format!("{out_dir}/screen-{n}.png");
        let file = std::fs::File::create(&path).expect("create png");
        let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header().unwrap().write_image_data(&rgb).unwrap();
        eprintln!("rendered screen {n} -> {path}");
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::getrandom(buf).map_err(|_| ())
}

/// Android entry point. NativeActivity (via android-activity, which
/// Slint's backend wraps) calls this instead of `fn main`. There is no
/// `HOME` and no CLI args on Android, so we point the store at the app's
/// private internal storage before handing off to the shared `run()`.
#[cfg(target_os = "android")]
static ANDROID_APP: std::sync::OnceLock<slint::android::AndroidApp> = std::sync::OnceLock::new();

/// The `AndroidApp` handle, stashed in `android_main`, so `platform::
/// safe_area_insets` can read the content rect (status-bar / nav-bar insets).
#[cfg(target_os = "android")]
pub(crate) fn android_app() -> Option<&'static slint::android::AndroidApp> {
    ANDROID_APP.get()
}

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    if let Some(path) = app.internal_data_path() {
        std::env::set_var("APP_DATA_DIR", path);
    }
    // Keep a handle for safe-area insets (content_rect); AndroidApp is a
    // cheap clonable handle.
    let _ = ANDROID_APP.set(app.clone());
    // Stash the JavaVM + Activity so the keystore/camera JNI backends can
    // reach them (ndk-context is populated by android-activity at startup;
    // this is a belt-and-suspenders no-op if already set).
    slint::android::init(app).expect("slint android init");
    run();
}
