//! Async result-queue plumbing — moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md); U5 replaces the queue statics with one
//! generic type.

use crate::*;

/// Process-global "how many logical network operations are in flight"
/// counter, driving the ambient `net-busy` dot beside a screen's title
/// (`NetDot` in app.slint). Every worker thread that touches
/// `ChainClient`/transport constructs a [`NetOpGuard`] as its first line —
/// it increments on creation and decrements on `Drop`, so every early
/// return/error path still clears it. Counts LOGICAL operations, not
/// individual HTTP requests (a single refresh/broadcast issues several —
/// per-request toggling would flicker as requests are paced/slower).
pub(crate) static NET_OPS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard for one logical network operation — see [`NET_OPS`]. Push
/// the new busy state to the UI thread via the same `slint::Weak` +
/// `upgrade_in_event_loop` trampoline every async worker already uses
/// (`REFRESH_RESULTS` et al.); logs `cb: net-ops n=<count>` ONLY on the
/// 0→1 and →0 transitions (counts only, matching the `cb:` log contract —
/// never per-request).
pub(crate) struct NetOpGuard {
    pub(crate) weak: slint::Weak<AppWindow>,
}

impl NetOpGuard {
    pub(crate) fn new(weak: slint::Weak<AppWindow>) -> Self {
        let prev = NET_OPS.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("cb: net-ops n=1");
            let w = weak.clone();
            let _ = w.upgrade_in_event_loop(|w| w.global::<Ui>().set_net_busy(true));
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
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().set_net_busy(false));
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
/// [`SCAN_LANE`]'s guarded state: the admission-rule lane plus the queued
/// jobs it has admitted but not yet run, keyed by their `JobId`.
pub(crate) type ScanLaneState = (app_core::netq::Lane, HashMap<app_core::netq::JobId, Box<dyn FnOnce() + Send>>);

pub(crate) static SCAN_LANE: std::sync::LazyLock<std::sync::Mutex<ScanLaneState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new((app_core::netq::Lane::new(), HashMap::new())));

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
pub(crate) fn scan_lane_submit(key: String, job: impl FnOnce() + Send + 'static) -> bool {
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
pub(crate) fn spawn_scan_lane_worker(id: app_core::netq::JobId, key: String, job: Box<dyn FnOnce() + Send>) {
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

/// One finished background scan, waiting to be applied on the UI thread.
/// `address` guards staleness: if the user switched notebooks while the
/// worker ran, the result is dropped (apply_bundle would refuse anyway —
/// this just keeps the failure silent and correct).
pub(crate) struct RefreshResult {
    pub(crate) address: String,
    /// `None` = the `/address/:a` stats pre-check short-circuited: nothing
    /// moved since the store's stamped fingerprint, so no bundle (or
    /// pending/dropped checks) was ever fetched — the apply half just
    /// stamps fresh fees and reports "up to date" (429 politeness,
    /// 2026-07-20).
    pub(crate) bundle: Option<Result<app_core::notes_core::bundle::SyncBundle, String>>,
    /// Fresh `/address/:a` stats to stamp into the store after a successful
    /// full apply — `None` when the pre-check endpoint failed or is
    /// unsupported (regtest server.py), which never blocks the scan itself.
    pub(crate) new_stats: Option<AddrStats>,
    /// (txid, confirmed?) for the pending sweep/consolidate records that
    /// existed at snapshot time — fetched on the worker so
    /// resolve_spend_statuses never blocks the UI thread.
    pub(crate) statuses: Vec<(String, Option<bool>)>,
    /// Task #14 (dropped-pending detection): every PENDING record's
    /// (notes AND sweep/consolidate) CURRENT-txid lookup result, gathered
    /// on the worker thread alongside `statuses` — see
    /// [`gather_dropped_checks`] / [`fetch_dropped_checks`].
    pub(crate) dropped_lookup: HashMap<String, TxLookupStatus>,
    /// Populated only for entries whose lookup came back `NotFound` —
    /// keyed by the record's first spent input (txid, vout).
    pub(crate) dropped_unspent: HashMap<(String, u32), bool>,
}

pub(crate) static REFRESH_RESULTS: std::sync::Mutex<Vec<RefreshResult>> = std::sync::Mutex::new(Vec::new());

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
pub(crate) fn open_client(
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
pub(crate) fn open_client_watched(
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

/// Which ↻ tap kicked off a [`wallet_stores_refresh_async`] scan — drives
/// the final `cb: refresh-coins|refresh-notebooks notebooks=<n>` log label
/// and each tap's own post-scan UI work in
/// `apply_wallet_stores_refresh_results`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletStoresPurpose {
    Coins,
    Notebooks,
}

/// One active notebook's bundle fetch, gathered on the worker thread —
/// part of a [`WalletStoresRefreshResult`].
pub(crate) struct NotebookBundleResult {
    pub(crate) index: u32,
    pub(crate) bundle: Result<app_core::notes_core::bundle::SyncBundle, String>,
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
pub(crate) struct WalletStoresRefreshResult {
    pub(crate) purpose: WalletStoresPurpose,
    pub(crate) fp8: String,
    pub(crate) network: Network,
    pub(crate) account: u32,
    pub(crate) current_index: Option<u32>,
    pub(crate) current_address: Option<String>,
    /// (txid, confirmed?)/dropped-check results for the snapshot-time
    /// active notebook only — same shape as [`RefreshResult`]'s fields,
    /// gathered so applying its slice matches `refresh()`/
    /// `apply_refresh_results` exactly.
    pub(crate) current_statuses: Vec<(String, Option<bool>)>,
    pub(crate) current_dropped_lookup: HashMap<String, TxLookupStatus>,
    pub(crate) current_dropped_unspent: HashMap<(String, u32), bool>,
    /// Every active notebook's bundle fetch, including the snapshot-time
    /// active one.
    pub(crate) results: Vec<NotebookBundleResult>,
    /// Taproot change-chain gap walk (unit 3, `../PLAN-chain-notes-app-taproot-change.md`) —
    /// `scan_change_chain` gap 1, account-level (folded into the SAME
    /// (fp8, network, account) staleness guard the notebook results use
    /// above, so no separate guard is needed on apply). `Err` on a
    /// transport/parse failure; empty `Ok` for watch/WIF/hex material
    /// (no change chain to walk) or when no material was cached this
    /// session.
    pub(crate) change: Result<Vec<ChangeCoin>, String>,
}

pub(crate) static WALLET_STORES_REFRESH_RESULTS: std::sync::Mutex<Vec<WalletStoresRefreshResult>> =
    std::sync::Mutex::new(Vec::new());

/// One finished notebook gap-discovery walk (worker thread), waiting to be
/// applied on the UI thread. The identity/network/account snapshot guards
/// staleness — switching identities mid-probe drops the result.
pub(crate) struct DiscoveryResult {
    pub(crate) fp8: String,
    pub(crate) network: Network,
    pub(crate) account: u32,
    pub(crate) found: Vec<u32>,
}

pub(crate) static DISCOVERY_RESULTS: std::sync::Mutex<Vec<DiscoveryResult>> = std::sync::Mutex::new(Vec::new());

/// A finished rebroadcast raw-hex fetch (`on_act_retry`'s sub-case (b): a
/// chain-recovered/watch record with no locally cached hex) — waiting to
/// enter the universal confirm screen on the UI thread. Mirrors
/// `SpendingRefreshResult`'s staleness pattern, anchored on the identity
/// address (switching identity mid-fetch drops the result rather than
/// misapplying it).
pub(crate) struct RebroadcastFetchResult {
    pub(crate) ref_id: String,
    pub(crate) is_note: bool,
    pub(crate) identity_addr: String,
    pub(crate) result: Result<String, String>,
}

pub(crate) static REBROADCAST_FETCH_RESULTS: std::sync::Mutex<Vec<RebroadcastFetchResult>> =
    std::sync::Mutex::new(Vec::new());

/// A finished Activity Rebroadcast (`on_act_retry`) broadcast POST, waiting
/// to be applied on the UI thread — clears `State.act_pending_ref` and
/// shows the toast (2026-07-16: rebroadcast used to give no feedback at
/// all, "like nothing happened", per Sal).
pub(crate) struct ActRetryResult {
    pub(crate) ref_id: String,
    pub(crate) result: Result<String, String>,
}

pub(crate) static ACT_RETRY_RESULTS: std::sync::Mutex<Vec<ActRetryResult>> = std::sync::Mutex::new(Vec::new());

/// A finished Activity Speed-up (`on_act_bump_confirm`) broadcast POST. The
/// re-sign (bump_*_build at stage A, record_bumped_* + save at the
/// Broadcast tap) already ran synchronously and
/// saved the store BEFORE this — same "record already saved" shape as the
/// notebook compose path — so a broadcast failure here needs no navigation
/// (the bump dialog already closed onto the Activity screen); only status +
/// toast + a refresh.
pub(crate) struct ActBumpResult {
    pub(crate) ref_id: String,
    pub(crate) txid: String,
    pub(crate) fee: u64,
    pub(crate) new_rate: f64,
    pub(crate) result: Result<String, String>,
}

pub(crate) static ACT_BUMP_RESULTS: std::sync::Mutex<Vec<ActBumpResult>> = std::sync::Mutex::new(Vec::new());

/// Non-`result` half of [`SweepBroadcastResult`] — built on the UI thread
/// before spawning (owns everything the apply side needs), moved into the
/// worker, then wrapped with the real broadcast result and pushed. `Clone`
/// so it can also ride in `PendingPayload::Sweep` (universal confirm
/// screen, funding-unification follow-up 2026-07-17).
#[derive(Clone)]
pub(crate) struct SweepSnapshot {
    /// The active notebook's address at spawn time — if it no longer
    /// matches on the apply side (identity/account/notebook switched
    /// mid-flight), the tx is already on-chain but its bookkeeping is
    /// dropped (logged `stale-drop`) rather than misapplied to the WRONG
    /// store; the next refresh's UTXO scan still reconciles balances.
    pub(crate) identity_addr: String,
    pub(crate) dest: String,
    pub(crate) dest_spk_hex: String,
    pub(crate) value: u64,
    pub(crate) fee: u64,
    pub(crate) vsize: u64,
    pub(crate) raw_hex: String,
    /// Per-notebook lock list: (notebook index, [(txid display-hex, vout)]).
    pub(crate) notebook_locks: Vec<(u32, Vec<(String, u32)>)>,
    pub(crate) all_inputs: Vec<app_core::store::TxInput>,
    /// Empty for a MIXED sweep (`TxRecord.mixed_inputs` — CHANGE 2): no
    /// per-input owner scheme covers both input kinds, so a mixed record
    /// can't be bumped either.
    pub(crate) input_indexes: Vec<u32>,
    pub(crate) mixed: bool,
    /// CHANGE 2: spending-wallet coins that rode as inputs — pruned from
    /// the runtime cache and re-scanned on success.
    pub(crate) spending_spent: Vec<(String, u32)>,
    /// Sweeping notebook funds INTO the spending wallet's next receive
    /// address (`on_spending_sweep_here`) — marked used on success.
    pub(crate) pending_spending_sweep_index: Option<u32>,
    pub(crate) notebooks_n: usize,
    /// Taproot CHANGE-chain coins (`m/86'/…/1/{index}`) that rode as
    /// inputs — pruned from `State.change_coins` on success (unit 6, see
    /// `../PLAN-chain-notes-app-taproot-change.md`), same treatment as
    /// `spending_spent` above: the next wallet-stores refresh re-scans
    /// chain 1 and would otherwise re-offer an already-spent coin.
    pub(crate) change_spent: Vec<(String, u32)>,
}

pub(crate) struct SweepBroadcastResult {
    pub(crate) snap: SweepSnapshot,
    pub(crate) result: Result<String, String>,
}

pub(crate) static SWEEP_BROADCAST_RESULTS: std::sync::Mutex<Vec<SweepBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

/// Non-`result` half of a single-notebook consolidate broadcast (screen 16,
/// kind "consolidate") — same shape as [`SweepSnapshot`], one store instead
/// of many. `Clone` for `PendingPayload::Consolidate`.
#[derive(Clone)]
pub(crate) struct ConsolidateSnapshot {
    pub(crate) identity_addr: String,
    pub(crate) value: u64,
    pub(crate) fee: u64,
    pub(crate) vsize: u64,
    pub(crate) raw_hex: String,
    pub(crate) dest_spk_hex: String,
    pub(crate) inputs: Vec<app_core::store::TxInput>,
}

pub(crate) struct ConsolidateBroadcastResult {
    pub(crate) snap: ConsolidateSnapshot,
    pub(crate) result: Result<String, String>,
}

pub(crate) static CONSOLIDATE_BROADCAST_RESULTS: std::sync::Mutex<Vec<ConsolidateBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

/// Non-`result` half of a wallet-consolidate broadcast (Settings/Coins →
/// "Consolidate wallet…", keyed non-watch path) — spans potentially several
/// SOURCE notebook stores plus a DESTINATION store, so its staleness anchor
/// is the identity/network/account triple (`fp8`), same guard shape as
/// [`SpendingRefreshResult`], not a single notebook address. `Clone` for
/// `PendingPayload::WConsol`.
#[derive(Clone)]
pub(crate) struct WConsolSnapshot {
    pub(crate) fp8: String,
    pub(crate) network: Network,
    pub(crate) account: u32,
    pub(crate) dest_index: u32,
    pub(crate) dest_spk_hex: String,
    pub(crate) value: u64,
    pub(crate) fee: u64,
    pub(crate) vsize: u64,
    pub(crate) raw_hex: String,
    /// (source notebook index, [(txid display-hex, vout)]) — mirrors
    /// `SweepSnapshot.notebook_locks`.
    pub(crate) source_locks: Vec<(u32, Vec<(String, u32)>)>,
    pub(crate) all_inputs: Vec<app_core::store::TxInput>,
    pub(crate) input_indexes: Vec<u32>,
    pub(crate) sources_n: usize,
}

pub(crate) struct WConsolBroadcastResult {
    pub(crate) snap: WConsolSnapshot,
    pub(crate) result: Result<String, String>,
}

pub(crate) static WCONSOL_BROADCAST_RESULTS: std::sync::Mutex<Vec<WConsolBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

/// Non-`result` half of a psbt-broadcast (screen 14 "Broadcast" — the
/// watch/external-sign flow's finalize+broadcast button, also used by
/// plain external-funding compose with no watch bookkeeping at all).
/// `finalize_extract` runs synchronously (local, fast) BEFORE spawning, so
/// `txid`/`raw`/`vsize` are already final — only the broadcast POST itself
/// is async. `identity_addr` is the staleness anchor; on a mismatch the
/// pending `watch_note`/`watch_spend` bookkeeping is dropped too (cleared,
/// not left to misapply against a switched-to identity next time).
pub(crate) struct PsbtBroadcastSnapshot {
    pub(crate) identity_addr: String,
    pub(crate) txid: String,
    pub(crate) raw: String,
    pub(crate) vsize: usize,
}

pub(crate) struct PsbtBroadcastResult {
    pub(crate) snap: PsbtBroadcastSnapshot,
    pub(crate) result: Result<String, String>,
}

pub(crate) static PSBT_BROADCAST_RESULTS: std::sync::Mutex<Vec<PsbtBroadcastResult>> =
    std::sync::Mutex::new(Vec::new());

/// Non-`result` half of a spending-wallet consolidate broadcast (CHANGE 3,
/// Coins screen spending segment "Consolidate spending coins…") — merges
/// EVERY spending coin into one, at the next fresh spending receive
/// address, signed in-app (no external wallet). Staleness anchor is the
/// identity/network/account triple, like [`WConsolSnapshot`] (the spending
/// section lives at the account level, not a single notebook). `Clone` for
/// `PendingPayload::SpendingConsolidate`.
#[derive(Clone)]
pub(crate) struct SpendingConsolidateSnapshot {
    pub(crate) fp8: String,
    pub(crate) network: Network,
    pub(crate) account: u32,
    /// The receive index consolidated INTO — marked used on success.
    pub(crate) dest_index: u32,
    pub(crate) dest_addr: String,
    pub(crate) dest_spk_hex: String,
    pub(crate) value: u64,
    pub(crate) fee: u64,
    pub(crate) vsize: u64,
    pub(crate) raw_hex: String,
    /// Every spending coin that rode as an input (outpoint + value) —
    /// pruned from the runtime cache on success.
    pub(crate) spent: Vec<(String, u32, u64)>,
}

pub(crate) struct SpendingConsolidateResult {
    pub(crate) snap: SpendingConsolidateSnapshot,
    pub(crate) result: Result<String, String>,
}

pub(crate) static SPENDING_CONSOLIDATE_RESULTS: std::sync::Mutex<Vec<SpendingConsolidateResult>> =
    std::sync::Mutex::new(Vec::new());

/// Notebook path (`on_compose_send`): `compose_and_record` already wrote the
/// note Pending + locked its inputs BEFORE broadcast was attempted (existing
/// invariant), so a broadcast failure is never a build/sign failure —
/// staying on compose would risk a double-compose. Land on Activity instead
/// (Rebroadcast is right there for the already-saved record).
pub(crate) struct NotebookComposeResult {
    pub(crate) note_id: String,
    pub(crate) fee: u64,
    pub(crate) vsize: usize,
    pub(crate) to: Option<String>,
    pub(crate) private: bool,
    /// `ComposedNote.pq_flags` — 0 for every ordinary note. Logged
    /// separately (`cb: pq-compose flags=<n>`) rather than appended to the
    /// `cb: compose` line itself, since that line's field order is a
    /// de-facto e2e grep contract (see the CLAUDE.md rule).
    pub(crate) pq_flags: u8,
    pub(crate) result: Result<String, String>,
}

pub(crate) static NOTEBOOK_COMPOSE_RESULTS: std::sync::Mutex<Vec<NotebookComposeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Spending-wallet path (`on_spending_compose_send`): unlike the notebook
/// path, nothing is recorded until broadcast actually succeeds — a failure
/// leaves the draft exactly as it was, so staying on compose to retry is
/// safe (no double-compose risk, nothing was locked).
pub(crate) struct SpendingComposeResult {
    pub(crate) text: String,
    pub(crate) private: bool,
    pub(crate) to: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`.
    pub(crate) recipients: Vec<String>,
    pub(crate) gift: u64,
    pub(crate) raw: String,
    pub(crate) txid: String,
    pub(crate) vsize: usize,
    pub(crate) built_fee: u64,
    pub(crate) built_change: u64,
    pub(crate) spent_outpoints: Vec<(String, u32)>,
    pub(crate) change_index: u32,
    pub(crate) change_raw: String,
    pub(crate) source: FundingSource,
    pub(crate) result: Result<String, String>,
}

pub(crate) static SPENDING_COMPOSE_RESULTS: std::sync::Mutex<Vec<SpendingComposeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Mixed-source path (`on_compose_send_mixed`): same "nothing recorded until
/// broadcast succeeds" shape as spending — a failure is safe to retry from
/// compose.
pub(crate) struct MixedComposeResult {
    pub(crate) text: String,
    pub(crate) private: bool,
    pub(crate) to: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`.
    pub(crate) recipients: Vec<String>,
    pub(crate) gift: u64,
    pub(crate) raw: String,
    pub(crate) txid: String,
    pub(crate) vsize: usize,
    pub(crate) built_fee: u64,
    pub(crate) built_change: u64,
    pub(crate) change_default: app_core::mixed::ChangeDefault,
    pub(crate) notebook_spent: Vec<app_core::store::OutPointRef>,
    pub(crate) spent_spending: Vec<(String, u32)>,
    /// Taproot CHANGE-chain coins ridden as inputs (unit 5) — pruned from
    /// `State.change_coins` on success, same treatment as `spent_spending`.
    pub(crate) change_spent: Vec<(String, u32)>,
    pub(crate) payloads_len: usize,
    pub(crate) recipient_count: usize,
    pub(crate) change_index: u32,
    pub(crate) spending_source: Option<FundingSource>,
    pub(crate) result: Result<String, String>,
}

pub(crate) static MIXED_COMPOSE_RESULTS: std::sync::Mutex<Vec<MixedComposeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Finished used/new address probes for the create-notebook picker (worker
/// thread). Applied to the picker rows on the UI thread; the (account, page)
/// snapshot guards staleness — paging or switching account/screen drops it.
pub(crate) struct PickerProbeResult {
    pub(crate) account: u32,
    pub(crate) page: u32,
    /// (receive index, pill "used"|"new", balance string) per probed row.
    pub(crate) rows: Vec<(u32, &'static str, String)>,
}

pub(crate) static PICKER_PROBE_RESULTS: std::sync::Mutex<Vec<PickerProbeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Finished Bitcoin Core preflight check (`PLAN-chain-notes-app-core-rpc.md`
/// §2.2/§2.3/U4, surfaced §3/U6). `network`+`base` are the snapshot the
/// worker started against — `on_apply_pending_node_health` drops a stale
/// result (network switched, or the node URL changed) rather than paint it
/// over a config the user has since moved on from.
pub(crate) struct NodeHealthResult {
    pub(crate) network: Network,
    pub(crate) base: String,
    pub(crate) text: SharedString,
    pub(crate) warn: bool,
}

pub(crate) static NODE_HEALTH_RESULTS: std::sync::Mutex<Vec<NodeHealthResult>> =
    std::sync::Mutex::new(Vec::new());

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
pub(crate) struct SpendingRefreshResult {
    pub(crate) fp8: String,
    pub(crate) network: Network,
    pub(crate) account: u32,
    pub(crate) scan: Result<app_core::funding::FundingScan, String>,
}

pub(crate) static SPENDING_REFRESH_RESULTS: std::sync::Mutex<Vec<SpendingRefreshResult>> =
    std::sync::Mutex::new(Vec::new());

impl State {
/// Push the scan-freshness gate to the UI: `wallet-scan-busy` is true while
/// ANY scan that feeds a money-flow's coin cache is in flight (notebook
/// refresh, spending-wallet scan, or the wallet-wide stores refresh). The
/// Sign buttons on compose and screen 16 read it — see the field docs on
/// `State.scan_gate`. Call after every counter/flag change.
pub(crate) fn update_scan_gate(&self, w: &AppWindow) {
    let st = self;
    let busy = st.scan_gate.busy();
    if busy != w.global::<Ui>().get_wallet_scan_busy() {
        // Transition-only, like `cb: net-ops` — and a log contract: the UI
        // e2e suites wait for `busy=false` before tapping a money-flow
        // Sign (rapid ↻ retaps can queue several scans on a slow server;
        // the gate stays closed until EVERY one lands).
        println!("cb: scan-gate busy={busy}");
    }
    w.global::<Ui>().set_wallet_scan_busy(busy);
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
pub(crate) fn apply_bundle_to_notebook_file(&self, material: &app_core::identity::KeyMaterial, notebook_spks: &[Vec<u8>], spending_window_spks: &[Vec<u8>], index: u32, bundle: &app_core::notes_core::bundle::SyncBundle) -> bool {
    let st = self;
    let Ok(ident) = realize(material, st.network, st.account, index) else { return false };
    let mut store =
        st.notebook_store(index).unwrap_or_else(|| Store::new(&ident.output_x(), st.network));
    let applied = match ident.full() {
        Some(id) => store.apply_bundle(
            bundle,
            id,
            st.network,
            notebook_spks,
            spending_window_spks,
            &mlkem_secrets_for(&ident, st.pq_imported.as_ref()),
        ),
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
pub(crate) fn wallet_stores_refresh_async(&mut self, w: &AppWindow, purpose: WalletStoresPurpose) {
    let st = self;
    let label = purpose.label();
    if st.scan_gate.wallet_stores_busy() {
        println!("cb: {label} busy");
        return;
    }
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
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
    let creds = st.core_rpc_creds_for(&base, network);
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
                    weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_stores_refresh());
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
        let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_stores_refresh());
    };
    if scan_lane_submit(key, job) {
        st.scan_gate.set_wallet_stores(true);
        st.update_scan_gate(w);
        w.global::<Ui>().set_status("syncing…".into());
    }
}

/// The UI-thread half of `on_act_retry`'s sub-case (b): clear the transient
/// fetch guard, drop a stale result, and either enter the confirm screen
/// (fetch succeeded) or report the failure — same shape as
/// `apply_spending_refresh_results`.
pub(crate) fn apply_pending_rebroadcast_fetch_results(&mut self, w: &AppWindow) {
    let st = self;
    let results: Vec<RebroadcastFetchResult> =
        REBROADCAST_FETCH_RESULTS.lock().expect("rebroadcast fetch results mutex").drain(..).collect();
    for r in results {
        st.act_pending_ref = None;
        if st.ident.as_ref().map(|i| i.address.as_str()) != Some(r.identity_addr.as_str()) {
            println!("cb: rebroadcast-fetch stale-drop");
            continue;
        }
        match r.result {
            Ok(raw) if !raw.is_empty() => st.enter_rebroadcast_confirm(w, r.ref_id, r.is_note, raw),
            Ok(_) => {
                println!("cb: act-retry ref={} err=nothing-to-rebroadcast", r.ref_id);
                w.global::<Ui>().set_status("nothing to rebroadcast".into());
            }
            Err(e) => {
                println!("cb: act-retry ref={} err={e}", r.ref_id);
                w.global::<Ui>().set_status(format!("couldn't rebroadcast: {}", friendly_net_err(&e)).into());
            }
        }
    }
    st.update_activity(w);
}

pub(crate) fn apply_act_retry_results(&mut self, w: &AppWindow) {
    let st = self;
    let results: Vec<ActRetryResult> =
        ACT_RETRY_RESULTS.lock().expect("act-retry results mutex").drain(..).collect();
    for r in results {
        st.act_pending_ref = None;
        match r.result {
            Ok(txid) => {
                println!("cb: act-retry ref={} txid={txid} ok", r.ref_id);
                w.global::<Ui>().set_status(format!("rebroadcast {}…", &txid[..12.min(txid.len())]).into());
                show_toast(w, &format!("Rebroadcast ok · {}", &txid[..8.min(txid.len())]));
            }
            Err(e) => {
                println!("cb: act-retry ref={} err={e}", r.ref_id);
                let base = st.base_url().unwrap_or_default();
                w.global::<Ui>().set_status(
                    format!("rebroadcast failed: {}", friendly_broadcast_err(&e, &base)).into(),
                );
                show_toast(w, "Rebroadcast failed");
            }
        }
    }
    st.update_activity(w);
}

pub(crate) fn apply_act_bump_results(&mut self, w: &AppWindow) {
    let st = self;
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
                w.global::<Ui>().set_status(format!("sped up: {}…", &bt[..12.min(bt.len())]).into());
                show_toast(w, &format!("Sped up · {}", &bt[..8.min(bt.len())]));
            }
            Err(e) => {
                println!("cb: act-bump ref={} broadcast err={e}", r.ref_id);
                let base = st.base_url().unwrap_or_default();
                w.global::<Ui>().set_status(
                    format!("signed but broadcast failed: {}", friendly_broadcast_err(&e, &base))
                        .into(),
                );
                show_toast(w, "Speed-up broadcast failed");
            }
        }
    }
    st.update_activity(w);
    st.update_home(w);
}

pub(crate) fn apply_sweep_broadcast_result(&mut self, w: &AppWindow, r: SweepBroadcastResult) {
    let st = self;
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
                } else if let Some(mut store) = st.notebook_store(*index) {
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
                st.update_spending_ui(w);
                st.spending_refresh_async(w);
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
            w.global::<Ui>().set_status(
                format!(
                    "swept the wallet — {} sats to {}…",
                    commas(snap.value),
                    &snap.dest[..14.min(snap.dest.len())]
                )
                .into(),
            );
            st.update_notebook_list(w);
            w.global::<Ui>().set_screen(Screen::Notebooks); // wallet-level flow → the list
        }
        Err(e) => {
            println!("cb: sweep broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(
                format!("sweep broadcast failed: {}", friendly_broadcast_err(&e, &base)).into(),
            );
        }
    }
}

pub(crate) fn apply_consolidate_broadcast_result(&mut self, w: &AppWindow, r: ConsolidateBroadcastResult) {
    let st = self;
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
            w.global::<Ui>().set_status(format!("consolidating: {}…", &txid[..12.min(txid.len())]).into());
            w.global::<Ui>().set_screen(Screen::Home); // done — home, like the PSBT flow
            st.update_home(w);
        }
        Err(e) => {
            println!("cb: consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(
                format!("consolidate broadcast failed: {}", friendly_broadcast_err(&e, &base))
                    .into(),
            );
        }
    }
}

pub(crate) fn apply_wconsol_broadcast_result(&mut self, w: &AppWindow, r: WConsolBroadcastResult) {
    let st = self;
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
                let mut dstore = st.notebook_store(snap.dest_index)
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
                let Some(mut store) = st.notebook_store(*index) else { continue };
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
                let _ = st.activate(&m, false);
            }
            st.update_notebook_list(w);
            println!(
                "cb: wallet-consolidate txid={txid} coins={} notebooks={} value={} fee={}",
                snap.all_inputs.len(),
                snap.sources_n,
                snap.value,
                snap.fee
            );
            w.global::<Ui>().set_status(
                format!(
                    "consolidated — {} sats now at {}",
                    commas(snap.value),
                    st.notebook_display_name(snap.dest_index)
                )
                .into(),
            );
            w.global::<Ui>().set_screen(Screen::Notebooks);
        }
        Err(e) => {
            println!("cb: wallet-consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

pub(crate) fn apply_psbt_broadcast_result(&mut self, w: &AppWindow, r: PsbtBroadcastResult) {
    let st = self;
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
                st.record_watch_note(&wn, txid, raw, vsize as u64);
                // PLAN-pnte-redesign.md: the note id IS the txid.
                println!(
                    "cb: compose id={txid} txid={txid} fee={} vsize={vsize} to={} private={} gift={} watch={} broadcast=ok",
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
                st.record_watch_spend(&ws, txid, raw, vsize as u64);
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
            w.global::<Ui>().set_status(format!("broadcast {}…", &txid[..12.min(txid.len())]).into());
            st.funding_coins.clear();
            st.built_psbt = None;
            st.signed_psbt = None;
            st.ur_frames.clear();
            w.global::<Compose>().set_compose_text("".into());
            w.global::<Ui>().set_fund_external(false);
            w.global::<Ui>().set_psbt_signed(false);
            if wallet_flow {
                st.refresh(w); // active store first — the list rows read disk + memory
                st.update_notebook_list(w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
            } else {
                w.global::<Ui>().set_screen(Screen::Home);
                st.refresh(w);
            }
        }
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

pub(crate) fn apply_spending_consolidate_result(&mut self, w: &AppWindow, r: SpendingConsolidateResult) {
    let st = self;
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
            st.update_spending_ui(w);
            st.spending_refresh_async(w); // authoritative reconciliation
            println!(
                "cb: spending-consolidate txid={txid} coins={} value={} fee={}",
                snap.spent.len(),
                snap.value,
                snap.fee
            );
            // Coins-management op, like notebook consolidate — stays on the
            // Coins screen (spending segment), not a money-flow "go home".
            show_toast(w, &format!("Consolidated · {}…", &txid[..8.min(txid.len())]));
            st.update_wallet_coins(w);
        }
        Err(e) => {
            println!("cb: spending-consolidate broadcast err={e}");
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(
                format!("consolidate failed: {}", friendly_broadcast_err(&e, &base)).into(),
            );
            show_toast(w, "Broadcast failed");
        }
    }
}

/// Drains the CHANGE-4 wallet-tx result queues and applies each on the UI
/// thread — the shared `apply-pending-wallet-tx` trampoline target. Also
/// clears the shared busy flag.
pub(crate) fn apply_pending_wallet_tx_results(&mut self, w: &AppWindow) {
    let st = self;
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
    w.global::<Confirm>().set_wallet_tx_busy(false);
    for r in sweep {
        st.apply_sweep_broadcast_result(w, r);
    }
    for r in consolidate {
        st.apply_consolidate_broadcast_result(w, r);
    }
    for r in wconsol {
        st.apply_wconsol_broadcast_result(w, r);
    }
    for r in psbt {
        st.apply_psbt_broadcast_result(w, r);
    }
    for r in spending_consolidate {
        st.apply_spending_consolidate_result(w, r);
    }
}

pub(crate) fn apply_notebook_compose_result(&mut self, w: &AppWindow, r: NotebookComposeResult) {
    let st = self;
    match r.result {
        Ok(txid) => {
            println!(
                "cb: compose id={} txid={txid} fee={} vsize={} to={} private={} broadcast=ok",
                r.note_id, r.fee, r.vsize, r.to.as_deref().unwrap_or("self"), r.private
            );
            if r.pq_flags != 0 {
                println!("cb: pq-compose flags={}", r.pq_flags);
            }
            w.global::<Ui>().set_status(format!("broadcast {}…", &txid[..12.min(txid.len())]).into());
            w.global::<Compose>().set_compose_text("".into());
            w.global::<Ui>().set_change_address("".into());
            w.global::<Ui>().set_change_expanded(false);
            w.global::<Ui>().set_spend_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.global::<Ui>().set_change_choice("".into());
            w.global::<Ui>().set_screen(Screen::Home);
            st.refresh_async(w);
        }
        Err(e) => {
            println!("cb: compose broadcast err={e}");
            w.global::<Ui>().set_return_screen(Screen::Home);
            st.update_activity(w);
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(
                format!(
                    "broadcast failed: {} — note saved, retry from here",
                    friendly_broadcast_err(&e, &base)
                )
                .into(),
            );
            show_toast(w, "Broadcast failed — note saved. Retry from this list.");
            w.global::<Ui>().set_screen(Screen::Activity);
        }
    }
}

pub(crate) fn apply_spending_compose_result(&mut self, w: &AppWindow, r: SpendingComposeResult) {
    let st = self;
    match r.result {
        Ok(_echo) => {
            // Drop the coins this tx just spent from the runtime cache
            // immediately (finding 1: an immediate second compose must
            // never see an already-spent UTXO).
            st.spending_coins.retain(|c| {
                !r.spent_outpoints.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
            });
            st.update_spending_ui(w);
            st.spending_refresh_async(w);
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
                        // PLAN-pnte-redesign.md: the note id IS the txid.
                        note_id: r.txid.clone(),
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
                        // The spending-wallet compose path builds via
                        // `psbt_build::build_funding_psbt_amount`, not
                        // `ComposeRequest` — pq layers aren't wired into
                        // that builder yet (out of scope for this pass;
                        // see the compose-send glue notes).
                        pq_flags: 0,
                        locked: None,
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
                r.txid, r.txid, r.built_fee, r.vsize,
                r.to.as_deref().unwrap_or("self"), r.private,
                if r.recipients.len() > 1 { format!(" recipients={}", r.recipients.len()) } else { String::new() }
            );
            w.global::<Ui>().set_status(format!("broadcast {}…", &r.txid[..12.min(r.txid.len())]).into());
            w.global::<Compose>().set_compose_text("".into());
            w.global::<Ui>().set_change_address("".into());
            w.global::<Ui>().set_change_expanded(false);
            w.global::<Ui>().set_spend_expanded(false);
            w.global::<Ui>().set_payfrom_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.global::<Ui>().set_change_choice("".into());
            w.global::<Ui>().set_screen(Screen::Home);
            st.refresh_async(w);
        }
        // Universal confirm screen (2026-07-17): nothing was recorded, so
        // this is still safe to retry — but the retry point is compose
        // (screen 6, draft intact), not the confirm screen the user is
        // currently on (its Broadcast button is now inert: stage B already
        // dropped `pending_broadcast` for every non-psbt kind once it fired).
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
            w.global::<Ui>().set_screen(Screen::Compose);
        }
    }
}

pub(crate) fn apply_mixed_compose_result(&mut self, w: &AppWindow, r: MixedComposeResult) {
    let st = self;
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
                        // PLAN-pnte-redesign.md: the note id IS the txid.
                        note_id: r.txid.clone(),
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
                        // Mixed-source compose also bypasses `ComposeRequest`
                        // (see the spending-wallet path's identical note) —
                        // no pq layer here yet.
                        pq_flags: 0,
                        locked: None,
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
                st.update_spending_ui(w);
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
                st.spending_refresh_async(w);
            } else if !r.spent_spending.is_empty() {
                st.spending_refresh_async(w);
            }
            println!(
                "cb: compose id={} txid={} fee={} vsize={} to={} private={} funded=mixed{}{} broadcast=ok",
                r.txid, r.txid, r.built_fee, r.vsize,
                r.to.as_deref().unwrap_or("self"), r.private,
                if change_n > 0 { format!(" change={change_n}") } else { String::new() },
                if r.recipients.len() > 1 { format!(" recipients={}", r.recipients.len()) } else { String::new() }
            );
            w.global::<Ui>().set_status(format!("broadcast {}…", &r.txid[..12.min(r.txid.len())]).into());
            w.global::<Compose>().set_compose_text("".into());
            w.global::<Ui>().set_change_address("".into());
            w.global::<Ui>().set_change_expanded(false);
            w.global::<Ui>().set_spend_expanded(false);
            w.global::<Ui>().set_payfrom_expanded(false);
            st.coins_overridden = false;
            st.selected_coins.clear();
            st.mixed_selected.clear();
            st.change_choice.clear();
            w.global::<Ui>().set_change_choice("".into());
            w.global::<Ui>().set_screen(Screen::Home);
            st.refresh_async(w);
        }
        Err(e) => {
            let base = st.base_url().unwrap_or_default();
            w.global::<Ui>().set_status(format!("broadcast failed: {}", friendly_broadcast_err(&e, &base)).into());
        }
    }
}

/// Drains all three compose-result queues and applies each on the UI
/// thread — the shared `apply-pending-compose` trampoline target. Also
/// clears the busy/progress state common to every path.
pub(crate) fn apply_compose_results(&mut self, w: &AppWindow) {
    let st = self;
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
    w.global::<Compose>().set_compose_sending(false);
    w.global::<Ui>().set_compose_stage("".into());
    // Universal confirm screen (2026-07-17): every compose broadcast now
    // fires from screen 26, gated on wallet_tx_busy, not compose_busy — see
    // `on_confirm_broadcast`. Unset it here alongside the (now largely
    // vestigial) compose flags so a failed spending/mixed attempt leaves
    // screen 26's Broadcast button tappable again.
    st.wallet_tx_busy = false;
    w.global::<Confirm>().set_wallet_tx_busy(false);
    for r in nb {
        st.apply_notebook_compose_result(w, r);
    }
    for r in sp {
        st.apply_spending_compose_result(w, r);
    }
    for r in mx {
        st.apply_mixed_compose_result(w, r);
    }
}

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
pub(crate) fn maybe_start_discovery(&mut self, w: &AppWindow) {
    let st = self;
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
    let creds = st.core_rpc_creds_for(&base, network);
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
        let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_discovery());
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
pub(crate) fn refresh_async(&mut self, w: &AppWindow) {
    let st = self;
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    st.maybe_start_discovery(w);
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
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
    let creds = st.core_rpc_creds_for(&base, network);
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
                let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_refresh());
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
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_refresh());
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
        let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_refresh());
    };
    if scan_lane_submit(key, job) {
        w.global::<Ui>().set_status("syncing…".into());
        st.scan_gate.admit_notebook();
        st.update_scan_gate(w);
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
pub(crate) fn apply_active_bundle(&mut self, w: &AppWindow, bundle: Result<app_core::notes_core::bundle::SyncBundle, String>, statuses: &[(String, Option<bool>)], dropped_lookup: &HashMap<String, TxLookupStatus>, dropped_unspent: &HashMap<(String, u32), bool>, // Fresh `/address/:a` stats to stamp as the store's scan fingerprint on
    // a successful apply (429-politeness short-circuit, 2026-07-20).
    // `None` = leave the existing stamp alone (stats endpoint failed, or a
    // path that doesn't pre-check yet — the wallet-wide refresh).
    new_stats: Option<AddrStats>) {
    let st = self;
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
            let notebook_spks = st.notebook_spks_for();
            // Spending-self-notes fix (Unit A): derived once for this apply
            // — a single-notebook scan, so no cross-notebook reuse needed
            // here (the wallet-wide caller derives it once itself; see
            // `apply_wallet_stores_refresh_results`).
            let spending_window_spks = st.spending_window_spks_for();
            let mlkem_secrets = mlkem_secrets_for(st.ident.as_ref().unwrap(), st.pq_imported.as_ref());
            let applied = match &keyed {
                Some(identity) => st.store.as_mut().unwrap().apply_bundle(
                    &bundle,
                    identity,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                    &mlkem_secrets,
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
                    w.global::<Ui>().set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.global::<Ui>().set_status("couldn't reach the network — tap refresh to retry".into());
        }
    }
    st.update_home(w);
}

/// The UI-thread half of [`refresh_async`]: identical bookkeeping to the
/// synchronous [`refresh`], fed from the worker's results.
pub(crate) fn apply_refresh_results(&mut self, w: &AppWindow) {
    let st = self;
    let results: Vec<RefreshResult> =
        REFRESH_RESULTS.lock().expect("refresh results mutex").drain(..).collect();
    for r in results {
        // Every drained result releases its scan-gate slot — BEFORE the
        // staleness guard, or a stale-dropped scan would wedge the gate.
        st.scan_gate.drain_notebook();
        st.update_scan_gate(w);
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
            w.global::<Ui>().set_status("up to date".into());
            st.update_home(w);
            continue;
        };
        st.apply_active_bundle(w, bundle, &r.statuses, &r.dropped_lookup, &r.dropped_unspent, r.new_stats);
        if w.global::<Ui>().get_screen() == Screen::PayFrom {
            st.update_funding_screen_ui(w);
            st.log_funding_refresh();
            // A landed notebook rescan must repaint the (now possibly
            // independently expanded) Notebook panel, not just the row's
            // summary balance — independent-expand rework, 2026-07-18.
            st.update_payfrom_panels(w);
        }
        if w.global::<Ui>().get_screen() == Screen::Compose {
            w.global::<Ui>().set_pay_from_balance(st.balance_text_for(w.global::<Ui>().get_pay_from().as_str()).into());
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
pub(crate) fn apply_wallet_stores_refresh_results(&mut self, w: &AppWindow) {
    let st = self;
    let results: Vec<WalletStoresRefreshResult> =
        WALLET_STORES_REFRESH_RESULTS.lock().expect("wallet stores refresh mutex").drain(..).collect();
    for r in results {
        st.scan_gate.set_wallet_stores(false);
        st.update_scan_gate(w);
        let label = r.purpose.label();
        if st.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
            || st.network != r.network
            || st.account != r.account
        {
            println!("cb: {label} stale-drop");
            w.global::<Ui>().set_status("".into());
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
        let notebook_spks = st.notebook_spks_for();
        // Spending-self-notes fix (Unit A): derived ONCE for this whole
        // wallet-wide pass and reused across every notebook below — the
        // spending wallet is account-level, so re-deriving per notebook
        // would repeat the same ~2×upto secp derivations for nothing.
        let spending_window_spks = st.spending_window_spks_for();
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
                st.apply_active_bundle(w, nr.bundle.clone(), &r.current_statuses, &r.current_dropped_lookup, &r.current_dropped_unspent, // The wallet-wide refresh doesn't stats-pre-check (yet)
                    // — leave the store's fingerprint stamp alone.
                    None, );
            } else if let (Ok(bundle), Some(material)) = (&nr.bundle, &material) {
                if st.apply_bundle_to_notebook_file(material, &notebook_spks, &spending_window_spks, nr.index, bundle, ) {
                    scanned += 1;
                }
            }
        }
        scanned += 1; // the snapshot-time-active notebook, unconditionally
        println!("cb: {label} notebooks={scanned}");
        w.global::<Ui>().set_status("".into());
        // Repaint the Coins screen/card regardless of which ↻ kicked this
        // scan off — `update_wallet_coins` is a pure re-derive from `st`
        // (no side effects), and the change coins it now folds in just
        // landed above.
        st.update_wallet_coins(w);
        match r.purpose {
            WalletStoresPurpose::Coins => {
                if st.spending_capable
                    && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
                {
                    st.spending_refresh_async(w);
                }
                st.refresh_compose(w);
            }
            WalletStoresPurpose::Notebooks => st.update_notebook_list(w),
        }
    }
}

pub(crate) fn refresh(&mut self, w: &AppWindow) {
    let st = self;
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    st.maybe_start_discovery(w);
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let creds = st.core_rpc_creds_for(&base, st.network);
    let client = match open_client_watched(&base, st.network, creds, &st.core_rpc_watch) {
        Ok(c) => c,
        Err(e) => {
            println!("cb: refresh err={e}");
            w.global::<Ui>().set_status("couldn't reach the network — tap refresh to retry".into());
            st.update_home(w);
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
            let notebook_spks = st.notebook_spks_for();
            // Spending-self-notes fix (Unit A) — see the matching comment
            // in `apply_active_bundle`.
            let spending_window_spks = st.spending_window_spks_for();
            let mlkem_secrets = mlkem_secrets_for(st.ident.as_ref().unwrap(), st.pq_imported.as_ref());
            let applied = match &keyed {
                Some(identity) => st.store.as_mut().unwrap().apply_bundle(
                    &bundle,
                    identity,
                    network,
                    &notebook_spks,
                    &spending_window_spks,
                    &mlkem_secrets,
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
                    w.global::<Ui>().set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.global::<Ui>().set_status("couldn't reach the network — tap refresh to retry".into());
        }
    }
    st.update_home(w);
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
pub(crate) fn refresh_fees_price(&mut self, _w: &AppWindow) {
    let st = self;
    if let Some(t) = st.fees_fetched_at {
        if t.elapsed() < std::time::Duration::from_secs(60) {
            return;
        }
    }
    let Some(base) = st.base_url() else { return };
    let creds = st.core_rpc_creds_for(&base, st.network);
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

/// Kick off a spending-wallet coin scan on a worker thread (funding-
/// unification M3) — never block the UI thread with the chain call. A
/// no-op when the identity can't derive a spending wallet, or none is
/// configured (no node). Results land through [`SPENDING_REFRESH_RESULTS`]
/// + the `apply-pending-spending-refresh` trampoline, exactly like
///   [`refresh_async`].
///
/// Also goes through the [`SCAN_LANE`] queue (2026-07-21) keyed
/// `spscan/<fp8>/<network>/<account>` — a SECOND, general layer behind
/// the `scan_gate.spending_busy()` early-return above. That early-return
/// stays because it covers the wider enqueue→apply window (a scan that
/// already landed on the worker thread but hasn't finished applying on
/// the UI thread yet); the lane additionally serializes/coalesces at
/// admission time the same way every other scan class does. Gate-counter
/// increment + status only fire when [`scan_lane_submit`] returns `true`.
pub(crate) fn spending_refresh_async(&mut self, w: &AppWindow) {
    let st = self;
    st.spending_scan_async(w, SPENDING_GAP_SHALLOW);
}

/// Manual "Scan for existing funds…" deep scan (network-efficiency
/// follow-up, 2026-07-23): the automatic scan above now walks a SHALLOW
/// gap-3 range (the app's own usage is sequential, so a small look-ahead
/// past the last handed-out index is enough) — but a seed that was heavily
/// used in ANOTHER BIP-84 wallet before this app ever touched it could have
/// funds sitting beyond that reach. This is the on-demand full gap-20
/// discovery pass for that case: same worker-thread / scan-lane / gate /
/// apply path as [`spending_refresh_async`], only the gap differs.
pub(crate) fn spending_scan_deep_async(&mut self, w: &AppWindow) {
    let st = self;
    println!("cb: spending-scan-deep");
    st.spending_scan_async(w, SPENDING_GAP_DEEP);
}

pub(crate) fn spending_scan_async(&mut self, w: &AppWindow, gap: u32) {
    let st = self;
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
    let creds = st.core_rpc_creds_for(&base, network);
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
        let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_spending_refresh());
    };
    if scan_lane_submit(key, job) {
        w.global::<Ui>().set_status("scanning spending wallet…".into());
        st.scan_gate.admit_spending();
        st.update_scan_gate(w);
    }
}

/// Derive `spending_source` on demand from the session key material. The
/// descriptor needs no network scan — it was only ever populated by
/// [`apply_spending_refresh_results`], which made scan-independent flows
/// ("Sweep notebook funds here", spending consolidate — both only need the
/// descriptor + a store index) fail with "not scanned yet" when tapped
/// before a fresh session's first scan landed.
pub(crate) fn ensure_spending_source(&mut self) {
    let st = self;
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
pub(crate) fn apply_spending_refresh_results(&mut self, w: &AppWindow) {
    let st = self;
    let results: Vec<SpendingRefreshResult> =
        SPENDING_REFRESH_RESULTS.lock().expect("spending refresh mutex").drain(..).collect();
    for r in results {
        // Release the scan-gate slot BEFORE the staleness guard — a
        // stale-dropped scan must not wedge the gate closed.
        st.scan_gate.drain_spending();
        st.update_scan_gate(w);
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
                w.global::<Ui>().set_status("".into());
            }
            Err(e) => {
                println!("cb: spending-refresh err={e}");
                w.global::<Ui>().set_status(format!("spending wallet scan failed: {}", friendly_net_err(&e)).into());
            }
        }
        st.update_spending_ui(w);
        if w.global::<Ui>().get_screen() == Screen::Sweep && w.global::<Ui>().get_sweep_kind() == "sweep" {
            // A wallet-sweep preview computed before the scan landed shows
            // notebook coins only (Sal 2026-07-17) — recompute it so the
            // spending coins join the inputs summary and fee preview.
            st.update_sweep_screen(w);
        }
        if w.global::<Ui>().get_screen() == Screen::Compose {
            // CHANGE 5: a user already sitting on compose when the scan
            // lands sees the default upgrade to "spending" too — but only
            // absent an explicit pick this session (payfrom_manual).
            if !st.payfrom_manual && w.global::<Ui>().get_pay_from() != "spending" {
                st.resolve_payfrom_default(w);
            }
            if w.global::<Ui>().get_pay_from() == "spending" {
                st.refresh_compose(w);
            }
        }
        if w.global::<Ui>().get_screen() == Screen::PayFrom {
            st.log_funding_refresh();
            // funding-unification UI rework: a landed scan must repaint the
            // Spending panel (independent-expand rework, 2026-07-18: it now
            // reads its own `sp-panel-coins`/`sp-panel-title`, not the
            // legacy singular `spend-coins`/`spend-title` — those stay
            // driven by whichever source is `payfrom_active_source`), or the
            // panel shows stale "0 coins" under a since-scanned wallet.
            st.refresh_compose(w);
            st.update_payfrom_panels(w);
        }
    }
}

/// Populate every spending-wallet-facing property: the Settings card
/// (capability/enabled/balance/next-receive QR), the compose picker's
/// subtitle, and the Coins screen's "spending" segment rows. Cheap local
/// derivation only — no chain call (callers that need fresh data call
/// [`spending_refresh_async`] first).
pub(crate) fn update_spending_ui(&self, w: &AppWindow) {
    let st = self;
    w.global::<Ui>().set_spending_capable(st.spending_capable);
    let enabled = st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
    w.global::<Ui>().set_spending_enabled(enabled);
    if !st.spending_capable {
        w.global::<PayFrom>().set_spending_summary("".into());
        w.global::<Ui>().set_spending_balance_line("".into());
        w.global::<Settings>().set_spending_address("".into());
        w.global::<Settings>().set_spending_qr(slint::Image::default());
        let empty: Vec<SpendingCoinItem> = Vec::new();
        w.global::<Coins>().set_spending_coins_list(VecModel::from_slice(&empty));
        return;
    }
    let n = st.spending_coins.len();
    let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    if !st.spending_scanned {
        w.global::<PayFrom>().set_spending_summary(if enabled { "tap to scan…".to_string() } else { String::new() }.into());
        w.global::<Ui>().set_spending_balance_line("not scanned yet — tap refresh".into());
    } else {
        let line = format!("{} sats · {n} coin{}", commas(total), if n == 1 { "" } else { "s" });
        w.global::<PayFrom>().set_spending_summary(line.clone().into());
        w.global::<Ui>().set_spending_balance_line(line.into());
    }
    if let (Some(src), Some(store)) = (st.spending_source.as_ref(), st.store.as_ref()) {
        if let Ok(d) = src.derive(0, store.spending.next_receive) {
            w.global::<Settings>().set_spending_address(d.address.clone().into());
            w.global::<Settings>().set_spending_qr(qr::qr_image(&d.address.to_uppercase()).unwrap_or_default());
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
    w.global::<Coins>().set_spending_coins_list(VecModel::from_slice(&rows));
}
}
