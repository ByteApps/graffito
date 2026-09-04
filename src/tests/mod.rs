//! Unit tests, split one file per (former) inline `#[cfg(test)] mod …`
//! block that used to live directly in `src/lib.rs` (U0 hygiene pass).
//! Each file starts `use crate::*;` — a child module of `crate` sees
//! everything `lib.rs` sees, private items included.

#[path = "net_err.rs"]
mod net_err_tests;
#[path = "broadcast_err.rs"]
mod broadcast_err_tests;

/// Complementary to `core_rpc_wiring_contract` (below `open_client_watched`,
/// further down this file): that module guards every CALL SITE reaching for
/// `st.core_rpc_watch`; this one guards where the value itself comes from —
/// `activate()`'s one-line delegation to `app_core::chain::identity_watch_descriptors`
/// two screens up. A real `State` (via the existing `State::test_stub`,
/// which enumerates every field on purpose — see its own doc comment) with
/// a throwaway temp `data_dir` so `save_store`/`save_config` have somewhere
/// to write; `persist: false` so this never touches the Keychain.
#[path = "activate_core_rpc_watch.rs"]
mod activate_core_rpc_watch_tests;

/// Source-contract test guarding the U7 ranged-descriptor wiring
/// (`open_client_watched`, above) — the GUI app's counterpart to
/// `core_rpc_cli_scan_wires_ranged_watch_descriptors`
/// (`app-core/tests/core_rpc_conformance.rs`), which proves the SAME
/// mechanism end-to-end but only for `examples/cli.rs`; it never touches
/// this file's own production call sites, so a regression here (a 7th
/// address-resolving site added on the plain constructor, or one of the
/// 6 existing sites reverted to it) stays green forever otherwise — that
/// gap is what this module closes.
///
/// This can't run against a live node (`cargo test --lib` has none, by
/// design — see the workspace CLAUDE.md), so it inspects the SOURCE TEXT
/// of this very file instead (`include_str!`, so it always sees the
/// CURRENT contents, mutation and all). Brittle by nature — same
/// tradeoff as the `cb:`/`cli:` log-grep contracts already documented in
/// the workspace CLAUDE.md — but it is what turns red on exactly the two
/// regressions the U7 gap allows: (1) reverting one of the 6 named sites
/// below to plain `open_client`, and (2) swapping any of their
/// descriptor arguments for an empty slice (`&[]`) — which calls
/// `open_client_watched` but is behaviorally identical to the plain
/// constructor, since `watch_descriptors` is a no-op on an empty list.
///
/// Why not make `open_client` itself always configure watching (the
/// stronger fix that would remove this choice entirely)? Evaluated and
/// rejected: `watch_descriptors` is NOT free per call — a fresh
/// `CoreRpcTransport` is built on every `open_client`, `wallet_ready`
/// starts false, so `ensure_watch_wallet` (`createwallet`/`loadwallet`)
/// and `ranged_family_imported_end` (`listdescriptors`, one per
/// descriptor family) are REAL round trips EVERY call —
/// `GLOBAL_WATCH_CACHE` only ever short-circuits the per-address `addr()`
/// fallback, never `watch_descriptors` itself. Forcing that onto the 9
/// broadcast-only call sites (money-movement critical, and exactly the
/// kind of avoidable request this app's whole network-politeness effort
/// — see the workspace CLAUDE.md's "Network efficiency" section — exists
/// to eliminate) and the 3 third-party-funding-wallet `scan_funding`
/// sites (a DIFFERENT descriptor family than this identity's own —
/// configuring ours ahead of one of those helps nothing) would silently
/// reverse the U7 commit's own deliberate, tested, documented split. A
/// type-level split (a wrapper type the plain constructor can't expose
/// address-resolving methods from) is ALSO not viable without touching
/// the FROZEN `ChainClient` API: `scan_funding` itself is legitimately
/// called through BOTH constructors today (identity-own, at
/// `spending_scan_async`, vs. third-party, at the 3 sites above) — which
/// constructor is correct depends on which descriptor is being scanned,
/// a runtime fact no static method-based split can see.
///
/// **If you add a new call site that resolves one of the identity's OWN
/// addresses** (a new `.address_probe(`/`.build_bundle(` call — caught
/// automatically below, no list to update — or a new helper like
/// `discover_indexes` that takes a `ChainClient` and walks this
/// identity's own addresses/descriptors, which this test can't detect
/// generically): wire it through `open_client_watched` with a real
/// descriptor snapshot (`st.core_rpc_watch.clone()` before a worker-
/// thread spawn, same as every site here), and add its enclosing
/// function's name to `NAMED_WATCH_SITES` below.
mod core_rpc_wiring_contract;

#[path = "core_rpc_settings.rs"]
mod core_rpc_settings_tests;
mod ui_flow_quantum_key;

/// U8 (PLAN-graffito-app-arch.md): in-process ports of the never-calibrated
/// pq compose legs of the coordinate Mac suite
/// (ui-automation/tests/graffito-app-selfpq.sh, SUPERSEDED — see its own
/// header) — self-note + passphrase, self-note + ML-KEM, and locked-note
/// unlock. Same real State/AppWindow flow as `ui_flow_quantum_key`, no
/// window/coordinates/keychain prompt.
mod ui_flow_selfpq_passphrase;
mod ui_flow_selfpq_kem;
mod ui_flow_locked_note_unlock;

/// U12 (PLAN-graffito-app-arch.md): in-process ports of the network-free legs
/// of the coordinate Mac suite
/// (ui-automation/tests/graffito-app-multi-recipient.sh) — multi-select
/// picker chips, the universal confirm screen's byte-true multi-recipient
/// decode, and Reply-all prefill on an own multi-recipient note. The
/// broadcast leg itself needs a real chain and stays on the Mac suite.
mod ui_flow_multi_select;
mod ui_flow_multi_confirm;
mod ui_flow_multi_reply_all;
/// U10 (PLAN-graffito-app-arch.md): in-process ports of the NETWORK-FREE
/// legs of the coordinate Mac suite (ui-automation/tests/graffito-app.sh) —
/// notebooks create/name/open/archive, the universal-confirm cancel
/// regression, the spending-wallet enable toggle + its M4 empty-wallet
/// default rule, the cross-wallet payfrom verdict, the dispatch-follows-
/// the-verdict poison sequence, and the sub-dust change fold. Everything
/// else in that suite (funded scans, sweeps, broadcasts) needs a real node
/// and stays there — see each file's own header for exactly what it skips
/// and why. Same real State/AppWindow flow as `ui_flow_quantum_key`.
mod ui_flow_app_notebooks;
mod ui_flow_app_cancel_regression;
mod ui_flow_app_spending_wallet;
mod ui_flow_app_payfrom_state;
mod ui_flow_app_dispatch;
mod ui_flow_app_subdust_fold;
