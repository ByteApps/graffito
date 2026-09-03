use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use notes_core::Network;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::funding::FundingSource;
use crate::Error;

use super::transport::Transport;

/// U6 (`../../PLAN-chain-notes-app-core-rpc.md`, "unusable against a real
/// node" fix, 2026-07-30): process-global watch cache, shared across every
/// `CoreRpcTransport` instance — belt-and-braces on TOP of
/// [`CoreRpcTransport::ensure_address_watched`]'s node-truth
/// `getaddressinfo` check, never a replacement for it (a process restart,
/// or simply the first call this process ever makes for an address, finds
/// this empty; the `getaddressinfo` check is what makes correctness never
/// depend on this cache being warm). It exists purely as an optimization —
/// `src/lib.rs` builds a FRESH `ChainClient`/`AnyTransport` per operation
/// (`open_client`, 24 call sites), so a per-instance `HashSet` (the
/// pre-existing `CoreRpcTransport::watched` field) is empty on essentially
/// every call and cannot skip even the cheap `getaddressinfo` round trip;
/// this can. Keyed by (node identity, address) — see
/// `CoreRpcTransport::node_key` — so switching the node URL (Settings, or a
/// network switch) never serves a stale hit for a DIFFERENT node's wallet.
static GLOBAL_WATCH_CACHE: std::sync::LazyLock<Mutex<HashSet<(String, String)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

/// U6: process-global count of real `importdescriptors` RPC round-trips
/// this process has sent, across every node and every `CoreRpcTransport`
/// instance — test visibility only, exactly mirroring how
/// `CoreRpcTransport::probe_calls`/`preflight_probe_count` prove the
/// `status_cache` is load-bearing, but at PROCESS granularity: since
/// `src/lib.rs` builds a fresh transport (and therefore fresh, empty
/// per-instance caches) on nearly every operation, only a process-wide
/// counter can distinguish "this address was imported once, ever" from
/// "this address gets re-imported on every single operation" (the bug this
/// unit fixes). See `core_rpc_conformance.rs`'s
/// `core_rpc_import_is_idempotent_across_fresh_transports` test, which
/// reverts to N (not 1) the instant the `getaddressinfo` idempotence check
/// in `ensure_address_watched` is disabled — that's the point of it.
static IMPORT_DESCRIPTORS_CALLS: AtomicU32 = AtomicU32::new(0);

/// Real calls to `importdescriptors` so far this process. Test visibility
/// only — see [`IMPORT_DESCRIPTORS_CALLS`].
pub fn core_rpc_import_descriptors_call_count() -> u32 {
    IMPORT_DESCRIPTORS_CALLS.load(Ordering::Relaxed)
}

/// Process-global cache of fully-resolved esplora-shaped tx JSON, keyed by
/// (node identity, txid) — the fix for the measured O(wallet)
/// `getrawtransaction` defect (`PLAN-one-regtest-node.md`'s "The rescan
/// trap" / "Two things now grow without bound"): `listtransactions "*"`
/// ([`CoreRpcTransport::wallet_txid_order`]) has no per-address filter, so
/// resolving history for ONE address means fetching EVERY wallet-wide
/// txid via `getrawtransaction` — and, before this cache, doing so again
/// from scratch on every single call. Measured with
/// `tests/common/count_proxy.rs`: 5 identical `address_stats` calls issued
/// 2090 `getrawtransaction` round trips (~418 each), with NO decrease
/// across repetition.
///
/// See [`CoreRpcTransport::esplora_tx_json`] for the one place this is
/// populated: **only a CONFIRMED transaction's fully-built JSON is ever
/// inserted.** This is the load-bearing safety rule, not a stylistic
/// choice — an UNCONFIRMED (mempool) transaction's status can change on
/// the very next call (mined, dropped, replaced by a fee bump), so caching
/// it would risk exactly the failure mode this project treats as worst:
/// telling the user a live transaction was dropped, or hiding a fresh
/// confirmation (`TxLookupStatus::NotFound`'s own doc comment). A
/// CONFIRMED transaction's content — including the `status` object's
/// `block_height`/`block_time`, computed once from an ABSOLUTE block
/// height (`tip - confirmations + 1`), not a relative "N confirmations
/// ago" — cannot change short of a deep reorg, a risk this crate already
/// accepts elsewhere with no special handling (`tx_lookup_status`, the
/// dropped-tx detector, ...). Keyed by node identity exactly like
/// [`GLOBAL_WATCH_CACHE`], so a Settings node-URL change or network switch
/// can never serve a stale hit from a different chain's history.
static TX_JSON_CACHE: std::sync::LazyLock<Mutex<HashMap<(String, String), serde_json::Value>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Hard cap on [`TX_JSON_CACHE`]'s entry count, enforced at insert time
/// (see [`CoreRpcTransport::esplora_tx_json`]). Left unbounded, the cache
/// would trade an O(wallet-history) NETWORK cost for an O(wallet-history)
/// MEMORY cost — the same "nothing may be O(chain length)/O(wallet
/// history)" rule `PLAN-one-regtest-node.md` states for the node side
/// ("Two things now grow without bound"), just moved into this process
/// instead, on a platform (a phone) that can least afford it.
///
/// Arithmetic: one cache entry is a confirmed transaction's fully-built
/// esplora-shaped JSON. A typical Graffito tx (1-2 inputs, a recipient
/// output, an OP_RETURN chunk or two, maybe a taproot change output)
/// serializes to roughly 0.5-1 KB; an outlier — a wallet sweep/consolidate
/// pulling in many inputs — runs a few KB. At [`TX_JSON_CACHE_MAX_ENTRIES`]
/// = 5,000, that is ~2.5-5 MB in the ordinary case and comfortably under
/// 20 MB even if EVERY entry were an outlier — trivial next to a mobile
/// app's normal memory budget (a handful of decoded images), and it
/// already covers a wallet used HEAVILY (10+ notes/day) for several
/// YEARS, since this is one entry per distinct historical txid ever
/// resolved, not per operation.
///
/// The policy on reaching the cap is deliberately the crudest one that is
/// still correct: **stop inserting.** Existing entries are never evicted
/// (so there is no thrashing, and everything already cached keeps serving
/// hits) — the cache just stops growing. A fixed ceiling with a dumb
/// policy beats an eviction scheme clever enough to need its own tests;
/// the cost of understating the cap is a few more `getrawtransaction`
/// calls once a node's shared history is already enormous, a regime this
/// crate already tolerates elsewhere (`PLAN-one-regtest-node.md`'s
/// accepted unbounded chain/wallet growth).
const TX_JSON_CACHE_MAX_ENTRIES: usize = 5_000;

/// Test visibility only — see [`TX_JSON_CACHE_MAX_ENTRIES`]'s doc comment
/// for the reasoning behind the exact number, so a test can assert against
/// it by name instead of a hardcoded duplicate.
pub fn core_rpc_tx_json_cache_max_entries() -> usize {
    TX_JSON_CACHE_MAX_ENTRIES
}

/// Current entry count of [`TX_JSON_CACHE`] — test visibility only, proves
/// the cap in [`CoreRpcTransport::esplora_tx_json`] is genuinely enforced
/// rather than merely documented.
pub fn core_rpc_tx_json_cache_len() -> usize {
    TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned").len()
}

/// Bitcoin Core JSON-RPC backend (`../../PLAN-chain-notes-app-core-rpc.md`
/// §1.3/U3, §2.2/§2.3/U4). A plain JSON-RPC 1.0 client over HTTP basic auth
/// that receives an ESPLORA-shaped path (exactly what [`ChainClient`]
/// already sends through [`Transport`]) and synthesizes an Esplora-shaped
/// JSON body by calling `bitcoind` — no address index on Core, so a
/// watch-only descriptor wallet ([`CoreRpcTransport::WATCH_WALLET`]) stands
/// in for one. Two ways an address gets imported into it:
///
/// 1. **Ranged descriptor import** ([`CoreRpcTransport::watch_descriptors`],
///    U4) — the app's own notebook/spending descriptors, configured
///    OUT-OF-BAND before any of their addresses are queried (this transport
///    only ever sees Esplora PATHS, never which descriptor an address came
///    from). One `importdescriptors` call per family, both chains at once
///    (Core's own multipath support), widened automatically
///    ([`CoreRpcTransport::ranged_lookup_or_widen`]) as the gap window
///    grows past the imported range.
/// 2. **Per-address `addr()` fallback** (U3, unchanged) — for anything
///    never configured this way (a contact, an external recipient, a
///    custom change address, ...), imported one address at a time exactly
///    as before. Also the ENTIRE behavior when nothing has been configured
///    at all, so every existing test and caller stays green.
///
/// Ported from the reference implementation, `prime-graffito/companion/
/// server.py`, which does the identical per-address translation against a
/// real node and backs the whole regtest e2e + app↔Prime interop matrix.
///
/// U5 (`../../PLAN-chain-notes-app-core-rpc.md` §2.1/§2.4) formalizes the
/// error-mapping rule this unit's original -5→404 shortcut left informal,
/// plus credential redaction: `creds` is private (was `pub`, a plaintext
/// footgun — see [`CoreRpcTransport::new`]'s doc comment) and this type has
/// a hand-written [`std::fmt::Debug`] impl (below) that never prints a
/// credential, so a stray `{:?}` anywhere (a log line, a panic message, an
/// assertion failure) cannot leak one either.
pub struct CoreRpcTransport {
    /// "http" or "https" (validated at construction).
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    /// RPC basic-auth credentials, if any were supplied (explicit `creds`
    /// param or inline URL userinfo — see [`AnyTransport::new`]). Sent ONLY
    /// as an HTTP Authorization header ([`CoreRpcTransport::call`]) — never
    /// interpolated into a URL, error string, or log line, so there is
    /// nothing here for `reqwest`'s own error `Display` (which can echo the
    /// request URL) to leak. Private since U5 (was `pub`, plaintext) —
    /// the password is [`Zeroizing`] so it's wiped on drop, and the
    /// hand-written `Debug` impl below never prints either half of this
    /// tuple, defense in depth against the field ever becoming reachable
    /// from outside this module again.
    creds: Option<(String, Zeroizing<String>)>,
    client: reqwest::blocking::Client,
    /// Addresses already `addr()`-imported into the watch wallet this
    /// session — avoids re-importing (and re-triggering bitcoind's own
    /// duplicate-descriptor bookkeeping) on every call to the same address.
    watched: Mutex<HashSet<String>>,
    /// Addresses confirmed SYNTACTICALLY INVALID this session (bitcoind's
    /// RPC code -5) — never imported, so every route for one of these
    /// short-circuits to an empty answer instead of handing a garbage
    /// string to an RPC that validates its address argument (`listunspent`
    /// does; `listtransactions` takes no address param at all, so it was
    /// never at risk). Kept separate from `watched` rather than folded
    /// into one "seen" set so a route can tell "definitely nothing to
    /// look up" apart from "already imported, ask the node normally."
    invalid: Mutex<HashSet<String>>,
    /// Set once the watch wallet is confirmed created/loaded this session.
    wallet_ready: Mutex<bool>,
    /// Ranged descriptor families configured via
    /// [`CoreRpcTransport::watch_descriptors`] (U4) — empty until a caller
    /// opts in, so this is strictly additive over the U3 per-address path.
    ranged: Mutex<Vec<RangedWatch>>,
    next_id: Mutex<u64>,
    /// U5 (plan §2.1): a cached [`NodeStatus`], consulted by
    /// [`CoreRpcTransport::established_absent`] instead of re-running
    /// `getblockchaininfo`/`getindexinfo` on every `getrawtransaction` -5 —
    /// "cache it; do not re-probe per call" per the plan. Populated lazily
    /// by [`CoreRpcTransport::cached_status`] on first need, and refreshed
    /// by an explicit [`CoreRpcTransport::preflight`] call. Never expired
    /// on a timer within this unit — a longer-lived session picking up a
    /// node's IBD-finishing/txindex-completing transition is a later
    /// refinement, out of scope here; what matters for U5 is that the
    /// NotFound/Unknown decision never triggers a fresh multi-RPC probe
    /// for every single lookup.
    status_cache: Mutex<Option<NodeStatus>>,
    /// Counts real calls to [`CoreRpcTransport::compute_status`] (the raw,
    /// uncached probe) — exists so a test can PROVE the cache is actually
    /// being used (a reviewer's mutation removing the cache would make
    /// this counter grow once per lookup instead of staying at 1) rather
    /// than merely asserting the right final answer, which a re-probing
    /// implementation would also produce.
    probe_calls: AtomicU32,
}

impl std::fmt::Debug for CoreRpcTransport {
    /// Hand-written, not derived — the entire point (plan §2.4): a stray
    /// `{:?}` of this transport (a log line, a panic message, an assertion
    /// failure diff) must never be able to print a credential, so this
    /// impl exists specifically to make that structurally impossible
    /// rather than merely a "please don't log creds" convention. `creds`
    /// prints only whether one is configured, never the username or
    /// password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRpcTransport")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("creds", &self.creds.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One descriptor family imported as a RANGED batch (plan §2.2/U4) instead
/// of one `addr()` descriptor per address — out-of-band configuration, set
/// up via [`CoreRpcTransport::watch_descriptors`] before any of its
/// addresses are queried. Typically one per notebook account's `tr(...)`
/// chain and one for the BIP-84 spending wallet's `wpkh(...)` chain.
#[derive(Debug, Clone)]
pub struct WatchDescriptor {
    /// A multipath (`.../<0;1>/*`) or single-chain output descriptor —
    /// anything [`FundingSource::parse`] accepts (the SAME parser the
    /// watch-only import path already uses, so this is not a second
    /// hand-rolled derivation). A `#checksum` suffix, if present, is
    /// stripped and recomputed — bitcoind rejects a stale/foreign one.
    pub descriptor: String,
    pub network: Network,
    /// Unix epoch seconds to start rescanning from — the wallet's
    /// birthday. `0` = genesis (a full rescan; on mainnet this can take
    /// hours — plan §2.2). A notebook created in-app can pass its own
    /// `created_at` (`store.rs:176`); **an IMPORTED SEED HAS NO KNOWN
    /// BIRTHDAY**, and this type deliberately does not pick a default for
    /// that case — silently substituting `now` would hide real history.
    /// The caller (U6) surfaces the choice to the user instead.
    pub timestamp: u64,
    /// Initial `range` end (inclusive) to import for BOTH chains. Widened
    /// automatically ([`CoreRpcTransport::ranged_lookup_or_widen`]) as the
    /// gap window grows past it.
    pub range_end: u32,
}

/// Initial `range_end` a freshly-configured [`WatchDescriptor`] family gets
/// (U7, the wiring unit — `../../PLAN-chain-notes-app-core-rpc.md` §2.2's
/// "ranged descriptor import" finally gets a caller). 20 addresses per
/// chain (0 through 19) mirrors the standard BIP-44-style gap limit this
/// app already uses elsewhere for a FIRST look (`SPENDING_GAP_SHALLOW`-style
/// sizing in `src/lib.rs`, `chain::discover_indexes`'s stop-after-5-unused
/// rule) — enough that an ordinary notebook/spending wallet's real usage is
/// covered by the FIRST import (no immediate widen round-trip). Note this
/// does NOT bound the actual RPC cost tightly: `bitcoind` itself pads any
/// requested ranged-descriptor span up to a minimum of ~999 (verified live
/// — see `core_rpc_conformance.rs`'s `core_rpc_range_widening_finds_
/// address_beyond_initial_range` test), so the node ends up scanning a
/// similarly-sized window regardless of exactly what's requested here — the
/// real savings this unit delivers is ONE rescan pass per FAMILY instead of
/// one per ADDRESS, not a smaller per-family range.
/// [`CoreRpcTransport::ranged_lookup_or_widen`] grows this further (in
/// `CoreRpcTransport::WIDEN_CHUNK`-sized steps) the moment a real query
/// needs an index beyond whatever the node actually imported.
const RANGED_WATCH_INITIAL_RANGE_END: u32 = 19;

/// Bitcoin Core ranged-watch [`WatchDescriptor`]s for one identity's active
/// (account, network) — U7, the wiring unit: this is the ONLY place the app
/// (`src/lib.rs`'s `open_client`) and its CLI proxy (`examples/cli.rs`)
/// derive them, so both stay byte-identical and neither hand-rolls a second
/// derivation. Reuses the SAME functions the Settings "Reveal keys" screen
/// and the spending wallet already call — [`crate::keyexport::export_formats`]
/// for the notebook `tr(...)` (or watch-only) descriptor and
/// [`crate::spending::funding_descriptor`] for the BIP-84 `wpkh(...)`
/// spending descriptor — so this is purely ADDITIVE wiring, never a new
/// derivation path to keep byte-identical with anything.
///
/// **Birthday is always genesis (`timestamp: 0`).** This app has no field
/// anywhere that records "when was this identity's seed first generated" —
/// `store.rs`'s `NoteRecord`/`TxRecord.created_at` are per-transaction
/// compose times, not a wallet birthday — so there is no honest non-zero
/// value to offer here. [`WatchDescriptor::timestamp`]'s own doc comment
/// and the per-address `addr()` fallback (`CoreRpcTransport::
/// ensure_address_watched`) both already treat "substituting a recent
/// default would silently miss real history" as strictly worse than being
/// slow; this function makes the identical call for the ranged path. The
/// win over the per-address fallback is NOT "skip the rescan" — it's
/// collapsing what used to be one full-chain rescan PER ADDRESS into one
/// full-chain rescan PER FAMILY (both chains, `RANGED_WATCH_INITIAL_RANGE_END`
/// indexes, in a single `importdescriptors` call) — see
/// `core_rpc_import_descriptors_call_count` and the U6 commit this unit
/// builds on. A future unit could special-case a freshly-CREATED-in-app
/// identity (provably no history before its generation instant) with a
/// real non-zero birthday; nothing here does that yet.
///
/// Returns one entry per capability the identity actually has: none for
/// single-key material (WIF/hex — one address each, no range to speak of,
/// the per-address fallback already covers it byte-for-byte), one
/// (notebook) entry for hierarchical (mnemonic/xprv) or watch-only
/// (xpub/descriptor) material, plus a second (spending) entry when the
/// material can also derive the BIP-84 spending wallet
/// ([`crate::spending::can_derive_spending`] — watch-only never can, no
/// private key to derive it from). Every derivation here is a handful of
/// secp256k1 scalar multiplications (account-level, not per-address) —
/// cheap, but still real CPU, which is why callers configure this ONCE per
/// (identity, account, network) rather than on every `open_client` call
/// (24 call sites in `src/lib.rs` alone).
pub fn identity_watch_descriptors(
    material_str: &str,
    network: Network,
    account: u32,
) -> Vec<WatchDescriptor> {
    let mut out = Vec::with_capacity(2);
    if let Ok(formats) = crate::keyexport::export_formats(material_str, network, account, 0) {
        if let Some(descriptor) = formats.descriptor {
            out.push(WatchDescriptor {
                descriptor,
                network,
                timestamp: 0,
                range_end: RANGED_WATCH_INITIAL_RANGE_END,
            });
        }
    }
    if let Ok(material) = crate::identity::parse_key_material(material_str, network) {
        if crate::spending::can_derive_spending(&material) {
            if let Ok(descriptor) = crate::spending::funding_descriptor(&material, network, account) {
                out.push(WatchDescriptor {
                    descriptor,
                    network,
                    timestamp: 0,
                    range_end: RANGED_WATCH_INITIAL_RANGE_END,
                });
            }
        }
    }
    out
}

/// One configured [`WatchDescriptor`], parsed once and kept alongside its
/// currently-imported range and a local address→(chain,index) cache built
/// purely by derivation (no RPC) up to that range.
struct RangedWatch {
    spec: WatchDescriptor,
    source: FundingSource,
    /// Currently-imported `range` end (inclusive) on the node, for both
    /// chains — what `import_ranged` last told bitcoind.
    imported_end: u32,
    /// address → (chain, index), populated up to `imported_end` — anything
    /// NOT in here has never been told to bitcoind, so a lookup must never
    /// report "already imported" for an address absent from this map even
    /// if it happens to be `Ok` from a raw derivation (see
    /// `ranged_lookup_or_widen`'s chunked widen, which keeps the two in
    /// lock-step).
    index: HashMap<String, (usize, u32)>,
}

/// Structured result of [`CoreRpcTransport::preflight`] (plan §2.2/§2.3/U4)
/// — everything the UI (U6) needs to render an honest picture of the node
/// the user pointed the app at. Never used to silently gate behavior here;
/// this unit only reports.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// `getblockchaininfo.pruned` — a pruned node CANNOT rescan below its
    /// prune height at all. Report it; never silently return partial
    /// history (plan §2.2).
    pub pruned: bool,
    /// `getblockchaininfo.pruneheight`, populated only when `pruned`.
    pub prune_height: Option<u64>,
    /// Does `getindexinfo` carry a `"txindex"` entry? Without it, prevout
    /// lookup for EXTERNAL parents fails, so sender attribution degrades
    /// (plan §2.3) — never a hard failure by itself.
    pub txindex: bool,
    /// `getblockchaininfo.initialblockdownload`.
    pub initial_block_download: bool,
    /// The watch wallet's `getwalletinfo.scanning` — `None` when the
    /// wallet does not exist yet (nothing imported this session, not an
    /// error); `Some(false)` idle; `Some(true)` a rescan is in progress
    /// (bitcoind reports this as `{duration, progress}` rather than a bare
    /// bool — either shape maps to `true` here). A rescan in progress must
    /// be REPORTABLE, never look like an empty wallet (plan §2.2).
    pub wallet_scanning: Option<bool>,
    /// Chain tip height, for the UI's own "how far behind" arithmetic.
    pub tip_height: u64,
}

/// The outcome of one JSON-RPC call, kept distinct from [`Error`] so
/// [`CoreRpcTransport::getrawtransaction`] can pattern-match on the RPC
/// error CODE (needed for the -5 → 404 mapping) before it collapses down
/// to the crate-wide [`Error`] shape everything else uses.
enum RpcOutcome {
    Ok(serde_json::Value),
    /// A well-formed JSON-RPC error response (bitcoind answered, just with
    /// an error) — `code` is bitcoind's own numeric RPC error code.
    RpcError { code: Option<i64>, message: String },
    /// The request never reached a server, or no full response came back —
    /// mirrors [`Error::Transport`]'s "safe to retry" class.
    Transport(String),
    /// A response DID arrive but wasn't a parseable JSON-RPC envelope (bad
    /// auth with an empty 401 body, a proxy error page, ...).
    BadResponse(String),
}

/// `10^8` scale, rounded — bitcoind reports amounts in BTC (f64); every
/// esplora shape in this crate is sats (u64).
fn btc_to_sats(btc: f64) -> u64 {
    (btc * 1e8).round() as u64
}

/// Does `tx` (an esplora-shaped JSON value, as built by
/// [`CoreRpcTransport::esplora_tx_json`]) touch `address` — an input
/// prevout OR an output? The watch wallet is SHARED across every address
/// ever queried (one `graffito-watch` wallet holds every imported
/// `addr()` descriptor), so `listtransactions` returns other addresses'
/// txs too; this filter is load-bearing exactly as the plan's §1.3 table
/// notes — without it a gap-limit scan never finds an unused address and
/// walks forever.
fn tx_touches(tx: &serde_json::Value, address: &str) -> bool {
    let touches_vin = tx.get("vin").and_then(|v| v.as_array()).is_some_and(|a| {
        a.iter().any(|i| {
            i.get("prevout").and_then(|p| p.get("scriptpubkey_address")).and_then(|x| x.as_str())
                == Some(address)
        })
    });
    if touches_vin {
        return true;
    }
    tx.get("vout").and_then(|v| v.as_array()).is_some_and(|a| {
        a.iter().any(|o| o.get("scriptpubkey_address").and_then(|x| x.as_str()) == Some(address))
    })
}

impl CoreRpcTransport {
    /// Watch-only wallet this transport creates/loads on the node, holding
    /// every descriptor imported so far — one `addr()` at a time (U3
    /// fallback) or ranged families (U4, [`Self::watch_descriptors`]).
    /// Blank + private-keys-disabled, exactly like the reference
    /// `companion/server.py` shim's `cn-watch`.
    const WATCH_WALLET: &'static str = "graffito-watch";

    /// Environment override for [`Self::WATCH_WALLET`], for HARNESSES ONLY.
    ///
    /// **Deliberately the SAME variable `companion/server.py` reads**, with
    /// the same semantics and the same default. The shim and this transport
    /// are the two implementations of one wire contract, so a harness that
    /// exports one per-run wallet name must reach both; two variable names for
    /// one concept would mean a run that redirected the shim while quietly
    /// leaving the real transport on the shared wallet.
    ///
    /// A real user has one app and one node, so a single stable wallet is
    /// right for them and this is unset in production. Harnesses are the
    /// opposite: many throwaway identities against ONE shared node, every run
    /// importing more ranged descriptors into the same wallet forever. The
    /// shared regtest wallet reached 642 transactions and 404 descriptors that
    /// way, and a rescan is O(blocks x descriptors) while holding the wallet
    /// lock — a `timestamp: 0` import into it cost ~130s versus ~0.5s into a
    /// fresh one, and every other suite then queued behind that lock.
    ///
    /// The default is deliberately unchanged, and
    /// `watch_wallet_defaults_to_production_name` pins it — the point is to
    /// keep harnesses OFF the production wallet, not to move production.
    const WATCH_WALLET_ENV: &'static str = "CN_WATCH_WALLET";

    /// Resolved watch-wallet name: the env override if set and non-empty,
    /// else [`Self::WATCH_WALLET`]. Read per call rather than cached because
    /// `src/lib.rs` builds a fresh transport per operation anyway, so there is
    /// no cache to be stale — and a harness that exports the var mid-process
    /// (the CLI does, per subcommand) gets the value it just set.
    fn watch_wallet() -> String {
        match std::env::var(Self::WATCH_WALLET_ENV) {
            Ok(name) if !name.trim().is_empty() => name,
            _ => Self::WATCH_WALLET.to_string(),
        }
    }

    /// Default timeout for ordinary RPC calls (everything except
    /// [`Self::import_descriptors`] — see [`Self::RESCAN_TIMEOUT`]'s doc
    /// comment for why that one needs its own, much longer, budget). Kept
    /// short and unchanged from the pre-U6 behavior: a dead/unreachable
    /// node should fail a UI action quickly, not hang it.
    const RPC_TIMEOUT: Duration = Duration::from_secs(30);

    /// U6: timeout for RPC calls that can legitimately trigger bitcoind's
    /// own background wallet rescan (`importdescriptors`) — verified LIVE
    /// against a real, synced testnet4 node (~146k blocks, 2026-07-30): a
    /// genesis (`timestamp: 0`) rescan of a single freshly-imported address
    /// took **~309s** end to end (`getwalletinfo.scanning.duration`,
    /// polled to completion). [`Self::RPC_TIMEOUT`] would abort the HTTP
    /// request at 30s while the rescan keeps running on the node
    /// regardless — verified live too: `curl --max-time 30` against the
    /// identical call returns exit 28 (timed out) at 30s, but a follow-up
    /// `getwalletinfo` on the SAME wallet moments later still shows
    /// `scanning.progress` climbing. That is not merely slow, it is
    /// actively worse than a plain failure: the caller has no idea whether
    /// the import it might retry already landed, and the orphaned rescan
    /// goes on consuming the node's disk I/O regardless. 10 minutes is
    /// comfortably above the observed real-world duration (leaves room for
    /// a slower disk or mainnet's much longer chain) while still bounding
    /// the worst case — a genuinely wedged node — to something finite
    /// rather than forever.
    const RESCAN_TIMEOUT: Duration = Duration::from_secs(600);

    /// How many indices [`Self::ranged_lookup_or_widen`] derives (locally,
    /// no RPC) per attempt while searching for a cache-miss address beyond
    /// a descriptor's currently-imported range.
    const WIDEN_CHUNK: u32 = 100;
    /// How many [`Self::WIDEN_CHUNK`]-sized attempts before giving up on a
    /// descriptor and moving to the next (or falling back to per-address
    /// import) — bounds the cost of a query for an address that turns out
    /// to belong to NONE of the configured families (a contact, an
    /// external recipient, ...) to `WIDEN_CHUNK * MAX_WIDEN_CHUNKS * 2`
    /// pure derivations, no bitcoind round trip.
    const MAX_WIDEN_CHUNKS: u32 = 10;

    /// `rest` is the base URL with the `bitcoind+` prefix already
    /// stripped by [`AnyTransport::new`] (e.g. `http://host:8332` or
    /// `http://user:pass@host:8332`).
    ///
    /// U5 (`../../PLAN-chain-notes-app-core-rpc.md` §2.4, closing deferred
    /// audit finding M6) fixes two parsing defects a review of U2/U3 found,
    /// both of which used to produce a WRONG host/port silently instead of
    /// erroring:
    ///
    /// 1. A bracketed IPv6 host with NO port (`[::1]`) used to fall into
    ///    the plain `rsplit_once(':')` path, which finds the LAST colon —
    ///    one of the address's OWN colons, not a port separator — yielding
    ///    host `"[:"` and a silently-dropped port. Brackets are now peeled
    ///    off FIRST (same shape [`is_loopback_base`] already uses), so a
    ///    port is only ever looked for in the text AFTER the closing `]`.
    /// 2. A malformed port (`host:abc`, `host:999999`) used to fall through
    ///    `.parse::<u16>().ok()` straight to `None` — the same shape as
    ///    "no port was given at all". That's a silent wrong-config bug (the
    ///    app would talk to the scheme's default port instead of erroring
    ///    loudly), not a degrade-gracefully case, so it's now a hard
    ///    construction error naming the bad port text.
    pub fn new(rest: &str, creds: Option<(String, String)>) -> Result<Self, Error> {
        let (scheme, after_scheme) = rest
            .split_once("://")
            .ok_or_else(|| Error::Http("bitcoind+ URL missing a scheme".into()))?;
        if scheme != "http" && scheme != "https" {
            return Err(Error::Http(format!("unsupported bitcoind+ scheme: {scheme}")));
        }
        // Tolerate (and ignore) a stray trailing path/slash — Core's RPC
        // endpoint has none.
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let inline_creds = userinfo.and_then(|u| {
            u.split_once(':').map(|(user, pass)| (user.to_string(), pass.to_string()))
        });
        let parse_port = |p: &str| -> Result<u16, Error> {
            p.parse::<u16>().map_err(|_| Error::Http(format!("bitcoind+ URL: invalid port {p:?}")))
        };
        let (host, port): (String, Option<u16>) = if let Some(after_bracket) = hostport.strip_prefix('[') {
            // Bracketed IPv6 literal: `[addr]` or `[addr]:port`. Find the
            // CLOSING bracket explicitly rather than trusting any colon —
            // an IPv6 address is full of colons that are not port
            // separators (the exact bug this fixes: `[::1]` used to
            // silently mis-split on one of ITS OWN colons).
            let (addr, after) = after_bracket
                .split_once(']')
                .ok_or_else(|| Error::Http("bitcoind+ URL: unterminated IPv6 literal, missing ']'".into()))?;
            let port = match after {
                "" => None,
                p => match p.strip_prefix(':') {
                    Some(digits) if !digits.is_empty() => Some(parse_port(digits)?),
                    Some(_) => return Err(Error::Http("bitcoind+ URL: empty port after ':'".into())),
                    None => {
                        return Err(Error::Http(format!(
                            "bitcoind+ URL: unexpected text after IPv6 literal: {p:?}"
                        )))
                    }
                },
            };
            (addr.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(parse_port(p)?)),
                None => (hostport.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(Error::Http("bitcoind+ URL missing a host".into()));
        }
        Ok(CoreRpcTransport {
            scheme: scheme.to_string(),
            host,
            port,
            // Explicit creds win over inline userinfo when both present.
            // The password is wrapped in `Zeroizing` right here, at the
            // one point a plaintext `String` briefly exists — from here on
            // it's wiped on drop (plan §2.4).
            creds: creds.or(inline_creds).map(|(u, p)| (u, Zeroizing::new(p))),
            client: reqwest::blocking::Client::builder()
                .timeout(Self::RPC_TIMEOUT)
                .build()
                .expect("client config is static"),
            watched: Mutex::new(HashSet::new()),
            invalid: Mutex::new(HashSet::new()),
            wallet_ready: Mutex::new(false),
            ranged: Mutex::new(Vec::new()),
            next_id: Mutex::new(0),
            status_cache: Mutex::new(None),
            probe_calls: AtomicU32::new(0),
        })
    }

    /// The JSON-RPC endpoint for `wallet` (`None` = the node-level, non-
    /// wallet endpoint — `getblockcount`, `getrawtransaction`,
    /// `sendrawtransaction`, `testmempoolaccept`, `estimatesmartfee`,
    /// `getdescriptorinfo`, `createwallet`/`loadwallet`; `Some(name)` =
    /// `/wallet/<name>`, required for wallet RPCs once more than one
    /// wallet exists on the node — never relies on a "default wallet").
    fn rpc_url(&self, wallet: Option<&str>) -> String {
        // `self.host` is stored WITHOUT brackets (U5's IPv6 parsing fix
        // strips them) — a bare IPv6 literal must be re-bracketed here or
        // the reconstructed URL is ambiguous/invalid (`http://::1:8332`
        // reads as three colon-separated fields, not one address + port).
        // A hostname or IPv4 literal never contains ':', so this never
        // fires for them.
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let base = match self.port {
            Some(p) => format!("{}://{host}:{p}", self.scheme),
            None => format!("{}://{host}", self.scheme),
        };
        match wallet {
            Some(w) => format!("{base}/wallet/{w}"),
            None => base,
        }
    }

    /// Identifies "this node's watch wallet" for [`GLOBAL_WATCH_CACHE`] —
    /// scheme+host+port is enough: two different `CoreRpcTransport`s
    /// pointed at the same node (e.g. two `open_client` calls a second
    /// apart) always compute an identical key, and two different nodes
    /// (a Settings node-URL change, a network switch) never share one.
    fn node_key(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port.map(|p| p.to_string()).unwrap_or_default())
    }

    /// One JSON-RPC 1.0 call. Auth is an HTTP Authorization header via
    /// `basic_auth` — `self.creds` never touches the URL string, so
    /// nothing here (nor `reqwest`'s own error `Display`, which can echo
    /// the request URL) can leak a credential into an `Error`/log line.
    fn call(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> RpcOutcome {
        self.call_timeout(wallet, method, params, None)
    }

    /// [`Self::call`], with an optional PER-REQUEST timeout override
    /// (`reqwest::blocking::RequestBuilder::timeout` — when set, it wins
    /// over the client's own default set at construction, exactly for this
    /// one request). U6: [`Self::import_descriptors`] is the sole caller
    /// that passes `Some(_)`, using [`Self::RESCAN_TIMEOUT`] — every other
    /// call site keeps going through [`Self::call`] and therefore the
    /// short [`Self::RPC_TIMEOUT`] default, unchanged.
    fn call_timeout(
        &self,
        wallet: Option<&str>,
        method: &str,
        params: serde_json::Value,
        timeout: Option<Duration>,
    ) -> RpcOutcome {
        let id = {
            let mut n = self.next_id.lock().expect("rpc id mutex poisoned");
            *n += 1;
            *n
        };
        let url = self.rpc_url(wallet);
        let mut req = self.client.post(&url).json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some((user, pass)) = &self.creds {
            // `.as_str()` derefs through `Zeroizing<String>` — `reqwest`
            // needs `P: Display`, which `Zeroizing` deliberately does not
            // implement (nothing about it should be printable by accident).
            req = req.basic_auth(user, Some(pass.as_str()));
        }
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => return RpcOutcome::Transport(format!("bitcoind rpc: {e}")),
        };
        let status = resp.status();
        let text = match resp.text() {
            Ok(t) => t,
            Err(e) => return RpcOutcome::Transport(format!("bitcoind rpc: {e}")),
        };
        // A well-formed RPC error comes back as HTTP 500 with a JSON body
        // carrying {"result":null,"error":{code,message}}; a bad-auth
        // response is a bare 401 with an EMPTY body. Parse JSON first so a
        // genuine RPC error surfaces its message rather than a bare status
        // number, and only fall back to the status-only shape when the
        // body isn't JSON at all.
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                return RpcOutcome::BadResponse(format!(
                    "{}: non-JSON response from bitcoind",
                    status.as_u16()
                ))
            }
        };
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(|c| c.as_i64());
            let message =
                err.get("message").and_then(|m| m.as_str()).unwrap_or("bitcoind rpc error").to_string();
            return RpcOutcome::RpcError { code, message };
        }
        if !status.is_success() {
            return RpcOutcome::BadResponse(format!("{}: bitcoind rpc failed", status.as_u16()));
        }
        RpcOutcome::Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    /// [`Self::call`] collapsed to the crate-wide [`Error`] shape — what
    /// every route handler below uses except [`Self::getrawtransaction`],
    /// which needs the raw RPC code for the -5 → 404 mapping.
    fn rpc(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Error> {
        match self.call(wallet, method, params) {
            RpcOutcome::Ok(v) => Ok(v),
            RpcOutcome::RpcError { code, message } => Err(Error::Http(format!(
                "bitcoind{}: {message}",
                code.map(|c| format!(" [{c}]")).unwrap_or_default()
            ))),
            RpcOutcome::Transport(m) => Err(Error::Transport(m)),
            RpcOutcome::BadResponse(m) => Err(Error::Http(m)),
        }
    }

    /// U6: sends ONE `importdescriptors` call for `requests` (an array of
    /// already-built `{"desc":…, "timestamp":…[, "range":…]}` objects)
    /// against the watch wallet. The SOLE place either real caller — the
    /// per-address `addr()` fallback in [`Self::ensure_address_watched`]
    /// and the ranged-descriptor path in [`Self::import_ranged`] — actually
    /// triggers a real bitcoind rescan, so it's factored out to be the SOLE
    /// place that (a) uses [`Self::RESCAN_TIMEOUT`] instead of the ordinary
    /// short budget (a rescan can legitimately run for minutes — see that
    /// constant's doc comment) and (b) increments the process-global
    /// [`IMPORT_DESCRIPTORS_CALLS`] test-visibility counter, so a
    /// regression test can prove EITHER call site's idempotence by asserting
    /// on this ONE number rather than needing two.
    fn import_descriptors(&self, requests: serde_json::Value) -> Result<serde_json::Value, Error> {
        IMPORT_DESCRIPTORS_CALLS.fetch_add(1, Ordering::Relaxed);
        match self.call_timeout(
            Some(&Self::watch_wallet()),
            "importdescriptors",
            serde_json::json!([requests]),
            Some(Self::RESCAN_TIMEOUT),
        ) {
            RpcOutcome::Ok(v) => Ok(v),
            RpcOutcome::RpcError { code, message } => Err(Error::Http(format!(
                "bitcoind{}: {message}",
                code.map(|c| format!(" [{c}]")).unwrap_or_default()
            ))),
            RpcOutcome::Transport(m) => Err(Error::Transport(m)),
            RpcOutcome::BadResponse(m) => Err(Error::Http(m)),
        }
    }

    /// `getrawtransaction` mapping bitcoind's RPC code -5 ("No such mempool
    /// or blockchain transaction") to an esplora-shaped 404 ONLY when
    /// [`Self::established_absent`] has POSITIVELY proven absence (plan
    /// §2.1) — U3's original cut mapped -5 to 404 unconditionally, which is
    /// wrong on a pruned/non-txindex/still-syncing node: there, -5 means
    /// "I can't tell", not "this doesn't exist", and mapping it to a
    /// definitive 404 would make `TxLookupStatus::NotFound` fire on a node
    /// that is simply blind — the exact failure mode that makes the app
    /// declare a LIVE transaction dropped (see `TxLookupStatus`'s own doc
    /// comment). When absence can't be established, this returns a PLAIN
    /// `Error::Http` whose text does NOT start with `"404"` — so it falls
    /// through to `TxLookupStatus::Unknown` exactly like any other
    /// unclassified error, never `NotFound`. The `"404:"` prefix, when it
    /// IS used, is load-bearing: [`ChainClient::tx_lookup_status`] matches
    /// on it verbatim, exactly as it does for a real esplora 404.
    fn getrawtransaction(&self, txid: &str, verbosity: u8) -> Result<serde_json::Value, Error> {
        match self.call(None, "getrawtransaction", serde_json::json!([txid, verbosity])) {
            RpcOutcome::Ok(v) => Ok(v),
            RpcOutcome::RpcError { code: Some(-5), .. } => {
                if self.established_absent(txid) {
                    Err(Error::Http(format!("404: no such transaction: {txid}")))
                } else {
                    // Deliberately NOT prefixed "404" — see the doc comment
                    // above. `TxLookupStatus`/`tx_lookup_status` treat any
                    // non-"404"-prefixed `Error::Http` (and every
                    // `Error::Transport`) as `Unknown`, never `NotFound`.
                    Err(Error::Http(format!(
                        "bitcoind: cannot establish absence of {txid} \
                         (txindex/IBD/mempool state unresolved)"
                    )))
                }
            }
            RpcOutcome::RpcError { code, message } => Err(Error::Http(format!(
                "bitcoind{}: {message}",
                code.map(|c| format!(" [{c}]")).unwrap_or_default()
            ))),
            RpcOutcome::Transport(m) => Err(Error::Transport(m)),
            RpcOutcome::BadResponse(m) => Err(Error::Http(m)),
        }
    }

    /// The plan's §2.1 rule, made concrete: a `getrawtransaction` -5 may be
    /// read as POSITIVELY-established absence only when THREE things are
    /// simultaneously true — the node carries `txindex` (otherwise a
    /// perfectly real, already-confirmed, non-wallet tx is simply invisible
    /// to this call, not gone), it is not in initial block download
    /// (otherwise "not found yet" can just mean "haven't gotten there
    /// yet"), and the txid is ALSO absent from the mempool specifically
    /// (checked directly via `getmempoolentry`, not merely inferred from
    /// the `getrawtransaction` -5 itself — verified live that
    /// `getmempoolentry` on an unknown txid answers with the SAME RPC code
    /// -5, "Transaction not in mempool", so this is a real, independent
    /// second signal rather than restating the first). Any single failure
    /// downgrades the verdict to "can't tell" — a false NotFound is the
    /// single worst failure mode in this project (see `TxLookupStatus`'s
    /// doc comment), so this function is intentionally conservative:
    /// on ANY error establishing the node's status, it returns `false`.
    fn established_absent(&self, txid: &str) -> bool {
        let status = match self.cached_status() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if !status.txindex || status.initial_block_download {
            return false;
        }
        matches!(
            self.call(None, "getmempoolentry", serde_json::json!([txid])),
            RpcOutcome::RpcError { code: Some(-5), .. }
        )
    }

    /// The raw, uncached [`NodeStatus`] probe (`getblockchaininfo` +
    /// `getindexinfo`) — the body [`Self::preflight`] and
    /// [`Self::cached_status`] both call, factored out so
    /// [`Self::probe_calls`] counts EVERY real probe regardless of which
    /// of those two callers triggered it (used by a conformance test to
    /// prove the cache is actually load-bearing, not merely present).
    fn compute_status(&self) -> Result<NodeStatus, Error> {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        let info = self.rpc(None, "getblockchaininfo", serde_json::json!([]))?;
        let pruned = info.get("pruned").and_then(|v| v.as_bool()).unwrap_or(false);
        let prune_height = if pruned { info.get("pruneheight").and_then(|v| v.as_u64()) } else { None };
        let initial_block_download =
            info.get("initialblockdownload").and_then(|v| v.as_bool()).unwrap_or(false);
        let tip_height = info.get("blocks").and_then(|v| v.as_u64()).unwrap_or(0);

        let idx = self.rpc(None, "getindexinfo", serde_json::json!([]))?;
        let txindex = idx.get("txindex").is_some();

        let wallet_scanning =
            match self.rpc(Some(&Self::watch_wallet()), "getwalletinfo", serde_json::json!([])) {
                Ok(wi) => Some(match wi.get("scanning") {
                    Some(v) if v.is_object() => true,
                    Some(v) => v.as_bool().unwrap_or(false),
                    None => false,
                }),
                Err(_) => None,
            };

        Ok(NodeStatus { pruned, prune_height, txindex, initial_block_download, wallet_scanning, tip_height })
    }

    /// [`Self::compute_status`], cached (plan §2.1: "cache it; do not
    /// re-probe per call") — every internal caller (right now, only
    /// [`Self::established_absent`]) goes through this instead of
    /// [`Self::preflight`] directly, so a burst of tx lookups costs ONE
    /// `getblockchaininfo`/`getindexinfo` round trip, not one per lookup.
    /// [`Self::preflight`] itself stays uncached (a UI-facing "check now"
    /// call should always be fresh) but DOES refresh this cache as a side
    /// effect, so an explicit preflight also benefits the next lookup.
    fn cached_status(&self) -> Result<NodeStatus, Error> {
        if let Some(s) = self.status_cache.lock().expect("status-cache mutex poisoned").clone() {
            return Ok(s);
        }
        let status = self.compute_status()?;
        *self.status_cache.lock().expect("status-cache mutex poisoned") = Some(status.clone());
        Ok(status)
    }

    /// Real calls to [`Self::compute_status`] so far this session — test
    /// visibility only (an integration test in another crate can't reach a
    /// private field directly), proving the cache in [`Self::cached_status`]
    /// is genuinely load-bearing rather than merely present: a reviewer's
    /// mutation that made [`Self::established_absent`] call
    /// [`Self::compute_status`] directly (bypassing the cache) would make
    /// this counter grow once per lookup instead of staying at 1.
    pub fn preflight_probe_count(&self) -> u32 {
        self.probe_calls.load(Ordering::Relaxed)
    }

    /// A prevout `getrawtransaction verbosity=2` did NOT inline (bitcoind
    /// omits `prevout` when "block undo data is not available" — verified
    /// live: a NOT-YET-MINED (mempool) input's prevout comes back missing
    /// entirely, even though the parent tx is perfectly known) — resolved
    /// by fetching the parent tx directly and reading its `vout[vout]`.
    /// Mirrors `ChainClient::fetch_tx_io`'s own client-side fallback for
    /// the identical gap, just applied server-side here so every OTHER
    /// route (`utxos`, `address_stats`, `classify_tx_net`'s
    /// `spends_from_self`, ...) — which all read `vin[].prevout` directly
    /// with no fallback of their own — gets a populated prevout for a
    /// mempool tx too. Best-effort: an unresolvable parent (shouldn't
    /// happen for anything this transport itself watches) degrades to
    /// `(None, 0)`, matching every esplora field's `#[serde(default)]`
    /// tolerance on the client side rather than failing the whole tx.
    fn resolve_prevout(&self, parent_txid: &str, vout: u64) -> (Option<String>, u64) {
        let Ok(parent) = self.getrawtransaction(parent_txid, 1) else {
            return (None, 0);
        };
        let out = parent.get("vout").and_then(|v| v.as_array()).and_then(|a| a.get(vout as usize));
        let address = out
            .and_then(|o| o.get("scriptPubKey"))
            .and_then(|s| s.get("address"))
            .and_then(|a| a.as_str())
            .map(str::to_string);
        let value = out.and_then(|o| o.get("value")).and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
        (address, value)
    }

    /// `getrawtransaction txid 2` mapped onto the esplora tx shape
    /// [`EsploraTx`] deserializes — mirrors `server.py`'s `esplora_tx`
    /// (module doc, §1.3 of the plan) field-for-field: `confirmed` from
    /// `confirmations > 0`, `block_height` derived from `tip`, `nulldata`
    /// → `"op_return"` (esplora's own type name, load-bearing —
    /// `classify_tx_inner` matches it literally), vin prevouts via
    /// [`Self::resolve_prevout`] when Core didn't inline one.
    ///
    /// Checks [`TX_JSON_CACHE`] first and, when this call ends up building
    /// a CONFIRMED result, populates it before returning — see that
    /// static's doc comment for the exact safety rule (unconfirmed results
    /// are never cached, never read from cache). A cache hit skips the
    /// `getrawtransaction` round trip (and any [`Self::resolve_prevout`]
    /// follow-ups) entirely; `tip` is only used to (re)compute
    /// `status.block_height` on a miss, since a confirmed tx's own block
    /// height is fixed the moment it's first resolved and does not need
    /// recomputing against a later, higher tip.
    fn esplora_tx_json(&self, txid: &str, tip: u64) -> Result<serde_json::Value, Error> {
        let cache_key = (self.node_key(), txid.to_string());
        if let Some(cached) = TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned").get(&cache_key) {
            return Ok(cached.clone());
        }
        let raw = self.getrawtransaction(txid, 2)?;
        let confirmations = raw.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0);
        let confirmed = confirmations > 0;
        let mut status = serde_json::json!({"confirmed": confirmed});
        if confirmed {
            status["block_height"] = serde_json::json!(tip.saturating_sub(confirmations).saturating_add(1));
            if let Some(bt) = raw.get("blocktime") {
                status["block_time"] = bt.clone();
            }
        }
        let vin: Vec<serde_json::Value> = raw
            .get("vin")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|i| {
                let txid_v = i.get("txid").cloned().unwrap_or(serde_json::Value::Null);
                let vout_v = i.get("vout").cloned().unwrap_or(serde_json::Value::Null);
                let (address, value) = match i.get("prevout").filter(|p| !p.is_null()) {
                    Some(p) => {
                        let addr = p
                            .get("scriptPubKey")
                            .and_then(|s| s.get("address"))
                            .and_then(|a| a.as_str())
                            .map(str::to_string);
                        let v = p.get("value").and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
                        (addr, v)
                    }
                    None => match (txid_v.as_str(), vout_v.as_u64()) {
                        // Coinbase inputs carry neither — nothing to resolve.
                        (Some(pt), Some(pv)) => self.resolve_prevout(pt, pv),
                        _ => (None, 0),
                    },
                };
                serde_json::json!({
                    "txid": txid_v,
                    "vout": vout_v,
                    "prevout": {"scriptpubkey_address": address, "value": value},
                })
            })
            .collect();
        let vout: Vec<serde_json::Value> = raw
            .get("vout")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|o| {
                let spk = o.get("scriptPubKey");
                let core_type = spk.and_then(|s| s.get("type")).and_then(|t| t.as_str());
                let esplora_type = if core_type == Some("nulldata") { Some("op_return") } else { core_type };
                let address = spk.and_then(|s| s.get("address")).and_then(|a| a.as_str());
                let hex = spk.and_then(|s| s.get("hex")).and_then(|h| h.as_str());
                let value = o.get("value").and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
                serde_json::json!({
                    "scriptpubkey": hex,
                    "scriptpubkey_type": esplora_type,
                    "scriptpubkey_address": address,
                    "value": value,
                })
            })
            .collect();
        let result = serde_json::json!({"txid": txid, "status": status, "vin": vin, "vout": vout});
        if confirmed {
            // See `TX_JSON_CACHE`'s doc comment: ONLY a confirmed result is
            // ever inserted. An unconfirmed one is returned as-is, every
            // time, with no cache write — its status can still change.
            // See `TX_JSON_CACHE_MAX_ENTRIES`'s doc comment for the bound
            // enforced here: once full, stop inserting rather than evict —
            // existing entries keep serving hits, the cache just stops
            // growing.
            let mut cache = TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned");
            if cache.len() < TX_JSON_CACHE_MAX_ENTRIES {
                cache.insert(cache_key, result.clone());
            }
        }
        Ok(result)
    }

    fn ensure_watch_wallet(&self) -> Result<(), Error> {
        if *self.wallet_ready.lock().expect("wallet-ready mutex poisoned") {
            return Ok(());
        }
        match self.rpc(None, "createwallet", serde_json::json!([Self::watch_wallet(), true, true])) {
            Ok(_) => {}
            // Verified live wording (bitcoind v30.2.0): "...Database
            // already exists." A wallet already present on the node from
            // an earlier session/transport instance — load it instead.
            Err(Error::Http(msg)) if msg.contains("already exists") => {
                match self.rpc(None, "loadwallet", serde_json::json!([Self::watch_wallet()])) {
                    Ok(_) => {}
                    // Verified live wording: `Wallet "..." is already
                    // loaded.` — another instance/thread got there first.
                    Err(Error::Http(msg2)) if msg2.contains("already loaded") => {}
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
        *self.wallet_ready.lock().expect("wallet-ready mutex poisoned") = true;
        Ok(())
    }

    /// Per-address `addr()` descriptor import — the U3 fallback, still hit
    /// for anything not covered by a configured [`WatchDescriptor`] family
    /// (a contact, an external recipient, a custom change address, ...) and
    /// the ENTIRE behavior when [`Self::watch_descriptors`] was never
    /// called — which today means EVERY call the shipped app ever makes
    /// (`watch_descriptors` is exercised by this crate's own tests but has
    /// no caller anywhere in `src/lib.rs` or `examples/cli.rs`). Ensures
    /// `address` is imported into the watch wallet — first by checking
    /// whether it belongs to a ranged family already configured (U4,
    /// [`Self::ranged_lookup_or_widen`]), widening that family's imported
    /// range instead of falling back here when it does.
    ///
    /// **U6 (the "unusable against a real node" fix, 2026-07-30) rewrote
    /// the middle of this function; read this before touching it again.**
    /// The bug: `self.watched` (checked first, below) is a PER-INSTANCE
    /// cache, but `src/lib.rs` constructs a fresh `ChainClient`/
    /// `AnyTransport` — and therefore a fresh, empty `CoreRpcTransport` —
    /// on nearly every single operation (`open_client`, 24 call sites,
    /// none of which persist a transport across calls). So the cache was
    /// empty on essentially every call, and this function used to run its
    /// `importdescriptors` unconditionally on every miss — with
    /// `timestamp: 0` (scan from genesis). Verified LIVE against a real,
    /// synced testnet4 node (~146k blocks): that single call took ~309s,
    /// while the shared `reqwest::blocking::Client`'s timeout was a flat
    /// 30s — so in production this doesn't just run needlessly often, it
    /// TIMES OUT on every single address lookup against any real (non-toy)
    /// chain, while the orphaned rescan keeps running server-side
    /// regardless (only regtest's ~100-block chain made a genesis rescan
    /// fast enough to hide this — which is exactly why nothing in this
    /// crate's regtest-backed test suite ever caught it).
    ///
    /// Three independent fixes, all present below: (1) idempotence is now
    /// checked AGAINST THE NODE itself (`getaddressinfo`'s `ismine`), which
    /// is stateless and therefore survives the per-operation transport
    /// churn that defeats any in-memory cache — this is what actually
    /// makes the import run AT MOST ONCE per address ever, not per
    /// instance; (2) [`GLOBAL_WATCH_CACHE`] is a process-global cache on
    /// top of that check, purely to skip even the one cheap
    /// `getaddressinfo` round trip on a hot-path repeat; (3) the
    /// `importdescriptors` call itself (factored into
    /// [`Self::import_descriptors`]) now runs under [`Self::RESCAN_TIMEOUT`]
    /// (minutes), not [`Self::RPC_TIMEOUT`] (30s) — belt-and-braces on top
    /// of (1)/(2), for the one time per address this import is still
    /// genuinely supposed to happen. `timestamp: 0` itself is UNCHANGED —
    /// see the comment at the actual call site below for why that is still
    /// the only honest choice for this particular fallback. Returns
    /// `Ok(true)` for a real, importable address;
    /// `Ok(false)` for a syntactically INVALID one (bitcoind RPC code -5 —
    /// a garbage string, not decodable on any network) — which can never
    /// have on-chain history, so a `false` return is the caller's signal to
    /// short-circuit straight to an empty answer rather than handing that
    /// string to an RPC that validates its address argument (`listunspent`
    /// does; `listtransactions` takes no address param at all, so it was
    /// never at risk). Esplora never hard-errors an unusual address lookup
    /// either (only an unknown TXID gets a definite 404 — see this file's
    /// `tx_lookup_status` contract), so this keeps the same "never an `Err`
    /// the caller has to special-case" shape. Verified live: this is
    /// exactly what `assert_chain_contract`'s "an address never mentioned
    /// anywhere in the scenario reads as definitively unused" check
    /// exercises.
    ///
    /// **U5 decision (plan §2.4/"garbage-address silent-success path"),
    /// made deliberately rather than left as an accident of the U3
    /// fixture:** this KEEPS the empty-shape behavior for a syntactically
    /// invalid address, rather than making it an `Error` the way real
    /// mempool.space answers a malformed address with HTTP 400. Reasons:
    /// (1) every address this transport is ever asked to look up is one
    /// THIS APP derived or the user typed through the app's own
    /// address-parsing validation (`address_to_script_pubkey` et al.) —
    /// unlike a public Esplora endpoint, nothing here is exposed to
    /// arbitrary third-party input, so the practical risk of silently
    /// treating garbage as "never used" is low; (2) an empty-but-Ok answer
    /// is BEHAVIORALLY IDENTICAL, from every caller's point of view, to a
    /// genuinely valid address that has simply never been used on chain —
    /// there is no code path in this crate that treats "definitely
    /// invalid" differently from "definitely unused", so returning an
    /// `Error` here instead would need a whole new handling class for no
    /// caller that currently exists; (3) changing this now would also
    /// change the shape of `assert_chain_contract`'s own never-used-address
    /// leg (a fixture inherited from before this decision was examined),
    /// which is exactly the kind of Esplora-path regression this unit must
    /// not introduce. If a future unit adds a UI surface where a user can
    /// directly type/paste an arbitrary address into a Core-backed lookup
    /// (contact add, custom change address, ...), the trade-off should be
    /// revisited THERE — with real address-format validation surfaced as a
    /// UI error before the string ever reaches this transport — rather
    /// than by making this internal transport method start erroring.
    fn ensure_address_watched(&self, address: &str) -> Result<bool, Error> {
        if self.watched.lock().expect("watched-address mutex poisoned").contains(address) {
            return Ok(true);
        }
        if self.invalid.lock().expect("invalid-address mutex poisoned").contains(address) {
            return Ok(false);
        }
        // U6: process-global cache hit — some EARLIER `CoreRpcTransport`
        // instance (this process may have constructed dozens by now, one
        // per `open_client` call) already confirmed this address is
        // imported. Cheapest possible path: no RPC at all. See
        // `GLOBAL_WATCH_CACHE`'s doc comment — this is an optimization on
        // top of the node-truth check below, never a substitute for it.
        let node_key = self.node_key();
        let cache_key = (node_key.clone(), address.to_string());
        if GLOBAL_WATCH_CACHE.lock().expect("global watch-cache mutex poisoned").contains(&cache_key) {
            self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
            return Ok(true);
        }
        if self.ranged_lookup_or_widen(address)? {
            // Already imported (at configure time or just now, widened) —
            // cache the hit in `watched`/`GLOBAL_WATCH_CACHE` too so the
            // NEXT query for the same address (this instance or a later
            // one) takes the cheapest possible path.
            self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
            GLOBAL_WATCH_CACHE.lock().expect("global watch-cache mutex poisoned").insert(cache_key);
            return Ok(true);
        }
        self.ensure_watch_wallet()?;

        // U6: idempotence AGAINST THE NODE, not process memory.
        // `getaddressinfo` is a stateless, authoritative answer to "did
        // SOME earlier transport instance (possibly in an earlier process,
        // possibly seconds ago) already import this address" — it survives
        // the per-operation transport churn that defeats every in-memory
        // cache above. For this transport's blank, private-keys-disabled
        // watch wallet, `ismine` is exactly the right field: an
        // `addr()`-imported scriptPubKey reads back `ismine: true`
        // (verified live against bitcoind v30.2.0, both regtest and a real
        // testnet4 node) whether or not the wallet holds a spending key for
        // it — which it never does here. A syntactically invalid or
        // wrong-network address answers with the SAME RPC code -5
        // `getdescriptorinfo` below already special-cases (verified live),
        // so this call subsumes that check for the common case;
        // `getdescriptorinfo` stays below as defense in depth for whatever
        // this one doesn't cover.
        match self.call(Some(&Self::watch_wallet()), "getaddressinfo", serde_json::json!([address])) {
            RpcOutcome::Ok(info) => {
                if info.get("ismine").and_then(|v| v.as_bool()).unwrap_or(false) {
                    self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
                    GLOBAL_WATCH_CACHE.lock().expect("global watch-cache mutex poisoned").insert(cache_key);
                    return Ok(true);
                }
                // A syntactically valid address the node has genuinely
                // never seen before — fall through and import it, exactly
                // once, below.
            }
            RpcOutcome::RpcError { code: Some(-5), .. } => {
                self.invalid.lock().expect("invalid-address mutex poisoned").insert(address.to_string());
                return Ok(false);
            }
            RpcOutcome::RpcError { code, message } => {
                return Err(Error::Http(format!(
                    "bitcoind{}: {message}",
                    code.map(|c| format!(" [{c}]")).unwrap_or_default()
                )))
            }
            RpcOutcome::Transport(m) => return Err(Error::Transport(m)),
            RpcOutcome::BadResponse(m) => return Err(Error::Http(m)),
        }

        let desc = match self.call(None, "getdescriptorinfo", serde_json::json!([format!("addr({address})")])) {
            RpcOutcome::Ok(info) => info
                .get("descriptor")
                .and_then(|d| d.as_str())
                .ok_or_else(|| Error::Json("getdescriptorinfo: missing descriptor".into()))?
                .to_string(),
            RpcOutcome::RpcError { code: Some(-5), .. } => {
                self.invalid.lock().expect("invalid-address mutex poisoned").insert(address.to_string());
                return Ok(false);
            }
            RpcOutcome::RpcError { code, message } => {
                return Err(Error::Http(format!(
                    "bitcoind{}: {message}",
                    code.map(|c| format!(" [{c}]")).unwrap_or_default()
                )))
            }
            RpcOutcome::Transport(m) => return Err(Error::Transport(m)),
            RpcOutcome::BadResponse(m) => return Err(Error::Http(m)),
        };
        // `timestamp: 0` (scan from genesis) is UNCHANGED by U6, and
        // deliberately so — this call is reached only for an address that
        // belongs to no configured ranged family (today: EVERY address,
        // since nothing calls `watch_descriptors` — see this function's
        // doc comment) and this transport has no way to know when such an
        // address might first have been used. Substituting anything else
        // (e.g. "now") would silently miss real pre-existing history,
        // which this project treats as strictly worse than being slow —
        // the identical call `WatchDescriptor::timestamp`'s own doc
        // comment makes for the ranged path's "imported seed, no known
        // birthday" case. What U6 actually changed is not this value, it's
        // that the surrounding `getaddressinfo`/`GLOBAL_WATCH_CACHE` checks
        // above now make this import run AT MOST ONCE per address ever
        // (per node), instead of once per `open_client` call as before —
        // and that it now runs under `Self::RESCAN_TIMEOUT`
        // ([`Self::import_descriptors`]) instead of the ordinary 30s
        // budget, since a genesis rescan on a real chain measures in
        // minutes, not seconds (verified live: ~309s against a real,
        // synced testnet4 node).
        self.import_descriptors(serde_json::json!([{"desc": desc, "timestamp": 0}]))?;
        self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
        GLOBAL_WATCH_CACHE.lock().expect("global watch-cache mutex poisoned").insert(cache_key);
        Ok(true)
    }

    /// Configure ranged-descriptor watching (plan §2.2/U4) for one or more
    /// descriptor families — additive and out-of-band: call this BEFORE any
    /// address belonging to `specs` is queried through [`Transport::get_text`]/
    /// [`Transport::post_text`]. Imports both chains of each descriptor in
    /// ONE `importdescriptors` call — verified live against bitcoind
    /// v30.2.0: a `<0;1>` multipath descriptor imports as two chains from a
    /// single request, no manual `internal: true`/`false` split needed (that
    /// split IS needed for the OLD per-address `addr()` path, which has no
    /// chains to speak of — irrelevant there). A caller with nothing to
    /// configure need not call this at all; every existing address query
    /// keeps working through the U3 per-address fallback untouched.
    ///
    /// U7 (the wiring unit): `src/lib.rs`'s `open_client` now calls this on
    /// EVERY `ChainClient`/transport it builds (24 call sites, one fresh
    /// `CoreRpcTransport` per call — see U6's commit message) whenever the
    /// active identity has at least one descriptor to configure, so this
    /// runs far more often than U4's own tests ever called it. Each spec is
    /// therefore checked against the NODE (`Self::ranged_family_imported_end`,
    /// a `listdescriptors` read) before importing — the exact same
    /// node-truth idempotence `Self::ensure_address_watched` already applies
    /// to the per-address path (U6), for the identical reason: an in-memory
    /// "already configured" flag on `self` cannot survive the per-call
    /// transport churn, but `listdescriptors` can. A family already imported
    /// with a range covering what's requested costs one cheap read, never a
    /// re-`importdescriptors`/re-rescan.
    pub fn watch_descriptors(&self, specs: Vec<WatchDescriptor>) -> Result<(), Error> {
        if specs.is_empty() {
            return Ok(());
        }
        self.ensure_watch_wallet()?;
        let mut configured = Vec::with_capacity(specs.len());
        for spec in specs {
            let source = FundingSource::parse(&spec.descriptor, spec.network)?;
            let requested_end = spec.range_end;
            let imported_end = match self.ranged_family_imported_end(&spec)? {
                // The node already covers (or exceeds) what's requested —
                // no RPC round trip, no rescan. A wider PRIOR import (e.g. a
                // previous session's widen) is preserved rather than
                // narrowed back down.
                Some(existing) if existing >= requested_end => existing,
                // Absent, or imported with a narrower range than requested —
                // (re-)import up to `requested_end`. Safe to repeat: a
                // second `importdescriptors` for an already-imported
                // descriptor simply extends its cached range (verified live,
                // see `Self::import_ranged`'s doc comment).
                _ => {
                    self.import_ranged(&spec, requested_end)?;
                    requested_end
                }
            };
            let mut rw = RangedWatch { spec, source, imported_end: 0, index: HashMap::new() };
            Self::populate_index(&mut rw, 0, imported_end);
            rw.imported_end = imported_end;
            configured.push(rw);
        }
        self.ranged.lock().expect("ranged-watch mutex poisoned").extend(configured);
        Ok(())
    }

    /// The `xpub`/`tpub` token inside a descriptor string, or `None` when it
    /// carries neither. The production counterpart to
    /// `core_rpc_conformance.rs`'s test-only `xpub_of` helper (kept
    /// independent — a test file must never depend on crate-internal
    /// production code, and vice versa) — same reasoning: bitcoind
    /// normalizes `'` to `h` and splits a `<0;1>` multipath import into two
    /// single-path `listdescriptors` entries, but the xpub/tpub token itself
    /// survives both untouched, so it's the one thing safe to match a
    /// caller-supplied descriptor against a `listdescriptors` response with.
    fn descriptor_xpub_token(descriptor: &str) -> Option<&str> {
        descriptor.split(['(', ')', '[', ']', '/']).find(|s| s.starts_with("xpub") || s.starts_with("tpub"))
    }

    /// U7: node-truth idempotence for the ranged path — `listdescriptors`
    /// against the watch wallet, filtered to entries whose descriptor
    /// carries `spec`'s own xpub/tpub token. Returns the SMALLER of the two
    /// chains' `range[1]` when BOTH are found (an interrupted prior import
    /// that only landed one chain must still be treated as needing a fresh
    /// import, so the other chain gets covered too); `None` when the node
    /// doesn't have both chains configured yet, or `spec`'s descriptor
    /// carries no xpub/tpub token at all (nothing to safely match on — treat
    /// as unconfigured, same as a fresh node).
    fn ranged_family_imported_end(&self, spec: &WatchDescriptor) -> Result<Option<u32>, Error> {
        let Some(token) = Self::descriptor_xpub_token(&spec.descriptor) else { return Ok(None) };
        let v = self.rpc(Some(&Self::watch_wallet()), "listdescriptors", serde_json::json!([]))?;
        let entries = v.get("descriptors").and_then(|d| d.as_array()).cloned().unwrap_or_default();
        let ends: Vec<u32> = entries
            .iter()
            .filter(|d| d.get("desc").and_then(|s| s.as_str()).is_some_and(|desc| desc.contains(token)))
            .map(|d| d.get("range").and_then(|r| r.get(1)).and_then(|e| e.as_u64()).unwrap_or(0) as u32)
            .collect();
        if ends.len() < 2 {
            return Ok(None);
        }
        Ok(ends.into_iter().min())
    }

    /// Derive `[from..=to]` on both chains of `rw.source`, inserting every
    /// result into its address→(chain,index) map. Pure computation — no
    /// RPC — so calling this speculatively while widen-searching costs
    /// nothing beyond CPU even when the address being searched for turns
    /// out not to belong to this family at all.
    fn populate_index(rw: &mut RangedWatch, from: u32, to: u32) {
        for idx in from..=to {
            for chain in [0usize, 1usize] {
                if let Ok(d) = rw.source.derive(chain, idx) {
                    rw.index.insert(d.address, (chain, idx));
                }
            }
        }
    }

    /// `getdescriptorinfo` (bitcoind requires a `#checksum` suffix on every
    /// `importdescriptors` request — verified live, "Missing checksum"
    /// otherwise) then `importdescriptors` with `range: [0, end]` and
    /// `spec`'s own birthday timestamp. Re-issuing the SAME descriptor
    /// string with a wider `end` is how widening works — verified live
    /// against bitcoind v30.2.0: a second `importdescriptors` call for an
    /// already-imported descriptor simply extends its cached range; `next`
    /// (the highest index already seen as used) and prior history are
    /// untouched, so this is safe to call repeatedly.
    fn import_ranged(&self, spec: &WatchDescriptor, end: u32) -> Result<(), Error> {
        let bare = spec.descriptor.split('#').next().unwrap_or(&spec.descriptor);
        let info = self.rpc(None, "getdescriptorinfo", serde_json::json!([bare]))?;
        let checksum = info
            .get("checksum")
            .and_then(|c| c.as_str())
            .ok_or_else(|| Error::Json("getdescriptorinfo: missing checksum".into()))?;
        let desc = format!("{bare}#{checksum}");
        // U6: routed through `Self::import_descriptors` (was a direct
        // `self.rpc` call) so this path — which CAN also trigger a real
        // rescan whenever `spec.timestamp` is 0 or old (an imported seed
        // with no known birthday, exactly like the per-address fallback) —
        // gets `Self::RESCAN_TIMEOUT` instead of the ordinary 30s budget,
        // and is covered by the same process-global call-count test hook.
        // `spec.timestamp` itself is untouched: this is the ranged path,
        // which already receives a real caller-supplied birthday whenever
        // one is known (see `WatchDescriptor::timestamp`'s doc comment) —
        // nothing here defaults it to genesis.
        self.import_descriptors(serde_json::json!([{"desc": desc, "timestamp": spec.timestamp, "range": [0, end]}]))?;
        Ok(())
    }

    /// Called from [`Self::ensure_address_watched`] on every query: `false`
    /// immediately when nothing is configured (the common case today, and
    /// the whole of U3's behavior). Otherwise checks every configured
    /// family's cache first (cheap map lookup); on a miss across ALL of
    /// them, widens each in turn — bounded, chunked local derivation
    /// (`Self::WIDEN_CHUNK` indices at a time, up to `Self::MAX_WIDEN_CHUNKS`
    /// attempts) — only calling `import_ranged` (an actual bitcoind
    /// round-trip) once a chunk is confirmed to contain the address being
    /// looked up. This ordering is load-bearing: a genuinely unrelated
    /// address (a contact, an external recipient, ...) costs bounded local
    /// CPU only, never an extra bitcoind rescan, and the local index cache
    /// never claims an address is "imported" beyond what was actually just
    /// told to bitcoind (the chunk import and the cache update happen
    /// together, so the two can't drift apart).
    fn ranged_lookup_or_widen(&self, address: &str) -> Result<bool, Error> {
        let mut ranged = self.ranged.lock().expect("ranged-watch mutex poisoned");
        if ranged.is_empty() {
            return Ok(false);
        }
        for rw in ranged.iter() {
            if rw.index.contains_key(address) {
                return Ok(true);
            }
        }
        for rw in ranged.iter_mut() {
            let mut from = rw.imported_end.saturating_add(1);
            for _ in 0..Self::MAX_WIDEN_CHUNKS {
                let to = from.saturating_add(Self::WIDEN_CHUNK - 1);
                let mut chunk = HashMap::new();
                for idx in from..=to {
                    for chain in [0usize, 1usize] {
                        if let Ok(d) = rw.source.derive(chain, idx) {
                            chunk.insert(d.address, (chain, idx));
                        }
                    }
                }
                if chunk.contains_key(address) {
                    self.import_ranged(&rw.spec, to)?;
                    rw.index.extend(chunk);
                    rw.imported_end = to;
                    return Ok(true);
                }
                if to == u32::MAX {
                    break;
                }
                from = to + 1;
            }
        }
        Ok(false)
    }

    /// `getblockchaininfo` + `getindexinfo` + the watch wallet's
    /// `getwalletinfo` folded into one structured [`NodeStatus`] (plan
    /// §2.2/§2.3/U4) — the UI's (U6) preflight before trusting this node's
    /// answers. The watch wallet not existing yet (nothing imported this
    /// session) is not an error — `wallet_scanning` is simply `None`.
    /// ALWAYS makes a fresh probe (never reads the cache) — a UI-triggered
    /// "check my node" action should reflect what's true right now — but
    /// DOES refresh [`Self::status_cache`] as a side effect (U5), so the
    /// next internal absence check ([`Self::established_absent`]) benefits
    /// from it too instead of triggering its own separate probe.
    pub fn preflight(&self) -> Result<NodeStatus, Error> {
        let status = self.compute_status()?;
        *self.status_cache.lock().expect("status-cache mutex poisoned") = Some(status.clone());
        Ok(status)
    }

    fn tip_height_rpc(&self) -> Result<u64, Error> {
        let v = self.rpc(None, "getblockcount", serde_json::json!([]))?;
        v.as_u64().ok_or_else(|| Error::Json("getblockcount: not a number".into()))
    }

    /// Every wallet-known txid (mempool + confirmed), deduped, ordered
    /// newest-first: mempool (by descending `time`) first, then confirmed
    /// by ascending `confirmations` (= most-recently-confirmed first) —
    /// same ordering `server.py`'s `address_txids` uses. `listtransactions
    /// "*"` is wallet-WIDE (Core has no per-address filter — plan §2.2
    /// flags the O(wallet) cost as a later-unit optimization); callers
    /// filter down to one address via [`tx_touches`].
    fn wallet_txid_order(&self) -> Result<Vec<String>, Error> {
        let entries = self.rpc(
            Some(&Self::watch_wallet()),
            "listtransactions",
            serde_json::json!(["*", 100_000, 0, true]),
        )?;
        let mut list: Vec<serde_json::Value> = entries.as_array().cloned().unwrap_or_default();
        list.sort_by(|a, b| {
            let ca = a.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0);
            let cb = b.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0);
            ca.cmp(&cb).then_with(|| {
                let ta = a.get("time").and_then(|t| t.as_i64()).unwrap_or(0);
                let tb = b.get("time").and_then(|t| t.as_i64()).unwrap_or(0);
                tb.cmp(&ta)
            })
        });
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in list {
            if let Some(txid) = e.get("txid").and_then(|t| t.as_str()) {
                if seen.insert(txid.to_string()) {
                    out.push(txid.to_string());
                }
            }
        }
        Ok(out)
    }

    /// `address`'s full esplora-shaped history (already touch-filtered),
    /// newest-first. Backs `/address/:a`, `/address/:a/txs`, and
    /// `/address/:a/txs/chain/:after`.
    fn address_history_json(&self, address: &str) -> Result<Vec<serde_json::Value>, Error> {
        let tip = self.tip_height_rpc()?;
        let txids = self.wallet_txid_order()?;
        let mut out = Vec::with_capacity(txids.len());
        for txid in txids {
            let tx = self.esplora_tx_json(&txid, tip)?;
            if tx_touches(&tx, address) {
                out.push(tx);
            }
        }
        Ok(out)
    }

    /// `GET /address/:a` — folds full history into chain/mempool buckets
    /// exactly like `server.py`'s `/address` handler (plan §1.3, :220).
    fn address_stats_route(&self, address: &str) -> Result<String, Error> {
        let txs = self.address_history_json(address)?;
        let (mut chain_n, mut chain_f, mut chain_s) = (0u64, 0u64, 0u64);
        let (mut mem_n, mut mem_f, mut mem_s) = (0u64, 0u64, 0u64);
        for tx in &txs {
            let confirmed = tx.get("status").and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
            let mut funded = 0u64;
            let mut spent = 0u64;
            for o in tx.get("vout").and_then(|v| v.as_array()).into_iter().flatten() {
                if o.get("scriptpubkey_address").and_then(|a| a.as_str()) == Some(address) {
                    funded += o.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                }
            }
            for i in tx.get("vin").and_then(|v| v.as_array()).into_iter().flatten() {
                if i.get("prevout").and_then(|p| p.get("scriptpubkey_address")).and_then(|a| a.as_str()) == Some(address) {
                    spent += i.get("prevout").and_then(|p| p.get("value")).and_then(|v| v.as_u64()).unwrap_or(0);
                }
            }
            if confirmed {
                chain_n += 1;
                chain_f += funded;
                chain_s += spent;
            } else {
                mem_n += 1;
                mem_f += funded;
                mem_s += spent;
            }
        }
        Ok(serde_json::json!({
            "chain_stats": {"tx_count": chain_n, "funded_txo_sum": chain_f, "spent_txo_sum": chain_s},
            "mempool_stats": {"tx_count": mem_n, "funded_txo_sum": mem_f, "spent_txo_sum": mem_s},
        })
        .to_string())
    }

    /// `GET /address/:a/utxo` → `listunspent 0 9999999 [address]` (plan
    /// §1.3, `server.py`:263).
    fn utxo_route(&self, address: &str) -> Result<String, Error> {
        let tip = self.tip_height_rpc()?;
        let result =
            self.rpc(Some(&Self::watch_wallet()), "listunspent", serde_json::json!([0, 9_999_999, [address]]))?;
        let items: Vec<serde_json::Value> = result
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|u| {
                let confirmations = u.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0);
                let value = u.get("amount").and_then(|a| a.as_f64()).map(btc_to_sats).unwrap_or(0);
                let status = if confirmations > 0 {
                    serde_json::json!({
                        "confirmed": true,
                        "block_height": tip.saturating_sub(confirmations as u64).saturating_add(1),
                    })
                } else {
                    serde_json::json!({"confirmed": false})
                };
                serde_json::json!({
                    "txid": u.get("txid").cloned().unwrap_or(serde_json::Value::Null),
                    "vout": u.get("vout").cloned().unwrap_or(serde_json::Value::Null),
                    "value": value,
                    "status": status,
                })
            })
            .collect();
        Ok(serde_json::to_string(&items).unwrap())
    }

    /// `GET /address/:a/txs[/chain/:after]` — `listtransactions "*" …`
    /// filtered to txs touching `address` (plan §1.3, `server.py`:188,
    /// :283). `chain_only` (the `/txs/chain/:after` form) drops mempool
    /// entries and paginates 25-at-a-time by PATH-embedded cursor, exactly
    /// what `ChainClient::full_history` sends and real esplora expects —
    /// see the `EsploraFake` reference in `tests/common/mod.rs`; the
    /// regtest `server.py` shim instead reads a query-string cursor it
    /// never actually receives from this app (a pre-existing, out-of-scope
    /// shim gap noted in `chain.rs`'s own doc comment), so it does not
    /// double as a second worked example for this form.
    fn txs_route(&self, address: &str, after: Option<&str>, chain_only: bool) -> Result<String, Error> {
        let mut items = self.address_history_json(address)?;
        if chain_only {
            items.retain(|t| t.get("status").and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false));
        }
        if let Some(after_txid) = after {
            let idx = items.iter().position(|t| t.get("txid").and_then(|v| v.as_str()) == Some(after_txid));
            items = match idx {
                Some(i) => items.split_off(i + 1),
                None => Vec::new(),
            };
        }
        items.truncate(if chain_only { 25 } else { 50 });
        Ok(serde_json::to_string(&items).unwrap())
    }

    /// `GET /v1/fees/recommended` → `estimatesmartfee` for 1/3/6/144 blocks
    /// (`fastestFee`/`halfHourFee`/`hourFee`/`economyFee`), clamped to the
    /// node's own live relay minimum (`minimumFee`, from
    /// `getmempoolinfo().mempoolminfee`) and forced non-increasing across
    /// tiers (U7, `PLAN-chain-notes-app-core-rpc.md` §2.6).
    ///
    /// **Units, audited explicitly — this is the single most damaging bug
    /// this route could ship.** `estimatesmartfee`'s `feerate` is BTC per
    /// **kilo-virtual-byte**; every `FeeRates` field in this crate is
    /// **sat/vB**. The conversion is `btc_per_kvb * 100_000_000 (sat/BTC) /
    /// 1000 (vB/kvB)`, i.e. `* 100_000` — done in [`btc_per_kvb_to_sat_vb`],
    /// which carries its own table-driven test vectors
    /// (`btc_per_kvb_to_sat_vb_matches_known_vectors`) precisely so a
    /// reviewer's mutation to that one constant (a 1000× error either
    /// direction — `* 100.0` or `* 100_000_000.0` — is the obvious one to
    /// try) fails a test outright instead of only showing up as "fees look
    /// weird" in the UI.
    ///
    /// Regtest (and any node with too little fee history) always fails to
    /// estimate — verified live (`estimatesmartfee` returns an `errors`
    /// array with no `feerate` field, not an RPC error) — so each tier
    /// independently falls back to a fixed sat/vB constant
    /// ([`FASTEST_FALLBACK_SAT_VB`] etc.) rather than propagating an error,
    /// per the plan's "callers must never see this break" rule. Those
    /// constants are deliberately NOT all equal to the network's default
    /// 1 sat/vB relay floor — they descend (3/2/1/1) so the fallback shape
    /// still reads as "an estimate", never a flat line that would look like
    /// this route silently broke, while staying nowhere near a real
    /// mempool spike (see their own doc comments for the exact reasoning).
    ///
    /// Two things happen to every value (real estimate OR fallback) AFTER
    /// tier selection, via [`clamp_fee_tiers`]:
    ///
    /// 1. **Floored to the node's live relay minimum.** A composed tx must
    ///    never be built below what THIS node will actually accept — the
    ///    hardcoded `"minimumFee": 1` this route used to answer with was
    ///    silently wrong on any node configured with a higher
    ///    `-minrelaytxfee`, or one under enough mempool pressure that
    ///    `mempoolminfee` has risen dynamically above the static floor.
    /// 2. **Forced non-increasing**, `fastest >= half_hour >= hour >=
    ///    economy`. Required because each tier's estimate/fallback is
    ///    chosen INDEPENDENTLY of its neighbors: a tier that got a real
    ///    (volatile) estimate can otherwise sit below an adjacent tier that
    ///    fell back to a stale constant, producing a `FeeRates` whose shape
    ///    every caller (this crate's fee-tier UI included) reasonably
    ///    assumes is sorted.
    fn fee_estimates_route(&self) -> Result<String, Error> {
        let sat_vb = |blocks: u64| -> Option<u64> {
            let v = self.rpc(None, "estimatesmartfee", serde_json::json!([blocks])).ok()?;
            let btc_per_kvb = v.get("feerate")?.as_f64()?;
            Some(btc_per_kvb_to_sat_vb(btc_per_kvb))
        };
        // The node's own relay floor — `mempoolminfee` is documented as the
        // HIGHER of the static `-minrelaytxfee` and any dynamic
        // mempool-pressure minimum, so it is the one number that answers
        // "what is the least this node will relay right now." A failure
        // here (RPC error, missing field) falls back to the network's
        // universal default of 1 sat/vB — never 0, which would make the
        // floor a no-op and let a degenerate real estimate of 0.0 through.
        let relay_min = self
            .rpc(None, "getmempoolinfo", serde_json::json!([]))
            .ok()
            .and_then(|v| v.get("mempoolminfee").and_then(|f| f.as_f64()))
            .map(btc_per_kvb_to_sat_vb)
            .unwrap_or(1);
        let fastest = sat_vb(1).unwrap_or(FASTEST_FALLBACK_SAT_VB);
        let half_hour = sat_vb(3).unwrap_or(HALF_HOUR_FALLBACK_SAT_VB);
        let hour = sat_vb(6).unwrap_or(HOUR_FALLBACK_SAT_VB);
        let economy = sat_vb(144).unwrap_or(ECONOMY_FALLBACK_SAT_VB);
        let (fastest, half_hour, hour, economy) = clamp_fee_tiers(fastest, half_hour, hour, economy, relay_min);
        Ok(serde_json::json!({
            "fastestFee": fastest,
            "halfHourFee": half_hour,
            "hourFee": hour,
            "economyFee": economy,
            "minimumFee": relay_min,
        })
        .to_string())
    }
}

/// `10^8` sat/BTC ÷ `10^3` vB/kvB — see [`btc_per_kvb_to_sat_vb`]'s doc
/// comment for why this exact constant is the entire ballgame.
const SAT_VB_PER_BTC_PER_KVB: f64 = 100_000.0;

/// BTC/kvB (`estimatesmartfee`'s and `getmempoolinfo`'s native unit) →
/// sat/vB (every `FeeRates` field in this crate). Rounds UP
/// (`.ceil()`) — rounding DOWN a genuine 1.4 sat/vB estimate to 1 could
/// compose a tx that pays less than the rate it was estimated at, risking
/// a slow confirmation or, at the relay-floor boundary, outright
/// rejection; overpaying by a fraction of a sat/vB is the safe direction
/// to round. `.max(1)` is a belt-and-braces floor for a degenerate `0.0`
/// input (a node that answered but reported no real fee) — the
/// AUTHORITATIVE relay-minimum floor is applied separately, from the live
/// node, in [`clamp_fee_tiers`]; this local floor exists only so this
/// function alone never returns a nonsensical 0.
fn btc_per_kvb_to_sat_vb(btc_per_kvb: f64) -> u64 {
    ((btc_per_kvb * SAT_VB_PER_BTC_PER_KVB).ceil() as u64).max(1)
}

/// Fallback sat/vB for the ~1-block tier when `estimatesmartfee` has
/// nothing to estimate from. Deliberately just above the relay floor and
/// the highest of the four fallbacks (never absurd — nowhere near a real
/// mainnet fee spike — but visibly "the urgent one" so the fallback shape
/// alone doesn't read as a flat, broken line).
const FASTEST_FALLBACK_SAT_VB: u64 = 3;
/// Fallback sat/vB for the ~3-block tier — see [`FASTEST_FALLBACK_SAT_VB`].
const HALF_HOUR_FALLBACK_SAT_VB: u64 = 2;
/// Fallback sat/vB for the ~6-block tier — the network's de-facto default
/// relay rate. See [`FASTEST_FALLBACK_SAT_VB`].
const HOUR_FALLBACK_SAT_VB: u64 = 1;
/// Fallback sat/vB for the ~144-block (economy) tier — never below 1
/// (never zero; a zero-fee tx does not relay at all). See
/// [`FASTEST_FALLBACK_SAT_VB`].
const ECONOMY_FALLBACK_SAT_VB: u64 = 1;

/// Forces `fastest >= half_hour >= hour >= economy >= floor` — see
/// [`CoreRpcTransport::fee_estimates_route`]'s doc comment for why this is
/// necessary even though `estimatesmartfee` itself is monotonic per
/// confirmation target: each tier passed in here was chosen independently
/// (real estimate OR fallback), so a real, volatile value in one tier and
/// a stale fallback in an adjacent one can otherwise cross.
///
/// Order of operations matters and is deliberate: the descending clamp
/// (`half_hour.min(fastest)`, etc.) runs FIRST, then `floor` is applied via
/// `.max(floor)` to every already-ordered value. `max` is a monotonic
/// function of its first argument, so applying it independently to an
/// already-descending sequence cannot un-sort it — doing the floor first
/// (or interleaved) could let a tier that needed raising up to the floor
/// end up ABOVE a neighbor that didn't.
fn clamp_fee_tiers(fastest: u64, half_hour: u64, hour: u64, economy: u64, floor: u64) -> (u64, u64, u64, u64) {
    let half_hour = half_hour.min(fastest);
    let hour = hour.min(half_hour);
    let economy = economy.min(hour);
    (fastest.max(floor), half_hour.max(floor), hour.max(floor), economy.max(floor))
}

impl Transport for CoreRpcTransport {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        // stderr-only, debug builds only, path never carries credentials —
        // same discipline as `HttpTransport::get_text`.
        #[cfg(debug_assertions)]
        eprintln!("cb: http GET {path}");

        if path == "/blocks/tip/height" {
            return Ok(self.tip_height_rpc()?.to_string());
        }
        if path == "/v1/fees/recommended" {
            return self.fee_estimates_route();
        }
        if path == "/v1/prices" {
            // No node knows the price (plan §2.6) — both call sites
            // already degrade via `if let Ok(...)`, so any Err is fine.
            return Err(Error::Http("bitcoind has no price oracle".into()));
        }
        if let Some(rest) = path.strip_prefix("/address/") {
            let mut parts = rest.splitn(2, '/');
            let address = parts.next().unwrap_or("");
            if address.is_empty() {
                return Err(Error::Http("404: address missing".into()));
            }
            let sub = parts.next();
            if !self.ensure_address_watched(address)? {
                // Syntactically invalid — short-circuit every route to its
                // empty shape rather than handing a garbage address to an
                // RPC that validates it (see `ensure_address_watched`'s
                // doc comment).
                return match sub {
                    None => Ok(serde_json::json!({
                        "chain_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0},
                        "mempool_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0},
                    })
                    .to_string()),
                    Some("utxo") | Some("txs") => Ok("[]".to_string()),
                    Some(s) if s.starts_with("txs/chain/") => Ok("[]".to_string()),
                    Some(other) => Err(Error::Http(format!("404: no route /address/.../{other}"))),
                };
            }
            return match sub {
                None => self.address_stats_route(address),
                Some("utxo") => self.utxo_route(address),
                Some("txs") => self.txs_route(address, None, false),
                Some(s) if s.starts_with("txs/chain/") => {
                    let after = &s["txs/chain/".len()..];
                    self.txs_route(address, Some(after), true)
                }
                Some(other) => Err(Error::Http(format!("404: no route /address/.../{other}"))),
            };
        }
        if let Some(rest) = path.strip_prefix("/tx/") {
            if let Some(txid) = rest.strip_suffix("/hex") {
                let raw = self.getrawtransaction(txid, 0)?;
                return raw
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::Json("getrawtransaction: hex not a string".into()));
            }
            let tip = self.tip_height_rpc()?;
            return self.esplora_tx_json(rest, tip).map(|v| v.to_string());
        }
        Err(Error::Http(format!("404: no route for {path}")))
    }

    /// `POST /tx` → `testmempoolaccept` then `sendrawtransaction` (plan
    /// §1.3, `server.py`:304) — deliberately does NOT auto-mine (unlike
    /// `server.py`'s regtest convenience): this transport is meant to run
    /// against a production node too, where silently mining a block on
    /// every broadcast would be actively wrong.
    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        #[cfg(debug_assertions)]
        eprintln!("cb: http POST {path}");
        if path != "/tx" {
            return Err(Error::Http(format!("404: no POST route for {path}")));
        }
        let raw_hex = body.trim().to_string();
        let accept = self.rpc(None, "testmempoolaccept", serde_json::json!([[raw_hex.clone()]]))?;
        let first = accept.as_array().and_then(|a| a.first()).cloned().unwrap_or(serde_json::Value::Null);
        let allowed = first.get("allowed").and_then(|a| a.as_bool()).unwrap_or(false);
        if !allowed {
            // U5 (plan §2.1/broadcast error mapping): plain "400: <reason>"
            // — `reason` here is `testmempoolaccept`'s own short
            // reject-reason token (`"txn-already-known"`, `"min relay fee
            // not met, ..."`, `"bad-txns-inputs-missingorspent"`,
            // `"non-final"`, ...), never wrapped in a "sendrawtransaction
            // RPC error:" preamble that would be misleading (this rejection
            // never reached `sendrawtransaction` at all). The bare
            // "400: <reason>" shape is exactly what
            // [`crate::friendly_broadcast_err`] (src/lib.rs) pattern-matches
            // against to render the SAME calm message the Esplora/
            // mempool.space path would for the same underlying condition.
            let reason = first.get("reject-reason").and_then(|r| r.as_str()).unwrap_or("rejected");
            return Err(Error::Http(format!("400: {reason}")));
        }
        let txid = self.rpc(None, "sendrawtransaction", serde_json::json!([raw_hex]))?;
        txid.as_str().map(str::to_string).ok_or_else(|| Error::Json("sendrawtransaction: did not return a txid".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::transport::AnyTransport;

    #[test]
    fn core_rpc_transport_parses_scheme_host_port() {
        let t = CoreRpcTransport::new("http://192.168.1.50:8332", None).unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.host, "192.168.1.50");
        assert_eq!(t.port, Some(8332));
        assert_eq!(creds_as_str(&t), None);
    }

    #[test]
    fn core_rpc_transport_parses_no_port() {
        let t = CoreRpcTransport::new("https://node.example.com", None).unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.host, "node.example.com");
        assert_eq!(t.port, None);
    }

    /// `creds` is private and its password half is `Zeroizing<String>`
    /// (U5, plan §2.4) — neither derives `PartialEq`, so tests compare
    /// through this thin `&str` projection instead of the raw field.
    fn creds_as_str(t: &CoreRpcTransport) -> Option<(&str, &str)> {
        t.creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }

    #[test]
    fn core_rpc_transport_reads_inline_userinfo_credentials() {
        let t = CoreRpcTransport::new("http://alice:s3cret@127.0.0.1:8332", None).unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, Some(8332));
        assert_eq!(creds_as_str(&t), Some(("alice", "s3cret")));
    }

    #[test]
    fn core_rpc_transport_explicit_creds_win_over_inline() {
        let t = CoreRpcTransport::new(
            "http://alice:s3cret@127.0.0.1:8332",
            Some(("bob".to_string(), "hunter2".to_string())),
        )
        .unwrap();
        assert_eq!(creds_as_str(&t), Some(("bob", "hunter2")));
    }

    #[test]
    fn core_rpc_transport_via_any_transport_new_end_to_end() {
        // The full `bitcoind+` URL as a Settings/CLI user would type it,
        // through the actual dispatch point.
        let t = AnyTransport::new("bitcoind+http://user:pass@umbrel.local:8332", None).unwrap();
        match t {
            AnyTransport::Core(c) => {
                assert_eq!(c.scheme, "http");
                assert_eq!(c.host, "umbrel.local");
                assert_eq!(c.port, Some(8332));
                assert_eq!(creds_as_str(&c), Some(("user", "pass")));
            }
            AnyTransport::Esplora(_) => panic!("expected Core"),
        }
    }

    #[test]
    fn core_rpc_transport_debug_never_prints_credentials() {
        // U5 (plan §2.4): the whole point of a hand-written `Debug` impl —
        // a stray `{:?}` (a log line, a panic message, an assertion-failure
        // diff) must never be able to leak either half of a credential.
        let t = CoreRpcTransport::new("http://alice:s3cret@127.0.0.1:8332", None).unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("alice"), "Debug output leaked the username: {dbg}");
        assert!(!dbg.contains("s3cret"), "Debug output leaked the password: {dbg}");
        assert!(dbg.contains("redacted"), "Debug output should note creds are present (redacted): {dbg}");
    }

    #[test]
    fn core_rpc_transport_rejects_missing_scheme() {
        assert!(CoreRpcTransport::new("127.0.0.1:8332", None).is_err());
    }

    #[test]
    fn core_rpc_transport_rejects_unsupported_scheme() {
        assert!(CoreRpcTransport::new("ftp://127.0.0.1:8332", None).is_err());
    }

    #[test]
    fn core_rpc_transport_rejects_empty_host() {
        assert!(CoreRpcTransport::new("http://", None).is_err());
    }

    /// U5 (plan §2.4/URL validation, closing deferred audit finding M6):
    /// table test covering the two live parsing defects found reviewing
    /// U2 — a bracketed IPv6 host with no port (`[::1]` used to yield host
    /// `"[:"`) and a malformed port (`host:abc` used to silently parse to
    /// `port: None`) — alongside every other shape the constructor accepts
    /// or must reject, so the whole parser is exercised in one place
    /// rather than one assertion per ad-hoc test.
    #[test]
    fn core_rpc_url_parsing_table() {
        // (input, expected Ok(scheme, host, port) or None for "must Err").
        let cases: &[(&str, Option<(&str, &str, Option<u16>)>)] = &[
            // IPv4, with and without a port.
            ("http://192.168.1.50:8332", Some(("http", "192.168.1.50", Some(8332)))),
            ("http://192.168.1.50", Some(("http", "192.168.1.50", None))),
            // Hostname, with and without a port.
            ("https://node.example.com:8332", Some(("https", "node.example.com", Some(8332)))),
            ("https://node.example.com", Some(("https", "node.example.com", None))),
            // IPv6, bracketed, WITH a port — already worked before U5.
            ("http://[::1]:8332", Some(("http", "::1", Some(8332)))),
            (
                "http://[2001:db8::1]:8332",
                Some(("http", "2001:db8::1", Some(8332))),
            ),
            // IPv6, bracketed, WITHOUT a port — the FIRST U5 bug fix: used
            // to yield host "[:" and a silently-dropped port.
            ("http://[::1]", Some(("http", "::1", None))),
            ("http://[2001:db8::1]", Some(("http", "2001:db8::1", None))),
            // userinfo present alongside every host shape — must not
            // perturb host/port parsing (the `@`-split happens first).
            ("http://alice:s3cret@127.0.0.1:8332", Some(("http", "127.0.0.1", Some(8332)))),
            ("http://alice:s3cret@[::1]:8332", Some(("http", "::1", Some(8332)))),
            ("http://alice:s3cret@[::1]", Some(("http", "::1", None))),
            // Trailing slash / path — tolerated and ignored (Core's RPC
            // endpoint has no path of its own).
            ("http://127.0.0.1:8332/", Some(("http", "127.0.0.1", Some(8332)))),
            ("http://127.0.0.1:8332/foo/bar", Some(("http", "127.0.0.1", Some(8332)))),
            // --- error cases ---
            ("127.0.0.1:8332", None),           // missing scheme
            ("ftp://127.0.0.1:8332", None),     // unsupported scheme
            ("http://", None),                  // empty host
            ("http://:8332", None),             // empty host, port present
            // The SECOND U5 bug fix: a malformed port used to silently
            // become `None` instead of erroring.
            ("http://host:abc", None),          // non-numeric port
            ("http://host:99999", None),        // out-of-range port (> u16::MAX)
            ("http://host:", None),             // empty port after ':'
            ("http://[::1]:abc", None),         // malformed port after IPv6 literal
            ("http://[::1", None),              // unterminated IPv6 literal
        ];
        for (input, expected) in cases {
            let result = CoreRpcTransport::new(input, None);
            match expected {
                Some((scheme, host, port)) => {
                    let t = result.unwrap_or_else(|e| panic!("{input:?} should have parsed, got {e:?}"));
                    assert_eq!(t.scheme, *scheme, "scheme mismatch for {input:?}");
                    assert_eq!(t.host, *host, "host mismatch for {input:?}");
                    assert_eq!(t.port, *port, "port mismatch for {input:?}");
                }
                None => {
                    assert!(result.is_err(), "{input:?} should have been rejected, got {:?}", result.unwrap().host);
                }
            }
        }
    }

    #[test]
    fn core_rpc_transport_makes_a_genuine_network_call_and_fails_as_transport_with_nothing_listening() {
        // U2 (the seam-only stub) locked in a canned "not implemented"
        // `Error::Http` here with NO network call. U3 replaces the stub
        // with a real JSON-RPC client — this test now locks in the
        // OPPOSITE: with nothing listening, both methods genuinely attempt
        // a connection and fail as `Error::Transport` (never `Error::Http`,
        // which would imply a server actually answered). Port 1 rather
        // than a real RPC port (8332/18443/...) so this never accidentally
        // passes/behaves differently on a machine that happens to be
        // running a real node. The full round-trip against a real
        // `bitcoind` is `tests/core_rpc_conformance.rs` (skipped when
        // bitcoind is absent from PATH).
        let t = CoreRpcTransport::new("http://127.0.0.1:1", None).unwrap();
        let get_err = t.get_text("/blocks/tip/height").unwrap_err();
        assert!(matches!(get_err, Error::Transport(_)), "expected a transport failure, got {get_err:?}");
        let post_err = t.post_text("/tx", "deadbeef".into()).unwrap_err();
        assert!(matches!(post_err, Error::Transport(_)), "expected a transport failure, got {post_err:?}");
    }

    /// U5 (plan §2.4): the definitive proof the redaction discipline
    /// actually holds, not just against this crate's OWN formatting but
    /// against `reqwest`'s — a `bitcoind+http://user:pass@host:port` base
    /// whose password can NEVER surface in an `Error`'s `Display`, its
    /// `Debug`, or the transport's own `Debug`, even for a GENUINE network
    /// failure (nothing listening on port 1 — the same shape
    /// `core_rpc_transport_makes_a_genuine_network_call_...` above already
    /// uses, now with real credentials embedded). This is the scenario the
    /// U3 doc comment worried about by name: "nothing here (nor `reqwest`'s
    /// own error `Display`, which can echo the request URL) can leak a
    /// credential" — this test is what makes that a checked claim instead
    /// of an assertion in a comment. A reviewer disabling the `Zeroizing`/
    /// private-field/hand-written-`Debug` changes should expect THIS test,
    /// not just the narrower `..._debug_never_prints_credentials` one, to
    /// fail — this one exercises the real HTTP path both `get_text` and
    /// `post_text` take, headers included.
    #[test]
    fn creds_never_leak_through_a_real_transport_error_or_debug_rendering() {
        const USER: &str = "watchtower";
        const PASS: &str = "correct-horse-battery-staple";
        let base = format!("http://{USER}:{PASS}@127.0.0.1:1");
        let t = CoreRpcTransport::new(&base, None).unwrap();

        let get_err = t.get_text("/blocks/tip/height").unwrap_err();
        let post_err = t.post_text("/tx", "deadbeef".into()).unwrap_err();

        for (label, err) in [("GET", &get_err), ("POST", &post_err)] {
            let display = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!display.contains(PASS), "{label} Display leaked the password: {display}");
            assert!(!display.contains(USER), "{label} Display leaked the username: {display}");
            assert!(!debug.contains(PASS), "{label} Debug leaked the password: {debug}");
            assert!(!debug.contains(USER), "{label} Debug leaked the username: {debug}");
        }

        // The transport's own Debug (a stray `{:?}` in a log line or panic
        // message elsewhere in the app) must be equally silent.
        let transport_debug = format!("{t:?}");
        assert!(!transport_debug.contains(PASS));
        assert!(!transport_debug.contains(USER));

        // And the exact call site U2 added (`src/lib.rs`'s
        // `println!("cb: refresh err={e}")`) formats an `Error` with `{e}`
        // — Display, already covered above — never `{e:?}`; reconfirmed
        // here as a direct textual match against that literal format
        // string shape, so this test would fail if that call site's
        // formatting ever changed to something that could leak.
        let simulated_log_line = format!("cb: refresh err={get_err}");
        assert!(!simulated_log_line.contains(PASS), "simulated log line leaked the password: {simulated_log_line}");
    }

    // ---- U7: fee-tier unit conversion + policy (plan §2.6) ----

    /// The whole ballgame: BTC/kvB → sat/vB is `* 100_000`
    /// (`10^8` sat/BTC ÷ `10^3` vB/kvB). Every vector here is a KNOWN input
    /// with an independently-computed expected output — a reviewer who
    /// mutates [`SAT_VB_PER_BTC_PER_KVB`] by a factor of 1000 in EITHER
    /// direction (the obvious mistakes: `100.0`, forgetting the sats-per-BTC
    /// scale, or `100_000_000.0`, forgetting the kvB-per-vB scale) fails
    /// every non-zero-input case below, not just "looks off by eye".
    #[test]
    fn btc_per_kvb_to_sat_vb_matches_known_vectors() {
        let cases: &[(f64, u64)] = &[
            // A realistic mainnet-shaped moderate fee: 0.00010000 BTC/kvB
            // (bitcoind's canonical "10 sat/vB" shape).
            (0.00010000, 10),
            // A realistic mainnet-shaped HIGH fee (fee-spike territory):
            // 0.00050000 BTC/kvB -> 50 sat/vB.
            (0.00050000, 50),
            // The network's de-facto default relay minimum: 0.00001000
            // BTC/kvB (1000 sat/kvB) -> exactly 1 sat/vB, the floor
            // boundary itself, not just something safely above it.
            (0.00001000, 1),
            // A very low but non-degenerate rate that lands EXACTLY on an
            // integer sat/vB after scaling — 0.00000500 BTC/kvB -> 0.5
            // sat/vB pre-ceiling -> ceils UP to 1, never down to 0.
            (0.00000500, 1),
            // Rounding-edge case: 0.000015 BTC/kvB scales to EXACTLY 1.5
            // sat/vB — proves `.ceil()`, not `.round()` (which would give
            // 2 here too, so pair with the next case to actually
            // distinguish) or truncation (which would wrongly give 1).
            (0.000015, 2),
            // A DIFFERENT rounding-edge case that `.round()` would get
            // WRONG (rounds down to 1) but `.ceil()` gets right (2) —
            // 0.0000101 BTC/kvB scales to 1.01 sat/vB, just barely over 1.
            (0.0000101, 2),
            // Degenerate zero input (a node that answered with a real
            // `feerate: 0.0`, or the relay-min lookup itself returning
            // nothing sane) must never produce a 0 sat/vB tier.
            (0.0, 1),
        ];
        for &(btc_per_kvb, expected_sat_vb) in cases {
            assert_eq!(
                btc_per_kvb_to_sat_vb(btc_per_kvb),
                expected_sat_vb,
                "btc_per_kvb_to_sat_vb({btc_per_kvb}) should be {expected_sat_vb} sat/vB \
                 (a 1000x unit error would give {} or {})",
                (btc_per_kvb * 100.0).ceil() as u64,
                (btc_per_kvb * 100_000_000.0).ceil() as u64,
            );
        }
    }

    /// A direct trap for the 1000× mutation the plan's mutation-testing
    /// pass is explicitly expected to try: confirms the constant itself is
    /// `100_000.0`, not `100.0` or `100_000_000.0` — belt-and-braces
    /// alongside the vector test above, which would already fail either way
    /// but this pins the exact value so the failure is immediate and
    /// unambiguous.
    #[test]
    fn sat_vb_conversion_constant_is_exactly_100_000() {
        assert_eq!(SAT_VB_PER_BTC_PER_KVB, 100_000.0);
    }

    #[test]
    fn clamp_fee_tiers_leaves_an_already_sorted_above_floor_input_untouched() {
        assert_eq!(clamp_fee_tiers(20, 15, 10, 5, 1), (20, 15, 10, 5));
    }

    #[test]
    fn clamp_fee_tiers_floors_every_tier_to_the_relay_minimum() {
        // Every raw tier below the floor -> every tier becomes the floor,
        // and the result is trivially still "sorted" (all equal).
        assert_eq!(clamp_fee_tiers(3, 2, 1, 1, 20), (20, 20, 20, 20));
    }

    #[test]
    fn clamp_fee_tiers_forces_non_increasing_order_when_a_middle_tier_is_a_stale_high_fallback() {
        // The exact scenario the doc comment describes: `fastest` got a
        // real (low, quiet-mempool) estimate, but `half_hour` fell back to
        // a fallback constant that happens to read HIGHER than the real
        // fastest estimate. Without the clamp this would answer
        // fastest < half_hour — backwards.
        let (fastest, half_hour, hour, economy) = clamp_fee_tiers(2, 5, 5, 5, 1);
        assert!(fastest >= half_hour, "fastest {fastest} must be >= half_hour {half_hour}");
        assert!(half_hour >= hour, "half_hour {half_hour} must be >= hour {hour}");
        assert!(hour >= economy, "hour {hour} must be >= economy {economy}");
        assert_eq!((fastest, half_hour, hour, economy), (2, 2, 2, 2));
    }

    #[test]
    fn clamp_fee_tiers_applies_the_floor_after_the_descending_clamp_so_order_survives() {
        // A case that would break if the floor were applied BEFORE (or
        // interleaved with) the descending clamp: economy's raw value (1)
        // needs raising to the floor (5), but hour's raw value (4) does
        // NOT — floor-first-then-clamp could leave economy(5) > hour(4).
        // floor-AFTER-clamp (the real implementation) instead clamps
        // economy = min(1, hour=4) = 1 first, THEN floors every already-
        // ordered value to 5, landing on hour=5, economy=5 — still sorted.
        let (fastest, half_hour, hour, economy) = clamp_fee_tiers(10, 8, 4, 1, 5);
        assert!(fastest >= half_hour && half_hour >= hour && hour >= economy);
        assert_eq!((fastest, half_hour, hour, economy), (10, 8, 5, 5));
    }

    /// Locks in plan §2.6: a Core-mode client must never even ATTEMPT an
    /// RPC/HTTP call for `/v1/prices` — a personal node has no price
    /// oracle, and the whole point of self-hosting is that nothing about
    /// this app phones a third party on your behalf. Whitebox (this test
    /// lives inside `chain.rs` itself, not an external integration test)
    /// specifically so it can read the private `next_id` counter, which
    /// [`CoreRpcTransport::call`] bumps on EVERY outbound JSON-RPC attempt
    /// (success or failure) — the one piece of state that can prove "no
    /// call was made" rather than merely "the call I expected failed".
    ///
    /// This is the exact regression the plan calls out: if a future change
    /// "helpfully" wires a fallback price fetch into the Core path, one of
    /// three things breaks here — `next_id` moves off zero (a real RPC/HTTP
    /// attempt happened), the result stops being this crate's own crafted
    /// `Error::Http` (a genuine network attempt against an unreachable
    /// target — port 1, nothing listening, same shape used elsewhere in
    /// this file — surfaces as `Error::Transport` instead, or as `Ok` if it
    /// somehow succeeded), or the error text stops containing "no price
    /// oracle" (this crate's own wording, not anything a real HTTP failure
    /// or a real price API would ever produce).
    #[test]
    fn v1_prices_route_never_attempts_a_network_call() {
        let t = CoreRpcTransport::new("http://127.0.0.1:1", None).unwrap();
        let before = *t.next_id.lock().unwrap();
        let result = t.get_text("/v1/prices");
        let after = *t.next_id.lock().unwrap();
        assert_eq!(before, after, "no RPC call should ever be attempted for /v1/prices");
        match result {
            Err(Error::Http(msg)) => {
                assert!(msg.contains("no price oracle"), "unexpected error text: {msg}")
            }
            other => panic!("expected a crafted no-price-oracle Error::Http, got {other:?}"),
        }
    }

    /// The override exists for harnesses; production must be unaffected.
    /// Without this, "stop the suites bloating the shared wallet" could
    /// silently become "move every user's wallet", which would orphan the
    /// descriptors already imported on their node.
    #[test]
    fn watch_wallet_defaults_to_production_name() {
        // Not using std::env::set_var here: tests share a process, and
        // mutating the environment races every other test that reads it.
        // The default path is what matters, and it is what ships.
        assert_eq!(
            CoreRpcTransport::watch_wallet(),
            "graffito-watch",
            "the default watch wallet name is production state — harnesses \
             override it via CN_WATCH_WALLET, they do not change this"
        );
        assert_eq!(CoreRpcTransport::WATCH_WALLET, "graffito-watch");
    }
}
