//! Esplora/mempool.space chain client → in-memory notes-core SyncBundle.
//!
//! Mirrors the companion's scan semantics exactly (chain-scan.js /
//! index.html in prime-chain-notes): full history = `/address/:a/txs`
//! then `/address/:a/txs/chain?after_txid=` while pages come back full
//! (25); a tx enters `notes_onchain` iff it carries ≥1 OP_RETURN payload;
//! `spends_from_self` = any input prevout is ours (the OWN-note rule),
//! `pays_self` = any output is ours, sender = first taproot input
//! prevout, recipient = first non-self non-OP_RETURN output (taproot
//! preferred). Payload extraction reuses notes-core's own script parser.
//!
//! The `Transport` trait isolates HTTP so tests inject canned JSON.
//!
//! `HttpTransport` also owns two request-shaping behaviors that only make
//! sense against a real server, never against the canned-transport tests:
//! a global inter-request pacer (throttles bursty scans so mempool.space
//! stops handing back 429s in the first place) and a bounded 429
//! retry-with-backoff (for the 429s that get through anyway). See the
//! comment on `Transport for HttpTransport` below for the exact rules.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use notes_core::address::address_to_script_pubkey;
use notes_core::bundle::{BundleUtxo, FeeRates, OnchainTx, SyncBundle};
use notes_core::tx::op_return_payload;
use notes_core::Network;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::funding::FundingSource;
use crate::Error;

pub trait Transport {
    fn get_text(&self, path: &str) -> Result<String, Error>;
    fn post_text(&self, path: &str, body: String) -> Result<String, Error>;
}

/// Task #14 (dropped-pending detection): the outcome of a `/tx/:txid`
/// lookup, kept distinct from a plain `Option` so a definitive "no such
/// tx" (esplora 404) can never be confused with "couldn't tell" (network
/// error, non-404 status, bad body) — see [`ChainClient::tx_lookup_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxLookupStatus {
    /// The node has it — Some(confirmed-in-a-block?).
    Found(bool),
    /// The node definitively has no record of this txid.
    NotFound,
    /// Anything else — never grounds for a dropped verdict.
    Unknown,
}

/// mempool.space bases per network. Regtest has no public instance —
/// callers supply a custom base (companion/server.py shape) instead.
pub fn default_base(network: Network) -> Option<&'static str> {
    match network {
        Network::Mainnet => Some("https://mempool.space/api"),
        Network::Testnet4 => Some("https://mempool.space/testnet4/api"),
        Network::Signet => Some("https://mempool.space/signet/api"),
        Network::Regtest => None,
    }
}

/// Named Bitcoin-node presets for the Settings dropdown (each is an Esplora/
/// mempool-compatible API base). `Some(url)` is an explicit base; `None` means
/// "network default" — stored as `node_url = None` so the choice keeps
/// tracking [`default_base`]. A trailing "Custom…"
/// entry (raw URL text field) is a UI concern and not listed here, so an empty
/// list (regtest) still yields a one-option dropdown of just Custom.
pub fn node_presets(network: Network) -> Vec<(&'static str, Option<&'static str>)> {
    match network {
        // Blockstream's Esplora is mainnet + testnet3 only — not testnet4 or
        // signet — so it's offered on mainnet alone.
        Network::Mainnet => vec![
            ("mempool.space", None),
            ("Blockstream", Some("https://blockstream.info/api")),
        ],
        Network::Testnet4 => vec![("mempool.space", None)],
        Network::Signet => vec![("mempool.space", None)],
        Network::Regtest => vec![],
    }
}

/// Default block-explorer website base — everything before `/tx/{txid}`. None
/// where there's no public explorer (regtest).
pub fn default_explorer_base(network: Network) -> Option<&'static str> {
    match network {
        Network::Mainnet => Some("https://mempool.space"),
        Network::Testnet4 => Some("https://mempool.space/testnet4"),
        Network::Signet => Some("https://mempool.space/signet"),
        Network::Regtest => None,
    }
}

/// Named block-explorer presets for the Settings dropdown (website base, i.e.
/// everything before `/tx/{txid}`). Same `None = network default` convention
/// as [`node_presets`]; Custom is a UI concern appended by the caller.
pub fn explorer_presets(network: Network) -> Vec<(&'static str, Option<&'static str>)> {
    match network {
        Network::Mainnet => vec![
            ("mempool.space", None),
            ("Blockstream", Some("https://blockstream.info")),
        ],
        Network::Testnet4 => vec![("mempool.space", None)],
        Network::Signet => vec![("mempool.space", None)],
        Network::Regtest => vec![],
    }
}

/// Block-explorer tx permalink. `explorer` = the custom website base from
/// Settings (None = network default). Returns "" when no explorer is available
/// (regtest with no custom base set), matching the "no link" UI convention.
pub fn explorer_tx_url(explorer: Option<&str>, network: Network, txid: &str) -> String {
    match explorer
        .map(str::to_string)
        .or_else(|| default_explorer_base(network).map(String::from))
    {
        Some(base) => format!("{}/tx/{txid}", base.trim_end_matches('/')),
        None => String::new(),
    }
}

pub struct HttpTransport {
    base: String,
    client: reqwest::blocking::Client,
    /// Whether requests through this transport go through the global
    /// inter-request pacer. The pacer exists to be polite to SHARED public
    /// infrastructure (mempool.space's per-IP 429 limits) — a loopback
    /// server (regtest server.py, a local node) needs no such courtesy,
    /// and pacing it would only slow the e2e suites and shift their
    /// timing calibrations.
    paced: bool,
}

/// True for bases whose host is loopback — the pacer/politeness exemption.
/// Deliberately narrow: a LAN node (`umbrel.local`, `192.168.…`) stays
/// paced, which is harmless at 5 req/s.
fn is_loopback_base(base: &str) -> bool {
    let host = base
        .split("://")
        .nth(1)
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = host.strip_prefix('[').map(|h| h.split(']').next().unwrap_or(h)).unwrap_or_else(|| {
        // Not bracketed IPv6 — strip an optional :port.
        host.split(':').next().unwrap_or(host)
    });
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

impl HttpTransport {
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        let paced = !is_loopback_base(&base);
        HttpTransport {
            base,
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("client config is static"),
            paced,
        }
    }
}

/// Process-global request pacer: `HttpTransport`s are constructed ad-hoc per
/// operation (a scan spins up several in a row), so nothing on `self` can
/// hold the "last request" timestamp — it has to be a process-wide static.
/// Holds the `Instant` of the most recently RESERVED slot (not necessarily
/// already elapsed).
static LAST_REQUEST_SLOT: Mutex<Option<Instant>> = Mutex::new(None);

/// Minimum spacing between the start of consecutive requests, across every
/// `HttpTransport` instance and every worker thread.
const MIN_REQUEST_SPACING: Duration = Duration::from_millis(200);

/// Block the calling thread until at least [`MIN_REQUEST_SPACING`] has
/// passed since the previous request STARTED. Concurrent callers each
/// reserve their own slot under the lock (compute + stamp only — the
/// actual sleep happens after unlocking) so they serialize onto distinct
/// 200ms-apart slots instead of racing to stamp "now" and all sleeping the
/// same short amount.
fn pace() {
    let wait = {
        let mut slot = LAST_REQUEST_SLOT.lock().expect("request pacer mutex poisoned");
        let now = Instant::now();
        let next_slot = match *slot {
            Some(prev) if prev + MIN_REQUEST_SPACING > now => prev + MIN_REQUEST_SPACING,
            _ => now,
        };
        *slot = Some(next_slot);
        next_slot.saturating_duration_since(now)
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

/// 429 retry-with-backoff delay for a given attempt (1-based: the delay
/// before retry #1, #2, #3). `retry_after_secs` is the server's
/// `Retry-After` header, if present and parseable as a plain integer
/// second count — it wins over the exponential fallback (1s / 2s / 4s for
/// attempts 1/2/3), and either way the result is capped at 10s so a
/// misbehaving/huge header value can't stall a scan indefinitely. Pure —
/// no I/O — so it's covered by a direct unit test rather than exercised
/// through real HTTP/real sleeps.
fn retry_delay(attempt: u32, retry_after_secs: Option<u64>) -> Duration {
    let secs = retry_after_secs.unwrap_or(match attempt {
        1 => 1,
        2 => 2,
        _ => 4,
    });
    Duration::from_secs(secs.min(10))
}

/// Parses a `Retry-After` header value as a plain integer second count
/// (mempool.space's own shape). The HTTP-date form is not handled — a
/// header we can't parse this way just falls back to the exponential
/// schedule in [`retry_delay`].
fn parse_retry_after(value: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    value?.to_str().ok()?.trim().parse().ok()
}

/// Trims a response body down to something fit for a UI status line: an
/// HTML error page (mempool.space's 429 body is one) gets its markup
/// stripped, everything is whitespace-collapsed, and the whole thing is
/// capped at ~120 chars — with the numeric status ALWAYS first, so
/// existing callers that sniff the front of an `Error::Http` message (e.g.
/// [`ChainClient::tx_lookup_status`]'s "starts with 404" check) keep
/// working unchanged. Pure — direct unit test, no HTTP involved.
fn trim_error_body(status: u16, body: &str) -> String {
    const MAX_LEN: usize = 120;
    // Drop anything from the first tag-opening '<' onward (`<html`, `</`,
    // `<!DOCTYPE`) — good enough to strip an HTML document without a real
    // HTML parser, while a bare comparison in a rejection body ("min relay
    // fee not met, 429 < 1000") passes through untouched.
    let tag_start = body.match_indices('<').find_map(|(i, _)| {
        let next = body[i + 1..].chars().next()?;
        (next.is_ascii_alphabetic() || next == '/' || next == '!').then_some(i)
    });
    let text_only = match tag_start {
        Some(i) => &body[..i],
        None => body,
    };
    let collapsed = text_only.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed: String = collapsed.chars().take(MAX_LEN).collect();
    if trimmed.is_empty() {
        format!("{status}")
    } else {
        format!("{status}: {trimmed}")
    }
}

impl Transport for HttpTransport {
    // `.send()` failing means the request never reached a server at all
    // (DNS, connection refused/reset, timeout) — `Error::Transport`, the
    // class `ChainClient::broadcast` retries once. A `.text()` failure
    // happens after a response header/status DID arrive, but a body that
    // never fully lands (connection dropped mid-transfer) is the same
    // "no usable server response" shape, so it's tagged `Transport` too.
    // Only a cleanly-received non-2xx status (a real response, just an
    // error one) is `Error::Http` — never retried, since retrying a
    // rejected request can't help... with ONE exception: a clean 429 is
    // retried up to 3 times (delay from `Retry-After` if the server sent
    // one, else 1s/2s/4s), since a 429'd request was never accepted by the
    // server in the first place — retrying it is exactly as safe as the
    // first attempt (including the broadcast POST: a 429'd tx was never
    // accepted, and rebroadcasting an already-accepted tx is a harmless
    // no-op anyway, see `ChainClient::broadcast`'s own doc comment). Every
    // attempt, including retries, goes through the global pacer
    // (`pace()`) so a burst of scan requests can't 429 itself in the first
    // place. Retries exhausted ⇒ falls through to the normal non-2xx
    // handling below, same as any other error status.
    fn get_text(&self, path: &str) -> Result<String, Error> {
        let url = format!("{}{}", self.base, path);
        // Per-request instrumentation for the networking-efficiency work
        // (2026-07-22) — debug builds only, so release/App Store builds never
        // log request paths. Suites/repros run the debug binary and grep these.
        //
        // STDERR, never stdout (fixed 2026-07-25): `examples/cli.rs` is a
        // UNIX-style filter whose stdout is DATA — callers capture it with
        // `$(…)` (a PSBT from `fund-build`, an address, a descriptor, bundle
        // JSON). Tracing to stdout spliced these lines into that data and
        // broke every such command: `regtest-e2e.sh`'s external-funding legs
        // died with `fund-sign … not a valid PSBT (base64 or hex)` because
        // the captured "PSBT" started with 7 `cb: http GET …` lines. Every
        // other `cli:`/`cb:` line already goes to stderr; keep it that way.
        // (The GUI redirects both streams to one log, so its suites' greps
        // are unaffected.)
        #[cfg(debug_assertions)]
        eprintln!("cb: http GET {path}");
        let mut attempt = 0u32;
        loop {
            if self.paced {
                pace();
            }
            let resp = self.client.get(&url).send().map_err(|e| Error::Transport(e.to_string()))?;
            let status = resp.status();
            let retry_after = parse_retry_after(resp.headers().get(reqwest::header::RETRY_AFTER));
            let text = resp.text().map_err(|e| Error::Transport(e.to_string()))?;
            if status.is_success() {
                return Ok(text);
            }
            if status.as_u16() == 429 && attempt < 3 {
                attempt += 1;
                std::thread::sleep(retry_delay(attempt, retry_after));
                continue;
            }
            return Err(Error::Http(trim_error_body(status.as_u16(), &text)));
        }
    }

    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        let url = format!("{}{}", self.base, path);
        // stderr, not stdout — see the `get_text` note above.
        #[cfg(debug_assertions)]
        eprintln!("cb: http POST {path}");
        let mut attempt = 0u32;
        loop {
            if self.paced {
                pace();
            }
            let resp = self
                .client
                .post(&url)
                .body(body.clone())
                .send()
                .map_err(|e| Error::Transport(e.to_string()))?;
            let status = resp.status();
            let retry_after = parse_retry_after(resp.headers().get(reqwest::header::RETRY_AFTER));
            let text = resp.text().map_err(|e| Error::Transport(e.to_string()))?;
            if status.is_success() {
                return Ok(text);
            }
            if status.as_u16() == 429 && attempt < 3 {
                attempt += 1;
                std::thread::sleep(retry_delay(attempt, retry_after));
                continue;
            }
            return Err(Error::Http(trim_error_body(status.as_u16(), &text)));
        }
    }
}

/// The backend seam (`../../PLAN-chain-notes-app-core-rpc.md` §1.2):
/// second-chain-backend selection rides the URL **scheme**, not a separate
/// settings enum. `AnyTransport` implements [`Transport`] by delegating to
/// whichever variant [`AnyTransport::new`] picked, so `ChainClient`, every
/// free scan function, `netq`, `store`, `compose`, and the whole UI layer
/// stay untouched — no `dyn`, no generics fallout.
pub enum AnyTransport {
    /// `http(s)://host/api` — mempool.space/Esplora, unchanged behavior.
    Esplora(HttpTransport),
    /// `bitcoind+http(s)://host[:port]` — Bitcoin Core JSON-RPC.
    Core(CoreRpcTransport),
}

impl AnyTransport {
    /// Parses `base` and picks a backend. Anything that does not start
    /// with `bitcoind+` is handed to [`HttpTransport::new`] EXACTLY as
    /// every call site already did — this refactor must not change one
    /// byte of the Esplora path's behavior (request paths, pacing, 429
    /// retry, error classification all untouched).
    ///
    /// `creds` is an explicit parameter (not read from anywhere) so
    /// `app-core` stays platform-agnostic — a later unit sources it from
    /// the platform Keychain; `examples/cli.rs` reads
    /// `CORE_RPC_USER`/`CORE_RPC_PASS` env vars instead. When `base` also
    /// carries inline `user:pass@` userinfo (`bitcoind+http://user:pass@
    /// host:8332`, needed so the CLI can address a node with no Keychain
    /// at all), the explicit `creds` parameter wins if both are present.
    pub fn new(base: &str, creds: Option<(String, String)>) -> Result<Self, Error> {
        match base.strip_prefix("bitcoind+") {
            Some(rest) => Ok(AnyTransport::Core(CoreRpcTransport::new(rest, creds)?)),
            None => Ok(AnyTransport::Esplora(HttpTransport::new(base))),
        }
    }
}

impl Transport for AnyTransport {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        match self {
            AnyTransport::Esplora(t) => t.get_text(path),
            AnyTransport::Core(t) => t.get_text(path),
        }
    }
    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        match self {
            AnyTransport::Esplora(t) => t.post_text(path, body),
            AnyTransport::Core(t) => t.post_text(path, body),
        }
    }
}

/// "Bitcoin Core" vs "Esplora" — small label for the Settings UI (a later
/// unit) to name the active backend from its stored node URL.
pub fn node_backend_label(base: &str) -> &'static str {
    if base.starts_with("bitcoind+") {
        "Bitcoin Core"
    } else {
        "Esplora"
    }
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
/// Ported from the reference implementation, `prime-chain-notes/companion/
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
/// ever queried (one `chain-notes-watch` wallet holds every imported
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
    const WATCH_WALLET: &'static str = "chain-notes-watch";

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
                .timeout(std::time::Duration::from_secs(30))
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

    /// One JSON-RPC 1.0 call. Auth is an HTTP Authorization header via
    /// `basic_auth` — `self.creds` never touches the URL string, so
    /// nothing here (nor `reqwest`'s own error `Display`, which can echo
    /// the request URL) can leak a credential into an `Error`/log line.
    fn call(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> RpcOutcome {
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
            match self.rpc(Some(Self::WATCH_WALLET), "getwalletinfo", serde_json::json!([])) {
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
    fn esplora_tx_json(&self, txid: &str, tip: u64) -> Result<serde_json::Value, Error> {
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
        Ok(serde_json::json!({"txid": txid, "status": status, "vin": vin, "vout": vout}))
    }

    fn ensure_watch_wallet(&self) -> Result<(), Error> {
        if *self.wallet_ready.lock().expect("wallet-ready mutex poisoned") {
            return Ok(());
        }
        match self.rpc(None, "createwallet", serde_json::json!([Self::WATCH_WALLET, true, true])) {
            Ok(_) => {}
            // Verified live wording (bitcoind v30.2.0): "...Database
            // already exists." A wallet already present on the node from
            // an earlier session/transport instance — load it instead.
            Err(Error::Http(msg)) if msg.contains("already exists") => {
                match self.rpc(None, "loadwallet", serde_json::json!([Self::WATCH_WALLET])) {
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
    /// called (every existing test and caller). `timestamp: 0` triggers a
    /// rescan from genesis on a real mainnet node; harmless on the short
    /// regtest chains U3 was tested against. Ensures `address` is imported
    /// into the watch wallet — first by checking whether it belongs to a
    /// ranged family already configured (U4, [`Self::ranged_lookup_or_widen`]),
    /// widening that family's imported range instead of falling back here
    /// when it does. Returns `Ok(true)` for a real, importable address;
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
        if self.ranged_lookup_or_widen(address)? {
            // Already imported (at configure time or just now, widened) —
            // cache the hit in `watched` too so the NEXT query for the same
            // address takes the cheapest possible path.
            self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
            return Ok(true);
        }
        self.ensure_watch_wallet()?;
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
        self.rpc(
            Some(Self::WATCH_WALLET),
            "importdescriptors",
            serde_json::json!([[{"desc": desc, "timestamp": 0}]]),
        )?;
        self.watched.lock().expect("watched-address mutex poisoned").insert(address.to_string());
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
    pub fn watch_descriptors(&self, specs: Vec<WatchDescriptor>) -> Result<(), Error> {
        if specs.is_empty() {
            return Ok(());
        }
        self.ensure_watch_wallet()?;
        let mut configured = Vec::with_capacity(specs.len());
        for spec in specs {
            let source = FundingSource::parse(&spec.descriptor, spec.network)?;
            self.import_ranged(&spec, spec.range_end)?;
            let mut rw = RangedWatch { spec, source, imported_end: 0, index: HashMap::new() };
            let end = rw.spec.range_end;
            Self::populate_index(&mut rw, 0, end);
            rw.imported_end = end;
            configured.push(rw);
        }
        self.ranged.lock().expect("ranged-watch mutex poisoned").extend(configured);
        Ok(())
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
        self.rpc(
            Some(Self::WATCH_WALLET),
            "importdescriptors",
            serde_json::json!([[{"desc": desc, "timestamp": spec.timestamp, "range": [0, end]}]]),
        )?;
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
            Some(Self::WATCH_WALLET),
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
            self.rpc(Some(Self::WATCH_WALLET), "listunspent", serde_json::json!([0, 9_999_999, [address]]))?;
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

// ---- esplora JSON shapes (only the fields we consume) ----

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// Field-tolerant: real esplora sends script hex + `v1_p2tr` types, the
/// regtest server.py sends only addresses on prevouts and Core-style
/// type names — taproot detection therefore goes by address prefix
/// (chain-scan.js's P2TR_RE rule), never by type string.
#[derive(Debug, Clone, Deserialize)]
pub struct EsploraOut {
    #[serde(default)]
    pub scriptpubkey: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub value: u64,
}

fn is_taproot_addr(addr: &str) -> bool {
    addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraVin {
    /// Outpoint being spent (present on real esplora and server.py alike).
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vout: Option<u32>,
    #[serde(default)]
    pub prevout: Option<EsploraOut>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraTx {
    pub txid: String,
    pub vin: Vec<EsploraVin>,
    pub vout: Vec<EsploraOut>,
    pub status: EsploraStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: EsploraStatus,
}

/// Private mirror of esplora's `{chain_stats, mempool_stats}` nesting for
/// `GET /address/:a` — flattened into [`AddrStats`] on the way out so
/// callers don't have to reach through two levels for the fields they
/// need. All fields `#[serde(default)]`-tolerant like every other esplora
/// shape in this file.
#[derive(Debug, Clone, Deserialize)]
struct EsploraAddrStatsGroup {
    #[serde(default)]
    tx_count: u64,
    #[serde(default)]
    funded_txo_sum: u64,
    #[serde(default)]
    spent_txo_sum: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct EsploraAddrStats {
    #[serde(default)]
    chain_stats: EsploraAddrStatsGroup,
    #[serde(default)]
    mempool_stats: EsploraAddrStatsGroup,
}

impl Default for EsploraAddrStatsGroup {
    fn default() -> Self {
        EsploraAddrStatsGroup { tx_count: 0, funded_txo_sum: 0, spent_txo_sum: 0 }
    }
}

/// Flat "did anything change since last scan" fingerprint for one address —
/// esplora's `GET /address/:a` chain + mempool stats, flattened. A later
/// wiring pass compares this against the last-persisted value ([`Store`]'s
/// `addr_stats` field) to short-circuit a refresh when nothing moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrStats {
    pub chain_tx_count: u64,
    pub chain_funded: u64,
    pub chain_spent: u64,
    pub mempool_tx_count: u64,
    pub mempool_funded: u64,
    pub mempool_spent: u64,
}

fn parse_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))
}

pub struct ChainClient<T: Transport> {
    pub transport: T,
    pub network: Network,
}

impl<T: Transport> ChainClient<T> {
    pub fn new(transport: T, network: Network) -> Self {
        ChainClient { transport, network }
    }

    pub fn tip_height(&self) -> Result<u64, Error> {
        let text = self.transport.get_text("/blocks/tip/height")?;
        text.trim().parse().map_err(|_| Error::Json("tip height not a number".into()))
    }

    pub fn fee_rates(&self) -> Result<FeeRates, Error> {
        parse_json(&self.transport.get_text("/v1/fees/recommended")?)
    }

    pub fn btc_usd(&self) -> Result<Option<f64>, Error> {
        let v: serde_json::Value = parse_json(&self.transport.get_text("/v1/prices")?)?;
        Ok(v.get("USD").and_then(|u| u.as_f64()))
    }

    pub fn utxos(&self, address: &str) -> Result<Vec<BundleUtxo>, Error> {
        let raw: Vec<EsploraUtxo> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/utxo"))?)?;
        Ok(raw
            .into_iter()
            .map(|u| BundleUtxo {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                height: u.status.block_height.filter(|_| u.status.confirmed),
                // None = "the bundle's scanned address" (this call scans
                // exactly one address's own UTXOs) — notes-core's documented
                // default, byte-identical to pre-bump behavior.
                owner_address: None,
            })
            .collect())
    }

    /// Full history, newest-first, deduped — the chain-scan.js loop:
    /// first `/txs` (mempool + ≤25 confirmed), then paginate
    /// `/txs/chain?after_txid=` while pages return a full 25.
    pub fn full_history(&self, address: &str) -> Result<Vec<EsploraTx>, Error> {
        let mut txs: Vec<EsploraTx> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/txs"))?)?;
        let mut seen: std::collections::HashSet<String> =
            txs.iter().map(|t| t.txid.clone()).collect();
        // Esplora paginates with the last-seen txid as a PATH segment
        // (`/txs/chain/:txid`). The `?after_txid=` query form is ignored by
        // mempool.space (returns the same page → would loop forever), and the
        // regtest companion only reads the query form — so pagesize/param
        // handling differs by backend. Guard on it: keep paging while a page
        // brings NEW txids; stop as soon as one adds nothing (empty, or a
        // backend that ignored the cursor and echoed a page we've seen).
        let mut last = txs.iter().filter(|t| t.status.confirmed).last().map(|t| t.txid.clone());
        while let Some(after) = last.take() {
            let page: Vec<EsploraTx> = parse_json(&self.transport.get_text(&format!(
                "/address/{address}/txs/chain/{after}"
            ))?)?;
            let fresh: Vec<EsploraTx> =
                page.into_iter().filter(|t| seen.insert(t.txid.clone())).collect();
            if fresh.is_empty() {
                break;
            }
            last = fresh.iter().filter(|t| t.status.confirmed).last().map(|t| t.txid.clone());
            txs.extend(fresh);
        }
        Ok(txs)
    }

    /// Scan a funding source's receive + change chains (gap-limited) for
    /// spendable UTXOs. An address counts as "used" if it has ANY history
    /// (so a spent-then-empty address doesn't prematurely end the gap walk);
    /// UTXOs are collected for used addresses. Also reports the first unused
    /// change index for a new change output.
    ///
    /// Network-efficiency merge (2026-07-23): this single walk ALSO collects
    /// every used address (either chain) plus the first unused RECEIVE index
    /// — exactly what a separate `chain::discover_spending` gap walk used to
    /// report, at zero extra request cost (this loop already visits every
    /// address and already calls `full_history` to decide "used"). Callers
    /// that only need coins (the external funding-wallet paths) simply don't
    /// read the new fields; the spending-wallet refresh path
    /// (`spending_refresh_async`) now needs only ONE `scan_funding` call
    /// instead of `discover_spending` + `scan_funding`.
    pub fn scan_funding(
        &self,
        src: &crate::funding::FundingSource,
        gap: u32,
    ) -> Result<crate::funding::FundingScan, Error> {
        use crate::funding::{FundingScan, FundingUtxo};
        use crate::notebooks::SpendingAddr;
        let mut utxos = Vec::new();
        let mut used = Vec::new();
        let mut seen_addr = std::collections::HashSet::new();
        let mut next_change_index = 0u32;
        let mut next_receive_index = 0u32;
        let ranged = src.is_ranged();

        for chain in [0usize, 1usize] {
            let mut consecutive_unused = 0u32;
            let mut index = 0u32;
            let mut first_unused: Option<u32> = None;
            loop {
                let d = src.derive(chain, index)?;
                // Fixed (non-multipath) descriptors can share an address
                // across chains — stop the chain once we revisit one.
                if !seen_addr.insert(d.address.clone()) {
                    break;
                }
                let is_used = !self.full_history(&d.address)?.is_empty();
                if is_used {
                    consecutive_unused = 0;
                    used.push(SpendingAddr {
                        chain: chain as u32,
                        index,
                        address: d.address.clone(),
                        script_pubkey_hex: hex::encode(&d.spk),
                    });
                    for u in self.utxos(&d.address)? {
                        utxos.push(FundingUtxo {
                            txid: u.txid,
                            vout: u.vout,
                            value: u.value,
                            address: d.address.clone(),
                            chain,
                            index,
                            confirmed: u.height.is_some(),
                        });
                    }
                } else {
                    if first_unused.is_none() {
                        first_unused = Some(index);
                    }
                    consecutive_unused += 1;
                }
                index += 1;
                if !ranged || consecutive_unused >= gap {
                    break;
                }
                // Backstop against a backend that reports history for EVERY
                // address (a server-side filter bug once walked this loop
                // forever): no sane wallet needs more indexes than this.
                if index >= 10_000 {
                    return Err(Error::Funding(
                        "descriptor scan ran away (backend reports every address as used?)".into(),
                    ));
                }
            }
            let next = first_unused.unwrap_or(0);
            if chain == 1 {
                next_change_index = next;
            } else {
                next_receive_index = next;
            }
        }
        Ok(FundingScan { utxos, next_change_index, used, next_receive_index })
    }

    /// One-page probe for the notebook picker: has this address ANY
    /// on-chain history (first /txs page non-empty), and what do its
    /// UTXOs sum to right now? Deliberately cheap — two requests, no
    /// history paging.
    pub fn address_probe(&self, address: &str) -> Result<(bool, u64), Error> {
        let txs: Vec<EsploraTx> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/txs"))?)?;
        let balance = self.utxos(address)?.iter().map(|u| u.value).sum();
        Ok((!txs.is_empty(), balance))
    }

    /// `GET /address/:a` — esplora's per-address chain + mempool stats,
    /// flattened into [`AddrStats`]. The "did anything change since last
    /// scan" fingerprint: a later wiring pass compares this against the
    /// last-persisted value to short-circuit a refresh when nothing moved.
    pub fn address_stats(&self, address: &str) -> Result<AddrStats, Error> {
        let raw: EsploraAddrStats =
            parse_json(&self.transport.get_text(&format!("/address/{address}"))?)?;
        Ok(AddrStats {
            chain_tx_count: raw.chain_stats.tx_count,
            chain_funded: raw.chain_stats.funded_txo_sum,
            chain_spent: raw.chain_stats.spent_txo_sum,
            mempool_tx_count: raw.mempool_stats.tx_count,
            mempool_funded: raw.mempool_stats.funded_txo_sum,
            mempool_spent: raw.mempool_stats.spent_txo_sum,
        })
    }

    /// Network-efficiency (build-39): a ONE-request "does this address have
    /// ANY on-chain history" check for [`discover_indexes`]'s gap walk —
    /// cheaper than [`Self::address_probe`], which costs two requests
    /// (`/txs` + `/utxo`) to also compute a balance discovery never needs.
    /// Reuses [`Self::address_stats`]'s single `/address/:a` fetch; "used"
    /// means any tx at all, confirmed or still sitting in the mempool.
    pub fn address_used(&self, address: &str) -> Result<bool, Error> {
        let stats = self.address_stats(address)?;
        Ok(stats.chain_tx_count > 0 || stats.mempool_tx_count > 0)
    }

    /// Broadcast raw tx hex; returns the txid mempool.space echoes back.
    ///
    /// One automatic retry, TRANSPORT-class failures only (`Error::Transport`
    /// — the request never reached a server: connection reset, timeout, a
    /// dying cellular link; the exact shape a weak-connection broadcast hits,
    /// see the "note saved, retry from here" Activity path). A real server
    /// RESPONSE with an error status (`Error::Http` — 400 bad tx, 409, ...)
    /// is reported immediately, no retry: retrying a rejected tx can't help,
    /// and could even mask the real reason for a caller that only sees the
    /// final error. Sleeping ~2s between attempts is fine to block on: this
    /// always runs on a worker `std::thread` (every call site here spawns
    /// one for exactly this reason), never the UI/event-loop thread. A
    /// retried broadcast re-POSTs the SAME raw bytes, so it's idempotent —
    /// same tx, same computed txid — a duplicate submission after a timeout
    /// is a harmless no-op server-side, not a double-spend.
    pub fn broadcast(&self, raw_hex: &str) -> Result<String, Error> {
        match self.transport.post_text("/tx", raw_hex.to_string()) {
            Ok(txid) => Ok(txid.trim().to_string()),
            Err(Error::Transport(_)) => {
                std::thread::sleep(std::time::Duration::from_secs(2));
                self.transport
                    .post_text("/tx", raw_hex.to_string())
                    .map(|txid| txid.trim().to_string())
            }
            Err(e) => Err(e),
        }
    }

    /// Raw hex of an on-chain/mempool tx — the keyless rebroadcast source.
    pub fn fetch_tx_hex(&self, txid: &str) -> Result<String, Error> {
        Ok(self.transport.get_text(&format!("/tx/{txid}/hex"))?.trim().to_string())
    }

    /// Task #14 (dropped-pending detection): unlike [`Self::fetch_tx_status`]
    /// — which collapses "definitely doesn't exist" and "transient network
    /// error" into the same `None` — this distinguishes them, since a
    /// dropped-tx verdict must NEVER be based on a mere hiccup. `NotFound`
    /// requires a definitive esplora 404 (what real mempool.space/esplora
    /// returns for an unknown txid); anything else — a non-404 error status,
    /// a connection failure, an unparseable body — is `Unknown` and must
    /// leave the caller's state untouched. (companion/server.py's regtest
    /// shim currently answers an unknown txid with a 400 carrying the raw
    /// bitcoind RPC error, not a 404 — so `NotFound` is reachable against
    /// real esplora/mempool.space but not through the local shim; see the
    /// e2e suite's dropped-tx leg, which therefore stays host-unit-test-only.)
    pub fn tx_lookup_status(&self, txid: &str) -> TxLookupStatus {
        match self.transport.get_text(&format!("/tx/{txid}")) {
            Ok(text) => match parse_json::<EsploraTx>(&text) {
                Ok(t) => TxLookupStatus::Found(t.status.confirmed),
                Err(_) => TxLookupStatus::Unknown,
            },
            Err(Error::Http(msg)) if msg.trim_start().starts_with("404") => TxLookupStatus::NotFound,
            Err(_) => TxLookupStatus::Unknown,
        }
    }

    /// Task #14: is this specific outpoint still sitting spendable at
    /// `address`? Backs the dropped-tx detector's second condition — a
    /// `NotFound` tx whose funding coin is STILL unspent means the
    /// broadcast never really took (as opposed to Orphaned, where the coin
    /// was spent by something else). Uses the same `/address/:a/utxo`
    /// endpoint `Self::utxos` already calls (esplora-shape already
    /// supported by both real esplora and companion/server.py — no new
    /// endpoint needed). `None` on a transport/parse failure — the caller
    /// must treat that as "don't know", not "unspent".
    pub fn outpoint_unspent(&self, address: &str, txid: &str, vout: u32) -> Option<bool> {
        let utxos = self.utxos(address).ok()?;
        Some(utxos.iter().any(|u| u.txid == txid && u.vout == vout))
    }

    /// Real confirmation status of a txid: Some(true) = in a block,
    /// Some(false) = in the mempool, None = unknown there (evicted /
    /// replaced / transport error). Feeds `Store::resolve_spend_statuses`.
    pub fn fetch_tx_status(&self, txid: &str) -> Option<bool> {
        let text = self.transport.get_text(&format!("/tx/{txid}")).ok()?;
        parse_json::<EsploraTx>(&text).ok().map(|t| t.status.confirmed)
    }

    /// A pending tx's inputs (as spendable outpoints with values) and
    /// outputs (spk bytes + value) — what a watch-mode RBF bump rebuilds
    /// from. Input values come from the vin prevout when the backend sends
    /// one, else from fetching the parent tx. `index_of` maps a prevout
    /// address to its owning notebook's receive index (a multi-notebook
    /// record's inputs span several leaves); unknown addresses stamp 0.
    pub fn fetch_tx_io(
        &self,
        txid: &str,
        index_of: impl Fn(&str) -> Option<u32>,
    ) -> Result<(Vec<crate::psbt_build::WatchCoin>, Vec<(Vec<u8>, u64)>, bool), Error> {
        let t: EsploraTx = parse_json(&self.transport.get_text(&format!("/tx/{txid}"))?)?;
        let mut coins = Vec::with_capacity(t.vin.len());
        for vin in &t.vin {
            let (ptxid, pvout) = match (&vin.txid, vin.vout) {
                (Some(x), Some(v)) => (x.clone(), v),
                _ => return Err(Error::Json("vin without outpoint".into())),
            };
            let (value, address) = match vin.prevout.as_ref() {
                Some(p) if p.value > 0 => (p.value, p.scriptpubkey_address.clone()),
                _ => {
                    // Backend sent no prevout value — read the parent tx.
                    let parent: EsploraTx =
                        parse_json(&self.transport.get_text(&format!("/tx/{ptxid}"))?)?;
                    let o = parent
                        .vout
                        .get(pvout as usize)
                        .ok_or_else(|| Error::Json("parent vout missing".into()))?;
                    (o.value, o.scriptpubkey_address.clone())
                }
            };
            let index = address.as_deref().and_then(&index_of).unwrap_or(0);
            // `index_of` only resolves NOTEBOOK (chain-0) addresses — a
            // change-including watch spend is non-bumpable by design (unit
            // 6), so this reconstruction never needs to represent chain 1.
            coins.push(crate::psbt_build::WatchCoin { txid: ptxid, vout: pvout, value, chain: 0, index });
        }
        let mut outputs = Vec::with_capacity(t.vout.len());
        for o in &t.vout {
            let spk = o
                .scriptpubkey
                .as_deref()
                .and_then(|h| hex::decode(h).ok())
                .ok_or_else(|| Error::Json("vout without script".into()))?;
            outputs.push((spk, o.value));
        }
        Ok((coins, outputs, t.status.confirmed))
    }

    /// Assemble the in-memory SyncBundle notes-core's extract_notes eats —
    /// identical shape to what the companion emits as QR/file bundles.
    pub fn build_bundle(
        &self,
        address: &str,
        since_height: Option<u64>,
    ) -> Result<SyncBundle, Error> {
        let tip_height = self.tip_height()?;
        // Network-efficiency (2026-07-23): fee_rates + btc_usd are only READ by
        // the fee-showing screens (compose/sweep/consolidate/bump), which now
        // fetch them lazily (`refresh_fees_price`, session-cached). A scan no
        // longer fetches either — the notes-core SyncBundle fields are required,
        // so they're filled with defaults the app's apply path ignores.
        let fee_rates = FeeRates::default();
        // Network-efficiency (2026-07-23): btc_usd was fetched on every scan
        // but only ever READ by the fee-showing screens (compose/sweep/
        // consolidate/bump) — those now fetch it lazily themselves
        // (`refresh_fees_price`, session-cached). The field stays for serde
        // compat; a scan never populates it.
        let btc_usd = None;
        let utxos = self.utxos(address)?;
        let history = self.full_history(address)?;

        let notes_onchain = history
            .iter()
            .filter(|t| match since_height {
                Some(h) => !t.status.confirmed || t.status.block_height.unwrap_or(u64::MAX) > h,
                None => true,
            })
            .filter_map(|t| classify_tx_net(t, address, self.network))
            .collect();

        Ok(SyncBundle {
            network: self.network.as_str().to_string(),
            full: since_height.is_none(),
            since_height,
            tip_height,
            bundle_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            fee_rates,
            btc_usd,
            utxos,
            notes_onchain,
            ..SyncBundle::default()
        })
    }
}

/// Receive-chain notebook gap discovery (rev-3 follow-up 2): probe the
/// account's receive indexes in order and return every index with ANY
/// on-chain history, stopping after `gap` consecutive never-used indexes.
/// Best-effort by design — a transport error (offline, backend down) stops
/// the walk and returns what was found so far, so a re-import without a
/// node simply discovers nothing. The caller `ensure_notebook`s each hit;
/// this function only reads the chain.
///
/// Network-efficiency (build-39): `known` lists receive indexes already
/// confirmed to be notebooks (e.g. the freshly-ensured notebook 0 on a seed
/// re-import) — the walk treats each as PRESENT with NO network request at
/// all (the "notebook-0 double-scan" fix; `refresh_async` already scanned
/// it moments earlier) and resets the gap counter, since a present notebook
/// is never a gap. Every other index costs exactly one request via
/// [`ChainClient::address_used`] instead of the old two-request
/// [`ChainClient::address_probe`].
pub fn discover_indexes<T: Transport>(
    client: &ChainClient<T>,
    material: &crate::identity::KeyMaterial,
    network: Network,
    account: u32,
    known: &[u32],
    gap: u32,
) -> Vec<u32> {
    let mut found = Vec::new();
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    while consecutive_unused < gap {
        if known.contains(&index) {
            // Already a confirmed notebook — present by construction, so no
            // request is needed. It IS still counted in `found` (it's a used
            // index): callers report `found=<total used> added=<newly created>`
            // and re-`ensure_notebook` idempotently, so a known index must
            // appear in `found` or the total under-counts (broke S5's
            // `found=3 added=2` when index 0 was skipped AND dropped).
            found.push(index);
            consecutive_unused = 0;
        } else {
            // A fixed (non-ranged) watch descriptor only derives index 0 —
            // the realize error ends the walk cleanly after that one probe.
            let Ok(ident) = crate::identity::realize(material, network, account, index) else {
                break;
            };
            match client.address_used(&ident.address) {
                Ok(true) => {
                    found.push(index);
                    consecutive_unused = 0;
                }
                Ok(false) => consecutive_unused += 1,
                Err(_) => break,
            }
        }
        index += 1;
        // Same runaway backstop as scan_funding: no sane wallet needs more.
        if index >= 10_000 {
            break;
        }
    }
    found
}

/// A spendable coin found gap-walking a keyed identity's taproot CHANGE
/// chain (`m/86'/{coin}'/{account}'/1/{index}`, [`crate::identity::realize_change`]),
/// via [`scan_change_chain`]. Mirrors [`crate::funding::FundingUtxo`]'s
/// shape (txid/vout/value/address/index/confirmed) plus the leaf's own
/// script pubkey, so folding these into the wallet's coin set later (a
/// later unit — see `../PLAN-chain-notes-app-taproot-change.md`) is a
/// straight field copy, not a translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeCoin {
    /// Chain-1 index — the same `index` [`crate::identity::realize_change`]
    /// took to derive this coin's address; needed later to derive its
    /// signing leaf.
    pub index: u32,
    pub address: String,
    pub script_pubkey_hex: String,
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

/// Gap-walk a keyed (Mnemonic/Xprv) identity's taproot CHANGE chain
/// (chain 1, [`crate::identity::realize_change`]) for spendable coins — the
/// change-chain sibling of [`discover_indexes`]'s receive-chain (chain 0)
/// walk, same "used" test ([`ChainClient::address_used`], one request) and
/// same gap-stop shape as [`discover_indexes`]/[`ChainClient::scan_funding`].
/// A used index's UTXOs are collected via [`ChainClient::utxos`].
///
/// `gap` is a parameter, not hardcoded here: the notebook-folding call site
/// (a later unit) uses gap=1 — external taproot wallets allocate change
/// sequentially, so a notebook's own change usage has no gaps — but a
/// future "scan deeper" action can pass more, same shallow/deep split
/// `scan_funding`'s two gap constants already establish for the spending
/// wallet.
///
/// WIF/hex/watch-only material has no change chain: `realize_change` errors
/// on the very first index for that material, so the walk ends immediately
/// with an empty `Vec` — not an `Err` — matching "a non-hierarchical
/// identity simply has nothing to fold in" rather than treating it as a
/// scan failure. A transport error (`address_used`/`utxos`) IS propagated,
/// same as `scan_funding`.
pub fn scan_change_chain<T: Transport>(
    client: &ChainClient<T>,
    material: &crate::identity::KeyMaterial,
    network: Network,
    account: u32,
    gap: u32,
) -> Result<Vec<ChangeCoin>, Error> {
    let mut coins = Vec::new();
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    loop {
        let ident = match crate::identity::realize_change(material, network, account, index) {
            Ok(i) => i,
            // Non-hierarchical/watch material — no change chain to walk.
            Err(_) => break,
        };
        if client.address_used(&ident.address)? {
            consecutive_unused = 0;
            let spk = notes_core::address::p2tr_script_pubkey(&ident.output_x());
            for u in client.utxos(&ident.address)? {
                coins.push(ChangeCoin {
                    index,
                    address: ident.address.clone(),
                    script_pubkey_hex: hex::encode(&spk),
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                    confirmed: u.height.is_some(),
                });
            }
        } else {
            consecutive_unused += 1;
        }
        index += 1;
        if consecutive_unused >= gap {
            break;
        }
        // Same runaway backstop as scan_funding/discover_indexes: no sane
        // wallet needs more indexes than this.
        if index >= 10_000 {
            break;
        }
    }
    Ok(coins)
}

/// Watch-only sibling of [`scan_change_chain`] (taproot change-chain unit
/// 6): gap-walk a WATCH identity's account's taproot CHANGE chain (chain 1
/// of its `tr(.../<0;1>/*)` descriptor, [`crate::funding::FundingSource::derive`])
/// for spendable coins — `realize_change` (unit 1) errors on Xpub material,
/// so a watch identity's change chain must come from the descriptor's own
/// ranged `<0;1>` multipath instead. Same "used" test
/// ([`ChainClient::address_used`], one request), same gap-stop shape, and
/// the SAME `ChangeCoin` return type as `scan_change_chain` — folding these
/// into `State.change_coins` is identical for both identity kinds.
///
/// A FIXED (non-ranged) descriptor — a bare single key with no `*`
/// wildcard, which only derives index 0 — has no change chain either:
/// [`crate::funding::FundingSource::is_ranged`] gates the walk, so it
/// returns an empty `Vec` immediately, matching `scan_change_chain`'s own
/// "nothing to walk" shape for non-hierarchical keyed material rather than
/// treating it as a scan failure.
pub fn scan_change_chain_watch<T: Transport>(
    client: &ChainClient<T>,
    source: &crate::funding::FundingSource,
    gap: u32,
) -> Result<Vec<ChangeCoin>, Error> {
    let mut coins = Vec::new();
    if !source.is_ranged() {
        return Ok(coins);
    }
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    loop {
        let d = source.derive(1, index)?;
        if client.address_used(&d.address)? {
            consecutive_unused = 0;
            for u in client.utxos(&d.address)? {
                coins.push(ChangeCoin {
                    index,
                    address: d.address.clone(),
                    script_pubkey_hex: hex::encode(&d.spk),
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                    confirmed: u.height.is_some(),
                });
            }
        } else {
            consecutive_unused += 1;
        }
        index += 1;
        if consecutive_unused >= gap {
            break;
        }
        // Same runaway backstop as scan_change_chain/scan_funding.
        if index >= 10_000 {
            break;
        }
    }
    Ok(coins)
}

/// Spending-wallet analog of [`discover_indexes`] (funding-unification
/// M2): probe BOTH chains of the wallet's BIP-84 branch — receive (0) and
/// change (1) — for on-chain history, stopping each chain after `gap`
/// consecutive never-used indexes (the same rule `discover_indexes` and
/// `scan_funding` use). Returns every address found used (for the store's
/// persisted list and self-spk set, via `Store::spending_apply_discovery`)
/// plus each chain's next-unused index. Best-effort like `discover_indexes`:
/// a transport error stops the walk and returns what was found so far, so a
/// words-only restore without a node simply discovers nothing yet.
pub fn discover_spending<T: Transport>(
    client: &ChainClient<T>,
    source: &crate::funding::FundingSource,
    gap: u32,
) -> (Vec<crate::notebooks::SpendingAddr>, u32, u32) {
    let mut used = Vec::new();
    let mut next_receive = 0u32;
    let mut next_change = 0u32;
    for chain in [0usize, 1usize] {
        let mut consecutive_unused = 0u32;
        let mut index = 0u32;
        let mut first_unused: Option<u32> = None;
        let mut transport_error = false;
        loop {
            let Ok(d) = source.derive(chain, index) else { break };
            match client.address_probe(&d.address) {
                Ok((true, _)) => {
                    used.push(crate::notebooks::SpendingAddr {
                        chain: chain as u32,
                        index,
                        address: d.address.clone(),
                        script_pubkey_hex: hex::encode(&d.spk),
                    });
                    consecutive_unused = 0;
                }
                Ok((false, _)) => {
                    if first_unused.is_none() {
                        first_unused = Some(index);
                    }
                    consecutive_unused += 1;
                }
                Err(_) => {
                    transport_error = true;
                    break;
                }
            }
            index += 1;
            // Same runaway backstop as scan_funding/discover_indexes.
            if consecutive_unused >= gap || index >= 10_000 {
                break;
            }
        }
        let next = first_unused.unwrap_or(0);
        if chain == 0 {
            next_receive = next;
        } else {
            next_change = next;
        }
        if transport_error {
            break;
        }
    }
    (used, next_receive, next_change)
}

/// tx → OnchainTx iff it carries ≥1 OP_RETURN payload. Classification
/// rules mirror chain-scan.js; payload parsing is notes-core's own.
/// Kept exactly as shipped (no `input_prevout_spks`) — additive sibling is
/// [`classify_tx_net`], which also needs a network to decode addresses
/// that arrive with no raw script hex (the regtest server.py shape).
pub fn classify_tx(tx: &EsploraTx, address: &str) -> Option<OnchainTx> {
    classify_tx_inner(tx, address, None)
}

/// [`classify_tx`] plus `input_prevout_spks` (funding-unification M2's
/// self-spk-SET ownership rule): every input's raw prevout scriptPubKey,
/// hex-encoded. Uses the raw `scriptpubkey` hex when the backend sends one
/// (real esplora); when it sends only `scriptpubkey_address` (the regtest
/// server.py shape — see the module-level gotcha), the spk is derived from
/// the address instead of left empty.
pub fn classify_tx_net(tx: &EsploraTx, address: &str, network: Network) -> Option<OnchainTx> {
    classify_tx_inner(tx, address, Some(network))
}

fn classify_tx_inner(tx: &EsploraTx, address: &str, network: Option<Network>) -> Option<OnchainTx> {
    let payloads: Vec<String> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() == Some("op_return"))
        .filter_map(|o| {
            let script = hex::decode(o.scriptpubkey.as_deref()?).ok()?;
            op_return_payload(&script).map(hex::encode)
        })
        .collect();
    if payloads.is_empty() {
        return None;
    }

    let spends_from_self = tx
        .vin
        .iter()
        .any(|i| i.prevout.as_ref().and_then(|p| p.scriptpubkey_address.as_deref()) == Some(address));
    let pays_self = tx.vout.iter().any(|o| o.scriptpubkey_address.as_deref() == Some(address));

    // FROZEN: prefer the first TAPROOT input prevout address — this is the
    // sender rule notes-core/contacts/reply-target logic keys off, since a
    // taproot address is the one that can double as a chain-notes identity.
    // Do not change the taproot-first preference.
    //
    // DISPLAY-ONLY fallback: when the tx has no taproot input at all (e.g.
    // funded purely from a native-segwit P2WPKH wallet), fall back to the
    // first input prevout address of ANY type, just so the UI can name the
    // funder instead of bucketing the note under an anonymous "unknown"
    // sender row. This never feeds `author_candidates` (below, taproot-only)
    // or any ECDH/crypto path — it's scanner display metadata only, and it
    // only fires when the taproot search above finds nothing.
    let input_addrs_any: Vec<&str> = tx
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter_map(|p| p.scriptpubkey_address.as_deref())
        .collect();
    let sender = input_addrs_any
        .iter()
        .find(|a| is_taproot_addr(a))
        .or_else(|| input_addrs_any.first())
        .map(|a| a.to_string());

    let externals: Vec<&str> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() != Some("op_return"))
        .filter_map(|o| o.scriptpubkey_address.as_deref())
        .filter(|a| *a != address)
        .collect();
    let recipient = externals
        .iter()
        .find(|a| is_taproot_addr(a))
        .or(externals.first())
        .map(|a| a.to_string());

    // Every taproot address in the tx (input prevouts AND outputs) except our
    // own — candidate authors for a received directed-private note. Under
    // external funding the author's key rides on a dust-to-self output, not the
    // spending input, so the decoder tries each of these (see notes-core).
    let mut author_candidates: Vec<String> = Vec::new();
    let input_addrs = tx
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter_map(|p| p.scriptpubkey_address.as_deref());
    let output_addrs = tx.vout.iter().filter_map(|o| o.scriptpubkey_address.as_deref());
    for a in input_addrs.chain(output_addrs) {
        if is_taproot_addr(a) && a != address && !author_candidates.iter().any(|c| c == a) {
            author_candidates.push(a.to_string());
        }
    }

    // Raw prevout spks for the self-spk-SET ownership rule (funding-
    // unification M2): prefer the raw hex esplora sends; fall back to
    // decoding `scriptpubkey_address` (the regtest server.py shape, which
    // carries no script hex at all — the module-level gotcha). `None`
    // network (the legacy `classify_tx` entry point) leaves this empty,
    // matching the pre-M2 behavior byte-for-byte.
    let input_prevout_spks: Vec<String> = match network {
        Some(net) => tx
            .vin
            .iter()
            .filter_map(|i| {
                let p = i.prevout.as_ref()?;
                if let Some(hex) = p.scriptpubkey.as_deref().filter(|h| !h.is_empty()) {
                    Some(hex.to_string())
                } else {
                    let addr = p.scriptpubkey_address.as_deref()?;
                    address_to_script_pubkey(net, addr).ok().map(|spk| hex::encode(&spk))
                }
            })
            .collect(),
        None => Vec::new(),
    };

    // Addresses of every NON-OP_RETURN output, in ascending vout order
    // (multi-recipient directed notes, FLAG_MULTI: notes-core's decoder
    // slices `output_addrs[0..count]` as the recipient list — recipients
    // precede change by construction). Skips an output whose script
    // doesn't decode to an address (never happens for our own P2TR/P2WPKH
    // outputs; notes-core degrades gracefully — never crashes — if it
    // ever did).
    let output_addrs: Vec<String> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() != Some("op_return"))
        .filter_map(|o| o.scriptpubkey_address.clone())
        .collect();

    Some(OnchainTx {
        txid: tx.txid.clone(),
        height: tx.status.block_height.filter(|_| tx.status.confirmed),
        blocktime: tx.status.block_time.filter(|_| tx.status.confirmed),
        spends_from_self,
        payloads,
        pays_self,
        sender: if spends_from_self { None } else { sender },
        author_candidates,
        // Unconditional: ownership is no longer equivalent to
        // spends_from_self (a spending-wallet- or externally-funded own
        // note spends other inputs), and the sender needs this field to
        // re-derive its own directed-private DM key on rescan. notes-core
        // surfaces it only for directed notes (the envelope flag), so a
        // self-note's "first non-self output" (its change) stays hidden.
        recipient,
        input_prevout_spks,
        output_addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{parse_key_material, realize, KeyMaterial};

    // Official BIP-86 account xpub (m/86'/0'/0') — imports as ranged watch
    // material, so discovery walks its real receive chain deterministically.
    const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    fn material() -> KeyMaterial {
        parse_key_material(BIP86_ACCT_XPUB, Network::Mainnet).unwrap()
    }

    fn addr(i: u32) -> String {
        realize(&material(), Network::Mainnet, 0, i).unwrap().address
    }

    /// Canned esplora for address probes: history/utxos only at the listed
    /// addresses; `fail` simulates an offline backend. Also answers the
    /// plain `/address/:a` stats endpoint (`address_used`/`address_stats`)
    /// with a one-tx-or-zero chain_stats shape, matching the same `used`
    /// list — so `discover_indexes`'s one-request check exercises the same
    /// fixtures the old two-request `address_probe` tests did.
    struct ProbeTransport {
        used: Vec<String>,
        fail: bool,
    }
    impl Transport for ProbeTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            if self.fail {
                return Err(Error::Http("offline".into()));
            }
            let used = self.used.iter().any(|a| path.contains(a.as_str()));
            if path.contains("/utxo") {
                Ok(if used {
                    r#"[{"txid":"aa","vout":0,"value":700,"status":{"confirmed":true,"block_height":9,"block_time":1}}]"#.into()
                } else {
                    "[]".into()
                })
            } else if path.contains("/txs") {
                Ok(if used {
                    r#"[{"txid":"aa","vin":[],"vout":[],"status":{"confirmed":true,"block_height":9,"block_time":1}}]"#.into()
                } else {
                    "[]".into()
                })
            } else {
                // Plain `/address/:a` stats endpoint.
                Ok(format!(
                    r#"{{"chain_stats":{{"tx_count":{},"funded_txo_sum":0,"spent_txo_sum":0}},"mempool_stats":{{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}}}"#,
                    if used { 1 } else { 0 }
                ))
            }
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("probes never POST")
        }
    }

    #[test]
    fn discovery_finds_used_indexes_past_holes() {
        // Indexes 0 and 2 used, 1 is a hole — the gap walk must continue
        // past it and only stop after `gap` consecutive unused indexes.
        // known=&[] here: same result the old two-request address_probe
        // walk produced, now via the one-request address_used check.
        let client = ChainClient::new(
            ProbeTransport { used: vec![addr(0), addr(2)], fail: false },
            Network::Mainnet,
        );
        assert_eq!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5), vec![0, 2]);
    }

    #[test]
    fn discovery_on_fresh_seed_is_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5).is_empty());
    }

    #[test]
    fn discovery_offline_is_best_effort_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![addr(0)], fail: true }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5).is_empty());
    }

    /// Same as `ProbeTransport` but records every path fetched, so a test
    /// can prove `known` indexes are skipped with NO request at all — the
    /// "notebook-0 double-scan" fix's core guarantee.
    struct LoggingProbeTransport {
        used: Vec<String>,
        log: std::cell::RefCell<Vec<String>>,
    }
    impl Transport for LoggingProbeTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            self.log.borrow_mut().push(path.to_string());
            let used = self.used.iter().any(|a| path.contains(a.as_str()));
            Ok(format!(
                r#"{{"chain_stats":{{"tx_count":{},"funded_txo_sum":0,"spent_txo_sum":0}},"mempool_stats":{{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}}}"#,
                if used { 1 } else { 0 }
            ))
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("probes never POST")
        }
    }

    #[test]
    fn discovery_skips_known_index_with_no_request() {
        // known=&[0]: index 0 must NOT be probed at all — yet the walk
        // still finds the higher used index (2) and the gap still
        // terminates correctly (index 0 being "present" resets the gap
        // counter, same as if it had been probed and found used).
        let a0 = addr(0);
        let transport =
            LoggingProbeTransport { used: vec![addr(2)], log: std::cell::RefCell::new(Vec::new()) };
        let client = ChainClient::new(transport, Network::Mainnet);
        let found = discover_indexes(&client, &material(), Network::Mainnet, 0, &[0], 5);
        // found INCLUDES the known index 0 (a used notebook — counted so the
        // caller's found=total/added=new stays right) plus the discovered 2 —
        // but index 0 was NOT probed (asserted below).
        assert_eq!(found, vec![0, 2]);
        let log = client.transport.log.borrow();
        assert!(
            !log.iter().any(|p| p.contains(&a0)),
            "index 0 must never be requested when it's already `known`: {log:?}"
        );
    }

    #[test]
    fn discovery_fresh_wallet_with_known_zero_terminates_empty() {
        // A fully-fresh wallet (nothing used anywhere) with known=&[0]:
        // index 0 is skipped (no request, but doesn't count toward the
        // gap), then the walk probes 1..=gap and finds nothing used —
        // `found` stays empty since a known index is never added to it.
        let transport =
            LoggingProbeTransport { used: vec![], log: std::cell::RefCell::new(Vec::new()) };
        let client = ChainClient::new(transport, Network::Mainnet);
        let found = discover_indexes(&client, &material(), Network::Mainnet, 0, &[0], 5);
        // Only the known index 0 is in `found` (counted, not probed); nothing
        // else on-chain, so no higher index is discovered.
        assert_eq!(found, vec![0]);
        let a0 = addr(0);
        let log = client.transport.log.borrow();
        assert!(!log.iter().any(|p| p.contains(&a0)), "index 0 must never be requested: {log:?}");
        // Exactly `gap` (5) requests — indexes 1..=5 — one per unused probe.
        assert_eq!(log.len(), 5);
    }

    /// Canned /tx/{txid}: two inputs with prevout addresses, one output.
    struct TxIoTransport;
    impl Transport for TxIoTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            assert!(path.starts_with("/tx/"), "unexpected fetch: {path}");
            Ok(r#"{"txid":"cc",
                "vin":[
                  {"txid":"aa","vout":0,"prevout":{"scriptpubkey_address":"bcrt1p-three","value":1000}},
                  {"txid":"bb","vout":1,"prevout":{"scriptpubkey_address":"bcrt1p-unknown","value":2000}}],
                "vout":[{"scriptpubkey":"51","value":2500}],
                "status":{"confirmed":false}}"#
                .into())
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!()
        }
    }

    #[test]
    fn fetch_tx_io_stamps_notebook_indexes_by_address() {
        let client = ChainClient::new(TxIoTransport, Network::Regtest);
        let (coins, outputs, confirmed) = client
            .fetch_tx_io("cc", |a| (a == "bcrt1p-three").then_some(3))
            .unwrap();
        assert!(!confirmed);
        assert_eq!(coins.len(), 2);
        assert_eq!((coins[0].index, coins[0].value), (3, 1000));
        // Unknown address (not one of our notebooks) stamps index 0.
        assert_eq!((coins[1].index, coins[1].value), (0, 2000));
        assert_eq!(outputs, vec![(vec![0x51], 2500)]);
    }

    const SPENDING_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                      abandon abandon abandon abandon about";

    #[test]
    fn discover_spending_finds_both_chains_past_holes() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r2 = src.derive(0, 2).unwrap().address; // index 1 is a hole
        let c0 = src.derive(1, 0).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r2.clone(), c0.clone()], fail: false },
            Network::Mainnet,
        );
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);

        assert_eq!(used.iter().filter(|a| a.chain == 0).count(), 2);
        assert!(used.iter().any(|a| a.chain == 0 && a.index == 0 && a.address == r0));
        assert!(used.iter().any(|a| a.chain == 0 && a.index == 2 && a.address == r2));
        // First unused receive index is the hole at 1 (same "first unused,
        // holes don't count as the frontier" rule scan_funding uses).
        assert_eq!(next_receive, 1);
        assert_eq!(used.iter().filter(|a| a.chain == 1).count(), 1);
        assert_eq!(next_change, 1);
        for a in &used {
            assert!(hex::decode(&a.script_pubkey_hex).is_ok(), "spk must be valid hex");
        }
    }

    #[test]
    fn discover_spending_on_fresh_wallet_is_empty() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);
        assert!(used.is_empty());
        assert_eq!(next_receive, 0);
        assert_eq!(next_change, 0);
    }

    #[test]
    fn discover_spending_offline_is_best_effort() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let client = ChainClient::new(ProbeTransport { used: vec![r0], fail: true }, Network::Mainnet);
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);
        assert!(used.is_empty());
        assert_eq!((next_receive, next_change), (0, 0));
    }

    /// Network-efficiency merge (2026-07-23), correctness proof #1: the
    /// extended `scan_funding`'s single walk must report the SAME used-
    /// address list + next-receive/next-change indexes that the OLD two-call
    /// shape (`discover_spending` + a plain `scan_funding`) produced — plus
    /// the same coins, since a missed coin is lost-funds visibility. Used at
    /// receive indexes {0,1} (a hole at neither) and change index 0.
    #[test]
    fn scan_funding_merge_matches_discover_spending() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r1 = src.derive(0, 1).unwrap().address;
        let c0 = src.derive(1, 0).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r1.clone(), c0.clone()], fail: false },
            Network::Mainnet,
        );

        let (disc_used, disc_next_receive, disc_next_change) = discover_spending(&client, &src, 20);
        let scan = client.scan_funding(&src, 20).unwrap();

        // Same used-address SET (chain, index, address, spk), order aside.
        let mut disc_keys: Vec<(u32, u32)> = disc_used.iter().map(|a| (a.chain, a.index)).collect();
        let mut scan_keys: Vec<(u32, u32)> = scan.used.iter().map(|a| (a.chain, a.index)).collect();
        disc_keys.sort();
        scan_keys.sort();
        assert_eq!(disc_keys, scan_keys, "used-address (chain,index) set must match exactly");
        for d in &disc_used {
            let s = scan
                .used
                .iter()
                .find(|a| a.chain == d.chain && a.index == d.index)
                .expect("every discover_spending hit must appear in the merged scan");
            assert_eq!(s.address, d.address);
            assert_eq!(s.script_pubkey_hex, d.script_pubkey_hex);
        }

        // Same next-unused indexes on both chains.
        assert_eq!(disc_next_receive, scan.next_receive_index);
        assert_eq!(disc_next_change, scan.next_change_index);

        // Same coins: one UTXO per used address (the ProbeTransport fixture's
        // fixed 700-sat coin), none missing/extra.
        assert_eq!(scan.utxos.len(), disc_used.len());
        for u in &scan.utxos {
            assert_eq!(u.value, 700);
        }
    }

    /// Correctness proof #2: the "shallow" gap the app's automatic scan now
    /// uses (3) catches sequential usage — indexes 0,1,2 used back-to-back,
    /// with three consecutive unused indexes after (3,4,5) ending the walk.
    #[test]
    fn scan_funding_shallow_gap3_catches_sequential_usage() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r1 = src.derive(0, 1).unwrap().address;
        let r2 = src.derive(0, 2).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r1.clone(), r2.clone()], fail: false },
            Network::Mainnet,
        );
        let scan = client.scan_funding(&src, 3).unwrap();
        let mut receive_used: Vec<u32> =
            scan.used.iter().filter(|a| a.chain == 0).map(|a| a.index).collect();
        receive_used.sort();
        assert_eq!(receive_used, vec![0, 1, 2]);
        assert_eq!(scan.utxos.iter().filter(|u| u.chain == 0).count(), 3);
    }

    /// Correctness proof #3 (documents the shallow/deep tradeoff): usage at
    /// index 5 ONLY (0–4 all empty) is beyond a gap-3 walk's reach — it stops
    /// after 3 consecutive unused indexes (2,3,4) without ever reaching 5 —
    /// but a gap-20 walk (the manual "Scan for existing funds…" deep scan)
    /// finds it. This is exactly the gappy-externally-used-seed case the deep
    /// scan exists to cover.
    #[test]
    fn scan_funding_deep_gap20_catches_what_shallow_gap3_misses() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r5 = src.derive(0, 5).unwrap().address;
        let client =
            ChainClient::new(ProbeTransport { used: vec![r5.clone()], fail: false }, Network::Mainnet);

        let shallow = client.scan_funding(&src, 3).unwrap();
        assert!(shallow.used.is_empty(), "gap-3 must not reach index 5");
        assert!(shallow.utxos.is_empty());

        let deep = client.scan_funding(&src, 20).unwrap();
        assert!(deep.used.iter().any(|a| a.chain == 0 && a.index == 5 && a.address == r5));
        assert_eq!(deep.utxos.iter().filter(|u| u.chain == 0 && u.index == 5).count(), 1);
    }

    // --- scan_change_chain (taproot change-chain unit 2) ---------------

    const CHANGE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn change_addr(i: u32) -> String {
        crate::identity::realize_change(
            &parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap(),
            Network::Mainnet,
            0,
            i,
        )
        .unwrap()
        .address
    }

    /// Change-chain indexes 0 and 1 used (each with a UTXO via the
    /// `ProbeTransport` fixture's fixed 700-sat coin) — the walk must
    /// return exactly those two coins, each carrying the right chain-1
    /// `index`, its change address, and the fixture's value.
    #[test]
    fn scan_change_chain_finds_change_coins() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0), change_addr(1)], fail: false },
            Network::Mainnet,
        );

        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 5).unwrap();

        assert_eq!(coins.len(), 2, "one coin per used change index");
        let mut indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        indexes.sort();
        assert_eq!(indexes, vec![0, 1]);
        for c in &coins {
            assert_eq!(c.value, 700);
            assert!(c.confirmed);
            assert!(hex::decode(&c.script_pubkey_hex).is_ok(), "spk must be valid hex");
            assert_eq!(c.address, change_addr(c.index));
        }
    }

    /// Nothing used on the change chain — the walk stops after `gap`
    /// probes with an empty result (no panic, no runaway).
    #[test]
    fn scan_change_chain_stops_after_gap_on_fresh_wallet() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 3).unwrap();
        assert!(coins.is_empty());
    }

    /// Used at change indexes {0,2} (a hole at 1) — documents the
    /// notebook gap-1 tradeoff Sal chose (2026-07-23): gap>=2 reaches past
    /// the hole and finds both, but the shallow default gap=1 stops right
    /// after the hole and only finds index 0.
    #[test]
    fn scan_change_chain_gap_stops_the_walk() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let used = vec![change_addr(0), change_addr(2)];

        let client_deep =
            ChainClient::new(ProbeTransport { used: used.clone(), fail: false }, Network::Mainnet);
        let deep = scan_change_chain(&client_deep, &m, Network::Mainnet, 0, 2).unwrap();
        let mut deep_indexes: Vec<u32> = deep.iter().map(|c| c.index).collect();
        deep_indexes.sort();
        assert_eq!(deep_indexes, vec![0, 2], "gap>=2 must reach past the hole at 1");

        let client_shallow = ChainClient::new(ProbeTransport { used, fail: false }, Network::Mainnet);
        let shallow = scan_change_chain(&client_shallow, &m, Network::Mainnet, 0, 1).unwrap();
        let shallow_indexes: Vec<u32> = shallow.iter().map(|c| c.index).collect();
        assert_eq!(shallow_indexes, vec![0], "gap=1 (the notebook default) stops at the hole");
    }

    /// A returned coin's address must equal `realize_change`'s own output
    /// for that index — ties the scan to the verified derivation rather
    /// than some independent path that could silently drift from it.
    #[test]
    fn scan_change_chain_addresses_match_realize_change() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0)], fail: false },
            Network::Mainnet,
        );
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 3).unwrap();
        assert_eq!(coins.len(), 1);
        let expected =
            crate::identity::realize_change(&m, Network::Mainnet, 0, coins[0].index).unwrap();
        assert_eq!(coins[0].address, expected.address);
    }

    /// Non-hierarchical material (raw hex key) has no change chain —
    /// `realize_change` errors immediately, so the walk returns an empty
    /// result gracefully (no Err, no panic), never even reaching the
    /// transport (constructed with `fail: true` to prove no request is
    /// attempted).
    #[test]
    fn scan_change_chain_non_hierarchical_material_is_empty() {
        let m = KeyMaterial::Hex([7u8; 32]);
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: true }, Network::Mainnet);
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 5).unwrap();
        assert!(coins.is_empty());
    }

    // --- scan_change_chain_watch (taproot change-chain unit 6) ----------

    /// The account-level `tr([fp/86'/{coin}'/{account}']xpub/<0;1>/*)`
    /// descriptor for `CHANGE_MNEMONIC`'s seed — the SAME seed/network/
    /// account [`change_addr`] (above) uses, so a watch-only import of this
    /// seed sees the SAME chain-1 addresses as the keyed import.
    fn change_watch_source(network: Network, account: u32) -> crate::funding::FundingSource {
        use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        let mnemonic =
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, CHANGE_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(crate::derive::btc_network(network), &seed).unwrap();
        let coin = crate::derive::coin_type(network);
        let account_xpriv = master
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_hardened_idx(86).unwrap(),
                    ChildNumber::from_hardened_idx(coin).unwrap(),
                    ChildNumber::from_hardened_idx(account).unwrap(),
                ],
            )
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &account_xpriv);
        let fp = master.fingerprint(&secp);
        crate::funding::FundingSource::parse(
            &format!("tr([{fp}/86'/{coin}'/{account}']{xpub}/<0;1>/*)"),
            network,
        )
        .unwrap()
    }

    /// Money-critical parity (unit 6): a watch-only import of the SAME seed
    /// must see the SAME chain-1 change addresses a keyed import does — the
    /// descriptor's `<0;1>` multipath derivation and `realize_change`'s
    /// leaf derivation are two independent code paths that must agree, or a
    /// watch-only user's change coins would be invisible (or worse, an
    /// external signer would be handed the wrong key origin for them).
    #[test]
    fn watch_change_addr_matches_keyed_realize_change() {
        let src = change_watch_source(Network::Mainnet, 0);
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        for j in [0u32, 1, 5, 41] {
            let watch = src.derive(1, j).unwrap();
            let keyed = crate::identity::realize_change(&m, Network::Mainnet, 0, j).unwrap();
            assert_eq!(watch.address, keyed.address, "index {j}: watch vs keyed address mismatch");
        }
    }

    /// [`scan_change_chain_watch`] finds the same coins [`scan_change_chain`]
    /// (the keyed walk) does, for the SAME seed/addresses — the watch-only
    /// scan sibling proven against the same `ProbeTransport` fixture unit 2
    /// already uses.
    #[test]
    fn scan_change_chain_watch_finds_coins() {
        let src = change_watch_source(Network::Mainnet, 0);
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0), change_addr(1)], fail: false },
            Network::Mainnet,
        );
        let coins = scan_change_chain_watch(&client, &src, 5).unwrap();
        assert_eq!(coins.len(), 2, "one coin per used change index");
        let mut indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        indexes.sort();
        assert_eq!(indexes, vec![0, 1]);
        for c in &coins {
            assert_eq!(c.value, 700);
            assert!(c.confirmed);
            assert!(hex::decode(&c.script_pubkey_hex).is_ok(), "spk must be valid hex");
            assert_eq!(c.address, change_addr(c.index));
        }
    }

    /// A fresh watch wallet (nothing used) stops after `gap` probes with an
    /// empty result — same shape as [`scan_change_chain_stops_after_gap_on_fresh_wallet`].
    #[test]
    fn scan_change_chain_watch_stops_after_gap_on_fresh_wallet() {
        let src = change_watch_source(Network::Mainnet, 0);
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let coins = scan_change_chain_watch(&client, &src, 3).unwrap();
        assert!(coins.is_empty());
    }

    /// A FIXED (non-ranged, no `*` wildcard) descriptor has no change chain
    /// to walk — the same "nothing to walk" shape `scan_change_chain`
    /// returns for non-hierarchical keyed material, proven here with
    /// `fail: true` to confirm no request is even attempted.
    #[test]
    fn scan_change_chain_watch_fixed_descriptor_is_empty() {
        let src = change_watch_source(Network::Mainnet, 0);
        // A definite (index-fixed) descriptor is already a plain `tr(key)`
        // with no wildcard — re-parsing its own string form gives a FIXED
        // FundingSource (single key, `is_ranged() == false`).
        let fixed_desc = src.definite(0, 0).unwrap().to_string();
        let fixed_src = crate::funding::FundingSource::parse(&fixed_desc, Network::Mainnet).unwrap();
        assert!(!fixed_src.is_ranged());
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: true }, Network::Mainnet);
        let coins = scan_change_chain_watch(&client, &fixed_src, 5).unwrap();
        assert!(coins.is_empty());
    }

    #[test]
    fn classify_tx_net_populates_input_prevout_spks_from_address_or_hex() {
        use notes_core::tx::op_return_script;
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Regtest).unwrap();
        let key = crate::spending::derive_spending_key(&m, Network::Regtest, 0, 0, 0).unwrap();
        let payload_hex = hex::encode(op_return_script(b"hi"));
        let spk_hex = hex::encode(&key.script_pubkey);

        // Regtest server.py shape: only `scriptpubkey_address` on the
        // prevout, no raw script hex — the spk must be DERIVED from it.
        let json_addr_only = format!(
            r#"{{"txid":"t1","vin":[{{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"{}","value":1000}}}}],"vout":[{{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}}],"status":{{"confirmed":false}}}}"#,
            key.address
        );
        let tx: EsploraTx = serde_json::from_str(&json_addr_only).unwrap();
        let onchain = classify_tx_net(&tx, "not-our-address", Network::Regtest).unwrap();
        assert_eq!(onchain.input_prevout_spks, vec![spk_hex.clone()]);
        // The legacy no-network entry point stays empty — byte-identical
        // to pre-M2 behavior.
        assert!(classify_tx(&tx, "not-our-address").unwrap().input_prevout_spks.is_empty());

        // Real esplora shape: raw scriptpubkey hex present — used directly.
        let json_hex = format!(
            r#"{{"txid":"t2","vin":[{{"txid":"a","vout":0,"prevout":{{"scriptpubkey":"{spk_hex}","value":1000}}}}],"vout":[{{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}}],"status":{{"confirmed":false}}}}"#
        );
        let tx2: EsploraTx = serde_json::from_str(&json_hex).unwrap();
        let onchain2 = classify_tx_net(&tx2, "not-our-address", Network::Regtest).unwrap();
        assert_eq!(onchain2.input_prevout_spks, vec![spk_hex]);
    }

    // ---- Unit C: sender falls back to the first non-taproot input prevout
    // address when the tx has no taproot input at all (e.g. funded purely
    // from a native-segwit P2WPKH wallet) — display-only, so an "Unknown"
    // received note can show a real funder address instead. ----

    #[test]
    fn sender_falls_back_to_first_non_taproot_input() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1q-wpkh-funder","value":1000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender.as_deref(), Some("bcrt1q-wpkh-funder"));
    }

    #[test]
    fn sender_prefers_taproot_input_regardless_of_order() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // Taproot input is SECOND in vin order — proves the preference isn't
        // just "first input", it's "first taproot input" even when a
        // non-taproot input comes first.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1q-wpkh-funder","value":1000}}}},
                {{"txid":"b","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1p-taproot-funder","value":2000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":2500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender.as_deref(), Some("bcrt1p-taproot-funder"));
    }

    #[test]
    fn sender_none_when_tx_spends_from_self() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // The tx spends OUR OWN address as an input — the return-site rule
        // (`sender: if spends_from_self { None } else { sender }`) must still
        // blank the sender, unaffected by the new fallback.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"our-address","value":1000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender, None);
    }

    #[test]
    fn sender_none_when_no_resolvable_prevout_address() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // No inputs at all resolve to a prevout address (prevout missing
        // entirely) — must degrade to None, never panic.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender, None);
    }

    // ---- task #14: dropped-pending detection — tx_lookup_status /
    // outpoint_unspent (the ChainClient half; the pure state machine that
    // consumes them, `store::resolve_dropped`, is tested in store.rs). ----

    /// Canned `/tx/:txid` transport: a 404 (real-esplora "definitely no
    /// such tx"), a non-404 error (transient), and a found tx, keyed by
    /// txid. `/address/:a/utxo` answers from a fixed outpoint list.
    struct TxLookupTransport {
        found_confirmed: Option<bool>, // Some(confirmed) for txid "found"
        utxos: Vec<(&'static str, u32)>, // (txid, vout) pairs deemed unspent
    }

    impl Transport for TxLookupTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            if path == "/tx/found" {
                let confirmed = self.found_confirmed.expect("found_confirmed must be set");
                return Ok(format!(
                    r#"{{"txid":"found","vin":[],"vout":[],"status":{{"confirmed":{confirmed}}}}}"#
                ));
            }
            if path == "/tx/missing" {
                return Err(Error::Http("404 Not Found: Transaction not found".into()));
            }
            if path == "/tx/flaky" {
                return Err(Error::Http("connection reset".into()));
            }
            if path == "/tx/bad-status" {
                // A non-404 HTTP error must NOT read as NotFound.
                return Err(Error::Http("500 Internal Server Error: oops".into()));
            }
            if path.starts_with("/address/") && path.ends_with("/utxo") {
                let items: Vec<String> = self
                    .utxos
                    .iter()
                    .map(|(t, v)| {
                        format!(
                            r#"{{"txid":"{t}","vout":{v},"value":1000,"status":{{"confirmed":true,"block_height":1}}}}"#
                        )
                    })
                    .collect();
                return Ok(format!("[{}]", items.join(",")));
            }
            Err(Error::Http(format!("unexpected path: {path}")))
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("dropped-detection never POSTs")
        }
    }

    #[test]
    fn tx_lookup_status_distinguishes_found_notfound_unknown() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: Some(true), utxos: vec![] },
            Network::Regtest,
        );
        assert_eq!(client.tx_lookup_status("found"), TxLookupStatus::Found(true));
        assert_eq!(client.tx_lookup_status("missing"), TxLookupStatus::NotFound);
        // A transport-level failure (no HTTP status at all) is Unknown, not
        // NotFound — a dropped verdict must never come from a network blip.
        assert_eq!(client.tx_lookup_status("flaky"), TxLookupStatus::Unknown);
        // A definite HTTP error that ISN'T a 404 is also Unknown, never
        // NotFound — only a real esplora 404 counts as definitive.
        assert_eq!(client.tx_lookup_status("bad-status"), TxLookupStatus::Unknown);
    }

    #[test]
    fn tx_lookup_status_found_reports_mempool_vs_confirmed() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: Some(false), utxos: vec![] },
            Network::Regtest,
        );
        assert_eq!(client.tx_lookup_status("found"), TxLookupStatus::Found(false));
    }

    #[test]
    fn outpoint_unspent_checks_the_address_utxo_set() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: None, utxos: vec![("aa", 0), ("bb", 1)] },
            Network::Regtest,
        );
        assert_eq!(client.outpoint_unspent("addr1", "aa", 0), Some(true));
        assert_eq!(client.outpoint_unspent("addr1", "aa", 1), Some(false));
        assert_eq!(client.outpoint_unspent("addr1", "cc", 0), Some(false));
    }

    // ---- broadcast: one retry, transport-class failures only ----

    /// Canned `/tx` POST transport whose first N attempts fail with a fixed
    /// error (transport- or response-shaped, caller's choice), then succeed
    /// — `attempts` counts every `post_text` call so tests can assert the
    /// retry fired exactly once (never more).
    struct BroadcastTransport {
        fail_first: std::cell::Cell<u32>,
        fail_err: Error,
        attempts: std::cell::Cell<u32>,
    }
    impl Transport for BroadcastTransport {
        fn get_text(&self, _path: &str) -> Result<String, Error> {
            unreachable!("broadcast never GETs")
        }
        fn post_text(&self, path: &str, _body: String) -> Result<String, Error> {
            assert_eq!(path, "/tx");
            self.attempts.set(self.attempts.get() + 1);
            let remaining = self.fail_first.get();
            if remaining > 0 {
                self.fail_first.set(remaining - 1);
                return Err(self.fail_err.clone());
            }
            Ok("deadbeef".into())
        }
    }

    #[test]
    fn broadcast_retries_once_after_a_transport_failure_then_succeeds() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(1),
            fail_err: Error::Transport("error sending request for url (...)".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        assert_eq!(client.broadcast("aabbcc").unwrap(), "deadbeef");
        assert_eq!(client.transport.attempts.get(), 2, "one retry after the transport failure");
    }

    #[test]
    fn broadcast_gives_up_after_two_transport_failures() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(99), // every attempt fails
            fail_err: Error::Transport("connection reset".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        let err = client.broadcast("aabbcc").unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
        assert_eq!(
            client.transport.attempts.get(),
            2,
            "exactly one retry, not an unbounded loop"
        );
    }

    #[test]
    fn broadcast_never_retries_a_server_rejection() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(99),
            fail_err: Error::Http("400 Bad Request: bad-txns-in-belowout".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        let err = client.broadcast("aabbcc").unwrap_err();
        assert!(matches!(err, Error::Http(_)));
        assert_eq!(
            client.transport.attempts.get(),
            1,
            "a real server response (even an error one) is reported immediately"
        );
    }

    // ---- 429 handling: pure backoff schedule, body trimming, is_rate_limited ----

    #[test]
    fn retry_delay_uses_retry_after_when_present_and_caps_at_10s() {
        assert_eq!(retry_delay(1, Some(3)), Duration::from_secs(3));
        assert_eq!(retry_delay(2, Some(3)), Duration::from_secs(3));
        // A server sending an outrageous Retry-After must not stall a scan.
        assert_eq!(retry_delay(1, Some(9_999)), Duration::from_secs(10));
    }

    #[test]
    fn retry_delay_falls_back_to_exponential_schedule_without_retry_after() {
        assert_eq!(retry_delay(1, None), Duration::from_secs(1));
        assert_eq!(retry_delay(2, None), Duration::from_secs(2));
        assert_eq!(retry_delay(3, None), Duration::from_secs(4));
        // Any attempt beyond 3 still saturates at the attempt-3 delay —
        // callers never actually retry past 3, but the function itself
        // doesn't need its own extra cap for that.
        assert_eq!(retry_delay(4, None), Duration::from_secs(4));
    }

    #[test]
    fn trim_error_body_strips_html_and_keeps_status_first() {
        let html = "<html><head><title>429 Too Many Requests</title></head>\
                     <body>You have been rate limited</body></html>";
        let trimmed = trim_error_body(429, html);
        assert!(trimmed.starts_with("429"));
        assert!(!trimmed.contains('<'));
        assert!(trimmed.len() < html.len());
    }

    #[test]
    fn trim_error_body_caps_long_plain_bodies() {
        let long = "x".repeat(500);
        let trimmed = trim_error_body(500, &long);
        assert!(trimmed.starts_with("500:"));
        // 120 chars of body plus the "500: " prefix.
        assert!(trimmed.len() <= 120 + "500: ".len());
    }

    #[test]
    fn trim_error_body_preserves_short_plain_bodies() {
        assert_eq!(trim_error_body(404, "Transaction not found"), "404: Transaction not found");
        // No body at all still carries the status.
        assert_eq!(trim_error_body(503, ""), "503");
    }

    #[test]
    fn loopback_bases_are_exempt_from_pacing() {
        assert!(is_loopback_base("http://127.0.0.1:18797/regtest/api"));
        assert!(is_loopback_base("http://localhost:3000/api"));
        assert!(is_loopback_base("http://[::1]:3000/api"));
        // Public and LAN hosts stay paced.
        assert!(!is_loopback_base("https://mempool.space/api"));
        assert!(!is_loopback_base("https://mempool.space/testnet4/api"));
        assert!(!is_loopback_base("http://umbrel.local:3006/api"));
        assert!(!is_loopback_base("http://192.168.1.10:3000/api"));
    }

    #[test]
    fn trim_error_body_keeps_plain_text_comparisons() {
        // bitcoind rejection bodies carry bare '<' comparisons — only a
        // tag-opening '<' starts the strip.
        assert_eq!(
            trim_error_body(400, "sendrawtransaction min relay fee not met, 429 < 1000"),
            "400: sendrawtransaction min relay fee not met, 429 < 1000"
        );
        assert_eq!(trim_error_body(400, "fee too low, 100 < 110 <html>junk</html>"), "400: fee too low, 100 < 110");
    }

    #[test]
    fn is_rate_limited_true_only_for_a_429_http_error() {
        assert!(Error::Http(trim_error_body(429, "rate limited")).is_rate_limited());
        assert!(!Error::Http(trim_error_body(404, "not found")).is_rate_limited());
        assert!(!Error::Transport("connection reset".into()).is_rate_limited());
    }

    // ---- address_stats: flattens esplora's nested chain/mempool shape ----

    struct AddrStatsTransport(&'static str);
    impl Transport for AddrStatsTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            assert!(path.starts_with("/address/"), "unexpected fetch: {path}");
            Ok(self.0.to_string())
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("address_stats never POSTs")
        }
    }

    #[test]
    fn address_stats_parses_nested_esplora_shape() {
        // Real-shaped esplora /address/:a response (extra fields present on
        // the wire — e.g. `address` itself — are ignored, not just absent).
        let json = r#"{
            "address": "tb1qdummy",
            "chain_stats": {
                "funded_txo_count": 3,
                "funded_txo_sum": 150000,
                "spent_txo_count": 1,
                "spent_txo_sum": 50000,
                "tx_count": 4
            },
            "mempool_stats": {
                "funded_txo_count": 1,
                "funded_txo_sum": 900,
                "spent_txo_count": 0,
                "spent_txo_sum": 0,
                "tx_count": 1
            }
        }"#;
        let client = ChainClient::new(AddrStatsTransport(json), Network::Testnet4);
        let stats = client.address_stats("tb1qdummy").unwrap();
        assert_eq!(
            stats,
            AddrStats {
                chain_tx_count: 4,
                chain_funded: 150000,
                chain_spent: 50000,
                mempool_tx_count: 1,
                mempool_funded: 900,
                mempool_spent: 0,
            }
        );
    }

    // ---- AnyTransport / CoreRpcTransport (U2: the backend seam) --------

    #[test]
    fn any_transport_picks_esplora_for_non_bitcoind_urls() {
        for base in [
            "https://mempool.space/api",
            "http://127.0.0.1:18797/regtest/api",
            "https://blockstream.info/api",
        ] {
            let t = AnyTransport::new(base, None).unwrap();
            assert!(matches!(t, AnyTransport::Esplora(_)), "{base} must select Esplora");
        }
    }

    #[test]
    fn any_transport_picks_core_for_bitcoind_scheme() {
        let t = AnyTransport::new("bitcoind+http://127.0.0.1:8332", None).unwrap();
        assert!(matches!(t, AnyTransport::Core(_)));
    }

    #[test]
    fn any_transport_esplora_behavior_is_unaffected() {
        // Constructing through AnyTransport must be indistinguishable from
        // constructing HttpTransport directly — same base stored, same
        // pacing decision (loopback exemption untouched).
        let base = "http://127.0.0.1:18797/regtest/api";
        match AnyTransport::new(base, None).unwrap() {
            AnyTransport::Esplora(t) => assert_eq!(t.base, base),
            AnyTransport::Core(_) => panic!("expected Esplora"),
        }
    }

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

    #[test]
    fn node_backend_label_reflects_scheme() {
        assert_eq!(node_backend_label("https://mempool.space/api"), "Esplora");
        assert_eq!(node_backend_label("http://127.0.0.1:18797/regtest/api"), "Esplora");
        assert_eq!(node_backend_label("bitcoind+http://127.0.0.1:8332"), "Bitcoin Core");
    }

    #[test]
    fn address_stats_tolerates_missing_stat_groups() {
        let client = ChainClient::new(AddrStatsTransport("{}"), Network::Testnet4);
        let stats = client.address_stats("tb1qdummy").unwrap();
        assert_eq!(
            stats,
            AddrStats {
                chain_tx_count: 0,
                chain_funded: 0,
                chain_spent: 0,
                mempool_tx_count: 0,
                mempool_funded: 0,
                mempool_spent: 0,
            }
        );
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

    /// The `ChainClient::btc_usd()` layer above the transport must also see
    /// exactly this — an `Err`, not a fabricated `Ok(None)` or `Ok(Some(_))`
    /// — since `src/lib.rs`'s call sites degrade via `if let Ok(usd) = ...`
    /// and silently keep the PREVIOUS cached price on any `Err`. A Core
    /// backend must never look like a successful (if empty) price fetch.
    #[test]
    fn chain_client_btc_usd_surfaces_the_core_no_price_oracle_error() {
        let t = CoreRpcTransport::new("http://127.0.0.1:1", None).unwrap();
        let client = ChainClient::new(t, Network::Regtest);
        let err = client.btc_usd().unwrap_err();
        assert!(matches!(err, Error::Http(_)), "expected Error::Http, got {err:?}");
    }
}
