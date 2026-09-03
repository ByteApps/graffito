use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Error;

use super::core_rpc::CoreRpcTransport;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn node_backend_label_reflects_scheme() {
        assert_eq!(node_backend_label("https://mempool.space/api"), "Esplora");
        assert_eq!(node_backend_label("http://127.0.0.1:18797/regtest/api"), "Esplora");
        assert_eq!(node_backend_label("bitcoind+http://127.0.0.1:8332"), "Bitcoin Core");
    }
}
