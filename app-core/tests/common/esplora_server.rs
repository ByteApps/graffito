//! U1 (`plans/PLAN-graffito-history-scaling.md`) real-socket counterpart of
//! [`super::EsploraFake`]: the in-process fake proves `ChainClient`'s
//! SEMANTICS (and, in `esplora_paths.rs`, `HttpTransport`'s exact request
//! paths) but never actually goes over a socket — every existing test
//! drives `ChainClient<EsploraFake>` directly, so `HttpTransport`/
//! `AnyTransport`'s own HTTP parsing (status codes, `Content-Length`,
//! connection handling) is never exercised end-to-end. `EsploraFakeServer`
//! serves a [`super::Scenario`] over a REAL `std::net::TcpListener`,
//! reusing [`super::EsploraFake`]'s exact routing for every response body
//! (one truth, no second implementation of the esplora shape to drift) —
//! so `esplora_server_smoke.rs` can prove `ChainClient<AnyTransport>`
//! (talking real HTTP/1.1 over loopback) produces the SAME bundle and the
//! SAME request-path sequence `ChainClient<EsploraFake>` does in-process.
//!
//! `scenario` is behind `Arc<Mutex<Scenario>>` (not a bare `&'a Scenario`,
//! which a `'static` server thread couldn't hold anyway) so a test can
//! MUTATE it BETWEEN scans — add a tx, bump the tip — and the very next
//! request sees the new state; that's what the history-scaling flow test's
//! "add a confirmed tx and refresh" / "add a mempool tx, refresh, confirm
//! it, refresh again" steps need.
//!
//! Minimal HTTP/1.1, just enough for `reqwest::blocking::Client`: parse the
//! request line (method + path), read `Content-Length` bytes of body for a
//! POST, answer with a real numeric status line + `Content-Length` +
//! `Connection: close`. No new dependency — same shape as
//! `common::mock_rpc`'s `MockRpcServer`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use app_core::chain::Transport;

use super::{EsploraFake, Scenario};

/// A pause/resume breakpoint gate (see [`EsploraFakeServer::pause_after`]):
/// deliberately NOT a sleep-based artificial delay. A loopback round trip
/// is fast enough that a background scan worker can race through dozens
/// of HTTP pages before a test's own polling thread gets even ONE
/// scheduling turn — under real (not simulated) OS thread scheduling, a
/// FIXED sleep-per-response still leaves that race open whenever the
/// polling thread itself gets starved for longer than the sleep (measured
/// happening in practice under a loaded test run: a 15ms per-response
/// delay still let 17 requests through before the polling thread's first
/// turn). A hard block that only a `resume()` call can lift is immune to
/// scheduling entirely — the walk PHYSICALLY cannot proceed past the
/// paused request no matter how slowly the test thread gets scheduled.
struct PauseGate {
    served: AtomicUsize,
    /// `None` = never pause. `Some(n)` = block the request whose 0-based
    /// index equals `n` (i.e. the (n+1)-th request) until `resume()`.
    pause_at: Mutex<Option<usize>>,
    released: Mutex<bool>,
    cvar: Condvar,
}

/// A running fake-Esplora server. Dropping it does not stop the listener
/// thread — each test starts its own on a fresh OS-assigned port (`bind
/// "127.0.0.1:0"`), so leaking that thread for the rest of the test
/// binary's life is harmless (same convention as `MockRpcServer`).
pub struct EsploraFakeServer {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    gate: Arc<PauseGate>,
}

impl EsploraFakeServer {
    pub fn start(scenario: Arc<Mutex<Scenario>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind esplora fake listener");
        let port = listener.local_addr().expect("local_addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_thread = requests.clone();
        let gate = Arc::new(PauseGate {
            served: AtomicUsize::new(0),
            pause_at: Mutex::new(None),
            released: Mutex::new(true),
            cvar: Condvar::new(),
        });
        let gate_thread = gate.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let scenario = scenario.clone();
                let requests = requests_thread.clone();
                let gate = gate_thread.clone();
                std::thread::spawn(move || handle_conn(stream, scenario, requests, gate));
            }
        });
        EsploraFakeServer { port, requests, gate }
    }

    /// The plain `http://127.0.0.1:<port>` base `AnyTransport::new` (and
    /// `HttpTransport::new`) resolve as a real Esplora backend.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Every request path served since the last call, in order — cleared,
    /// same convention as `EsploraFake::drain_requests`.
    pub fn drain_requests(&self) -> Vec<String> {
        std::mem::take(&mut *self.requests.lock().expect("requests mutex"))
    }

    /// Serve the next `n` requests normally, then BLOCK the (n+1)-th
    /// (0-based index `n`) — and every request after it, since they queue
    /// up behind it on the client's single sequential connection — until
    /// [`Self::resume`] is called. A test uses this to make "exactly N
    /// requests have happened, and no more can happen yet" a fact instead
    /// of a race: trigger the scan, wait (however long it takes) for the
    /// Nth request's effect to land, assert on `drain_requests()`, then
    /// `resume()` to let the rest of the walk proceed.
    pub fn pause_after(&self, n: usize) {
        self.gate.served.store(0, Ordering::SeqCst);
        *self.gate.pause_at.lock().expect("pause_at mutex") = Some(n);
        *self.gate.released.lock().expect("released mutex") = false;
    }

    /// Release a request blocked by [`Self::pause_after`] (a no-op if
    /// nothing is currently paused).
    pub fn resume(&self) {
        *self.gate.released.lock().expect("released mutex") = true;
        self.gate.cvar.notify_all();
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// `route`'s (and `EsploraFake::post_text`'s) error messages are always
/// `"<status>: <text>"` (see `common::route`/`Error::Http` call sites) — so
/// the real HTTP status line can carry the genuine numeric code instead of
/// always answering 200, and the body is just the text after the colon
/// (mirrors real esplora, which never repeats the status code in the body).
fn split_status(msg: &str) -> (u16, String) {
    if let Some((code, rest)) = msg.split_once(':') {
        if let Ok(n) = code.trim().parse::<u16>() {
            return (n, rest.trim().to_string());
        }
    }
    (500, msg.to_string())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    }
}

fn handle_conn(
    mut stream: TcpStream,
    scenario: Arc<Mutex<Scenario>>,
    requests: Arc<Mutex<Vec<String>>>,
    gate: Arc<PauseGate>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 1_000_000 {
            return; // runaway request — bail rather than hang the thread
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.lines();
    let Some(request_line) = lines.next() else { return };
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next().map(str::to_string) else { return };
    let Some(path) = parts.next().map(str::to_string) else { return };
    let content_length: usize = header_text
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[header_end..header_end + content_length]).to_string();

    // The pause/resume breakpoint (see `EsploraFakeServer::pause_after`'s
    // doc comment) lands HERE, before the response is computed/sent — it
    // blocks the CLIENT (whose `get_text`/`post_text` call is waiting on
    // this response), not merely this server thread. `served` is the
    // 0-based index of THIS request among every request this server has
    // ever received; the request is only counted into `requests` (and
    // therefore visible to `drain_requests()`) once fully served.
    let idx = gate.served.fetch_add(1, Ordering::SeqCst);
    if *gate.pause_at.lock().expect("pause_at mutex") == Some(idx) {
        let mut released = gate.released.lock().expect("released mutex");
        while !*released {
            released = gate.cvar.wait(released).expect("cvar wait");
        }
    }

    let result = {
        let sc = scenario.lock().expect("scenario mutex");
        let fake = EsploraFake::new(&sc);
        if method == "POST" { fake.post_text(&path, body) } else { fake.get_text(&path) }
    };

    let (status, resp_body) = match result {
        Ok(text) => (200u16, text),
        Err(app_core::Error::Http(msg)) => split_status(&msg),
        Err(e) => (500u16, format!("{e}")),
    };
    let body_bytes = resp_body.into_bytes();
    let response_text = format!(
        "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body_bytes.len()
    );
    let _ = stream.write_all(response_text.as_bytes());
    let _ = stream.write_all(&body_bytes);
    let _ = stream.flush();
    requests.lock().expect("requests mutex").push(path.clone());
}
