//! A minimal, in-process, LOCAL-ONLY bitcoind-JSON-RPC-shaped HTTP stub —
//! NOT bitcoind, NOT the shared node (`PLAN-one-regtest-node.md`). Built for
//! U5's node-CONFIGURATION-dependent tests in `../core_rpc_conformance.rs`
//! (pruned reporting, missing-txindex reporting, the NotFound/Unknown
//! decision table, and the ranged-import birthday timestamp): what those
//! tests actually verify is how `CoreRpcTransport` INTERPRETS RPC
//! responses, not anything that needs a differently-configured real node.
//! The shared, persistent regtest node this suite otherwise talks to is
//! permanently unpruned, always runs `txindex=1`, and isn't ours to
//! reconfigure or `setmocktime` on — so those four cases are driven here
//! instead, against controlled, table-driven synthetic response bodies.
//!
//! One canned [`MockResponse`] is scripted PER METHOD NAME — every test's
//! scenario is static (it never needs a different answer to the SAME
//! method across calls within one test) — and every `(method, params)`
//! pair actually received is recorded, so a test can also assert on WHAT
//! WAS SENT (e.g. the timestamp on an `importdescriptors` call), not just
//! what came back.
//!
//! No new dependency: this is `std::net::TcpListener` speaking just enough
//! HTTP/1.1 to satisfy `reqwest::blocking::Client` (parse headers, read
//! `Content-Length` bytes of body, always answer `200 OK` with a JSON-RPC
//! envelope and `Connection: close` — `CoreRpcTransport::call_timeout`
//! parses the JSON `error`/`result` fields first regardless of HTTP status,
//! so there's no need to mimic bitcoind's real 500-on-error convention).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub enum MockResponse {
    Ok(serde_json::Value),
    Err { code: i64, message: String },
}

#[derive(Default)]
struct MockState {
    responses: HashMap<String, MockResponse>,
    default: Option<MockResponse>,
    calls: Vec<(String, serde_json::Value)>,
}

/// A running mock server. Dropping it does not stop the listener thread —
/// each test starts its own on a fresh OS-assigned port (`bind
/// "127.0.0.1:0"`), so leaking that thread for the rest of the test
/// binary's life is harmless and far simpler than plumbing a shutdown
/// signal through a blocking `accept()` loop.
pub struct MockRpcServer {
    port: u16,
    state: Arc<Mutex<MockState>>,
}

impl MockRpcServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rpc listener");
        let port = listener.local_addr().expect("local_addr").port();
        let state = Arc::new(Mutex::new(MockState::default()));
        let state_thread = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = state_thread.clone();
                std::thread::spawn(move || handle_conn(stream, state));
            }
        });
        MockRpcServer { port, state }
    }

    /// Script the response for one RPC method name. Later calls for a
    /// method already set overwrite the earlier scripting.
    pub fn set(&self, method: &str, response: MockResponse) {
        self.state.lock().unwrap().responses.insert(method.to_string(), response);
    }

    /// Response for any method NOT explicitly `set` — defaults to a
    /// "method not found"-shaped error (`-32601`, mirroring bitcoind's own
    /// code for a genuinely unknown method) so a test that forgets to
    /// script something it turns out to need fails loudly and specifically,
    /// rather than silently returning `null`.
    pub fn set_default(&self, response: MockResponse) {
        self.state.lock().unwrap().default = Some(response);
    }

    /// Every `params` value received for `method`, in call order — the
    /// mechanism-proving half of a test (e.g. "was the birthday timestamp
    /// we asked for actually the one SENT on the wire", not just what the
    /// canned response claims back).
    pub fn calls_for(&self, method: &str) -> Vec<serde_json::Value> {
        self.state.lock().unwrap().calls.iter().filter(|(m, _)| m == method).map(|(_, p)| p.clone()).collect()
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.calls_for(method).len()
    }

    /// The `bitcoind+http://user:pass@127.0.0.1:<port>` base
    /// `AnyTransport::new` expects. The credentials are throwaway literals
    /// (`mockuser`/`mockpass`) baked into this mock — never anything real,
    /// so printing this string is harmless (unlike
    /// `Node::core_rpc_url()` in `core_rpc_conformance.rs`, which embeds the
    /// shared node's REAL credentials and must never be printed).
    pub fn base_url(&self) -> String {
        format!("bitcoind+http://mockuser:mockpass@127.0.0.1:{}", self.port)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn handle_conn(mut stream: TcpStream, state: Arc<Mutex<MockState>>) {
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
    let header_text = String::from_utf8_lossy(&buf[..header_end]);
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
    let body = &buf[header_end..header_end + content_length];
    let Ok(req) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);

    let response = {
        let mut s = state.lock().unwrap();
        s.calls.push((method.clone(), params));
        s.responses
            .get(&method)
            .cloned()
            .or_else(|| s.default.clone())
            .unwrap_or(MockResponse::Err { code: -32601, message: format!("mock: no scripted response for {method}") })
    };

    let body_json = match response {
        MockResponse::Ok(v) => serde_json::json!({"result": v, "error": null, "id": id}),
        MockResponse::Err { code, message } => {
            serde_json::json!({"result": null, "error": {"code": code, "message": message}, "id": id})
        }
    };
    let body_bytes = serde_json::to_vec(&body_json).unwrap();
    let response_text = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    let _ = stream.write_all(response_text.as_bytes());
    let _ = stream.write_all(&body_bytes);
    let _ = stream.flush();
}
