//! A local, forwarding, per-METHOD-counting JSON-RPC proxy — U5's answer to
//! "measure RPC call counts, not wall-clock time" (`regtest-hides-cost-bugs`
//! memory: a per-operation genesis rescan shipped in build 52 because a
//! 118-block regtest made it free; the fix was to assert on call counts,
//! which are chain-length independent, not elapsed time, which isn't).
//!
//! Sits BETWEEN the transport-under-test (`CoreRpcTransport`, pointed at
//! [`CountingProxy::base_url`] instead of the real node directly) and the
//! shared node: every request is parsed just enough to read the JSON-RPC
//! `method` name, tallied, and then forwarded VERBATIM (same body, same
//! path, real upstream credentials attached here — never by the caller) to
//! the real node; the upstream's response is relayed back unchanged. This
//! measures exactly what the coordinator asked for — "how many RPC calls
//! did the code under test issue" — as a plain count, independent of chain
//! height, node-to-node latency, or how long any individual call took.
//!
//! Deliberately does NOT wrap `Node`'s own raw setup calls (fixture mining,
//! throwaway-wallet sends in `core_rpc_conformance.rs`) — those go straight
//! to the real node as before. Only the "official" transport(s) actually
//! under test are pointed through this proxy, so the count reflects
//! production code's own RPC usage, not this suite's fixture-building
//! overhead.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct CountingProxy {
    port: u16,
    counts: Arc<Mutex<HashMap<String, u32>>>,
}

impl CountingProxy {
    /// `upstream_*` is the REAL shared node this proxy forwards to — never
    /// printed, never logged, held only in the forwarding thread's closure.
    pub fn start(upstream_host: String, upstream_port: u16, upstream_user: String, upstream_pass: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting-proxy listener");
        let port = listener.local_addr().expect("local_addr").port();
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let counts_thread = counts.clone();
        std::thread::spawn(move || {
            // A generous timeout — this proxy sits in front of the SAME
            // node whose own descriptor-rescan RPCs can legitimately run
            // for minutes (`CoreRpcTransport::RESCAN_TIMEOUT`); the proxy
            // must never time out before the thing it's forwarding to
            // would.
            let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(650)).build().unwrap();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let counts = counts_thread.clone();
                let client = client.clone();
                let (host, port, user, pass) =
                    (upstream_host.clone(), upstream_port, upstream_user.clone(), upstream_pass.clone());
                std::thread::spawn(move || handle_conn(stream, counts, client, host, port, user, pass));
            }
        });
        CountingProxy { port, counts }
    }

    /// The creds-less `bitcoind+http://127.0.0.1:<port>` base a transport
    /// under test should be pointed at instead of the real node — this
    /// proxy doesn't check incoming auth (it isn't the thing being tested),
    /// only what it forwards upstream carries the real credentials.
    pub fn base_url(&self) -> String {
        format!("bitcoind+http://127.0.0.1:{}", self.port)
    }

    pub fn snapshot(&self) -> HashMap<String, u32> {
        self.counts.lock().unwrap().clone()
    }

    pub fn total(&self) -> u32 {
        self.counts.lock().unwrap().values().sum()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn handle_conn(
    mut stream: TcpStream,
    counts: Arc<Mutex<HashMap<String, u32>>>,
    client: reqwest::blocking::Client,
    upstream_host: String,
    upstream_port: u16,
    upstream_user: String,
    upstream_pass: String,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
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
            return;
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.lines();
    // Request line: "POST /wallet/chain-notes-watch HTTP/1.1" — the path is
    // what tells the real node which wallet (or the node-level endpoint)
    // this call targets; must be preserved verbatim on forward.
    let path = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
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
    let body = buf[header_end..header_end + content_length].to_vec();

    if let Ok(req) = serde_json::from_slice::<serde_json::Value>(&body) {
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("<unparseable>").to_string();
        *counts.lock().unwrap().entry(method).or_insert(0) += 1;
    }

    let upstream_url = format!("http://{upstream_host}:{upstream_port}{path}");
    let resp = client.post(&upstream_url).basic_auth(&upstream_user, Some(&upstream_pass)).body(body).send();

    let (status_line, resp_body): (&str, Vec<u8>) = match resp {
        Ok(r) => {
            let ok = r.status().is_success() || r.status().as_u16() == 500; // bitcoind's own error convention
            let bytes = r.bytes().map(|b| b.to_vec()).unwrap_or_default();
            (if ok { "HTTP/1.1 200 OK" } else { "HTTP/1.1 502 Bad Gateway" }, bytes)
        }
        Err(e) => ("HTTP/1.1 502 Bad Gateway", format!("{{\"result\":null,\"error\":{{\"code\":-32000,\"message\":\"proxy forward failed: {e}\"}}}}").into_bytes()),
    };
    let response_text =
        format!("{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", resp_body.len());
    let _ = stream.write_all(response_text.as_bytes());
    let _ = stream.write_all(&resp_body);
    let _ = stream.flush();
}
