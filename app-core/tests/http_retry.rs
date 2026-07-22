//! `HttpTransport`'s 429 retry-with-backoff loop lives INSIDE
//! `get_text`/`post_text` (`app-core/src/chain.rs`) — a canned `Transport`
//! fake (as `tests/chain.rs` uses) would bypass that loop entirely, so this
//! drives a REAL `HttpTransport` against a REAL local HTTP server. The
//! server is a bare `std::net::TcpListener` + hand-written HTTP/1.1
//! responses (status line + headers + body over a raw `TcpStream`) — no
//! extra dependencies needed. `127.0.0.1` is loopback, so `HttpTransport`'s
//! politeness pacer is exempt (see `chain::is_loopback_base`) and these
//! tests stay fast; `Retry-After: 0` keeps the retry delay itself at ~0s
//! too, so no test-added sleeps are needed.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use app_core::chain::{HttpTransport, Transport};
use app_core::Error;

/// Reads (and discards) one HTTP request's request-line + headers off
/// `stream`, stopping at the blank line that ends the header block. We
/// never need the request itself — the server's behavior here is
/// scripted by call order, not by inspecting the request.
fn drain_request(stream: &TcpStream) {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read request line");
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
}

/// Writes a minimal, correct HTTP/1.1 response: status line, `Content-Length`
/// + `Connection: close` (so the client opens a fresh TCP connection for its
/// next attempt — keeps the server side of this test a plain one-request-
/// per-accept loop) + any extra headers, then the body.
fn write_response(mut stream: &TcpStream, status_line: &str, extra_headers: &[(&str, String)], body: &str) {
    let mut resp = format!("{status_line}\r\n");
    resp.push_str(&format!("Content-Length: {}\r\n", body.len()));
    resp.push_str("Connection: close\r\n");
    for (name, value) in extra_headers {
        resp.push_str(&format!("{name}: {value}\r\n"));
    }
    resp.push_str("\r\n");
    resp.push_str(body);
    stream.write_all(resp.as_bytes()).expect("write response");
    stream.flush().ok();
}

/// First request answers 429 (with `Retry-After: 0`), the retry answers
/// 200 with a JSON body — proves `get_text` retries a clean 429 and
/// surfaces the eventual success, and that the server actually saw both
/// requests (i.e. the retry really happened, not just an immediate error).
#[test]
fn retries_a_429_and_returns_the_eventual_200() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let request_count = Arc::new(AtomicUsize::new(0));

    let server_count = request_count.clone();
    let server = std::thread::spawn(move || {
        for i in 0..2u32 {
            let (stream, _) = listener.accept().expect("accept connection");
            server_count.fetch_add(1, Ordering::SeqCst);
            drain_request(&stream);
            if i == 0 {
                write_response(
                    &stream,
                    "HTTP/1.1 429 Too Many Requests",
                    &[("Retry-After", "0".to_string())],
                    "429 slow down",
                );
            } else {
                write_response(&stream, "HTTP/1.1 200 OK", &[], "[\"ok\"]");
            }
        }
    });

    let transport = HttpTransport::new(format!("http://127.0.0.1:{port}"));
    let result = transport.get_text("/anything");

    server.join().expect("server thread must not panic");

    assert_eq!(result, Ok("[\"ok\"]".to_string()), "the retry must surface the eventual 200 body");
    assert_eq!(
        request_count.load(Ordering::SeqCst),
        2,
        "the server must have observed exactly the initial request plus one retry"
    );
}

/// The server 429s EVERY request — `get_text` must exhaust its retry cap
/// (3 retries, so 4 requests total: the initial attempt plus 3) and return
/// an `Error::Http` whose message starts with the status-first "429:"
/// format (the invariant `Error::is_rate_limited()` and lib.rs's
/// `friendly_net_err` anchor on — asserted directly here, not just via
/// `is_rate_limited()`, so a regression in `trim_error_body`'s format is
/// caught even if `is_rate_limited()`'s own matching logic changes too).
#[test]
fn exhausts_retries_on_persistent_429_and_reports_rate_limited() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local addr").port();
    let request_count = Arc::new(AtomicUsize::new(0));

    let server_count = request_count.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..4u32 {
            let (stream, _) = listener.accept().expect("accept connection");
            server_count.fetch_add(1, Ordering::SeqCst);
            drain_request(&stream);
            write_response(
                &stream,
                "HTTP/1.1 429 Too Many Requests",
                &[("Retry-After", "0".to_string())],
                "429 slow down",
            );
        }
    });

    let transport = HttpTransport::new(format!("http://127.0.0.1:{port}"));
    let result = transport.get_text("/anything");

    server.join().expect("server thread must not panic");

    let err = result.expect_err("a persistently-429ing server must surface an error, not Ok");
    assert!(err.is_rate_limited(), "an exhausted-retry 429 must report is_rate_limited() == true");
    match &err {
        Error::Http(msg) => {
            assert!(msg.starts_with("429:"), "Error::Http message must be status-first ('429: ...'), got: {msg}")
        }
        other => panic!("expected Error::Http, got {other:?}"),
    }
    assert_eq!(
        request_count.load(Ordering::SeqCst),
        4,
        "attempt goes 0 -> 3 (three retries) behind the initial request: 4 requests total"
    );
}
