//! Debug-only, macOS-only loopback UI event injection channel.
//!
//! Lets a shell test harness drive the app over TCP instead of seizing the
//! real keyboard/mouse. `CGEventPostToPid` (per-process posting) was found
//! (2026-09-14) to be silently dropped by this app even when frontmost, so
//! the fix is in-process: dispatch synthetic `slint::platform::WindowEvent`s
//! straight into the running `AppWindow` on the UI thread. Same idea as the
//! KeyOS simulator's `siminject` and the iPhone cross-device tap server.
//!
//! Activated ONLY when env `GRAFFITO_INJECT_PORT=<u16>` is set. This whole
//! module is compiled out of release builds — see the `#[cfg(...)]` on its
//! `mod inject;` declaration in lib.rs.
//!
//! Wire protocol: line-delimited JSON on `127.0.0.1:<port>`, one request
//! object per line answered with one JSON reply per line. Many sequential
//! connections and many requests per connection are supported (the harness
//! opens a fresh connection per op via bash `/dev/tcp`). Coordinates are
//! LOGICAL points relative to the Slint window content area.
//!
//! Every op is dispatched on the UI thread via `slint::invoke_from_event_loop`
//! against a `Weak<AppWindow>`, and answered synchronously through a
//! channel — see `on_ui`.

use crate::AppWindow;
use serde_json::{json, Value};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, SharedString, Weak};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Install a winit backend that does NOT activate-on-launch, so driving the
/// app over the socket never steals focus from whatever was frontmost. Must
/// run BEFORE `AppWindow::new()`. A no-op unless `GRAFFITO_INJECT_PORT` is
/// set — every other launch keeps today's default platform untouched.
pub fn maybe_install_platform() {
    if std::env::var("GRAFFITO_INJECT_PORT").is_err() {
        return;
    }
    use winit::platform::macos::EventLoopBuilderExtMacOS;
    let mut event_loop_builder: i_slint_backend_winit::EventLoopBuilder =
        winit::event_loop::EventLoop::<i_slint_backend_winit::SlintEvent>::with_user_event();
    event_loop_builder.with_activate_ignoring_other_apps(false);
    let backend = match i_slint_backend_winit::Backend::builder()
        .with_event_loop_builder(event_loop_builder)
        .build()
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cb: inject backend build failed err={e}");
            return;
        }
    };
    if let Err(e) = slint::platform::set_platform(Box::new(backend)) {
        eprintln!("cb: inject set_platform failed err={e}");
    }
}

/// Start the loopback listener if `GRAFFITO_INJECT_PORT` is set. Must run
/// AFTER `AppWindow::new()` — it needs a `Weak` handle to reach the window
/// from the listener thread.
pub fn maybe_start_server(window: &AppWindow) {
    let Ok(port_str) = std::env::var("GRAFFITO_INJECT_PORT") else { return };
    let Ok(port) = port_str.parse::<u16>() else {
        eprintln!("cb: inject bad port={port_str}");
        return;
    };
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cb: inject bind failed err={e}");
            return;
        }
    };
    let weak = window.as_weak();
    eprintln!("cb: inject listening port={port}");
    std::thread::spawn(move || serve(listener, weak));
}

fn serve(listener: TcpListener, weak: Weak<AppWindow>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let weak = weak.clone();
        std::thread::spawn(move || handle_conn(stream, weak));
    }
}

fn handle_conn(stream: TcpStream, weak: Weak<AppWindow>) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle_op(&req, &weak),
            Err(e) => json!({"ok": false, "err": format!("bad json: {e}")}),
        };
        let mut out = reply.to_string();
        out.push('\n');
        if writer.write_all(out.as_bytes()).is_err() {
            break;
        }
    }
}

/// Run `f` on the UI thread against the upgraded window and block the
/// calling (listener) thread until it completes, returning the result.
/// `Err` covers both "the event loop is gone" and "the window is gone".
fn on_ui<R, F>(weak: &Weak<AppWindow>, f: F) -> Result<R, String>
where
    F: FnOnce(&AppWindow) -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let weak2 = weak.clone();
    if slint::invoke_from_event_loop(move || {
        let result = weak2.upgrade().map(|w| f(&w));
        let _ = tx.send(result);
    })
    .is_err()
    {
        return Err("event loop gone".into());
    }
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err("window gone".into()),
        Err(_) => Err("ui thread timeout".into()),
    }
}

fn handle_op(req: &Value, weak: &Weak<AppWindow>) -> Value {
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    let result = match op {
        "info" => on_ui(weak, |w| {
            let win = w.window();
            let scale = win.scale_factor();
            let logical = win.size().to_logical(scale);
            json!({"ok": true, "w": logical.width, "h": logical.height, "scale": scale})
        }),
        "tap" => match (num(req, "x"), num(req, "y")) {
            (Some(x), Some(y)) => tap(weak, x, y).map(|()| json!({"ok": true})),
            _ => return json!({"ok": false, "err": "missing x/y"}),
        },
        "type" => match req.get("text").and_then(Value::as_str) {
            Some(text) => press_release(weak, text.into()).map(|()| json!({"ok": true})),
            None => return json!({"ok": false, "err": "missing text"}),
        },
        "key" => match req.get("key").and_then(Value::as_str) {
            Some(key) => send_key(weak, key).map(|()| json!({"ok": true})),
            None => return json!({"ok": false, "err": "missing key"}),
        },
        "scroll" => match (num(req, "x"), num(req, "y"), num(req, "dy")) {
            (Some(x), Some(y), Some(dy)) => {
                // Harness semantics: dy>0 means the content scrolls UP
                // (reveals what's below), i.e. a wheel scrolled down —
                // so the WindowEvent's delta_y is the negation of dy.
                on_ui(weak, move |w| {
                    w.window().dispatch_event(WindowEvent::PointerScrolled {
                        position: LogicalPosition::new(x, y),
                        delta_x: 0.0,
                        delta_y: -dy,
                    });
                })
                .map(|()| json!({"ok": true}))
            }
            _ => return json!({"ok": false, "err": "missing x/y/dy"}),
        },
        other => return json!({"ok": false, "err": format!("unknown op {other}")}),
    };
    match result {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "err": e}),
    }
}

fn num(req: &Value, key: &str) -> Option<f32> {
    req.get(key).and_then(Value::as_f64).map(|v| v as f32)
}

/// PointerMoved + PointerPressed in one UI-thread invocation, a real sleep
/// on THIS (listener) thread, then PointerReleased in a second invocation —
/// two separate dispatches ~40ms apart so Slint's click detection (which
/// times the press/release gap) sees a realistic tap.
fn tap(weak: &Weak<AppWindow>, x: f32, y: f32) -> Result<(), String> {
    on_ui(weak, move |w| {
        let win = w.window();
        win.dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(x, y) });
        win.dispatch_event(WindowEvent::PointerPressed {
            position: LogicalPosition::new(x, y),
            button: PointerEventButton::Left,
        });
    })?;
    std::thread::sleep(Duration::from_millis(40));
    on_ui(weak, move |w| {
        w.window().dispatch_event(WindowEvent::PointerReleased {
            position: LogicalPosition::new(x, y),
            button: PointerEventButton::Left,
        });
    })
}

fn send_key(weak: &Weak<AppWindow>, key: &str) -> Result<(), String> {
    match key {
        "return" => press_release(weak, Key::Return.into()),
        "backspace" => press_release(weak, Key::Backspace.into()),
        // Slint's `InternalKeyEvent::shortcut()` checks the `control`
        // modifier only (not `meta`), regardless of OS — the Cmd<->Ctrl
        // swap that gives macOS users Cmd-for-shortcuts happens in
        // i-slint-backend-winit's translation of REAL winit key events,
        // a layer this synthetic dispatch bypasses entirely. So the chord
        // that actually triggers TextInput::select_all here is
        // Key::Control, not Key::Meta — verified empirically (see the
        // report this shipped with).
        "select-all" => on_ui(weak, |w| {
            let win = w.window();
            let ctrl: SharedString = Key::Control.into();
            let a: SharedString = "a".into();
            win.dispatch_event(WindowEvent::KeyPressed { text: ctrl.clone() });
            win.dispatch_event(WindowEvent::KeyPressed { text: a.clone() });
            win.dispatch_event(WindowEvent::KeyReleased { text: a });
            win.dispatch_event(WindowEvent::KeyReleased { text: ctrl });
        }),
        other => Err(format!("unknown key {other}")),
    }
}

/// One KeyPressed + KeyReleased carrying the WHOLE string. Slint's
/// `TextInput` inserts `event.key_event.text` with a single
/// `String::insert_str`, so multi-char (and multi-line, embedded `\n`)
/// text lands in one shot — no per-character fallback needed in practice
/// (verified; see the report this shipped with). `\n` is only ever
/// special-cased when it is the ENTIRE text of a single-line field's key
/// event, so embedded newlines in a longer string insert literally.
fn press_release(weak: &Weak<AppWindow>, text: SharedString) -> Result<(), String> {
    on_ui(weak, move |w| {
        let win = w.window();
        win.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        win.dispatch_event(WindowEvent::KeyReleased { text });
    })
}
