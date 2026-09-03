// In-process, HEADLESS Slint UI-test harness spike (2026-08-24).
//
// Proves the approach that replaces the flaky coordinate/simtap Mac suite
// (graffito-app-selfpq.sh — see the graffito-mac-ui-key-window memory): the
// `i-slint-backend-testing` ElementHandle API drives the REAL AppWindow with
// NO window, NO key-focus, NO screen coordinates, NO OS event system, and no
// keychain SecurityAgent prompt — the four things that made simtap flaky.
//
// FINDABILITY (init_no_event_loop, synchronous — mirrors the crate's own
// test_conditional): the REAL AppWindow's buttons are locatable by their
// visible text via find_by_accessible_label, once (a) the shared GhostButton
// carries accessible-role/label and (b) the UI is compiled with
// SLINT_EMIT_DEBUG_INFO=1 (element-tree introspection; build.rs gates it, the
// harness sets it). Findability is exactly what the coordinate suite lacked.
//
// The click proof (single_click reaching a handler) lives in
// tests/ui_harness_click.rs — the two backend init fns can each run once per
// process, so they need separate test binaries.

use graffito::{AppWindow, Compose, Screen, Ui};
use i_slint_backend_testing::{ElementHandle, ElementRoot};
use slint::ComponentHandle;

#[test]
fn findability_real_buttons_by_label_headless() {
    // The element-tree introspection these tests need is compiled in only
    // under SLINT_EMIT_DEBUG_INFO=1 (build.rs). Without it the tree is empty,
    // so skip rather than fail a bare `cargo test` — run via:
    //   SLINT_EMIT_DEBUG_INFO=1 cargo test --test ui_harness_spike --test ui_harness_click
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() != Ok("1") {
        eprintln!("SKIP: set SLINT_EMIT_DEBUG_INFO=1 to run the in-process UI harness tests");
        return;
    }
    i_slint_backend_testing::init_no_event_loop();

    let app = AppWindow::new().expect("AppWindow");
    app.global::<Ui>().set_screen(Screen::QuantumKeys); // Settings -> Quantum keys

    let labels: Vec<String> = app
        .root_element()
        .query_descendants()
        .find_all()
        .into_iter()
        .filter_map(|e| e.accessible_label())
        .map(|l| l.to_string())
        .filter(|l| !l.is_empty())
        .collect();
    eprintln!("findable accessible-labels on screen 29: {labels:?}");

    // The capability the coordinate suite lacked entirely: locate the exact
    // button the flaky Mac suite kept missing, by its visible text. (>=1, not
    // ==1: a GhostButton exposes the label on BOTH its root, role=button, and
    // its inner Text — the click proof filters/takes first, which is fine.)
    let found = ElementHandle::find_by_accessible_label(&app, "Copy public key").count();
    assert!(found >= 1, "expected to find 'Copy public key'; found {found}");

    // The quantum-keys level pills + the seed-derived section labels are all
    // reachable the same way — no scroll, no coordinates, no key-focus. These
    // are exactly the screen-29 controls the flaky Mac coordinate suite could
    // not reach reliably.
    for label in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Backup private key…"] {
        assert!(
            ElementHandle::find_by_accessible_label(&app, label).count() >= 1,
            "screen-29 control '{label}' not findable by accessible-label",
        );
    }
}

#[test]
fn findability_compose_security_panel() {
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() != Ok("1") {
        eprintln!("SKIP: set SLINT_EMIT_DEBUG_INFO=1 to run the in-process UI harness tests");
        return;
    }
    i_slint_backend_testing::init_no_event_loop();

    let app = AppWindow::new().expect("AppWindow");
    // Tall window so the whole (scrollable) compose screen lays out — a
    // Flickable clips content beyond its viewport, and the backend excludes
    // zero-geometry/clipped elements from the a11y tree.
    app.window().set_size(slint::LogicalSize::new(430.0, 2400.0));
    // Reproduce the state that reveals the self-pw compose Security panel:
    // a private, notebook-funded self-note with the panel expanded.
    app.global::<Ui>().set_screen(Screen::Compose);
    app.global::<Compose>().set_compose_private(true);
    app.global::<Ui>().set_watch_only(false);
    app.global::<Ui>().set_pay_from("notebook".into());
    app.global::<Compose>().set_pq_expanded(true);

    // The passphrase + quantum-encryption controls the self-pw feature adds
    // must be findable by their visible text — the exact controls the flaky
    // coordinate Mac suite had to reach by pixel.
    for label in ["Security", "Passphrase", "Quantum encryption (ML-KEM)"] {
        assert!(
            ElementHandle::find_by_accessible_label(&app, label).count() >= 1,
            "compose Security control '{label}' not findable by accessible-label",
        );
    }
}
