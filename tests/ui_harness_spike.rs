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

// Superseded 2026-09-07 by `findability_compose_status_strip_and_sheets`
// below (PLAN-graffito-compose-simplify.md): the "Security" collapsible
// this test drove no longer exists — it split into the status-strip pills,
// the gear card, and the passphrase/quantum per-note sheets. Renamed
// (not just edited) so a `findability_compose_security_panel` grep
// anywhere in the harness re-measure notes turns up this pointer.
#[test]
fn findability_compose_status_strip_and_sheets() {
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
    // A private, directed, notebook-funded compose — every status pill
    // applies (PLAN-graffito-compose-simplify.md: "Gift and PQ only on
    // directed notes"). No `State`/Rust handlers are wired in this raw
    // AppWindow spike, so the Rust-computed pill labels sit at their
    // literal `globals.slint` defaults ("Private", "1 sat/vB", "Gift 330",
    // "Notebook", "Passphrase", "PQ off") — exactly what a freshly opened
    // compose screen would show before any refresh runs. The fee pill's
    // "1 sat/vB" (2026-09-07 follow-up 4, superseding the tier-name "normal"
    // this test asserted until then) is the EFFECTIVE RATE, never the tier
    // name alone — see `format_rate_sat_vb` and the real-State assertions
    // in `ui_flow_compose_defaults.rs` for the tier/rate/cost combinations
    // this static spike can't exercise (no Rust handlers are wired here).
    app.global::<Ui>().set_screen(Screen::Compose);
    app.global::<Ui>().set_watch_only(false);
    app.global::<Ui>().set_directed(true);
    app.global::<Ui>().set_pay_from("notebook".into());
    app.global::<Ui>().set_fund_external(false);
    app.global::<Compose>().set_pill_quantum_tappable(true);

    // The gear icon (top-right, Format C) — the ONE new always-visible
    // findable entry point into every per-note setting.
    assert!(
        ElementHandle::find_by_accessible_label(&app, "Compose settings").count() >= 1,
        "the compose gear icon must be findable by accessible-label",
    );

    // The status-strip pills — each one's accessible-label is its CURRENT
    // text (`StatusPill.text`), since the pill IS the value, not a fixed
    // caption; a suite drives these by whatever `refresh_compose_pills`
    // last set, so this spike only proves the mechanism at its defaults.
    for label in ["Private", "1 sat/vB", "Gift 330", "Notebook", "Passphrase", "PQ off"] {
        assert!(
            ElementHandle::find_by_accessible_label(&app, label).count() >= 1,
            "compose status pill '{label}' not findable by accessible-label",
        );
    }

    // The gear card's rows (Format C, `MenuValueRow`) — findable by their
    // fixed LABEL text regardless of the current value.
    app.global::<Compose>().set_card_open(true);
    for label in [
        "New notes",
        "Fee",
        "Gift to recipients",
        "Pay from",
        "Change",
        "Passphrase",
        "Quantum encryption",
        "Edit compose defaults…",
    ] {
        assert!(
            ElementHandle::find_by_accessible_label(&app, label).count() >= 1,
            "gear card row '{label}' not findable by accessible-label",
        );
    }
    app.global::<Compose>().set_card_open(false);

    // The passphrase and quantum per-note sheets — same controls the old
    // "Security" collapsible held, now reached one at a time via
    // `Compose.sheet-kind` instead of a shared expand/collapse.
    app.global::<Compose>().set_sheet_kind("passphrase".into());
    assert!(
        ElementHandle::find_by_accessible_label(&app, "Passphrase").count() >= 1,
        "the passphrase sheet's enable switch must be findable",
    );
    app.global::<Compose>().set_sheet_kind("quantum".into());
    assert!(
        ElementHandle::find_by_accessible_label(&app, "Quantum encryption (ML-KEM)").count() >= 1,
        "the quantum sheet's ML-KEM switch must be findable",
    );
}
