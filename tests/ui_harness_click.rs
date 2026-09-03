// Click proof for the in-process UI harness (companion to
// tests/ui_harness_spike.rs's findability proof; separate binary because the
// event-loop init fn can run only once per process).
//
// single_click() on a button located by accessible-label fires its `clicked`
// handler — verified via a test-provided closure. In-process, headless, no
// window/focus/coordinates. This is the event-loop + spawn_local pattern from
// the i-slint-backend-testing crate's own click.rs.

use std::cell::Cell;
use std::rc::Rc;

use graffito::{AppWindow, Screen};
use i_slint_backend_testing::ElementHandle;
use slint::platform::PointerEventButton;

#[test]
fn single_click_reaches_the_handler_headless() {
    // The element-tree introspection these tests need is compiled in only
    // under SLINT_EMIT_DEBUG_INFO=1 (build.rs). Without it the tree is empty,
    // so skip rather than fail a bare `cargo test` — run via:
    //   SLINT_EMIT_DEBUG_INFO=1 cargo test --test ui_harness_spike --test ui_harness_click
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() != Ok("1") {
        eprintln!("SKIP: set SLINT_EMIT_DEBUG_INFO=1 to run the in-process UI harness tests");
        return;
    }
    i_slint_backend_testing::init_integration_test_with_system_time();

    slint::spawn_local(async move {
        let app = AppWindow::new().expect("AppWindow");
        app.set_screen(Screen::QuantumKeys);

        let fired = Rc::new(Cell::new(false));
        {
            let fired = fired.clone();
            // "Copy public key" -> pq-copy-public() (unconditional GhostButton
            // on screen 29; "Save public key…" is desktop-gated and off here).
            app.on_pq_copy_public(move || fired.set(true));
        }

        let button = ElementHandle::find_by_accessible_label(&app, "Copy public key")
            .next()
            .expect("find 'Copy public key' by accessible-label");

        assert!(!fired.get());
        button.single_click(PointerEventButton::Left).await;
        assert!(fired.get(), "single_click did not reach the clicked handler");

        slint::quit_event_loop().unwrap();
    })
    .unwrap();

    slint::run_event_loop().unwrap();
}
