//! Headless measurement of the Settings screen's tap points.
//!
//! The five coordinate-driven shell suites (ui-automation/tests/graffito*.sh)
//! carry hand-measured Y constants for the "Bitcoin node" card. Those went
//! stale when the card moved up to sit under "Network" (2026-09-10), and the
//! old way to re-measure them was to drive the real Mac window with simtap —
//! flaky (key-window trap), and it seizes the screen for however long it takes.
//!
//! This measures the SAME layout in-process with no window, no key focus and
//! no OS events, printing app-space logical points — the exact coordinate
//! space `tap X Y` uses. Run:
//!   SLINT_EMIT_DEBUG_INFO=1 cargo test --test ui_measure_settings -- --nocapture
use graffito::{AppWindow, Screen, Ui};
use i_slint_backend_testing::ElementRoot;
use slint::ComponentHandle;

#[test]
fn measure_settings_tap_points() {
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() != Ok("1") {
        eprintln!("SKIP: needs SLINT_EMIT_DEBUG_INFO=1");
        return;
    }
    i_slint_backend_testing::init_no_event_loop();
    let app = AppWindow::new().expect("AppWindow");
    // The suites drive a 480x812pt window; measure in that same space.
    // Two shapes: the Mac suites' 480x812pt window, and the phone's own dp
    // size with apple-platform FALSE (no iCloud card, so everything below it
    // sits higher — this is why the Android suites can never reuse the Mac
    // numbers). Size/platform come from env so one test serves both.
    let (w, h) = match std::env::var("MEASURE_SHAPE").as_deref() {
        Ok("android") => (411.0, 915.0),
        // iPhone logical size implied by the cross-device suite's own x=201
        // centre taps (402pt wide, e.g. iPhone 16/17 Pro).
        Ok("ios") => (402.0, 874.0),
        _ => (480.0, 812.0),
    };
    app.window().set_size(slint::LogicalSize::new(w, h));
    app.global::<Ui>().set_apple_platform(std::env::var("MEASURE_SHAPE").as_deref() != Ok("android"));
    app.global::<Ui>().set_screen(Screen::Settings);
    // The node card only reveals its credential rows once "Bitcoin Core" is
    // the row being BROWSED in the dropdown — `node-core-row-selected` is an
    // out-property derived from `Ui.node-index`, so drive it the same way the
    // app does. Core is the third-from-last row.
    let opts: Vec<slint::SharedString> =
        ["mempool.space", "blockstream", "Bitcoin Core", "Electrum server", "Custom…"]
            .iter()
            .map(|s| (*s).into())
            .collect();
    let n = opts.len() as i32;
    app.global::<Ui>().set_node_options(slint::ModelRc::new(slint::VecModel::from(opts)));
    app.global::<Ui>().set_node_index(n - 3);
    slint::platform::update_timers_and_animations();

    for (idx, name) in [(n - 3, "Bitcoin Core"), (n - 2, "Electrum server"), (n - 1, "Custom…")] {
        app.global::<Ui>().set_node_index(idx);
        slint::platform::update_timers_and_animations();
        eprintln!("\n--- node dropdown row browsed: {name} (index {idx}) ---");
        for e in app.root_element().query_descendants().match_inherits("Dropdown").find_all() {
            let p = e.absolute_position();
            let sz = e.size();
            eprintln!("  Dropdown   tap y={:.0}  (top {:.0}, h {:.0})", p.y + sz.height / 2.0, p.y, sz.height);
        }
        for (i, e) in app.root_element().query_descendants().match_inherits("EditField").find_all().into_iter().enumerate() {
            let p = e.absolute_position();
            let sz = e.size();
            eprintln!("  EditField[{i}] tap y={:.0} x={:.0}", p.y + sz.height / 2.0, p.x + sz.width / 2.0);
        }
    }
}
