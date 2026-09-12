//! Headless positions of the header icon buttons, for the shell suites.
use graffito::{AppWindow, Screen, Ui};
use i_slint_backend_testing::ElementRoot;
use slint::ComponentHandle;

#[test]
fn measure_header_icons() {
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() != Ok("1") { eprintln!("SKIP"); return; }
    i_slint_backend_testing::init_no_event_loop();
    let app = AppWindow::new().expect("AppWindow");
    app.window().set_size(slint::LogicalSize::new(480.0, 812.0));
    for (screen, name) in [(Screen::Notebooks, "notebooks"), (Screen::Home, "home")] {
        app.global::<Ui>().set_screen(screen);
        slint::platform::update_timers_and_animations();
        eprintln!("--- {name} ---");
        for (i, e) in app.root_element().query_descendants().match_inherits("SvgIconButton").find_all().into_iter().enumerate() {
            let p = e.absolute_position(); let s = e.size();
            if p.y < 140.0 {
                eprintln!("  SvgIconButton[{i}] centre x={:.0} y={:.0}", p.x + s.width/2.0, p.y + s.height/2.0);
            }
        }
        for (i, e) in app.root_element().query_descendants().match_inherits("SyncButton").find_all().into_iter().enumerate() {
            let p = e.absolute_position(); let s = e.size();
            eprintln!("  SyncButton[{i}]    centre x={:.0} y={:.0}", p.x + s.width/2.0, p.y + s.height/2.0);
        }
    }
}
