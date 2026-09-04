// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: cancel-regression, universal confirm screen.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "cancel regression: back from confirm
// screen leaves zero trace" + "cancel regression: compose reusable after
// cancel, broadcasts normally" legs (ui-automation/tests/graffito-app.sh) —
// minus the actual broadcast, which is network (see this file's own note
// below). Drives the real `on_compose_send` (Stage A: pure build+sign, no
// store mutation — see app-core/src/compose.rs's "paranoid cancel-leaves-
// zero-trace seam" doc) and `on_confirm_cancel` (the header back-chevron's
// handler) headless, same pattern as ui_flow_selfpq_passphrase.rs.
//
// Network: same gate as every other U10/U8 flow test — a bogus `node_urls`
// entry that's never dialed satisfies `on_compose_send`'s `base_url().
// is_none()` check, and a fresh `fees_fetched_at` short-circuits
// `refresh_fees_price`'s real HTTP call. The Mac leg's second half re-signs
// and taps Broadcast; that tap is `on_confirm_broadcast`, which — for a
// Compose payload — synchronously records the note then spawns a REAL
// broadcast thread against the configured node. This test stops at
// "Sign again reaches confirm again" (the U10 brief's explicit boundary)
// and never calls `on_confirm_broadcast`.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn funded_stub(tag: &str) -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "bb".repeat(32),
        vout: 0,
        value: 100_000,
        height: Some(100),
        pending_spend: false,
    });
    st.fees_fetched_at = Some(std::time::Instant::now());
    let app = AppWindow::new().expect("AppWindow");
    (st, app)
}

#[test]
fn back_from_confirm_leaves_zero_trace_then_resign_reaches_confirm_again() {
    let (mut st, app) = funded_stub("cancelregr");

    // "home: Compose note" -> "contacts: Self card" -> type the draft.
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    app.global::<Compose>()
        .set_compose_text("cancel-regression: this draft must survive a cancel".into());
    st.refresh_compose(&app);
    assert!(app.global::<Ui>().get_spend_enough(), "the staged coin must cover the note + fee");

    // Sign + review -> universal confirm screen (Stage A only).
    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "Sign must reach the confirm screen (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    assert!(st.pending_broadcast.is_some(), "a staged confirm must be pending");
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "Stage A records nothing yet");

    // Header back chevron -> on_confirm_cancel: zero trace.
    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "cancel returns to compose");
    assert!(st.pending_broadcast.is_none(), "cancel must drop the staged confirm");
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "a cancelled Sign must record nothing");
    assert_eq!(
        app.global::<Compose>().get_compose_text().as_str(),
        "cancel-regression: this draft must survive a cancel",
        "the draft text must survive the cancel — compose state is reusable"
    );

    // Sign again (same draft, second time) — must reach confirm again, and
    // still record nothing (this test stops here — no broadcast; see the
    // header note on why).
    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "the SAME draft must Sign again after a cancel (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    assert!(st.pending_broadcast.is_some());
    assert!(
        st.store.as_ref().unwrap().notes.is_empty(),
        "still nothing recorded — Stage B (Broadcast) never ran"
    );
}
