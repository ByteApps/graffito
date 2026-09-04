// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: spending-wallet toggle + the M4 default rule.
// ---------------------------------------------------------------------------
//
// Ports two Mac coordinate-suite legs (ui-automation/tests/graffito-app.sh):
// "spending wallet: Settings toggle on" and "spending wallet: enabled-but-
// empty still defaults compose to Notebook" — both config/State-flag facts,
// no chain scan needed. The two SKIPPED Mac legs in between ("enabling
// triggered an automatic scan", "funded receive address scanned via the
// funding screen's ↻") are real network scans (`spending_refresh_async`)
// and stay in the Mac suite.
//
// Network-free trick: `on_set_spending_enabled` only kicks
// `spending_refresh_async` when `!self.spending_scanned` — pre-marking the
// fixture `spending_scanned = true` (as if a scan already landed, empty)
// takes that branch off the table while leaving every other observable of
// the handler (store.spending.enabled, the Settings UI globals) exactly as
// production sets them. This is also exactly the "enabled but empty" state
// the M4 default-rule leg needs, so both legs share one fixture.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn toggle_on_sets_config_and_flags_then_empty_still_defaults_to_notebook() {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-spending-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.fees_fetched_at = Some(std::time::Instant::now());
    assert!(st.spending_capable, "a BIP-39 mnemonic must be spending-capable");
    assert!(
        !st.store.as_ref().unwrap().spending.enabled,
        "baseline: spending starts disabled"
    );

    let app = AppWindow::new().expect("AppWindow");

    // Pretend a scan already landed (empty) so the enable path below never
    // reaches for the network — see the header note.
    st.spending_scanned = true;

    // ---- leg: Settings toggle on ----
    st.on_set_spending_enabled(&app, true);
    assert!(st.store.as_ref().unwrap().spending.enabled, "config: spending must be enabled");
    assert!(app.global::<Ui>().get_spending_enabled(), "Settings UI must reflect the toggle");
    assert!(app.global::<Ui>().get_spending_capable());

    // ---- leg: enabled-but-empty still defaults compose to Notebook ----
    // A fresh compose session with the toggle on but `spending_coins`
    // still empty (no scan ever populated it) must default Pay-from to
    // Notebook, never Spending (Sal 2026-07-16, M4).
    assert!(st.spending_coins.is_empty(), "fixture never scanned any spending coins");
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    assert_eq!(
        st.payfrom_active_source, "notebook",
        "an enabled-but-empty spending wallet must not become the default pay-from source"
    );
    assert_eq!(app.global::<Ui>().get_pay_from().as_str(), "notebook");
    assert!(!app.global::<Ui>().get_spend_from_wallet());
}
