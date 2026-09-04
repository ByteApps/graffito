// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: dispatch follows the verdict.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "dispatch: deselect-spending-last signs
// via the notebook branch (no bail)" leg (ui-automation/tests/
// graffito-app.sh) — Sal's TestFlight-build-13 follow-up: the OLD code
// promoted whichever source was last TAPPED, so deselecting the spending
// wallet's final coin (a tap ON the spending source) left `pay-from` =
// "spending" while the actual cross-wallet selection was notebook-only —
// Sign then invoked the spending branch, which bailed "no coins selected"
// despite a green globally-sufficient verdict. `sync_and_finalize_payfrom`
// now re-derives the dispatch inputs (`pay-from`/`spend-from-wallet`/
// `fund-external`/`mixed-linkage-hint`) from `payfrom_state`'s shape, so
// this exact poison sequence must route Sign to `on_compose_send` (the
// notebook branch) — proven here by calling it directly and reaching the
// confirm screen, never a `bail=` status.
//
// app.slint's Sign button itself picks `Compose.compose-send()` (->
// `on_compose_send`) precisely when `!mixed-linkage-hint && pay-from ==
// "notebook"` (ui/screens/compose.slint) — this test asserts those exact
// flags land on the notebook branch after the deselect, then calls that
// branch to prove it actually signs instead of bailing.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NB_TXID: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const SP_TXID: &str = "4444444444444444444444444444444444444444444444444444444444444444";

#[test]
fn deselect_spending_last_signs_via_notebook_branch_no_bail() {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-dispatch-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.fees_fetched_at = Some(std::time::Instant::now());

    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: NB_TXID.to_string(),
        vout: 0,
        value: 50_000,
        height: Some(100),
        pending_spend: false,
    });
    let material = parse_key_material(MNEMONIC, Network::Regtest).expect("parse material");
    st.spending_source = app_core::spending::funding_source(&material, Network::Regtest, st.account).ok();
    let spend_key = app_core::spending::derive_spending_key(&material, Network::Regtest, st.account, 0, 0)
        .expect("derive spending key");
    st.spending_coins.push(FundingUtxo {
        txid: SP_TXID.to_string(),
        vout: 0,
        value: 30_000,
        address: spend_key.address,
        chain: 0,
        index: 0,
        confirmed: true,
    });
    st.store.as_mut().unwrap().spending_set_enabled(true);
    st.spending_scanned = true;

    let app = AppWindow::new().expect("AppWindow");
    st.pick_contact_core(&app, "self");
    app.global::<Compose>().set_compose_text("dispatch follows the verdict".into());
    st.refresh_compose(&app);

    // Reach the restored MIXED selection (both sources selected) — the
    // starting point the Mac leg's own chained state was in.
    st.on_toggle_coin(&app, "notebook".into(), format!("{NB_TXID}:0").into());
    assert!(st.payfrom_state(&app).shape == PayfromShape::Mixed, "setup: mixed before the poison sequence");

    // The poison sequence: deselect the spending coin LAST — a tap ON the
    // spending source, whose OLD bug promoted it as the active source even
    // though the resulting selection is notebook-only.
    st.on_toggle_coin(&app, "spending".into(), format!("{SP_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Notebook, "Sal sequence: notebook-only after deselect-spending-last");

    // `sync_and_finalize_payfrom` (run inside `on_toggle_coin`'s
    // `refresh_compose`) must have re-aligned the dispatch flags to the
    // verdict's shape — this IS app.slint's exact Sign-button routing
    // condition for the notebook branch.
    assert!(!app.global::<Ui>().get_mixed_linkage_hint(), "the linkage hint must clear — no longer mixed");
    assert_eq!(app.global::<Ui>().get_pay_from().as_str(), "notebook");
    assert!(!app.global::<Ui>().get_spend_from_wallet());
    assert!(!app.global::<Ui>().get_fund_external());
    assert_eq!(st.payfrom_active_source, "notebook");

    // Sign -> must run the NOTEBOOK branch (`on_compose_send`) and reach
    // the confirm screen — never bail red despite the green verdict.
    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "Sal sequence: Sign must dispatch the notebook branch and reach confirm (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    assert!(
        app.global::<Ui>().get_status().as_str().is_empty(),
        "no bail status may be set on the successful notebook dispatch"
    );
    assert!(st.pending_broadcast.is_some());

    // Cancel the confirm — zero trace, proven separately by the
    // cancel-regression leg; this test just needs to stop cleanly.
    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    assert!(st.store.as_ref().unwrap().notes.is_empty());
}
