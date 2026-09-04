// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: sub-dust change fold, predicted then explained.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "sub-dust fold: confirm screen explains
// change folded into the fee, compose cost line predicted it first" leg
// (ui-automation/tests/graffito-app.sh) — Sal's testnet4 build-14 question:
// a single sub-400-sat coin composes a valid tx whose leftover (below the
// 330-sat dust minimum) can't be a change output, so notes-core folds it
// into the fee — the honest-fee-label rule (2026-07-18) is that this must
// be visible BEFORE Sign (the compose cost line), not just discovered after
// the fact on the confirm screen.
//
// `refresh_compose` prints `cb: compose-est fold=<S>` only on a rising edge
// (`fold_amount != st.compose_fold_shown`) — asserted here via
// `st.compose_fold_shown` directly (stdout isn't capturable in-process, per
// the U10 brief) instead of a log grep. The confirm-screen explanation
// (`cb: confirm subdust-fold`) is `note_subdust_fold_warn`, called
// synchronously from `on_compose_send`'s success arm — asserted via
// `Ui.confirm-warn`.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn compose_est_predicts_fold_then_confirm_explains_it() {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-subdust-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.fees_fetched_at = Some(std::time::Instant::now());

    // A single 400-sat coin (the Mac leg's exact amount, 0.000004 BTC) —
    // at ~1 sat/vB (no fees fetched, `pick_contact_core` falls back to the
    // 1.0 default) a 1-input note leaves ~250-ish sats of would-be change,
    // under the 330-sat dust floor, so the builder folds it into the fee.
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "55".repeat(32),
        vout: 0,
        value: 400,
        height: Some(100),
        pending_spend: false,
    });

    let app = AppWindow::new().expect("AppWindow");
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Compose>().get_rate_text().as_str(), "1", "no fees fetched: falls back to 1 sat/vB");

    // The fold prediction must appear WHILE composing — before Sign is even
    // tapped (a live cost-line estimate, not a post-hoc confirm discovery).
    assert_eq!(st.compose_fold_shown, 0, "baseline: nothing folded yet");
    app.global::<Compose>().set_compose_text("subdust fold warn leg".into());
    st.refresh_compose(&app);
    assert!(
        st.compose_fold_shown > 0,
        "the compose cost line must predict the sub-dust fold before Sign"
    );
    assert!(app.global::<Ui>().get_spend_enough(), "the 400-sat coin must still cover the fee");

    // Sign -> universal confirm screen; `note_subdust_fold_warn` runs
    // synchronously right after `show_confirm` in `on_compose_send`'s
    // success arm and appends the fold explanation to Ui.confirm-warn.
    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "Sign must reach the confirm screen (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    let warn = app.global::<Ui>().get_confirm_warn().to_string();
    assert!(
        warn.contains("dust minimum"),
        "the confirm screen must explain the folded change: {warn:?}"
    );

    // No need to broadcast — cancel, same as the Mac leg.
    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    assert!(st.store.as_ref().unwrap().notes.is_empty());
}
