// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: the ONE cross-wallet payfrom verdict.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "payfrom state: ONE cross-wallet verdict
// (mixed / spending-only / empty / notebook-only)" leg (ui-automation/tests/
// graffito-app.sh) — Sal's iPhone TestFlight-build-12 bug cluster: sufficiency
// used to be judged per-wallet-PANEL, so a fully-funded selection could
// render red. `payfrom_state` (called inside `sync_and_finalize_payfrom` on
// every relevant change) now computes ONE verdict from the TRUE cross-wallet
// selection — this test walks the exact four selection shapes the Mac leg's
// `pf_last_matches` checks (its `cb: payfrom state src=… required=…
// selected=… enough=…` line), asserted here against `PayfromState` directly
// instead of a log grep, driving the real `on_toggle_coin` handler.
//
// Both sources are staged directly (a notebook UTXO pushed onto the store,
// a spending UTXO pushed onto `spending_coins`) rather than scanned — no
// network, per the U10 brief. `spending_source`/the spending coin's address
// are real derivations (`app_core::spending`, pure secp math, no I/O) so the
// real mixed-PSBT dry-run `on_toggle_coin` triggers (via `refresh_compose`)
// has a genuine descriptor to work from, exactly like a real scan would
// leave behind.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NB_TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SP_TXID: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn one_cross_wallet_verdict_across_the_four_shapes() {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-payfrom-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.fees_fetched_at = Some(std::time::Instant::now());

    // Notebook coin (50,000 sats) — the identity's own store.
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: NB_TXID.to_string(),
        vout: 0,
        value: 50_000,
        height: Some(100),
        pending_spend: false,
    });

    // Spending-wallet coin (30,000 sats) — staged as a landed scan would
    // leave it: a real descriptor + a real derived receive address.
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
    st.pick_contact_core(&app, "self"); // fresh compose session; M4 default picks spending (balance > 0)
    app.global::<Compose>().set_compose_text("payfrom state leg".into());
    st.refresh_compose(&app);

    // Add the notebook coin too — the mixed shape the Mac leg's earlier
    // (unported) legs left standing before this one starts.
    st.on_toggle_coin(&app, "notebook".into(), format!("{NB_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Mixed, "expected Mixed shape");
    assert_eq!(pf.source_label, "2 wallets");
    assert_eq!(pf.selected, 80_000);
    assert!(pf.enough, "mixed selection must be ONE globally-sufficient verdict");

    // STATE A: deselect the notebook coin -> spending-only, still enough=1
    // (never a per-panel red just because notebook's share left).
    st.on_toggle_coin(&app, "notebook".into(), format!("{NB_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Spending, "expected Spending shape");
    assert_eq!(pf.source_label, "Spending wallet");
    assert_eq!(pf.selected, 30_000);
    assert!(pf.enough, "state A: spending-only selection must be enough=1");

    // Genuine insufficiency: deselect the spending coin too -> nothing
    // selected anywhere. `required` must STILL be numeric (the blank-
    // Required defect Sal hit), never blank just because nothing is picked.
    st.on_toggle_coin(&app, "spending".into(), format!("{SP_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Empty, "expected Empty shape");
    assert_eq!(pf.selected, 0);
    assert!(!pf.enough);
    assert!(pf.required.is_some(), "required must stay numeric even with nothing selected");

    // STATE B: reselect notebook only -> enough=1 again (the warning state
    // clears, not just doesn't get worse).
    st.on_toggle_coin(&app, "notebook".into(), format!("{NB_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Notebook, "expected Notebook shape");
    assert_eq!(pf.source_label, "Notebook");
    assert_eq!(pf.selected, 50_000);
    assert!(pf.enough, "state B: notebook-only selection must be enough=1");

    // Restore: reselect spending too -> mixed, sufficient again.
    st.on_toggle_coin(&app, "spending".into(), format!("{SP_TXID}:0").into());
    let pf = st.payfrom_state(&app);
    assert!(pf.shape == PayfromShape::Mixed, "expected Mixed shape");
    assert_eq!(pf.source_label, "2 wallets");
    assert_eq!(pf.selected, 80_000);
    assert!(pf.enough, "restore: mixed selection sufficient again");
}
