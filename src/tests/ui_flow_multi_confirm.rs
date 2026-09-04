// ---------------------------------------------------------------------------
// In-process UI-flow test, U12: multi-recipient confirm screen.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "confirm screen: byte-true decode shows
// both recipient outputs, no warnings" leg
// (ui-automation/tests/graffito-app-multi-recipient.sh). Stages two
// recipient addresses and a funded notebook, drives the SAME picker path as
// `ui_flow_multi_select.rs` (primary pick -> "+ Add recipient" -> second
// pick -> chip) then Sign (`on_compose_send`) to the universal confirm
// screen, and asserts the decoded rows the real `Confirm` global would
// render come from `app_core::confirm::summarize_signed_tx` over the ACTUAL
// signed tx bytes (not a copy of the compose-time recipient list) — the
// Mac suite's "byte-true" claim.
//
// Network: `compose_note` (reached through `on_compose_send`) is a pure
// build+sign, no I/O — see `ui_flow_selfpq_passphrase.rs`'s identical note.
// The only network-shaped gate is `on_compose_send`'s `base_url().is_none()`
// check, satisfied here the same way: a bogus `node_urls` entry that is
// never dialed, plus a fresh `fees_fetched_at` that short-circuits
// `refresh_fees_price`'s real fetch for 60s.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn funded_stub() -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u12-multiconfirm-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    // A fresh hierarchical mnemonic's notebook index starts EMPTY (notebooks
    // are created deliberately — see `ensure_notebook`'s doc comment); every
    // production boot auto-creates notebook 0 (workspace CLAUDE.md's
    // "onboarding is unified" rule). Without it, `confirm_self_spks` has no
    // active notebook to realize, so this identity's own change output
    // fails to match `self_spks` and the confirm screen wrongly warns
    // "doesn't recognize" on its own change — do the same here.
    st.ensure_notebook(0);
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

fn recipient_addrs() -> (String, String) {
    let r1 = app_core::notes_core::bundle::Identity::from_app_seed(&[103u8; 32]).unwrap().address(Network::Regtest);
    let r2 = app_core::notes_core::bundle::Identity::from_app_seed(&[104u8; 32]).unwrap().address(Network::Regtest);
    (r1, r2)
}

/// Drive the SAME picker path `ui_flow_multi_select.rs` proves: primary pick
/// -> "+ Add recipient" -> second pick -> chip. Left as a free function
/// (not folded into `funded_stub`) so the confirm-screen assertions below
/// stay the focus of the test body, mirroring `ui_flow_selfpq_passphrase.rs`'s
/// `pick_contact_core` call.
fn pick_two_recipients(st: &mut State, app: &AppWindow, r1: &str, r2: &str) {
    app.global::<Ui>().set_pick_mode("compose".into());
    st.on_pick_contact(app, r1.to_string().into());
    st.on_add_recipient_open(app);
    st.on_pick_contact(app, r2.to_string().into());
}

#[test]
fn public_multi_recipient_confirm_shows_both_recipient_outputs_no_warnings() {
    let (mut st, app) = funded_stub();
    let (r1, r2) = recipient_addrs();

    pick_two_recipients(&mut st, &app, &r1, &r2);
    assert_eq!(st.to_address.as_deref(), Some(r1.as_str()));
    assert_eq!(st.to_addresses_extra, vec![r2.clone()]);

    // Private OFF (a PUBLIC multi note) — the Mac leg's exact toggle.
    app.global::<Compose>().set_compose_private(false);
    app.global::<Compose>().set_compose_text("multi-recipient e2e: hello to two friends".into());
    st.refresh_compose(&app);
    assert!(app.global::<Ui>().get_spend_enough(), "the staged 100,000-sat coin must cover 2 recipients + fee");

    // Sign -> the universal confirm screen (Stage A: build+sign, no store
    // mutation yet).
    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "Sign must reach the universal confirm screen (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    assert!(
        st.store.as_ref().unwrap().notes.is_empty(),
        "Stage A must not have recorded anything yet — that's Stage B's (Broadcast's) job"
    );

    // Byte-true decode: `show_confirm` re-decodes the ACTUAL signed raw tx
    // via `summarize_signed_tx`, not a copy of the compose-time recipient
    // list — this is what the Mac leg's comment calls out as the point of
    // the assertion (a broken `ctx.recipients` wiring would make one or
    // both recipient outputs fall through to "other" with a warning).
    let outputs = app.global::<Confirm>().get_confirm_outputs();
    let mut recipient_titles: Vec<String> = Vec::new();
    for i in 0..outputs.row_count() {
        let row = outputs.row_data(i).expect("output row");
        if row.kind.as_str() == "recipient" {
            recipient_titles.push(row.title.to_string());
        }
    }
    recipient_titles.sort();
    let mut expected = vec![r1.clone(), r2.clone()];
    expected.sort();
    assert_eq!(
        recipient_titles, expected,
        "the confirm screen must list BOTH recipients' decoded outputs, not one — got {} rows total",
        outputs.row_count()
    );

    assert_eq!(
        app.global::<Ui>().get_confirm_warn().as_str(),
        "",
        "a correctly-wired multi-recipient tx must decode with no warnings"
    );

    // Cancel — Stage A leaves zero trace, same rule as every other confirm
    // leg (ui_flow_selfpq_passphrase.rs).
    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "cancel returns to compose");
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "a cancelled Sign must record nothing");
}
