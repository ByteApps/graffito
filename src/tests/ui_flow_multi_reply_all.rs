// ---------------------------------------------------------------------------
// In-process UI-flow test, U12: Reply all prefill on an own multi-recipient
// note.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "Reply all: own multi-recipient note's
// view -> prefills BOTH addresses (primary + 1 chip)" leg
// (ui-automation/tests/graffito-app-multi-recipient.sh). That suite stages a
// genuinely OWN multi-recipient note (rather than a RECEIVED one) because
// staging a received multi note would need a second CLI identity driving
// notes-core's multi compose directly — its header calls this the PR's
// "explicitly-sanctioned fallback", since `reply_set` populates identically
// either way (own notes just have no sender to prepend). This test stages
// the fixture the SAME way: `app_core::compose::compose_and_record` — the
// exact core `on_compose_send` -> `compose_note` + (on Broadcast)
// `record_composed_note` run in production — with a primary recipient +
// one extra recipient, producing a `NoteRecord` with `received: false`,
// `sender: None`, `recipients: [r1, r2]`. Then drives the real
// `on_open_note` -> `on_reply_all_to_note` handlers, headless.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn recipient_addrs() -> (String, String) {
    let r1 = app_core::notes_core::bundle::Identity::from_app_seed(&[105u8; 32]).unwrap().address(Network::Regtest);
    let r2 = app_core::notes_core::bundle::Identity::from_app_seed(&[106u8; 32]).unwrap().address(Network::Regtest);
    (r1, r2)
}

/// Stage an activated, funded notebook with ONE recorded own multi-recipient
/// public note (to `r1` + chip `r2`), via the same core `compose_and_record`
/// the production Sign+Broadcast path calls. Returns the note id too.
fn multi_note_stub(r1: &str, r2: &str) -> (State, AppWindow, String) {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u12-replyall-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "dd".repeat(32),
        vout: 0,
        value: 100_000,
        height: Some(100),
        pending_spend: false,
    });

    let identity = st.ident.as_ref().unwrap().full().unwrap().clone_fields();
    let composed = app_core::compose::compose_and_record(
        st.store.as_mut().unwrap(),
        &identity,
        Network::Regtest,
        &app_core::compose::ComposeRequest {
            text: "multi-recipient e2e: hello to two friends",
            private: false,
            recipient: Some(r1),
            extra_recipients: &[r2],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1_700_000_000,
            pq_pw_cost: app_core::notes_core::pq::PwCost::DEFAULT,
            pq_password: None,
            pq_mlkem: None,
        },
    )
    .expect("compose_and_record");
    let note_id = composed.note_id.clone();

    {
        let n = st.store.as_ref().unwrap().notes.iter().find(|n| n.note_id == note_id).expect("recorded note");
        assert_eq!(n.recipients, vec![r1.to_string(), r2.to_string()], "fixture must be a genuine multi-recipient note");
        assert!(!n.received, "an OWN note — the PR's sanctioned reply-all fallback");
        assert!(n.sender.is_none());
    }

    let app = AppWindow::new().expect("AppWindow");
    (st, app, note_id)
}

#[test]
fn reply_all_on_own_multi_note_prefills_both_recipients() {
    let (mut st, app, note_id) = multi_note_stub(&recipient_addrs().0, &recipient_addrs().1);
    let (r1, r2) = recipient_addrs();

    // Open the note (screen 5): reply_set = the 2 recipients (self excluded
    // — neither r1 nor r2 is this identity's own address), sender is None
    // so plain "Reply" (note-reply-address) has nothing single to offer.
    st.on_open_note(&app, note_id.clone().into());
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Note);
    assert_eq!(
        app.global::<Note>().get_note_reply_address().as_str(),
        "",
        "an own MULTI-recipient note has no single reply counterparty — only Reply all"
    );
    let reply_set = app.global::<Note>().get_note_reply_set();
    assert_eq!(reply_set.row_count(), 2, "reply_set must carry both recipients");
    let reply_set_addrs: Vec<String> =
        (0..reply_set.row_count()).map(|i| reply_set.row_data(i).unwrap().address.to_string()).collect();
    assert_eq!(reply_set_addrs, vec![r1.clone(), r2.clone()], "reply_set must list both recipients in order");

    // Tap "Reply all" -> compose prefills BOTH addresses: primary + one
    // chip, exactly the Mac leg's `cb: reply-all to=<a1>,<a2> n=2` +
    // resulting-chip assertion, checked here on State/globals directly.
    st.on_reply_all_to_note(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "reply-all must land on compose");
    assert_eq!(app.global::<Ui>().get_compose_return(), Screen::Note, "cancel/back from this compose must return to the note");
    assert_eq!(st.to_address.as_deref(), Some(r1.as_str()), "reply-all must route the primary through pick_contact_core");
    assert_eq!(st.to_addresses_extra, vec![r2.clone()], "reply-all must seed the REST as extra chips");

    let chips = app.global::<Compose>().get_to_chips();
    assert_eq!(chips.row_count(), 1, "exactly one chip beyond the reply-all primary");
    assert_eq!(chips.row_data(0).unwrap().address.as_str(), r2.as_str());
}
