// ---------------------------------------------------------------------------
// In-process UI-flow test: multi-recipient pq compose gating
// (PLAN-graffito-multi-pq.md, 2026-09-06).
// ---------------------------------------------------------------------------
//
// Mirrors `ui_flow_multi_confirm.rs`'s picker/funding setup (two taproot
// recipients + a funded notebook) crossed with `ui_flow_selfpq_kem.rs`'s pq
// compose assertions: the ML-KEM switch must only turn on when EVERY
// recipient's contact carries a quantum key (all-or-nothing per note), the
// caption must list BOTH levels in recipient order, and the built
// `ComposeRequest.pq_mlkem` must carry one `(alg, ek)` per recipient —
// exactly what the cross-device suite's log-contract assertion
// (`mlkem=MlKem768,MlKem1024`) depends on. Also proves the all-or-nothing
// gate: removing one recipient's key must turn the switch back off rather
// than silently sealing a note that is pq for one recipient and not the
// other.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn funded_stub() -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-multipq-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
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
    let r1 = app_core::notes_core::bundle::Identity::from_app_seed(&[201u8; 32]).unwrap().address(Network::Regtest);
    let r2 = app_core::notes_core::bundle::Identity::from_app_seed(&[202u8; 32]).unwrap().address(Network::Regtest);
    (r1, r2)
}

fn pick_two_recipients(st: &mut State, app: &AppWindow, r1: &str, r2: &str) {
    app.global::<Ui>().set_pick_mode("compose".into());
    st.on_pick_contact(app, r1.to_string().into());
    st.on_add_recipient_open(app);
    st.on_pick_contact(app, r2.to_string().into());
}

/// Stamp a quantum key onto an EXISTING contact (`on_pick_contact`'s
/// `touch_contact` already created a keyless entry for every picked
/// address — pushing a second, duplicate `Contact` would be shadowed by
/// the first on lookup, since `resolve_pq_mlkem_eks` takes the first
/// address match). Mirrors what Settings' "add a quantum key" flow does to
/// a real contact.
fn give_contact_a_key(st: &mut State, address: &str, alg: app_core::notes_core::pq::MlKemAlg) {
    let kp = app_core::notes_core::pq::MlKemKeypair::generate(alg).unwrap();
    let armor = app_core::pqkeys::export_public_armor(&kp);
    let contact = st.contacts.iter_mut().find(|c| c.address == address).expect("touch_contact already added it");
    app_core::pqkeys::set_contact_pq_key(contact, &armor).expect("valid armor");
}

#[test]
fn multi_recipient_mlkem_needs_every_recipients_key_and_lists_both_levels() {
    use app_core::notes_core::pq::MlKemAlg;

    let (mut st, app) = funded_stub();
    let (r1, r2) = recipient_addrs();
    pick_two_recipients(&mut st, &app, &r1, &r2);
    assert_eq!(st.to_address.as_deref(), Some(r1.as_str()));
    assert_eq!(st.to_addresses_extra, vec![r2.clone()]);
    app.global::<Compose>().set_compose_private(true);

    // Only recipient 1 has a key yet: the ALL-OR-NOTHING rule must keep the
    // layer unavailable, never partially on.
    give_contact_a_key(&mut st, &r1, MlKemAlg::MlKem768);
    let (flags, _, _) = st.refresh_compose_pq(&app);
    assert_eq!(flags, 0, "ML-KEM must stay OFF until every recipient has a key");
    assert!(!app.global::<Compose>().get_pq_mlkem_available());
    assert!(
        app.global::<Compose>().get_pq_mlkem_caption().contains("1"),
        "the caption should name how many recipients still lack a key: {}",
        app.global::<Compose>().get_pq_mlkem_caption()
    );

    // Recipient 2 gets a DIFFERENT level (1024 vs Bob's — er, recipient 1's
    // — 768): mixed levels across recipients are allowed.
    give_contact_a_key(&mut st, &r2, MlKemAlg::MlKem1024);
    let (_flags, _alg, _multi_algs) = st.refresh_compose_pq(&app);
    assert!(
        app.global::<Compose>().get_pq_mlkem_available(),
        "every recipient now has a key — the layer must become available"
    );
    let caption = app.global::<Compose>().get_pq_mlkem_caption().to_string();
    assert!(caption.contains("768"), "caption must name recipient 1's level: {caption}");
    assert!(caption.contains("1024"), "caption must name recipient 2's level: {caption}");

    // Default-ON (2026-09-05 hybrid-by-default rule) once available.
    assert!(app.global::<Compose>().get_pq_mlkem_enabled(), "ML-KEM defaults ON once available");

    app.global::<Compose>().set_compose_text("multi pq gating test".into());
    st.refresh_compose(&app);
    assert!(app.global::<Ui>().get_spend_enough());

    st.on_compose_send(&app);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Confirm,
        "Sign must reach the universal confirm screen (status: {:?})",
        app.global::<Ui>().get_status().as_str()
    );
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "Stage A must not have recorded anything yet");

    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "cancel returns to compose");
}

#[test]
fn multi_recipient_mlkem_log_line_lists_algs_in_recipient_order() {
    use app_core::notes_core::pq::MlKemAlg;

    let (mut st, app) = funded_stub();
    let (r1, r2) = recipient_addrs();
    pick_two_recipients(&mut st, &app, &r1, &r2);
    app.global::<Compose>().set_compose_private(true);
    give_contact_a_key(&mut st, &r1, MlKemAlg::MlKem768);
    give_contact_a_key(&mut st, &r2, MlKemAlg::MlKem1024);
    st.refresh_compose_pq(&app);
    assert!(app.global::<Compose>().get_pq_mlkem_enabled());

    // The exact resolution `on_compose_send` performs at Sign time — pinned
    // here independently of stdout capture (the log line the cross-device
    // suite greps is a straight format over this same Vec, in this same
    // order: `eks.iter().map(|(alg, _)| format!("{alg:?}")).join(",")`).
    let addrs = st.compose_pq_recipient_addrs();
    assert_eq!(addrs, vec![r1.clone(), r2.clone()]);
    let eks = st.resolve_pq_mlkem_eks(&addrs).expect("both recipients have keys");
    assert_eq!(eks.len(), 2);
    assert_eq!(eks[0].0, MlKemAlg::MlKem768, "recipient order: r1 first");
    assert_eq!(eks[1].0, MlKemAlg::MlKem1024, "recipient order: r2 second");
    let mlkem_log = eks.iter().map(|(alg, _)| format!("{alg:?}")).collect::<Vec<_>>().join(",");
    assert_eq!(mlkem_log, "MlKem768,MlKem1024");
}
