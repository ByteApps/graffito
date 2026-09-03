// ---------------------------------------------------------------------------
// In-process UI-flow test, U8: self-note + ML-KEM (the generated key).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "self-note + ML-KEM (generated key)" leg
// (graffito-app-selfpq.sh) — every y-coordinate downstream of it was marked
// `CALIBRATE` and never measured (see ui_flow_selfpq_passphrase.rs's header
// for the full root-cause quote). Chains the SAME two things the Mac leg
// chained: `do_pq_generate` (proven end-to-end in ui_flow_quantum_key.rs)
// producing the personal quantum key, then a self-note compose that seals
// to it — through the real `on_pq_mlkem_toggled`/`on_compose_send`
// handlers, headless, no window/coordinates/keychain prompt.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn self_note_kem_compose_reaches_confirm_with_layered_label_then_cancels() {
    // Guards the shared GRAFFITO_KEYCHAIN_MEMORY env var + pq-imported
    // in-memory slot — see ui_flow_quantum_key.rs's KEYCHAIN_ENV doc.
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);

    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st =
        State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u8-selfkem-{}", std::process::id()));
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

    // Settings -> Quantum keys -> Generate (768, the Mac suite's default) —
    // the exact do_pq_generate flow ui_flow_quantum_key.rs proves.
    app.global::<QuantumKeys>().set_pq_gen_level("768".into());
    app.global::<QuantumKeys>().set_pq_gen_extra("selfpq kem compose harness entropy".into());
    st.do_pq_generate(&app);
    let kp_alg = st.pq_imported.as_ref().expect("generate populated State.pq_imported").alg();

    // "home: Compose note" -> "contacts: Self card", then the ML-KEM
    // Switch (`checked <=> Compose.pq-mlkem-enabled`, `toggled =>
    // Compose.pq-mlkem-toggled(self.checked)`).
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    app.global::<Compose>().set_pq_mlkem_enabled(true);
    st.on_pq_mlkem_toggled(&app, true);
    assert!(
        app.global::<Compose>().get_pq_mlkem_available(),
        "the freshly-generated key must make the ML-KEM layer available on a self-note"
    );

    // The Mac suite's exact typed note body for this leg.
    app.global::<Compose>().set_compose_text("mac note locked to my quantum key".into());
    st.refresh_compose(&app);
    assert!(
        app.global::<Ui>().get_spend_enough(),
        "the staged 100,000-sat coin must cover the note + fee"
    );

    // Canonical label, same rule as the passphrase leg — asserted against
    // graffito_core::seclabel's own output, not a copied string. The
    // ML-KEM level name never appears in the Flat self-note wording (see
    // `self_note_label`'s `(false, true)` arm), so any level value proves
    // the same thing the real one would.
    let choice = app_core::passphrase::SecurityChoice {
        private: true,
        directed: false,
        passphrase_bits: None,
        passphrase_verified: false,
        mlkem: Some(app_core::pqkeys::from_pq_alg(kp_alg)),
    };
    let expected_label = app_core::passphrase::security_label(&choice);
    assert_eq!(app.global::<Compose>().get_pq_security_label().as_str(), expected_label);
    assert!(app.global::<Ui>().get_pq_quantum_resistant(), "a self-note is always quantum-resistant");

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
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "a cancelled Sign must record nothing");

    keychain::delete_secret(PQ_IMPORTED_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
