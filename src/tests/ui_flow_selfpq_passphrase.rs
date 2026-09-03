// ---------------------------------------------------------------------------
// In-process UI-flow test, U8: self-note + passphrase compose.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "self-note + passphrase: compose,
// broadcast, locked store" leg (ui-automation/tests/graffito-app-selfpq.sh)
// — the first leg whose y-coordinates were marked `CALIBRATE` and never
// measured (the suite's header: navigating to the Quantum-keys screen was
// flaky enough that "everything DOWNSTREAM of the nav is therefore still
// UNCALIBRATED"). This drives the exact same production path — `on_pick_
// contact`/`pick_contact_core`, the passphrase toggle's `on_pq_passphrase_
// changed`, and the Sign button's `on_compose_send` — headless, with no
// window/coordinates/keychain prompt, per the slint-ui-testing memory.
//
// Network: `compose_note` (reached through `on_compose_send`) is a PURE
// build+sign, no I/O — see app-core/src/compose.rs's own doc comment ("the
// paranoid cancel-leaves-zero-trace seam"). The only network-shaped gate on
// the path is `on_compose_send`'s own `base_url().is_none()` check (a
// Bitcoin node must be CONFIGURED to Sign at all) — satisfied here with a
// bogus `node_urls` entry that is never dialed, plus a fresh `fees_fetched_
// at` timestamp that short-circuits `refresh_fees_price`'s real fetch for
// 60s (regtest's `default_base` is `None`, so without either of these the
// gate would either block Sign or attempt a real HTTP call).

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Stage a funded, activated notebook via the SAME `State::activate` boot
/// path production uses (parses key material, realizes the identity, loads/
/// creates the per-identity store) plus one spendable coin — the "staged
/// funded notebook — no network" fixture the U8 brief calls for.
fn funded_stub(tag: &str) -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st =
        State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u8-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "aa".repeat(32),
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
fn self_note_passphrase_reaches_confirm_with_layered_label_then_cancels() {
    let (mut st, app) = funded_stub("selfpw");

    // "home: Compose note" -> "contacts: Self card" (pick_contact_core is
    // the ONE sanctioned recipient-setting path both the picker and Reply
    // go through — see its own doc comment).
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose);
    assert!(app.global::<Compose>().get_compose_private(), "self-notes compose private by default");

    // The Security panel's passphrase toggle (`checked <=> Compose.pq-
    // passphrase-enabled`, `toggled => Compose.pq-passphrase-changed(...)`
    // in ui/screens/compose.slint) — same handler the Switch invokes.
    app.global::<Compose>().set_pq_passphrase_enabled(true);
    app.global::<Compose>().set_pq_passphrase_text("mac-orbit-cactus-77".into());
    st.on_pq_passphrase_changed(&app, "mac-orbit-cactus-77".into());

    // The Mac suite's exact typed note body for this leg.
    app.global::<Compose>().set_compose_text("mac note locked to a password".into());
    st.refresh_compose(&app);
    assert!(
        app.global::<Ui>().get_spend_enough(),
        "the staged 100,000-sat coin must cover the note + fee"
    );

    // The Security section's label must be graffito_core::seclabel's OWN
    // output for this exact choice — asserted against the canonical
    // function, never a copied string (U8 brief). A self-note is already
    // quantum-resistant on its own; the passphrase layer's mere PRESENCE
    // (not its strength) is what switches the Flat-flavor wording to the
    // loss warning (`self_note_label`'s `(true, false)` arm) — the typed
    // phrase here is unverified, but the label text doesn't vary on that
    // for a self-note with no ML-KEM layer, so `passphrase_bits`/
    // `passphrase_verified` can be any "layer present" values.
    let choice = app_core::passphrase::SecurityChoice {
        private: true,
        directed: false,
        passphrase_bits: Some(0.0),
        passphrase_verified: false,
        mlkem: None,
    };
    let expected_label = app_core::passphrase::security_label(&choice);
    assert_eq!(app.global::<Compose>().get_pq_security_label().as_str(), expected_label);
    assert!(app.global::<Ui>().get_pq_quantum_resistant(), "a self-note is always quantum-resistant");

    // Sign -> the universal confirm screen (Stage A: build+sign, no store
    // mutation yet — `cb: confirm show kind=compose`).
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

    // Cancel — the Mac leg never got this far to calibrate, but the whole
    // point of the universal confirm screen's split is that Cancel leaves
    // zero trace.
    st.on_confirm_cancel(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "cancel returns to compose");
    assert!(st.store.as_ref().unwrap().notes.is_empty(), "a cancelled Sign must record nothing");
}
