// ---------------------------------------------------------------------------
// In-process UI-flow test, U8: locked self-note unlock.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "view-only unlock, reopen asks again"
// leg (graffito-app-selfpq.sh) — its `NOTE_ROW_Y`/`UNLOCK_FIELD_Y`/
// `UNLOCK_BTN_Y` were `CALIBRATE` placeholders that suite never reached (see
// ui_flow_selfpq_passphrase.rs's header for the root cause). Builds the
// locked fixture through the SAME core the compose path uses —
// `app_core::compose::compose_and_record` with `pq_password` set, exactly
// what `on_compose_send` -> `compose_note` + (on Broadcast)
// `record_composed_note` do in production — then drives the real
// `on_open_note`/`on_unlock_note` handlers: wrong passphrase errors, right
// passphrase view-only-unlocks (never persisted — `unlock_note_view` takes
// `&self`, no `save_store()` call, by design), and reopening asks again.
// The saved store JSON is grepped for the plaintext exactly like the Mac
// suite's `STORE`/`grep` checks — "byte-exact isn't required, lockedness
// is" (U8 brief), so this doesn't reimplement notes-core's wire format.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE: &str = "correct horse battery staple";
const PLAINTEXT: &str = "topsecret note body only the passphrase should reveal";

/// Stage an activated identity + funded store, then record ONE locked
/// self-pq note via `compose_and_record` (`pq_password` set, no ML-KEM) —
/// the fixture `on_unlock_note` will be driven against. Returns the lock
/// guard too (the caller must hold it for its WHOLE body, not just setup —
/// see the doc on `keychain_env_lock`): `on_unlock_note` unconditionally
/// calls `ensure_pq_imported_loaded` (the LAUNCH-PATH rule's other
/// sanctioned keychain-read door) AFTER this function returns, and that
/// touches the SAME `pq-imported` slot/env var the KEM leg and
/// ui_flow_quantum_key.rs use — sharing their lock and memory-backend
/// opt-in avoids a real keychain round trip in a headless test process.
fn locked_note_stub() -> (State, AppWindow, String, std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
    let serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u8-lockednote-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "cc".repeat(32),
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
            text: PLAINTEXT,
            private: true,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1_700_000_000,
            pq_password: Some(PASSPHRASE.to_string()),
            pq_mlkem: None,
        },
    )
    .expect("compose_and_record");
    let note_id = composed.note_id.clone();

    {
        let n = st
            .store
            .as_ref()
            .unwrap()
            .notes
            .iter()
            .find(|n| n.note_id == note_id)
            .expect("recorded note");
        assert!(n.locked.is_some(), "a self-pq note must be stored LOCKED from the moment it's signed");
        assert!(n.text.is_none(), "the plaintext must never be cached in the record");
    }

    st.save_store();
    let store_path = st.store_path().expect("store path (identity is set)");

    let app = AppWindow::new().expect("AppWindow");
    (st, app, note_id, store_path, serial)
}

fn store_json_never_leaked(store_path: &std::path::Path) {
    let json = std::fs::read_to_string(store_path).expect("read store file");
    assert!(json.contains("\"locked\""), "store file has no locked body:\n{json}");
    assert!(
        !json.contains(PLAINTEXT),
        "PLAINTEXT LEAKED into the store file {store_path:?} — {json}"
    );
}

#[test]
fn locked_self_note_wrong_then_right_passphrase_then_reopen_asks_again() {
    let (mut st, app, note_id, store_path, _serial) = locked_note_stub();

    // Store on disk right after signing: locked, no plaintext — exactly
    // the Mac suite's post-broadcast STORE assertion.
    store_json_never_leaked(&store_path);

    // Open the note (screen 5) — refresh_note_unlock_ui reads `n.locked`.
    st.on_open_note(&app, note_id.clone().into());
    assert!(app.global::<Ui>().get_note_locked(), "a locked note must open locked");
    assert!(app.global::<Note>().get_note_unlock_needs_password());

    // Wrong passphrase -> the error path (`cb: unlock-note err=…`), note
    // stays locked.
    app.global::<Note>().set_note_unlock_passphrase("definitely-not-it".into());
    st.on_unlock_note(&app);
    assert!(
        !app.global::<Ui>().get_status().is_empty(),
        "a wrong passphrase must surface an error status"
    );
    assert!(app.global::<Ui>().get_status().as_str().contains("couldn't unlock"));
    assert!(app.global::<Ui>().get_note_locked(), "a wrong passphrase must leave the note locked");

    // Right passphrase -> view-only unlock: text shown, but NEVER written
    // back (`unlock_note_view` takes `&self` — no `save_store()` call in
    // `on_unlock_note`'s self-note branch).
    app.global::<Note>().set_note_unlock_passphrase(PASSPHRASE.into());
    st.on_unlock_note(&app);
    assert!(!app.global::<Ui>().get_note_locked(), "the right passphrase must view-only-unlock");
    assert!(
        app.global::<Note>().get_note_detail().as_str().contains(PLAINTEXT),
        "the decrypted text must be shown: {}",
        app.global::<Note>().get_note_detail()
    );
    assert!(
        st.store.as_ref().unwrap().notes.iter().find(|n| n.note_id == note_id).unwrap().text.is_none(),
        "view-only unlock must never write the plaintext back into the in-memory record"
    );

    // Reopen -> asks again: `locked` never clears, so refresh_note_unlock_ui
    // shows the password field again on every fresh open.
    st.on_open_note(&app, note_id.clone().into());
    assert!(app.global::<Ui>().get_note_locked(), "reopening a self-pq note must ask again");
    assert!(app.global::<Note>().get_note_unlock_needs_password());
    assert!(
        app.global::<Note>().get_note_unlock_passphrase().is_empty(),
        "the passphrase field must not carry over across opens"
    );

    // Save again post-unlock (simulating whatever else in the session
    // would trigger a save) — still no plaintext, since the in-memory
    // record was never mutated by the view-only path.
    st.save_store();
    store_json_never_leaked(&store_path);

    keychain::delete_secret(PQ_IMPORTED_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
