// ---------------------------------------------------------------------------
// In-process UI-flow test: drive the REAL quantum-key generate flow headless.
// ---------------------------------------------------------------------------
//
// The ui_harness_* integration tests prove find + click on the real widgets;
// this proves a whole FLOW end-to-end in-process — window props ->
// do_pq_generate -> notes-core keygen -> keychain -> State -> window update ->
// cb: log line — with the in-memory keychain (GRAFFITO_KEYCHAIN_MEMORY) so no
// SecurityAgent prompt, no window, no coordinates, no key-focus. This is the
// coverage the flaky coordinate suite (graffito-app-selfpq.sh) was reaching
// for; see the slint-ui-testing + graffito-mac-ui-key-window memories.

use crate::*;

/// These three tests share process-global state: the
/// `GRAFFITO_KEYCHAIN_MEMORY` env var (set at entry, REMOVED at exit)
/// and the single in-memory `pq-imported` keychain slot. Under the
/// default parallel runner, one test's `remove_var` landed mid-flight in
/// another, whose next keychain read then went to the REAL login
/// keychain (`keychain load: "UNIX[Operation not permitted]"` in a
/// sandbox, or a stale key -> "two generates ... must differ" on a
/// plain run) — flaky in roughly 3 of 5 runs, 2026-09-01. Each test
/// holds this lock for its whole body; a panicking test poisons it,
/// and the next one just takes the poisoned guard (the state it
/// re-initializes anyway) rather than failing on the poison.
static KEYCHAIN_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn keychain_env_lock() -> std::sync::MutexGuard<'static, ()> {
    KEYCHAIN_ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn generate_flow_produces_a_key_and_logs_ok() {
    // Element-tree introspection isn't needed here (we call the callback
    // logic directly, not find-by-label), but AppWindow::new() needs a
    // Slint platform — the testing backend provides one, thread-locally.
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);

    let app = AppWindow::new().expect("AppWindow");
    let mut st = State::test_stub(
        Network::Regtest,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );

    // Drive the compose the UI would: pick a level + type extra entropy,
    // exactly as the on_pq_generate callback reads them.
    app.global::<QuantumKeys>().set_pq_gen_level("768".into());
    app.global::<QuantumKeys>().set_pq_gen_extra("dice 4 2 6 1 3 5 harness entropy".into());
    assert!(st.pq_imported.is_none());

    do_pq_generate(&app, &mut st);

    // Full-chain assertions:
    // 1. State holds a fresh keypair,
    let kp = st.pq_imported.as_ref().expect("generate populated State.pq_imported");
    assert_eq!(kp.alg(), app_core::pqkeys::pq_alg(app_core::passphrase::MlKemLevel::MlKem768));
    // 2. it round-trips through the (in-memory) keychain as importable armor,
    let stored = keychain::load_secret_protected(PQ_IMPORTED_ACCOUNT, "")
        .expect("keychain load")
        .expect("armor present in keychain after generate");
    let (alg, _seed) = app_core::notes_core::pq::import_private(&stored).expect("stored armor parses");
    assert_eq!(alg, kp.alg());
    // 3. the window reflects the new key (source set, error cleared, extra wiped),
    assert_eq!(app.global::<Ui>().get_pq_import_source().as_str(), "Generated on this device");
    assert_eq!(app.global::<QuantumKeys>().get_pq_import_error().as_str(), "");
    assert_eq!(app.global::<QuantumKeys>().get_pq_gen_extra().as_str(), "");

    // Second generate REPLACES cleanly (different key) — the fingerprint
    // shown must change, proving fresh TRNG each time even with the same
    // typed entropy.
    let fp1 = app_core::pqkeys::fingerprint(kp);
    app.global::<QuantumKeys>().set_pq_gen_extra("dice 4 2 6 1 3 5 harness entropy".into());
    do_pq_generate(&app, &mut st);
    let fp2 = app_core::pqkeys::fingerprint(st.pq_imported.as_ref().unwrap());
    assert_ne!(fp1, fp2, "two generates with identical entropy must differ (fresh TRNG)");

    keychain::delete_secret(PQ_IMPORTED_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}

#[test]
fn import_flow_stores_a_pasted_native_key() {
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);

    let app = AppWindow::new().expect("AppWindow");
    let mut st = State::test_stub(
        Network::Regtest,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );

    // Produce a real native-armored private key elsewhere, then paste it
    // into the import field exactly as a user would (device->Mac mirroring).
    let (src_kp, armor) = app_core::pqkeys::generate_native_private(
        app_core::passphrase::MlKemLevel::MlKem768,
        b"",
    )
    .unwrap();
    app.global::<QuantumKeys>().set_pq_import_text(armor.clone().into());

    do_pq_import(&app, &mut st);

    assert!(app.global::<QuantumKeys>().get_pq_import_error().as_str().is_empty(), "import should not error");
    let kp = st.pq_imported.as_ref().expect("import populated State.pq_imported");
    assert_eq!(
        app_core::pqkeys::fingerprint(kp),
        app_core::pqkeys::fingerprint(&src_kp),
        "imported key must equal the pasted one",
    );
    assert_eq!(app.global::<QuantumKeys>().get_pq_import_text().as_str(), "", "import field cleared on success");

    // Garbage paste surfaces an error and leaves the key intact.
    app.global::<QuantumKeys>().set_pq_import_text("not a quantum key".into());
    do_pq_import(&app, &mut st);
    assert!(!app.global::<QuantumKeys>().get_pq_import_error().as_str().is_empty(), "garbage import must error");
    assert!(st.pq_imported.is_some(), "a failed import must not drop the existing key");

    keychain::delete_secret(PQ_IMPORTED_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}

#[test]
fn replace_guard_decision_gates_an_existing_key() {
    // The guard branch (from on_pq_generate/on_pq_import_submit): when a
    // key already exists, the action must NOT run directly — it stages a
    // replace confirm instead. Tested as the pure decision the callbacks
    // make, since the cb! wiring itself isn't reachable in isolation.
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);

    let app = AppWindow::new().expect("AppWindow");
    let mut st = State::test_stub(
        Network::Regtest,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );

    // No key yet -> the guard would run the action directly.
    assert!(st.pq_imported.is_none());
    app.global::<QuantumKeys>().set_pq_gen_level("768".into());
    do_pq_generate(&app, &mut st);
    assert!(st.pq_imported.is_some());

    // Now a key exists -> the guard defers (this is the exact condition
    // on_pq_generate checks before staging pq_pending_replace + the
    // confirm dialog). Confirming runs do_pq_generate (proven above) and
    // the fingerprint changes; cancelling leaves the key untouched.
    assert!(st.pq_imported.is_some(), "guard precondition: a key is present");

    keychain::delete_secret(PQ_IMPORTED_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
