// ---------------------------------------------------------------------------
// In-process UI-flow test, U11: S4 (create-seed onboarding, contact
// rename/remove, settings pills) — the network-free slice.
// ---------------------------------------------------------------------------
//
// Ports the parts of the Mac coordinate suite's S4 that need no chain and
// no faucet: create-12 → backup words → quiz → activated (landing
// directly on the notebook list, auto-named "Notebook 1" — the unified-
// onboarding contract), contact rename via the dialog, contact remove via
// the confirmation dialog, and the chunk/network settings pills
// round-tripping into `config.json`. The funding/directed-compose/
// activity/recipient-decrypt/coins/consolidate legs of S4 all need the
// regtest node + faucet and STAY in the Mac suite (graffito-app-matrix.sh)
// — see the workspace CLAUDE.md's `e2e-scripted-not-interactive` note for
// why those stay scripted rather than ported here.
//
// Contacts don't need a real directed-note compose to exist — S4's own
// contact is just whatever `on_compose_send` pushed into `State.contacts`
// via the recents list, and `on_start_rename`/`on_save_rename`/
// `on_confirm_remove`/`on_remove_contact` don't care how a contact got
// there. So the contact + settings legs below use a plain mnemonic-
// activated stub (persist=false — no keychain needed) with a contact
// pushed directly, rather than re-running the whole create-seed dance.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn create_seed_backup_quiz_lands_on_notebook_list_named_notebook_1() {
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s4-create-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");

    // Door: "Create a new 12-word seed" → the entropy-source screen (dice
    // feature, 2026-08-02) — picking "This device" generates immediately.
    st.on_door_create(&app, 12);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::EntropySource);
    assert_eq!(st.new_word_count, 12);

    st.on_pick_entropy_source(&app, "device".into());
    assert_eq!(app.global::<Ui>().get_screen(), Screen::BackupWords);
    assert!(!app.global::<BackupWords>().get_seed_from_dice());
    let phrase = st.pending_mnemonic.clone().expect("staged mnemonic");
    assert_eq!(phrase.split(' ').count(), 12);

    // "I wrote them down" → the backup quiz. `quiz_indices` is read
    // straight off State (the shell's own record of what it asked) rather
    // than grepping the `cb-test: quiz=` log line the Mac suite needs.
    st.on_backup_continue(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Quiz);
    assert_eq!(st.quiz_indices.len(), 3);
    let words: Vec<&str> = phrase.split(' ').collect();
    let answer: String =
        st.quiz_indices.iter().map(|&i| words[i]).collect::<Vec<_>>().join(" ");

    // Wrong answer: stays on the quiz, no identity yet.
    st.on_quiz_submit(&app, "definitely wrong words here".into());
    assert!(st.ident.is_none(), "a wrong quiz answer must not activate anything");
    assert!(!app.global::<Ui>().get_status().is_empty(), "a mismatch must surface a status message");

    // Right answer → activated, landing DIRECTLY on the notebook list
    // (unified onboarding, 2026-07-21 — no create-picker step). Status
    // isn't asserted empty here: `on_quiz_submit`'s success path clears it
    // and then immediately calls the real `refresh_async`, which (this
    // stub has no node configured, same as `default_base(Regtest) ==
    // None`) overwrites it with "no Bitcoin node…" — exactly what a real
    // user would see too until Settings points at one (S4's Mac leg does
    // that next, via `set_node_via_settings`). Not this leg's contract.
    st.on_quiz_submit(&app, answer.into());
    let ident = st.ident.as_ref().expect("quiz ok must activate");
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(st.account, 0);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Notebooks,
        "the quiz must land directly on the notebook list"
    );
    let rows = app.global::<Ui>().get_notebooks();
    assert_eq!(rows.row_count(), 1);
    assert_eq!(rows.row_data(0).unwrap().name.as_str(), "Notebook 1");

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}

/// A mnemonic-activated stub with NO keychain persistence (`activate(...,
/// false)`) — contacts and settings don't touch the identity keychain
/// slot at all, so this doesn't need `keychain_env_lock`/
/// `GRAFFITO_KEYCHAIN_MEMORY` the way the create-seed test above does.
fn activated_stub(tag: &str) -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s4-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    let app = AppWindow::new().expect("AppWindow");
    (st, app)
}

#[test]
fn contact_rename_via_dialog_and_remove_via_confirmation() {
    let (mut st, app) = activated_stub("contacts");
    let addr = "bcrt1pfriend0000000000000000000000000000000000000000000000000000".to_string();
    st.contacts.push(app_core::store::Contact {
        address: addr.clone(),
        name: "friend".to_string(),
        network: st.network.as_str().to_string(),
        updated_at: 0,
        synced: false,
        mlkem_ek: None,
    });

    // Pencil tap opens the rename dialog, seeded from the contact.
    st.on_start_rename(&app, addr.clone().into(), "friend".into(), false);
    assert_eq!(app.global::<Ui>().get_rename_address().as_str(), addr);
    assert_eq!(app.global::<Modals>().get_rename_input().as_str(), "friend");

    st.on_save_rename(&app, "matrix friend".into());
    assert_eq!(app.global::<Ui>().get_rename_address().as_str(), "", "the dialog closes on save");
    let renamed = st.contacts.iter().find(|c| c.address == addr).expect("contact still present");
    assert_eq!(renamed.name, "matrix friend");

    // × tap stages the confirm dialog (does NOT remove yet).
    st.on_confirm_remove(&app, addr.clone().into(), "matrix friend".into());
    assert_eq!(app.global::<Ui>().get_confirm_remove_address().as_str(), addr);
    assert_eq!(st.contacts.len(), 1, "staging the confirm dialog must not remove anything yet");

    // Remove (confirm modal) → the actual removal + a tombstone.
    st.on_remove_contact(&app, addr.clone().into());
    assert!(st.contacts.iter().all(|c| c.address != addr), "the contact must be gone");
    assert_eq!(app.global::<Ui>().get_confirm_remove_address().as_str(), "");
    assert!(
        st.tombstones.iter().any(|t| t.address == addr && t.network == st.network.as_str()),
        "removal must record a tombstone for cross-device deletion sync"
    );
}

#[test]
fn settings_pills_chunk_and_network_round_trip_into_config() {
    let (mut st, app) = activated_stub("settings");
    let config_path = st.data_dir.join("config.json");

    // Chunk pill: 80 (compat).
    st.on_set_chunk(&app, "80".into());
    assert_eq!(st.chunk, Some(80));
    assert_eq!(st.store.as_ref().unwrap().chunk_size, 80);
    assert_eq!(app.global::<Settings>().get_chunk_text().as_str(), "80");
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config.json"))
            .expect("config.json parses");
    assert_eq!(cfg["chunk"], serde_json::json!(80));

    // Network pill: signet, then back to regtest.
    st.on_set_network(&app, "signet".into());
    assert_eq!(st.network, Network::Signet);
    assert_eq!(app.global::<Settings>().get_settings_network().as_str(), "signet");
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config.json"))
            .expect("config.json parses");
    assert_eq!(cfg["network"], serde_json::json!("signet"));

    st.on_set_network(&app, "regtest".into());
    assert_eq!(st.network, Network::Regtest);
    assert_eq!(app.global::<Settings>().get_settings_network().as_str(), "regtest");
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config.json"))
            .expect("config.json parses");
    assert_eq!(cfg["network"], serde_json::json!("regtest"));
    // The chunk choice is device-level (Settings, not per-notebook) and
    // must survive the round trip through both network switches.
    assert_eq!(cfg["chunk"], serde_json::json!(80));
}
