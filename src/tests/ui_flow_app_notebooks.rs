// ---------------------------------------------------------------------------
// In-process UI-flow test, U10: notebooks create -> name -> open -> archive.
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "notebooks: create -> name -> open ->
// archive" leg (ui-automation/tests/graffito-app.sh) — drives the exact
// production handlers (`on_create_notebook`, `on_pick_account`'s "notebook"
// create branch, `on_nb_archive`) headless, asserting the same contract the
// Mac leg's `cb:` greps check (picker opens, the notebook is created+named,
// the list count/archived count move, the archive guard) via State/window
// globals instead of a log file.
//
// One deliberate divergence from `on_open_notebook` itself: that handler's
// synchronous half (`activate()` for the new index) is exactly what "open"
// means here, but its tail unconditionally kicks `refresh_async` +
// `spending_refresh_async` — real network dials against whatever node is
// configured. This suite stays network-free (workspace CLAUDE.md /
// U10 brief), so "open" is driven by calling the SAME `activate()` the
// handler calls, with the same `nb_index` assignment, stopping short of the
// two async kicks — the observable this leg's Mac assertion checks
// (`cb: open-notebook index=1`) is exactly "the active identity is now
// notebook 1", which this proves directly via `st.ident`.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn create_name_open_archive() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u10-notebooks-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    // A fresh multi-notebook identity's index starts EMPTY — `activate()`
    // only migrates a pre-existing store into "Main"; a truly fresh boot
    // adds notebook 0 explicitly (onboarding.rs's post-activate
    // `ensure_notebook(0)`, mirrored here since this fixture has no
    // pre-existing store to migrate).
    st.ensure_notebook(0);

    let app = AppWindow::new().expect("AppWindow");
    st.update_notebook_list(&app);
    assert_eq!(app.global::<Ui>().get_notebooks().row_count(), 1, "baseline: one notebook (0)");
    assert_eq!(app.global::<Notebooks>().get_archived_notebooks().row_count(), 0, "baseline: nothing archived");

    // "+ New notebook" -> the create-flavor account picker (screen 21).
    st.on_create_notebook(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::AccountPicker, "create opens the picker");
    assert_eq!(app.global::<AccountPicker>().get_account_pick_mode().as_str(), "notebook");

    // Inline name field, then tap the row for receive index 1 — creates
    // immediately (index 0 is disabled/already a notebook).
    app.global::<AccountPicker>().set_nb_create_name("E2E scratch".into());
    st.on_pick_account(&app, 1);

    let meta = st.notebooks.as_ref().unwrap().get(0, 1).cloned().expect("notebook 1 exists");
    assert_eq!(meta.name, "E2E scratch", "the inline name must land on the new notebook");
    assert!(!meta.archived);
    assert_eq!(app.global::<AccountPicker>().get_account_pick_mode().as_str(), "switch", "picker mode resets");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Notebooks, "create lands back on the list");
    assert_eq!(app.global::<Ui>().get_notebooks().row_count(), 2, "two notebooks listed");
    assert_eq!(app.global::<Notebooks>().get_archived_notebooks().row_count(), 0);

    // Open the new notebook: the same `activate()` call
    // `on_open_notebook` makes (see this file's header for why the
    // network-dialing tail is skipped here).
    let material = st.material.as_ref().unwrap().to_string();
    st.nb_index = 1;
    st.activate(&material, false).expect("open notebook 1");
    assert_eq!(st.ident.as_ref().unwrap().index, 1, "the active identity is now notebook 1");

    // Archive it (0 sats -> allowed). The guard reads `notebook_store(1)`,
    // which resolves to the just-activated (empty) live store.
    st.on_nb_archive(&app, 1, true);
    let meta = st.notebooks.as_ref().unwrap().get(0, 1).cloned().expect("notebook 1 still on the index");
    assert!(meta.archived, "notebook 1 must be archived");
    assert_eq!(app.global::<Ui>().get_notebooks().row_count(), 1, "one active notebook remains");
    assert_eq!(app.global::<Notebooks>().get_archived_notebooks().row_count(), 1, "one archived notebook");
}
