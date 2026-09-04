// ---------------------------------------------------------------------------
// In-process UI-flow test, U11: S3 (mnemonic import, account picker,
// disabled-spending gate).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's S3 — a hierarchical (mnemonic) import
// skips the account picker entirely (activates account 0 directly, its
// first notebook auto-created), the default-OFF spending wallet is not
// scanned on import, and Settings → Change account… to a fresh account
// auto-creates ITS first notebook too. All three are local: `activate()`
// and `on_pick_account` never reach `base_url()` on a node-less regtest
// stub (see `app-core/src/chain/client.rs::default_base`, `None` for
// regtest) except for the spending scan, which is gated even earlier —
// see `spending_disabled_gate_precedes_any_scan_admission` below.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn mnemonic_import_lands_on_notebook_list_no_picker_first_notebook_auto_created() {
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s3-import-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");

    // `spending_capable` isn't set until `activate()` runs, so nothing to
    // assert about the gate until after the import below (see the
    // dedicated gate test for why the gate's OUTCOME can't be
    // distinguished from "no node configured" without inspecting source —
    // and why that's the honest thing to do here rather than faking it).
    st.on_import_confirm(&app, MNEMONIC.into());

    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Notebooks,
        "a hierarchical import lands DIRECTLY on the notebook list — no account picker"
    );
    assert_eq!(st.account, 0);
    assert_eq!(st.nb_index, 0);
    let ident = st.ident.as_ref().expect("import populated State.ident");
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(ident.account, 0);
    assert_eq!(ident.index, 0);

    let rows = app.global::<Ui>().get_notebooks();
    assert_eq!(rows.row_count(), 1, "the first notebook must be auto-created");
    assert_eq!(
        rows.row_data(0).unwrap().name.as_str(),
        "Notebook 1",
        "it must carry the shared default name"
    );
    assert_eq!(app.global::<Notebooks>().get_archived_notebooks().row_count(), 0);

    // The disabled-spending gate (Sal 2026-07-22): capable (mnemonic is
    // hierarchical) but OFF by default, so nothing was ever admitted to
    // the spending scan lane.
    assert!(st.spending_capable, "a mnemonic identity must be spending-capable");
    assert!(
        !st.store.as_ref().unwrap().spending.enabled,
        "the spending wallet must start disabled (opt-in, default OFF)"
    );
    assert!(
        !st.scan_gate.spending_busy(),
        "no spending scan may have been admitted to the lane while disabled"
    );
    assert!(!st.spending_scanned, "a disabled spending wallet is never marked scanned");

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}

/// Behavioral proof (above) can't tell "the disabled check fired" apart
/// from "there's simply no node configured in this hermetic test" — BOTH
/// return before `scan_gate.spending_busy()` could ever become true, since
/// this whole file runs with an empty `node_urls` map on purpose (S3 is a
/// network-free port; wiring in even a bogus-but-dialed node to force the
/// distinction would spawn a real background HTTP attempt, which is
/// exactly what this port exists to avoid — see `ui_flow_selfpq_
/// passphrase.rs`'s header for the one place this codebase DOES accept a
/// bogus-but-never-dialed node URL, which doesn't apply here since
/// reaching the lane-submit at all would dial it).
///
/// So this closes the gap the same way `core_rpc_wiring_contract.rs`
/// (this same `src/tests/` directory) already does for an equally
/// unreachable-without-live-infra invariant: read the ACTUAL source of
/// `spending_scan_async` (mutation included — this isn't `include_str!`
/// of a frozen copy) and assert the disabled-check's `return` sits
/// textually BEFORE the lane-submission call. Brittle in the same
/// accepted way as every `cb:`/`cli:` log-grep contract this workspace
/// already leans on (see the workspace CLAUDE.md), but it's what turns
/// red if the check is ever deleted, reordered after the lane-submit, or
/// its condition flipped.
#[test]
fn spending_disabled_gate_precedes_any_scan_admission() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pending.rs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let start = src
        .find("pub(crate) fn spending_scan_async(")
        .expect("spending_scan_async must still exist in src/pending.rs");
    let body = &src[start..];
    // Bound the search to THIS function's body via brace counting, so a
    // later function's own `scan_lane_submit`-shaped text can't fool the
    // ordering check.
    let open = body.find('{').expect("function body must open with {");
    let bytes = body.as_bytes();
    let mut depth = 0i32;
    let mut end = open;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let func = &body[..=end];
    let disabled_check = func
        .find("cb: spending-refresh skipped=disabled")
        .expect("the disabled-gate log line must still exist inside spending_scan_async");
    let lane_submit = func
        .find("scan_lane_submit(")
        .expect("spending_scan_async must still submit through the scan lane");
    assert!(
        disabled_check < lane_submit,
        "the disabled-gate check must run BEFORE the scan is ever submitted to the lane \
         (disabled_check byte {disabled_check} vs lane_submit byte {lane_submit}) — a spending \
         scan admitted before this check would run for every disabled wallet"
    );
}

#[test]
fn account_switch_to_fresh_account_auto_creates_its_first_notebook() {
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s3-account-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");
    st.on_import_confirm(&app, MNEMONIC.into());
    assert_eq!(st.account, 0);

    // Settings → "Change account…" opens the switch-mode picker.
    st.on_open_account_picker(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::AccountPicker);
    assert_eq!(app.global::<AccountPicker>().get_account_pick_mode().as_str(), "switch");

    // Pick account 6 (the row S3's own picker page-2 tap lands on).
    st.on_pick_account(&app, 6);

    assert_eq!(st.account, 6);
    assert_eq!(st.nb_index, 0);
    let ident = st.ident.as_ref().expect("account switch re-activated");
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(ident.account, 6);
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Notebooks,
        "a fresh account switch lands on ITS notebook list"
    );
    let rows = app.global::<Ui>().get_notebooks();
    assert_eq!(rows.row_count(), 1, "a fresh account must auto-create its own first notebook");
    assert_eq!(rows.row_data(0).unwrap().name.as_str(), "Notebook 1");

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
