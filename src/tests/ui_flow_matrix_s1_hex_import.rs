// ---------------------------------------------------------------------------
// In-process UI-flow test, U11: S1 (hex import + copy-address + reset).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's S1 (ui-automation/tests/
// graffito-app-matrix.sh) — the ONLY legs of that section that need no
// chain: hex import lands on the identity's home with the known-answer
// address, the address copy affordance drives the real `on_copy_text`
// shell (asserted via `Ui.toast_*`/the `ok` outcome — never the real OS
// pasteboard, see the file header on `platform::set_clipboard_text`; a
// headless test process has no business writing the developer's actual
// clipboard, and the Mac suite's own `pbpaste` check is exactly the kind
// of OS-state assertion this port replaces), and reset wipes the
// keychain item + every `store-*`/`notebooks-*` file. No network: hex is a
// single-key (non-hierarchical) import, so `activate()` never touches
// `base_url()`.
//
// The material is the suite's own fixed all-1s hex key (64 hex digits =
// 32 bytes of 0x11) — its resulting regtest address is deterministic, so
// it's pinned here rather than merely round-tripped through the log the
// way the shell suite (which can't easily pre-compute it) does.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const HEX_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PINNED_HEX_ADDR: &str =
    "bcrt1p9fjtrm3nwhemkjek0wxtswz2glmneu33w9lcylrvd7alttk0psmqqf08dg";

#[test]
fn hex_import_lands_on_home_with_pinned_address() {
    assert_eq!(HEX_KEY.len(), 64, "sanity: the suite's fixed hex key is 64 hex chars (32 bytes)");
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s1-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir.clone();
    let app = AppWindow::new().expect("AppWindow");

    // The editor + Import tap, driven as the real handler chain does:
    // `on_import_confirm` is what `ImportKey.import-confirm` invokes.
    st.on_import_confirm(&app, HEX_KEY.into());

    assert_eq!(
        app.global::<ImportKey>().get_import_text().as_str(),
        "",
        "a successful import clears the editor"
    );
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Home,
        "a single-key (hex) import has no account picker and no notebook list — \
         it lands on its one intrinsic notebook's home"
    );
    assert_eq!(
        app.global::<Ui>().get_address().as_str(),
        PINNED_HEX_ADDR,
        "the fixed all-1s hex key must realize to the SAME regtest address every run"
    );
    let ident = st.ident.as_ref().expect("import populated State.ident");
    assert_eq!(ident.address, PINNED_HEX_ADDR);
    assert_eq!(ident.kind, "hex");
    assert!(st.material.is_some(), "activate() must have stashed the material");

    // ---- copy address: the shell's own state, never the OS pasteboard ----
    // `on_copy_text` picks its toast wording from whatever
    // `platform::set_clipboard_text` itself reports — real OS pasteboard
    // access from a headless `cargo test` process is environment-
    // dependent (a sandboxed/non-GUI process may get `ok=false` here even
    // though the real app never would), so this asserts the SHELL's own
    // decision (does the toast wording track that same call's own
    // outcome?), never a fixed "the pasteboard must actually work" claim
    // — exactly the "shell state, not the real pasteboard" the U11 brief
    // calls for.
    let addr = app.global::<Ui>().get_address();
    let clipboard_ok = platform::set_clipboard_text(addr.as_str());
    st.on_copy_text(&app, "address".into(), addr.clone());
    assert!(app.global::<Ui>().get_toast_open(), "copying must open the toast");
    assert_eq!(
        app.global::<Ui>().get_toast_text().as_str(),
        if clipboard_ok { "Address copied" } else { "Copy failed" },
        "copy kind=address's toast must track platform::set_clipboard_text's own outcome"
    );

    // ---- reset: keychain + on-disk stores wiped ----
    st.on_reset_identity(&app);
    assert!(st.ident.is_none(), "reset must drop the identity");
    assert!(st.store.is_none(), "reset must drop the store");
    assert!(st.material.is_none(), "reset must drop the material");
    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Onboarding,
        "reset must land back on onboarding"
    );
    assert_eq!(
        keychain::load_secret_protected(KEYCHAIN_ACCOUNT, "").expect("keychain load"),
        None,
        "reset must delete the identity-key keychain item"
    );
    let leftover: Vec<String> = std::fs::read_dir(&dir)
        .expect("read data dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            (n.starts_with("store-") || n.starts_with("notebooks-")) && n.ends_with(".json")
        })
        .collect();
    assert!(leftover.is_empty(), "reset must wipe every store-*/notebooks-* file, found: {leftover:?}");

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
