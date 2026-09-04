// ---------------------------------------------------------------------------
// In-process UI-flow test, U11: S2 (WIF import + reset).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's S2 — the WIF sibling of S1's hex leg
// (same `on_import_confirm`/single-key/no-picker/no-network shape, see
// that file's header for the shared reasoning). `PINNED_WIF` is the exact
// string the shell suite's inline Python constructs at runtime: version
// byte 0xef (testnet/regtest), 32 bytes of 0x07, the compressed flag
// 0x01, base58check-encoded — computed once (`app-core`'s own CLI,
// `APP_KEY=<wif> cli address regtest`, matches this file's `PINNED_WIF_
// ADDR`) and pinned here as a plain literal rather than re-deriving
// base58/SHA256 in this test file (no extra crate dependency needed for
// what's fundamentally a fixed input).

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const PINNED_WIF: &str = "cMpMxK92W1DjqDvWV3pMn4xLwAuQJhNF3MFqkEHUQRPQofUJku8R";
const PINNED_WIF_ADDR: &str =
    "bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm";

#[test]
fn wif_import_lands_on_home_with_pinned_address() {
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s2-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");

    st.on_import_confirm(&app, PINNED_WIF.into());

    assert_eq!(
        app.global::<Ui>().get_screen(),
        Screen::Home,
        "a single-key (WIF) import lands directly on its one intrinsic notebook's home"
    );
    assert_eq!(app.global::<Ui>().get_address().as_str(), PINNED_WIF_ADDR);
    let ident = st.ident.as_ref().expect("import populated State.ident");
    assert_eq!(ident.address, PINNED_WIF_ADDR);
    assert_eq!(ident.kind, "wif");

    st.on_reset_identity(&app);
    assert!(st.ident.is_none());
    assert_eq!(
        keychain::load_secret_protected(KEYCHAIN_ACCOUNT, "").expect("keychain load"),
        None,
        "reset must delete the identity-key keychain item"
    );

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
