// ---------------------------------------------------------------------------
// In-process UI-flow test, U12: multi-recipient picker (multi-select).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's "multi-select: picker -> primary pick ->
// + Add recipient -> picker (add mode) -> second pick -> chip" leg
// (ui-automation/tests/graffito-app-multi-recipient.sh). Network-free: no
// node URL is configured at all (`base_url()` returns `None`, so
// `refresh_fees_price` — called from `pick_contact_core` — never reaches for
// a client), matching the U12 brief's "picker/chip" leg, which never signs
// or broadcasts anything.
//
// Drives the exact same handlers the real picker taps invoke:
// `on_pick_contact` (primary pick, `picking_extra == false`) ->
// `on_add_recipient_open` (the compose screen's "+ Add recipient" button) ->
// `on_pick_contact` again (`picking_extra == true` routes to
// `add_recipient_chip`) — headless, no window/coordinates/keychain prompt,
// per the slint-ui-testing memory.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Stage an activated (but unfunded — this leg never signs) notebook. No
/// node URL configured at all: this leg never reaches `on_compose_send`, so
/// there's nothing for a bogus node URL to guard here (unlike the selfpq
/// fixtures, which DO reach Sign).
fn picker_stub() -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u12-multiselect-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    let app = AppWindow::new().expect("AppWindow");
    (st, app)
}

/// Two throwaway taproot addresses, generated the same way the app-core
/// multi-recipient test suite does (`Identity::from_app_seed` + `.address`)
/// — no network, no CLI subprocess, unlike the Mac suite's `cn_fresh_hex` +
/// `examples/cli`.
fn recipient_addrs() -> (String, String) {
    let r1 = app_core::notes_core::bundle::Identity::from_app_seed(&[101u8; 32]).unwrap().address(Network::Regtest);
    let r2 = app_core::notes_core::bundle::Identity::from_app_seed(&[102u8; 32]).unwrap().address(Network::Regtest);
    (r1, r2)
}

#[test]
fn picker_multi_select_appends_second_recipient_as_a_chip() {
    let (mut st, app) = picker_stub();
    let (r1, r2) = recipient_addrs();

    // Fresh state: nothing picked, add-mode off.
    assert!(st.to_address.is_none());
    assert!(st.to_addresses_extra.is_empty());
    assert!(!st.picking_extra);
    assert!(!app.global::<Ui>().get_picking_extra());

    // "home: Compose note -> contacts picker" -> primary pick (normal
    // pick-mode, not add-mode): on_pick_contact routes straight to
    // pick_contact_core since picking_extra is false.
    app.global::<Ui>().set_pick_mode("compose".into());
    st.on_pick_contact(&app, r1.clone().into());
    assert_eq!(st.to_address.as_deref(), Some(r1.as_str()), "primary recipient picked");
    assert!(st.to_addresses_extra.is_empty(), "no chips yet");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "primary pick lands on compose");
    assert!(!st.picking_extra, "primary pick is not add-mode");

    // "+ Add recipient" -> reopens the picker in its add-only sub-mode: the
    // add-mode/pick-mode transition the leg's header calls out.
    st.on_add_recipient_open(&app);
    assert!(st.picking_extra, "add-recipient-open must enter add-mode");
    assert!(app.global::<Ui>().get_picking_extra(), "the shell's picking-extra must mirror State (drives the picker's \"Add recipient\" header + hides the Self card)");
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Contacts, "add-recipient-open reopens the picker");
    assert_eq!(app.global::<Ui>().get_pick_mode().as_str(), "compose", "add-mode is still a compose pick, not sweep");

    // Second pick, in add-mode: on_pick_contact must route to
    // add_recipient_chip (NOT pick_contact_core — which would REPLACE the
    // primary instead of appending).
    st.on_pick_contact(&app, r2.clone().into());
    assert_eq!(st.to_address.as_deref(), Some(r1.as_str()), "the primary recipient must be untouched by the second pick");
    assert_eq!(st.to_addresses_extra, vec![r2.clone()], "the second pick must append as an extra chip, not replace");
    assert!(!st.picking_extra, "a successful add-mode pick must leave add-mode");
    assert!(!app.global::<Ui>().get_picking_extra());
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Compose, "second pick returns to compose");

    // The chips global the shell renders the removable To-chip row from.
    let chips = app.global::<Compose>().get_to_chips();
    assert_eq!(chips.row_count(), 1, "exactly one chip beyond the primary");
    let chip = chips.row_data(0).expect("chip row");
    assert_eq!(chip.address.as_str(), r2.as_str(), "the chip must carry the second recipient's address");
}
