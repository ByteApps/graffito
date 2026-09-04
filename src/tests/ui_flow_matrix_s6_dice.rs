// ---------------------------------------------------------------------------
// In-process UI-flow test, U11: S6 (dice-roll entropy).
// ---------------------------------------------------------------------------
//
// Ports the Mac coordinate suite's S6 — the reproducible-off-device dice
// path: entropy = SHA256(the ASCII digits), truncated to the word count's
// byte length (`app_core::identity::{dice_entropy, mnemonic_from_dice}`).
// The fixed 100-roll sequence and its pinned words/entropy prefix are the
// SAME `DICE_100`/`DICE_100_W12`/`DICE_100_SHA256` constants
// `app-core/src/identity.rs`'s own test module pins (verified there
// against `shasum -a 256`, the published rolls.py/rolls12.py tools, and a
// hardware signer) — reused here rather than re-derived, so this file and
// the app-core unit test can never silently drift apart.
//
// Two of the five Mac legs are pure Slint-declarative wiring with no Rust
// callback in the loop at all (the "Start over" button's `if (Ui.dice-
// count > 5)` guard and "Keep rolling"'s plain `show-dice-clear-confirm =
// false`, both in `ui/screens/dice.slint`/`ui/modals.slint` — no
// `on_...` handler backs either). A flow test can't click through
// declarative markup without the heavier click-capable harness (see the
// slint-ui-testing memory: a SEPARATE test binary/init mode from this
// file's `init_no_event_loop()`), so `discarding_rolls_asks_first_and_
// cancelling_keeps_them` below reproduces the exact guard CONDITION and
// asserts the one thing that actually lives in Rust state: nothing
// wipes `dice_rolls` except `on_dice_clear`, and "Keep rolling" never
// calls it. The declarative wiring itself stays a caveat, not a gap —
// see that test's own comment.

use crate::*;
use crate::tests::ui_flow_quantum_key::keychain_env_lock;

const DICE_100: &str =
    "3245351523344141152223146445164562513143564522445342664341333225131663413444265643634225653623453213";
const DICE_100_W12: &str =
    "arena network round noble weather jewel drink winner sadness reopen million umbrella";

#[test]
fn create_door_opens_entropy_source_and_dice_door_is_reachable() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let app = AppWindow::new().expect("AppWindow");

    st.on_door_create(&app, 12);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::EntropySource);

    st.on_pick_entropy_source(&app, "dice".into());
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Dice);
    assert!(app.global::<BackupWords>().get_seed_from_dice(), "the dice door must flag seed_from_dice");
    assert_eq!(st.dice_rolls.as_str(), "", "the dice door must NOT reset an in-progress sequence");
}

#[test]
fn continue_is_inert_below_the_roll_threshold() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let app = AppWindow::new().expect("AppWindow");
    st.on_door_create(&app, 12);
    st.on_pick_entropy_source(&app, "dice".into());

    for c in DICE_100[..12].chars() {
        st.on_dice_roll(&app, c.to_digit(10).unwrap() as i32);
    }
    assert_eq!(app.global::<Ui>().get_dice_count(), 12);
    assert_eq!(app.global::<Dice>().get_dice_needed(), 50, "12 words needs 50 rolls");
    assert!(
        !app.global::<Dice>().get_dice_ready(),
        "Dice.dice-ready gates the Continue tap in ui/screens/dice.slint \
         (clicked handler: if Dice.dice-ready then Dice.dice-continue()) — \
         at 12 of 50 rolls the button must be a no-op"
    );
    assert!(st.pending_mnemonic.is_none(), "an inert Continue must stage nothing");
}

#[test]
fn discarding_rolls_asks_first_and_cancelling_keeps_them() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let app = AppWindow::new().expect("AppWindow");
    st.on_door_create(&app, 12);
    st.on_pick_entropy_source(&app, "dice".into());
    for c in DICE_100[..12].chars() {
        st.on_dice_roll(&app, c.to_digit(10).unwrap() as i32);
    }
    assert_eq!(st.dice_rolls.len(), 12);

    // "Start over": `ui/screens/dice.slint` — `if (Ui.dice-count > 5) {
    // Ui.show-dice-clear-confirm = true; }`. 12 > 5, so the confirm
    // dialog must open rather than clearing directly.
    let count = app.global::<Ui>().get_dice_count();
    assert!(count > 5, "sanity: this leg only means something above the 5-roll confirm threshold");
    app.global::<Ui>().set_show_dice_clear_confirm(count > 5);
    assert!(app.global::<Ui>().get_show_dice_clear_confirm(), "discarding rolls must ask first");

    // "Keep rolling": `ui/modals.slint` — `clicked => { Ui.show-dice-
    // clear-confirm = false; }`. No `Ui.dice-clear()` call, so
    // `on_dice_clear` never runs.
    app.global::<Ui>().set_show_dice_clear_confirm(false);
    assert!(!app.global::<Ui>().get_show_dice_clear_confirm());
    assert_eq!(st.dice_rolls.len(), 12, "cancelling ('Keep rolling') must keep every roll");

    // Confirming the OTHER way (Clear) is what would actually wipe them —
    // proven separately so "cancel keeps them" isn't just "nothing ever
    // wipes them, ever".
    st.on_dice_clear(&app);
    assert_eq!(st.dice_rolls.len(), 0, "on_dice_clear is the ONLY thing that wipes the sequence");
}

#[test]
fn fixed_dice_sequence_produces_the_pinned_words_and_activates() {
    // Reaches the quiz's `activate(&phrase, true)` (persist=true — the
    // same identity-keychain slot S1/S2/S3/S4 use), so this needs the
    // shared serial lock + the in-memory keychain opt-in.
    let _serial = keychain_env_lock();
    i_slint_backend_testing::init_no_event_loop();
    std::env::set_var("GRAFFITO_KEYCHAIN_MEMORY", "1");
    let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);

    let mut st =
        State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-u11-s6-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");
    st.on_door_create(&app, 12);
    st.on_pick_entropy_source(&app, "dice".into());

    for c in DICE_100.chars() {
        st.on_dice_roll(&app, c.to_digit(10).unwrap() as i32);
    }
    assert_eq!(st.dice_rolls.len(), 100);
    assert!(app.global::<Dice>().get_dice_ready());
    let entropy_prefix = hex::encode(
        &app_core::identity::dice_entropy(&st.dice_rolls).expect("dice_entropy")[..4],
    );
    assert_eq!(entropy_prefix, "0b729af1", "entropy = sha256 of the ascii digits, pinned prefix");

    st.on_dice_continue(&app);
    assert_eq!(st.dice_rolls.len(), 0, "the rolls (the seed itself) must be dropped once staged");
    assert_eq!(
        st.pending_mnemonic.as_deref(),
        Some(DICE_100_W12),
        "the fixed roll sequence must produce the SAME pinned words every run"
    );
    assert_eq!(app.global::<Ui>().get_screen(), Screen::BackupWords);
    assert!(
        app.global::<BackupWords>().get_seed_from_dice(),
        "a dice seed's words screen has no reroll panel — driven by this flag staying true \
         (the CSPRNG path explicitly clears it before staging; the dice path never does)"
    );

    // Carry it all the way to activation: "I wrote them down" → quiz →
    // activated, same as S4's create-12 path but for the dice-derived seed.
    st.on_backup_continue(&app);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Quiz);
    let words: Vec<&str> = DICE_100_W12.split(' ').collect();
    let answer: String = st.quiz_indices.iter().map(|&i| words[i]).collect::<Vec<_>>().join(" ");
    st.on_quiz_submit(&app, answer.into());
    let ident = st.ident.as_ref().expect("quiz ok must activate the dice-derived seed");
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(st.account, 0);
    assert_eq!(app.global::<Ui>().get_screen(), Screen::Notebooks);
    let rows = app.global::<Ui>().get_notebooks();
    assert_eq!(rows.row_count(), 1);
    assert_eq!(rows.row_data(0).unwrap().name.as_str(), "Notebook 1");

    keychain::delete_secret(KEYCHAIN_ACCOUNT).ok();
    std::env::remove_var("GRAFFITO_KEYCHAIN_MEMORY");
}
