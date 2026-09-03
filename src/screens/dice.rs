//! Screen.dice — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Repaint the dice screen: counter, remaining, the LIVE hash, and whether
/// Continue is allowed.
///
/// The hash is shown deliberately and is not a secret leak in itself — it is
/// the seed entropy, but the user is staring at it, and being able to compare
/// it to `shasum -a 256` is the entire reason this mode exists. It is never
/// written to a log.
pub(crate) fn update_dice_ui(&self, w: &AppWindow) {
    let s = self;
    use app_core::identity::{dice_face_counts, dice_entropy, dice_min_rolls};
    let rolls: &str = &s.dice_rolls;
    let count = rolls.len();
    let need = dice_min_rolls(s.new_word_count).unwrap_or(99);
    let hex_all = dice_entropy(rolls).map(hex::encode).unwrap_or_default();
    let (a, b) = hex_all.split_at(hex_all.len().min(32));
    w.global::<Ui>().set_dice_count(count as i32);
    w.global::<Dice>().set_dice_needed(need as i32);
    w.global::<Ui>().set_dice_hash(a.into());
    w.global::<Dice>().set_dice_hash2(b.into());

    // Distribution sanity, same spirit as the reference implementations: a
    // face appearing far more than its 1/6 share usually means a loaded die or
    // invented numbers. Only meaningful once there are enough rolls to judge,
    // and it WARNS rather than blocks — an honest 100 rolls really can be
    // lopsided, and refusing would just teach people to fake a nicer-looking
    // sequence.
    let counts = dice_face_counts(rolls);
    let skewed = count >= 20 && counts.iter().any(|&c| c * 10 > count * 3);
    w.global::<Dice>().set_dice_warning(if skewed {
        "One number is coming up more than 30% of the time — if that's a real die, keep rolling.".into()
    } else {
        "".into()
    });
    w.global::<Dice>().set_dice_ready(count >= need);
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_dice_undo(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.dice_rolls.pop();
        s.update_dice_ui(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_dice_continue(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let words = s.new_word_count;
        let rolls = s.dice_rolls.clone();
        match app_core::identity::mnemonic_from_dice(&rolls, words) {
            Ok(m) => {
                // Count + the (already on-screen, therefore non-secret) hash
                // only — never the rolls, which are the seed itself.
                println!(
                    "cb: dice-continue rolls={} words={words} entropy={}",
                    rolls.len(),
                    hex::encode(
                        &app_core::identity::dice_entropy(&rolls).unwrap_or([0u8; 32])[..4]
                    )
                );
                s.stage_new_mnemonic(w, m.to_string());
                // The rolls ARE the seed, so drop them the moment the mnemonic
                // exists — holding them for the rest of the session would keep
                // a second copy of the secret in memory for no reason. Nothing
                // can navigate back to the dice screen from here (back on the
                // words screen goes to onboarding), so there is nothing to
                // preserve them for.
                s.dice_rolls = Zeroizing::new(String::new());
            }
            Err(e) => {
                println!("cb: dice-continue err");
                w.global::<Ui>().set_status(format!("{e}").into());
            }
        }
    }
}
