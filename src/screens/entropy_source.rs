//! Screen.entropy-source — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
#[allow(unused_variables)]
pub(crate) fn on_pick_entropy_source(&mut self, w: &AppWindow, kind: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let words = s.new_word_count;
        println!("cb: entropy-source {kind} words={words}");
        match kind.as_str() {
            "dice" => {
                // Deliberately does NOT reset the rolls: the back chevron on
                // the dice screen lands here, so wiping on entry meant a
                // mis-tap silently destroyed several minutes of rolling with
                // no warning and no undo. A fresh sequence starts at
                // `door_create` (a genuinely new seed) or via "Start over",
                // which now confirms.
                w.global::<BackupWords>().set_seed_from_dice(true);
                s.update_dice_ui(w);
                w.global::<Ui>().set_screen(Screen::Dice);
            }
            _ => match generate_mnemonic(words) {
                Ok(m) => {
                    w.global::<BackupWords>().set_seed_from_dice(false);
                    s.stage_new_mnemonic(w, m.to_string());
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            },
        }
    }
}
