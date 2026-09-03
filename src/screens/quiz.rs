//! Screen.quiz — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn on_quiz_submit(&mut self, w: &AppWindow, answer: SharedString) {
        let Some(phrase) = self.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = self.quiz_indices.iter().map(|i| words[*i]).collect();
        let got: Vec<String> =
            answer.split_whitespace().map(|x| x.to_lowercase()).collect();
        let ok = got == expect;
        println!("cb: quiz ok={ok}");
        if !ok {
            w.global::<Ui>().set_status("mismatch — check your written words and try again".into());
            return;
        }
        // A freshly created seed is a NEW identity — start at account 0, never
        // inheriting a persisted account from a previous identity (Sal
        // 2026-07-22; config.account survives an identity reset).
        self.account = 0;
        self.nb_index = 0;
        match self.activate(&phrase, true) {
            Ok(()) => {
                self.pending_mnemonic = None;
                w.global::<Ui>().set_status("".into());
                // Onboarding unification (Sal 2026-07-21, superseding the
                // 2026-07-11 empty-list rule): creating a seed behaves
                // exactly like importing one — the account's notebook 0
                // (the FIRST receive address) is created, auto-named
                // "Notebook 1", and the notebook LIST opens. More
                // notebooks are added from the list later; unwanted ones
                // archive.
                self.ensure_first_onboarded_notebook();
                self.update_notebook_list(w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                self.refresh_async(w);
                self.spending_refresh_async(w); // CHANGE 5
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    }
}
