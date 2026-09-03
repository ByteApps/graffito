//! Screen.quiz — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
#[allow(unused_variables)]
pub(crate) fn on_quiz_submit(&mut self, w: &AppWindow, answer: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = s.quiz_indices.iter().map(|i| words[*i]).collect();
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
        s.account = 0;
        s.nb_index = 0;
        match s.activate(&phrase, true) {
            Ok(()) => {
                s.pending_mnemonic = None;
                w.global::<Ui>().set_status("".into());
                // Onboarding unification (Sal 2026-07-21, superseding the
                // 2026-07-11 empty-list rule): creating a seed behaves
                // exactly like importing one — the account's notebook 0
                // (the FIRST receive address) is created, auto-named
                // "Notebook 1", and the notebook LIST opens. More
                // notebooks are added from the list later; unwanted ones
                // archive.
                s.ensure_first_onboarded_notebook();
                s.update_notebook_list(w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                s.refresh_async(w);
                s.spending_refresh_async(w); // CHANGE 5
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    }
}
