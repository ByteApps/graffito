//! Screen.terms — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn on_accept_terms(&mut self, w: &AppWindow) {
        self.terms_accepted = true;
        self.save_config();
        // `target` stays the old int purely for the log line below, which is
        // NOT part of U2's log-contract change (only `cb: sys-back` is) —
        // `target_screen` is the real Screen value passed to the window.
        let target = if self.material.is_some() { 17 } else { 0 };
        let target_screen = if self.material.is_some() { Screen::Notebooks } else { Screen::Onboarding };
        w.global::<Ui>().set_terms_accept_mode(false);
        w.global::<Ui>().set_screen(target_screen);
        println!("cb: accept-terms target={target}");
    }
}
