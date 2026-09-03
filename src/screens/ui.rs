//! the Ui global — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// Show the transient "Copied" toast. Bumps toast-nonce so a repeat copy
/// while a toast is still on screen extends the ~1.5s auto-dismiss window
/// (the countdown reset lives in app.slint's `changed toast-nonce` handler).
pub(crate) fn show_toast(w: &AppWindow, text: &str) {
    w.global::<Ui>().set_toast_text(text.into());
    w.global::<Ui>().set_toast_nonce(w.global::<Ui>().get_toast_nonce() + 1);
    w.global::<Ui>().set_toast_open(true);
}
