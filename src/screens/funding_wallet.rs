//! Screen.funding-wallet — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Populate the funding screen's Notebook row balance. Cheap local
/// derivation only — callers that need fresh chain data call
/// [`refresh_async`]/[`spending_refresh_async`] first (the funding-refresh
/// callback does both).
pub(crate) fn update_funding_screen_ui(&self, w: &AppWindow) {
    let st = self;
    w.global::<PayFrom>().set_funding_notebook_balance(st.balance_text_for("notebook").into());
}

/// `cb: funding-refresh` — logged whenever a background scan the funding
/// screen's ↻ kicked off lands while screen 20 is still open. Notebook and
/// spending scan on independent worker threads (same pattern as
/// `on_refresh_coins`), so this may print twice per tap (once per source
/// landing) — each time with the freshest values known so far.
pub(crate) fn log_funding_refresh(&self) {
    let st = self;
    let notebook = st.store.as_ref().map(|s| s.balance()).unwrap_or(0);
    let spending = if st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false) {
        if st.spending_scanned {
            st.spending_coins.iter().map(|c| c.value).sum::<u64>().to_string()
        } else {
            "?".to_string()
        }
    } else {
        "off".to_string()
    };
    println!("cb: funding-refresh notebook={notebook} spending={spending}");
}
}
