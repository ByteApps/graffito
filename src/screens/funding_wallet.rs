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

impl State {
#[allow(unused_variables)]
pub(crate) fn on_funding_changed(&mut self, w: &AppWindow, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let net = s.network;
        let _ = &mut s;
        let t = text.trim();
        if t.is_empty() {
            w.global::<FundingWalletScreen>().set_funding_feedback("".into());
            w.global::<FundingWalletScreen>().set_funding_valid(false);
            return;
        }
        if t.to_lowercase().starts_with("ur:") {
            w.global::<FundingWalletScreen>().set_funding_feedback("Hardware-wallet export (UR) — press Save & use to import.".into());
            w.global::<FundingWalletScreen>().set_funding_valid(true);
            return;
        }
        match FundingSource::parse(&extract_descriptor(t), net) {
            Ok(src) => {
                let a0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
                w.global::<FundingWalletScreen>().set_funding_feedback(format!("{} wallet · first address\n{a0}", src.kind.label()).into());
                w.global::<FundingWalletScreen>().set_funding_valid(true);
            }
            Err(e) => {
                w.global::<FundingWalletScreen>().set_funding_feedback(format!("{e}").into());
                w.global::<FundingWalletScreen>().set_funding_valid(false);
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_funding_use(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // A UR hardware-wallet export imports its account(s) into the list.
        if s.try_import_ur_account(w, &w.global::<FundingWalletScreen>().get_funding_descriptor()) {
            return;
        }
        // Otherwise: validate the descriptor, save to the list if new, activate.
        let input = extract_descriptor(&w.global::<FundingWalletScreen>().get_funding_descriptor());
        let net = s.network;
        let wallet = match FundingWallet::create(&input, "", net) {
            Ok(fw) => fw,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        if !s.funding_wallets.iter().any(|x| x.id == wallet.id) {
            s.funding_wallets.push(wallet.clone());
            s.save_funding_wallets();
        }
        s.activate_funding_wallet(w, &wallet.id);
    }

#[allow(unused_variables)]
pub(crate) fn on_funding_file(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        if let Some(path) =
            platform::pick_file(&[("Descriptor / wallet export", &["txt", "json", "desc", "ur"])])
        {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if s.try_import_ur_account(w, &content) {
                        return;
                    }
                    // A wallet-export file can list several script-type descriptors.
                    let descs = extract_all_descriptors(&content);
                    if descs.len() > 1 {
                        let added = s.save_funding_descriptors(w, &descs);
                        w.global::<Ui>().set_status(format!("imported {added} wallet(s) from file — pick one").into());
                    } else {
                        let d = descs.into_iter().next().unwrap_or_default();
                        w.global::<FundingWalletScreen>().set_funding_descriptor(d.clone().into());
                        // U4: direct call — on_funding_changed is a method
                        // now, so invoking it via Slint would re-enter this
                        // same &mut self borrow synchronously.
                        s.on_funding_changed(w, d.into());
                    }
                }
                Err(e) => w.global::<Ui>().set_status(format!("read failed: {e}").into()),
            }
        }
    }
}
