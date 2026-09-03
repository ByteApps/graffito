//! Screen.account-picker — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// One picker page: 5 ACCOUNTS, each shown by its notebook-0 address.
pub(crate) fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i, 0).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

pub(crate) fn show_account_picker(w: &AppWindow, material: &str, network: Network, page: u32, active: Option<u32>) {
    w.global::<AccountPicker>().set_account_page(page as i32);
    w.global::<AccountPicker>().set_accounts(VecModel::from_slice(&account_rows(material, network, page, active)));
    w.global::<Ui>().set_screen(Screen::AccountPicker);
}

impl State {
/// One picker page: 5 NOTEBOOK ADDRESSES — receive-chain indexes `0/i`
/// of the ACTIVE account (create-notebook / consolidate-destination
/// rows).
pub(crate) fn index_rows(&self, page: u32) -> Vec<AccountItem> {
    let st = self;
    let Some(material_str) = st.material.as_deref() else { return vec![] };
    let Ok(material) = parse_key_material(material_str, st.network) else { return vec![] };
    let active = st.ident.as_ref().map(|i| i.index);
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, st.network, st.account, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}
}

impl State {
pub(crate) fn on_accounts_page(&mut self, w: &AppWindow, delta: i32) {
        let page = (w.global::<AccountPicker>().get_account_page() + delta).max(0) as u32;
        let mode = w.global::<AccountPicker>().get_account_pick_mode();
        if mode == "notebook" || mode == "wconsol" {
            self.show_notebook_picker(w, page, mode.as_str());
            return;
        }
        let material = self
            .pending_import
            .as_ref()
            .or(self.material.as_ref())
            .map(|z| String::from(z.as_str()));
        let Some(material) = material else { return };
        let active = if self.pending_import.is_some() { None } else { Some(self.account) };
        show_account_picker(w, &material, self.network, page, active);
    }

pub(crate) fn on_pick_account(&mut self, w: &AppWindow, idx: i32) {
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            if self.wallet_tx_busy || self.pending_broadcast.is_some() {
                return;
            }
            // Wallet consolidate: the pick is the DESTINATION — a notebook
            // address (receive index) of the active account. A non-
            // notebook address becomes a notebook (named inline) so the
            // gathered coin can never land somewhere invisible. Picking IS
            // the trigger now (the confirm modal is gone) — build + sign
            // (or, watch, build the external-sign PSBT) right here.
            let index = idx.max(0) as u32;
            let Some(mut wc) = self.wconsol.take() else { return };
            // An archived destination un-archives: the wallet's coin must
            // never land in a hidden notebook.
            if self.notebooks.as_ref().and_then(|ix| ix.get(self.account, index)).map(|m| m.archived)
                == Some(true)
            {
                let account = self.account;
                if let Some(ix) = self.notebooks.as_mut() {
                    ix.set_archived(account, index, false);
                    self.save_notebooks();
                    println!("cb: archive-notebook index={index} archived=false");
                }
            }
            if self.notebooks.as_ref().and_then(|ix| ix.get(self.account, index)).is_none() {
                // The picker has no name field in this mode, so the new
                // notebook takes the default name ("Notebook <index+1>")
                // until the user renames it from the list.
                self.ensure_notebook(index);
            }
            let Some(addr) =
                self.nb_addrs.iter().find(|(a, ..)| *a == index).map(|(_, ad, _)| ad.clone())
            else {
                return;
            };
            let n: usize = wc.sources.iter().map(|(_, c, _)| c.len()).sum();
            let total: u64 = wc.sources.iter().map(|(_, _, v)| *v).sum();
            let vsize = app_core::notes_core::tx::estimate_sweep_vsize(n, 34);
            let rate = self.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < DUST_SATS {
                w.global::<Ui>().set_status("not enough across the wallet to cover the fee".into());
                self.wconsol = None;
                return;
            }
            wc.dest_index = index;
            wc.dest_addr = addr;
            wc.rate = rate;
            wc.fee = fee;
            wc.vsize = vsize as u64;
            self.build_wconsol_confirm(w, wc);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Create flow: the inline name field is already filled (or
            // left empty, taking the default "Notebook <index+1>") —
            // tapping an address creates right away.
            let index = idx.max(0) as u32;
            if self.notebooks.as_ref().and_then(|ix| ix.get(self.account, index)).is_some() {
                return; // row is disabled in the UI; never re-add
            }
            let name = w.global::<AccountPicker>().get_nb_create_name().trim().to_string();
            println!("cb: create-notebook index={index}");
            let Some(material) = self.material.as_ref().map(|z| String::from(z.as_str())) else {
                return;
            };
            self.nb_index = index;
            match self.activate(&material, false) {
                Ok(()) => {
                    self.ensure_notebook(index);
                    if !name.is_empty() {
                        let account = self.account;
                        if let Some(ix) = self.notebooks.as_mut() {
                            ix.rename(account, index, &name);
                            self.save_notebooks();
                            println!("cb: rename-notebook index={index}");
                        }
                    }
                    w.global::<AccountPicker>().set_account_pick_mode("switch".into());
                    w.global::<AccountPicker>().set_nb_create_name("".into());
                    w.global::<Ui>().set_status("".into());
                    self.update_notebook_list(w);
                    w.global::<Ui>().set_screen(Screen::Notebooks);
                }
                Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
            }
            return;
        }
        // Sal 2026-07-22: this picker mode is now switch-only — imports
        // never set `pending_import` any more (removed in on_import_confirm),
        // so this always falls back to the current identity's material.
        let Some(material) = self
            .pending_import
            .take()
            .map(|z| String::from(z.as_str()))
            .or_else(|| self.material.as_ref().map(|z| String::from(z.as_str())))
        else {
            return;
        };
        self.account = idx.max(0) as u32;
        self.nb_index = 0;
        println!("cb: pick-account {}", self.account);
        match self.activate(&material, false) {
            Ok(()) => {
                // Settings account switch: the account is a wallet — land on
                // ITS notebook list. A fresh/empty account (no notebooks at
                // all) auto-creates its first one so the switch never lands
                // on an empty list (Sal 2026-07-22); an account that already
                // has notebooks (even if all archived) is left untouched.
                let empty =
                    self.notebooks.as_ref().map(|ix| ix.active(self.account).count() == 0).unwrap_or(true);
                if empty {
                    self.ensure_first_onboarded_notebook();
                }
                w.global::<Ui>().set_status("".into());
                self.update_notebook_list(w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                self.refresh_async(w);
                self.spending_refresh_async(w);
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    }
}
