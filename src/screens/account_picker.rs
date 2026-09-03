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
#[allow(unused_variables)]
pub(crate) fn on_accounts_page(&mut self, w: &AppWindow, delta: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        let page = (w.global::<AccountPicker>().get_account_page() + delta).max(0) as u32;
        let mode = w.global::<AccountPicker>().get_account_pick_mode();
        if mode == "notebook" || mode == "wconsol" {
            s.show_notebook_picker(w, page, mode.as_str());
            return;
        }
        let material = s
            .pending_import
            .as_ref()
            .or(s.material.as_ref())
            .map(|z| String::from(z.as_str()));
        let Some(material) = material else { return };
        let active = if s.pending_import.is_some() { None } else { Some(s.account) };
        show_account_picker(w, &material, s.network, page, active);
    }

#[allow(unused_variables)]
pub(crate) fn on_pick_account(&mut self, w: &AppWindow, idx: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            if s.wallet_tx_busy || s.pending_broadcast.is_some() {
                return;
            }
            // Wallet consolidate: the pick is the DESTINATION — a notebook
            // address (receive index) of the active account. A non-
            // notebook address becomes a notebook (named inline) so the
            // gathered coin can never land somewhere invisible. Picking IS
            // the trigger now (the confirm modal is gone) — build + sign
            // (or, watch, build the external-sign PSBT) right here.
            let index = idx.max(0) as u32;
            let Some(mut wc) = s.wconsol.take() else { return };
            // An archived destination un-archives: the wallet's coin must
            // never land in a hidden notebook.
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).map(|m| m.archived)
                == Some(true)
            {
                let account = s.account;
                if let Some(ix) = s.notebooks.as_mut() {
                    ix.set_archived(account, index, false);
                    s.save_notebooks();
                    println!("cb: archive-notebook index={index} archived=false");
                }
            }
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_none() {
                // The picker has no name field in this mode, so the new
                // notebook takes the default name ("Notebook <index+1>")
                // until the user renames it from the list.
                s.ensure_notebook(index);
            }
            let Some(addr) =
                s.nb_addrs.iter().find(|(a, ..)| *a == index).map(|(_, ad, _)| ad.clone())
            else {
                return;
            };
            let n: usize = wc.sources.iter().map(|(_, c, _)| c.len()).sum();
            let total: u64 = wc.sources.iter().map(|(_, _, v)| *v).sum();
            let vsize = app_core::notes_core::tx::estimate_sweep_vsize(n, 34);
            let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < DUST_SATS {
                w.global::<Ui>().set_status("not enough across the wallet to cover the fee".into());
                s.wconsol = None;
                return;
            }
            wc.dest_index = index;
            wc.dest_addr = addr;
            wc.rate = rate;
            wc.fee = fee;
            wc.vsize = vsize as u64;
            s.build_wconsol_confirm(w, wc);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Create flow: the inline name field is already filled (or
            // left empty, taking the default "Notebook <index+1>") —
            // tapping an address creates right away.
            let index = idx.max(0) as u32;
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_some() {
                return; // row is disabled in the UI; never re-add
            }
            let name = w.global::<AccountPicker>().get_nb_create_name().trim().to_string();
            println!("cb: create-notebook index={index}");
            let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                return;
            };
            s.nb_index = index;
            match s.activate(&material, false) {
                Ok(()) => {
                    s.ensure_notebook(index);
                    if !name.is_empty() {
                        let account = s.account;
                        if let Some(ix) = s.notebooks.as_mut() {
                            ix.rename(account, index, &name);
                            s.save_notebooks();
                            println!("cb: rename-notebook index={index}");
                        }
                    }
                    w.global::<AccountPicker>().set_account_pick_mode("switch".into());
                    w.global::<AccountPicker>().set_nb_create_name("".into());
                    w.global::<Ui>().set_status("".into());
                    s.update_notebook_list(w);
                    w.global::<Ui>().set_screen(Screen::Notebooks);
                }
                Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
            }
            return;
        }
        // Sal 2026-07-22: this picker mode is now switch-only — imports
        // never set `pending_import` any more (removed in on_import_confirm),
        // so this always falls back to the current identity's material.
        let Some(material) = s
            .pending_import
            .take()
            .map(|z| String::from(z.as_str()))
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())))
        else {
            return;
        };
        s.account = idx.max(0) as u32;
        s.nb_index = 0;
        println!("cb: pick-account {}", s.account);
        match s.activate(&material, false) {
            Ok(()) => {
                // Settings account switch: the account is a wallet — land on
                // ITS notebook list. A fresh/empty account (no notebooks at
                // all) auto-creates its first one so the switch never lands
                // on an empty list (Sal 2026-07-22); an account that already
                // has notebooks (even if all archived) is left untouched.
                let empty =
                    s.notebooks.as_ref().map(|ix| ix.active(s.account).count() == 0).unwrap_or(true);
                if empty {
                    s.ensure_first_onboarded_notebook();
                }
                w.global::<Ui>().set_status("".into());
                s.update_notebook_list(w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                s.refresh_async(w);
                s.spending_refresh_async(w);
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    }
}
