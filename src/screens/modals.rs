//! the 15 modal overlays — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn on_act_bump_rate_changed(&mut self, w: &AppWindow, rate_s: SharedString) {
        let ref_id = w.global::<Ui>().get_bump_ref().to_string();
        let is_note = w.global::<Ui>().get_bump_is_note();
        if let Some(wb) =
            self.watch_bump.as_ref().filter(|wb| wb.ref_id == ref_id && wb.is_note == is_note)
        {
            match rate_s.trim().parse::<f64>() {
                Ok(r) if r > 0.0 => w.global::<Modals>().set_bump_new_fee(new_fee_line(r, wb.vsize, wb.old_fee).into()),
                _ => w.global::<Modals>().set_bump_new_fee("".into()),
            }
            return;
        }
        let Some((_, old_fee, vsize)) = self.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note))
        else {
            return;
        };
        match rate_s.trim().parse::<f64>() {
            Ok(r) if r > 0.0 => w.global::<Modals>().set_bump_new_fee(new_fee_line(r, vsize, old_fee).into()),
            _ => w.global::<Modals>().set_bump_new_fee("".into()),
        }
    }

pub(crate) fn on_act_bump_confirm(&mut self, w: &AppWindow) {
        if self.act_pending_ref.is_some() || self.wallet_tx_busy || self.pending_broadcast.is_some() {
            return;
        }
        let ref_id = w.global::<Ui>().get_bump_ref().to_string();
        let is_note = w.global::<Ui>().get_bump_is_note();
        let Ok(new_rate) = w.global::<Modals>().get_bump_rate().trim().parse::<f64>() else {
            w.global::<Modals>().set_bump_error("enter a number".into());
            return;
        };
        let net = self.network;
        if self.base_url().is_none() {
            w.global::<Modals>().set_bump_error("no Bitcoin node — set one in Settings".into());
            return;
        }
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            self.watch_bump_confirm(w, new_rate);
            return;
        }
        // CHANGE 2 defense-in-depth (see on_act_bump_open).
        if !is_note
            && self.store.as_ref().map(|st| st.txs.iter().any(|t| t.txids.iter().any(|x| x == &ref_id) && t.mixed_inputs)).unwrap_or(false)
        {
            w.global::<Modals>().set_bump_error("this sweep mixed notebook + spending coins — it can't be sped up".into());
            return;
        }
        let min_rate = match self.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note)) {
            Some((old_rate, _, _)) => old_rate + 1.0,
            None => {
                w.global::<Modals>().set_bump_error("transaction no longer pending".into());
                return;
            }
        };
        if new_rate + 1e-9 < min_rate {
            w.global::<Modals>().set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
            return;
        }
        let Some(identity) = self.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Modals>().set_bump_error("no identity".into());
            return;
        };
        // Multi-key records (wallet sweep/consolidate) carry per-input
        // owners — rev-3 records list notebook INDEXES within the active
        // account (`input_indexes`); legacy records list ACCOUNTS
        // (`input_accounts`, notebook 0 implied). Re-sign each input with
        // its owner's key.
        let (owner_ids, owners_are_indexes): (Vec<u32>, bool) = self
            .store
            .as_ref()
            .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == &ref_id)))
            .map(|t| {
                if !t.input_indexes.is_empty() {
                    (t.input_indexes.clone(), true)
                } else {
                    (t.input_accounts.clone(), false)
                }
            })
            .unwrap_or_default();
        let active_account = self.account;
        // PURE builds only (zero-trace cancel): the store is not touched
        // — no txid append, no fee/raw_hex update, no ledger swap, no
        // save — until the Broadcast tap runs `record_bumped_*` in stage
        // B. Cancel on screen 26 leaves the original pending tx exactly
        // as it was.
        let result: Result<BumpedBuild, app_core::Error> = if is_note {
            app_core::compose::bump_fee_build(
                self.store.as_ref().unwrap(),
                &identity,
                net,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Note)
        } else if !owner_ids.is_empty() {
            let mut distinct = owner_ids.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let idents: Result<Vec<(u32, app_core::notes_core::bundle::Identity)>, app_core::Error> =
                self.material
                    .as_deref()
                    .ok_or_else(|| app_core::Error::Store("no key material".into()))
                    .and_then(|m| {
                        parse_key_material(m, net)
                            .map_err(|e| app_core::Error::Store(format!("{e}")))
                    })
                    .and_then(|material| {
                        distinct
                            .iter()
                            .map(|a| {
                                let (acct, idx) = if owners_are_indexes {
                                    (active_account, *a)
                                } else {
                                    (*a, 0)
                                };
                                realize(&material, net, acct, idx)
                                    .map_err(|e| app_core::Error::Store(format!("{e}")))
                                    .and_then(|i| {
                                        i.full().map(|f| (*a, f.clone_fields())).ok_or_else(|| {
                                            app_core::Error::Store("watch key can't bump".into())
                                        })
                                    })
                            })
                            .collect()
                    });
            idents.and_then(|idents| {
                app_core::compose::bump_raw_tx_multi_build(
                    self.store.as_ref().unwrap(),
                    &idents,
                    &ref_id,
                    new_rate,
                    None, // device default — no override control on the bump dialog
                )
                .map(BumpedBuild::Tx)
            })
        } else {
            app_core::compose::bump_raw_tx_build(
                self.store.as_ref().unwrap(),
                &identity,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Tx)
        };
        match result {
            Ok(bumped) => {
                let (raw, txid, fee, vsize) = match &bumped {
                    BumpedBuild::Note(c) => {
                        (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee, c.tx.vsize)
                    }
                    BumpedBuild::Tx(tx) => {
                        (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee, tx.vsize)
                    }
                };
                // NOTHING is recorded or saved here — hand the signed
                // replacement to the universal confirm screen; stage B
                // (`on_confirm_broadcast`) applies `record_bumped_*` +
                // `save_store()` at the Broadcast tap, re-arms
                // `act_pending_ref` right before the POST, and spawns the
                // SAME worker pushing `ActBumpResult`.
                w.global::<Ui>().set_show_bump_dialog(false);
                let prevouts = self.stored_record_prevouts(&ref_id, is_note);
                let expected_change = self.stored_record_expected_change(&ref_id, is_note);
                let (self_spks, spending_spks) = self.confirm_self_spks();
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: self.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "bump",
                    raw_hex: raw,
                    txid,
                    vsize,
                    context: format!("Speed-up · {}", net.as_str()),
                    return_screen: Screen::Activity, // overwritten by show_confirm
                    payload: PendingPayload::Bump { ref_id: ref_id.clone(), fee, new_rate, bumped },
                };
                self.show_confirm(w, pending, ctx);
            }
            Err(e) => {
                println!("cb: act-bump ref={ref_id} err={e}");
                w.global::<Modals>().set_bump_error(format!("{e}").into());
            }
        }
    }

pub(crate) fn on_save_rename(&mut self, w: &AppWindow, name: SharedString) {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        let synced = w.global::<Modals>().get_rename_synced();
        self.name_contact(&addr, name.trim(), synced);
        self.save_contacts();
        println!("cb: save-contact addr={addr} name-len={}", name.trim().len());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_rename_address("".into());
        w.global::<Modals>().set_rename_input("".into());
        w.global::<Modals>().set_rename_synced(false);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Ui>().set_rename_pq_display("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
        self.update_home(w);
    }

pub(crate) fn on_contact_pq_file(&mut self, w: &AppWindow) {
        if let Some(path) = platform::pick_file(&[("Key", &["asc", "txt", "pgp", "gpg"])]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => w.global::<Modals>().set_rename_pq_input(text.trim().into()),
                Err(e) => w.global::<Modals>().set_rename_pq_error(format!("file: {e}").into()),
            }
        }
    }

pub(crate) fn on_remove_contact(&mut self, w: &AppWindow, addr: SharedString) {
        self.remove_contact(addr.as_str());
        self.save_contacts();
        println!("cb: remove-contact addr={addr}");
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_confirm_remove_address("".into());
        if w.global::<Ui>().get_rename_address() == addr {
            w.global::<Ui>().set_rename_address("".into());
        }
        self.update_home(w);
    }

pub(crate) fn on_fund_rename_save(&mut self, w: &AppWindow, text: SharedString) {
        let id = w.global::<Ui>().get_fund_rename_id().to_string();
        let name = text.trim();
        if !name.is_empty() {
            if let Some(fw) = self.funding_wallets.iter_mut().find(|fw| fw.id == id) {
                fw.label = name.to_string();
            }
            self.save_funding_wallets();
        }
        w.global::<Ui>().set_fund_rename_id("".into());
        self.refresh_funding_list(w);
    }

pub(crate) fn on_reset_identity(&mut self, w: &AppWindow) {
        println!("cb: reset-identity");
        let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);
        // Privacy: local stores cache decrypted note text — delete them.
        if let Ok(entries) = std::fs::read_dir(&self.data_dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if (name.starts_with("store-") || name.starts_with("notebooks-"))
                    && name.ends_with(".json")
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        self.ident = None;
        self.store = None;
        self.material = None;
        self.account = 0;
        self.nb_index = 0;
        self.notebooks = None;
        self.notebooks_fp8 = None;
        self.nb_addrs.clear();
        self.xacct_addrs.clear();
        self.discovery_pending = false;
        self.to_address = None;
        self.to_addresses_extra.clear();
        self.picking_extra = false;
        w.global::<Ui>().set_picking_extra(false);
        self.icloud_backup = false;
        w.global::<Ui>().set_icloud_backup(false);
        // The key is gone, so there is nothing to restore and nothing to
        // auto-unlock — leaving either set would show a "Restore saved key"
        // door pointing at an item we just deleted.
        self.auto_unlock = false;
        self.saved_key_present = false;
        w.global::<Onboarding>().set_saved_key_present(false);
        self.save_config();
        w.global::<Ui>().set_show_reset_confirm(false);
        self.clear_reveal(w);
        w.global::<Ui>().set_status("".into());
        w.global::<ImportKey>().set_import_text("".into());
        w.global::<Ui>().set_screen(Screen::Onboarding);
    }

pub(crate) fn on_oversize_bump(&mut self, w: &AppWindow) {
        if let Some(store) = &mut self.store {
            store.chunk_size = DEFAULT_CHUNK;
        }
        self.save_store();
        println!("cb: set-chunk-size {DEFAULT_CHUNK} ok (oversize-bump)");
        w.global::<Settings>().set_chunk_text(DEFAULT_CHUNK.to_string().into());
        w.global::<Settings>().set_chunk_custom(false);
        w.global::<Ui>().set_show_oversize_modal(false);
        self.refresh_compose(w);
    }

pub(crate) fn on_pq_copy_private(&mut self, w: &AppWindow) {
        let Some(ls) = self.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(self.pq_level));
        let armor = app_core::pqkeys::export_private_armor(&kp);
        let ok = platform::set_clipboard_secret(&armor);
        println!("cb: pq-key-export private len={}", armor.len());
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }

pub(crate) fn on_pq_save_private(&mut self, w: &AppWindow) {
        let Some(ls) = self.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(self.pq_level));
        let armor = app_core::pqkeys::export_private_armor(&kp);
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        if let Some(path) = platform::save_file("quantum-private-key.asc") {
            match std::fs::write(&path, armor.as_bytes()) {
                Ok(()) => {
                    println!("cb: pq-key-export private len={}", armor.len());
                    w.global::<Ui>().set_status("saved private key".into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    }

pub(crate) fn on_pq_replace_cancel(&mut self, w: &AppWindow) {
        self.pq_pending_replace = None;
        w.global::<Ui>().set_pq_show_replace_confirm(false);
    }

pub(crate) fn on_pq_imported_reveal_private(&mut self, w: &AppWindow) {
        let Some(kp) = self.pq_imported.as_ref() else { return };
        let armor = app_core::pqkeys::export_private_armor(kp);
        w.global::<Modals>().set_pq_imported_private_qr(qr::qr_image(&armor).unwrap_or_default());
        w.global::<Modals>().set_pq_imported_private_value(armor.into());
        println!("cb: pq-key-export private-reveal");
    }

pub(crate) fn on_pq_imported_copy_private(&mut self, w: &AppWindow) {
        let armor = w.global::<Modals>().get_pq_imported_private_value().to_string();
        if armor.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_secret(&armor);
        println!("cb: pq-key-export private len={}", armor.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }

pub(crate) fn on_nb_rename_save(&mut self, w: &AppWindow, name: SharedString) {
        let sel = w.global::<Ui>().get_nb_rename_index();
        if sel < 0 {
            return;
        }
        w.global::<Ui>().set_nb_rename_index(-1);
        w.global::<Modals>().set_nb_rename_input("".into());
        let index = sel as u32;
        let account = self.account;
        if let Some(ix) = self.notebooks.as_mut() {
            ix.rename(account, index, name.as_str());
            self.save_notebooks();
            println!("cb: rename-notebook index={index}");
        }
        self.update_notebook_list(w);
        if self.ident.as_ref().map(|i| i.index) == Some(index) {
            w.global::<Home>().set_notebook_title(self.notebook_display_name(index).into());
        }
    }
}
