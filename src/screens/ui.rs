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

impl State {
pub(crate) fn on_dice_roll(&mut self, w: &AppWindow, face: i32) {
        if (1..=6).contains(&face) {
            self.dice_rolls.push(char::from_digit(face as u32, 10).expect("1..=6 is a digit"));
            self.update_dice_ui(w);
        }
    }

pub(crate) fn on_dice_clear(&mut self, w: &AppWindow) {
        self.dice_rolls = Zeroizing::new(String::new());
        println!("cb: dice-clear");
        self.update_dice_ui(w);
    }

pub(crate) fn on_set_icloud_backup(&mut self, w: &AppWindow, enabled: bool) {
        self.icloud_backup = enabled;
        println!("cb: set-icloud-backup {enabled}");
        if let Some(material) = self.material.clone() {
            match keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material.trim(), enabled) {
                Ok(()) => {
                    // Re-stored under a new sync mode — still a saved key.
                    self.saved_key_present = true;
                    w.global::<Onboarding>().set_saved_key_present(true);
                    w.global::<Ui>().set_status(
                        if enabled { "iCloud backup on" } else { "iCloud backup off" }.into(),
                    );
                }
                Err(e) => {
                    w.global::<Ui>().set_status(format!("iCloud: {e}").into());
                    self.icloud_backup = !enabled;
                    w.global::<Ui>().set_icloud_backup(!enabled);
                }
            }
        }
    }

pub(crate) fn on_paste_compose(&mut self, w: &AppWindow) {
        if let Some(text) = platform::clipboard_text() {
            let combined = format!("{}{}", w.global::<Compose>().get_compose_text(), text);
            let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                w.global::<Compose>().set_compose_text(combined.clone().into());
                w.global::<Ui>().invoke_compose_changed();
            });
        }
    }

pub(crate) fn on_refresh(&mut self, w: &AppWindow) {
        self.refresh_async(w);
    }

/// The UI-thread half of [`show_notebook_picker`]'s worker — one finished
/// used/new probe. (account, page, screen) guards staleness (paging or
/// switching account/screen drops it); moved verbatim out of
/// `on_apply_pending_picker_probe` (U5), just applied to one already-owned
/// result instead of a freshly-drained `Vec`.
pub(crate) fn apply_picker_probe_result(&mut self, w: &AppWindow, r: PickerProbeResult) {
    let s = self;
    if s.account != r.account
        || w.global::<AccountPicker>().get_account_page() != r.page as i32
        || w.global::<Ui>().get_screen() != Screen::AccountPicker
    {
        println!("cb: picker-probe stale-drop");
        return;
    }
    let model = w.global::<AccountPicker>().get_accounts();
    for i in 0..model.row_count() {
        if let Some(mut row) = model.row_data(i) {
            if let Some((_, pill, bal)) =
                r.rows.iter().find(|(idx, ..)| *idx == row.index as u32)
            {
                row.pill = (*pill).into();
                row.balance = bal.clone().into();
                model.set_row_data(i, row);
            }
        }
    }
}

/// The UI-thread half of [`refresh_node_health`] — one finished Bitcoin
/// Core preflight check. Moved out of `on_apply_pending_node_health` (U5)
/// — same body, applied to one already-owned result.
pub(crate) fn apply_node_health_result(&mut self, w: &AppWindow, r: NodeHealthResult) {
    let s = self;
    if s.network != r.network || s.base_url().as_deref() != Some(r.base.as_str()) {
        println!("cb: node-health stale-drop");
        return;
    }
    w.global::<Settings>().set_node_health_text(r.text);
    w.global::<Ui>().set_node_health_warn(r.warn);
}

/// The UI-thread half of the deferred auto-unlock — mirrors
/// `read_saved_material`'s error handling, but with the result already in
/// hand. Moved out of `on_apply_pending_unlock` (U5) — same body, applied
/// to the worker's result directly (no `Mutex<Option<..>>` wrapper needed
/// now that [`post`] only ever schedules a job when there IS a result).
pub(crate) fn apply_unlock_result(&mut self, w: &AppWindow, r: Result<Option<String>, String>) {
    let s = self;
    match r {
        // Boot path, not onboarding: never create a notebook here.
        Ok(Some(m)) => s.activate_restored(w, m, false),
        Ok(None) => {
            println!("cb: unlock none");
            s.saved_key_present = false;
            w.global::<Onboarding>().set_saved_key_present(false);
        }
        // Both failure branches REVEAL the door. The auto-unlock branch
        // never runs the `identity_exists` probe (it went straight for the
        // key), so `saved_key_present` is still false here — and the status
        // line tells the user to "tap Restore" on a door that isn't
        // rendered. We know an item exists: that is why we tried to unlock
        // it. (Until 2026-07-26 the separate "Restore from iCloud" door
        // accidentally covered this, but only for a SYNCED key.)
        Err(e) if e == "cancelled" => {
            // Left on onboarding with the door there, so a mis-tapped or
            // timed-out prompt is one tap from retrying.
            println!("cb: unlock cancelled");
            s.saved_key_present = true;
            w.global::<Onboarding>().set_saved_key_present(true);
            w.global::<Ui>().set_status("unlock cancelled — tap Restore to try again".into());
        }
        Err(e) => {
            println!("cb: unlock err={e}");
            s.saved_key_present = true;
            w.global::<Onboarding>().set_saved_key_present(true);
            w.global::<Ui>().set_status(format!("keychain: {e}").into());
        }
    }
}

pub(crate) fn on_copy_text(&mut self, w: &AppWindow, kind: SharedString, text: SharedString) {
        let ok = platform::set_clipboard_text(text.as_str());
        println!("cb: copy kind={kind} len={} ok={ok}", text.len());
        let msg = if ok {
            match kind.as_str() {
                "address" => "Address copied",
                "backup-words" => "Recovery phrase copied",
                "note-text" => "Note copied",
                "txid" => "Txid copied",
                _ => "Copied",
            }
        } else {
            "Copy failed"
        };
        show_toast(w, msg);
    }

pub(crate) fn on_set_coins_segment(&mut self, w: &AppWindow, seg: SharedString) {
        w.global::<Ui>().set_coins_segment(seg.clone());
        if seg.as_str() == "spending" && self.spending_capable && !self.spending_scanned {
            self.spending_refresh_async(w);
        }
    }

pub(crate) fn on_open_activity(&mut self, w: &AppWindow) {
        println!("cb: open-activity");
        w.global::<Ui>().set_return_screen(if w.global::<Ui>().get_screen() == Screen::Notebooks { Screen::Notebooks } else { Screen::Home });
        self.update_activity(w);
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Activity);
    }

pub(crate) fn on_act_retry(&mut self, w: &AppWindow, ref_id: SharedString, is_note: bool) {
        if self.act_pending_ref.is_some() || self.wallet_tx_busy || self.pending_broadcast.is_some() {
            return;
        }
        let (raw, last_txid) = if is_note {
            let n = self
                .store
                .as_ref()
                .and_then(|st| st.notes.iter().find(|n| n.note_id.as_str() == ref_id.as_str()));
            (n.and_then(|n| n.raw_hex.clone()), n.and_then(|n| n.txids.last().cloned()))
        } else {
            let t = self
                .store
                .as_ref()
                .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id.as_str())));
            (t.and_then(|t| t.raw_hex.clone()), t.and_then(|t| t.txids.last().cloned()))
        };
        let ref_id_s = ref_id.to_string();
        if let Some(r) = raw.filter(|r| !r.is_empty()) {
            // Case (a): raw hex cached locally — summarize + show_confirm
            // right now, no network round trip needed.
            self.enter_rebroadcast_confirm(w, ref_id_s, is_note, r);
            return;
        }
        // Case (b): chain-recovered record (watch mode, or any record with
        // no cached hex) — the node that already knows the tx is the
        // keyless rebroadcast source. Never block the UI thread on the
        // fetch; land on the confirm screen from the fetch-result
        // trampoline (mirrors `spending_refresh_async`).
        let Some(base) = self.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let net = self.network;
        let identity_addr = self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let creds = self.core_rpc_creds_for(&base, net);
        self.act_pending_ref = Some(ref_id_s.clone());
        self.update_activity(w);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let client = open_client(&base, net, creds).map_err(|e| e.to_string());
            let result = last_txid
                .ok_or_else(|| "nothing to rebroadcast".to_string())
                .and_then(|t| client.and_then(|c| c.fetch_tx_hex(&t).map_err(|e| format!("{e}"))));
            let r = RebroadcastFetchResult { ref_id: ref_id_s, is_note, identity_addr, result };
            post(&weak, move |w, st| st.apply_rebroadcast_fetch_result(w, r));
        });
    }

pub(crate) fn on_act_explorer(&mut self, _w: &AppWindow, url: SharedString) {
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = platform::open_url(url.as_str());
    }

pub(crate) fn on_consolidate_open(&mut self, w: &AppWindow) {
        self.open_notebook_consolidate(w);
    }

pub(crate) fn on_start_rename(&mut self, w: &AppWindow, addr: SharedString, name: SharedString, synced: bool) {
        println!("cb: rename-start addr={addr}");
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_rename_address(addr.clone());
        w.global::<Modals>().set_rename_input(name);
        w.global::<Modals>().set_rename_synced(synced);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
        w.global::<Ui>().set_rename_pq_display(self.contact_pq_display_for(addr.as_str()).into());
    }

pub(crate) fn on_cancel_rename(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_rename_address("".into());
        w.global::<Modals>().set_rename_input("".into());
        w.global::<Modals>().set_rename_synced(false);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Ui>().set_rename_pq_display("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
    }

pub(crate) fn on_contact_pq_set(&mut self, w: &AppWindow, input: SharedString) {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = self.network.as_str().to_string();
        let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        else {
            return;
        };
        match app_core::pqkeys::set_contact_pq_key(contact, input.trim()) {
            Ok(fp) => {
                self.save_contacts();
                println!("cb: contact-pq-key ok fp={fp}");
                w.global::<Modals>().set_rename_pq_error("".into());
                w.global::<Modals>().set_rename_pq_input("".into());
                w.global::<Ui>().set_rename_pq_display(self.contact_pq_display_for(&addr).into());
                self.refresh_contacts(w);
            }
            Err(e) => {
                println!("cb: contact-pq-key err={e}");
                w.global::<Modals>().set_rename_pq_error(e.to_string().into());
            }
        }
    }

pub(crate) fn on_contact_pq_remove(&mut self, w: &AppWindow) {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = self.network.as_str().to_string();
        if let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        {
            contact.mlkem_ek = None;
            self.save_contacts();
            println!("cb: contact-pq-key removed");
            w.global::<Ui>().set_rename_pq_display("".into());
            self.refresh_contacts(w);
        }
    }

pub(crate) fn on_cancel_remove(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_confirm_remove_address("".into());
    }

pub(crate) fn on_compose_changed(&mut self, w: &AppWindow) {
        self.refresh_compose(w);
    }

pub(crate) fn on_refresh_coins(&mut self, w: &AppWindow) {
        self.wallet_stores_refresh_async(w, WalletStoresPurpose::Coins);
    }

pub(crate) fn on_refresh_notebooks(&mut self, w: &AppWindow) {
        self.wallet_stores_refresh_async(w, WalletStoresPurpose::Notebooks);
    }

pub(crate) fn on_toggle_fund_external(&mut self, w: &AppWindow, on: bool) {
        println!("cb: fund-external {on}");
        if !on {
            self.funding_coins.clear();
        }
        w.global::<Ui>().set_status("".into());
        self.refresh_compose(w);
        // Turning it on with no wallet active → go to the saved-wallets list.
        if on && self.funding.is_none() {
            w.global::<Ui>().set_funding_return(Screen::Compose);
            self.refresh_funding_list(w);
            w.global::<Ui>().set_screen(Screen::FundingWallets);
        }
    }

pub(crate) fn on_set_pay_from(&mut self, w: &AppWindow, kind: SharedString) {
        println!("cb: pay-from {kind}");
        self.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
        self.apply_pay_from(w, kind.as_str());
        self.refresh_compose(w);
    }

pub(crate) fn on_open_funding(&mut self, w: &AppWindow) {
        println!("cb: open-funding");
        w.global::<Ui>().set_status("".into());
        self.refresh_funding_list(w);
        w.global::<Ui>().set_screen(Screen::FundingWallets);
    }

pub(crate) fn on_fund_rename_cancel(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_fund_rename_id("".into());
    }

pub(crate) fn on_funding_import_ur(&mut self, w: &AppWindow, text: SharedString) {
        self.try_import_ur_account(w, text.as_str());
    }

pub(crate) fn on_funding_clear(&mut self, w: &AppWindow) {
        self.funding = None;
        self.funding_coins.clear();
        self.built_psbt = None;
        self.signed_psbt = None;
        w.global::<FundingWalletScreen>().set_funding_descriptor("".into());
        w.global::<FundingWalletScreen>().set_funding_feedback("".into());
        w.global::<FundingWalletScreen>().set_funding_valid(false);
        self.refresh_compose(w);
    }

pub(crate) fn on_psbt_copy(&mut self, w: &AppWindow) {
        let b64 = self.built_psbt.as_ref().map(|b| b.to_base64()).unwrap_or_default();
        if b64.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_text(&b64);
        if !ok {
            w.global::<Ui>().set_status("copy failed".into());
        }
        show_toast(w, if ok { "PSBT copied" } else { "Copy failed" });
    }

pub(crate) fn on_psbt_loaded(&mut self, w: &AppWindow, text: SharedString) {
        self.load_signed_psbt(w, text.as_bytes());
    }

pub(crate) fn on_psbt_broadcast(&mut self, w: &AppWindow) {
        if self.wallet_tx_busy {
            return;
        }
        let Some(psbt) = self.signed_psbt.clone() else {
            w.global::<Ui>().set_status("no signed PSBT".into());
            return;
        };
        let Some(base) = self.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let net = self.network;
        let snap = PsbtBroadcastSnapshot {
            identity_addr: self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
            txid,
            raw: raw.clone(),
            vsize,
        };
        self.wallet_tx_busy = true;
        w.global::<Confirm>().set_wallet_tx_busy(true);
        let creds = self.core_rpc_creds_for(&base, net);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let result = open_client(&base, net, creds)
                .map_err(|e| e.to_string())
                .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
            let r = PsbtBroadcastResult { snap, result };
            post(&weak, move |w, st| {
                st.clear_wallet_tx_busy(w);
                st.apply_psbt_broadcast_result(w, r);
            });
        });
    }

pub(crate) fn on_confirm_cancel(&mut self, w: &AppWindow) {
        // Busy-guard: a broadcast already in flight can't be canceled out
        // from under itself (mirrors the Broadcast-tap guard above) — the
        // psbt kind in particular delegates to on_psbt_broadcast's own
        // wallet_tx_busy management, so this is the same flag either way.
        if self.wallet_tx_busy {
            return;
        }
        let kind = self.pending_broadcast.as_ref().map(|p| p.kind).unwrap_or("?");
        println!("cb: confirm cancel kind={kind}");
        let return_screen = self.pending_broadcast.take().map(|p| p.return_screen).unwrap_or(Screen::Home);
        w.global::<Ui>().set_confirm_warn("".into());
        w.global::<Confirm>().set_confirm_txid("".into());
        w.global::<Confirm>().set_confirm_context("".into());
        w.global::<Confirm>().set_confirm_note("".into());
        w.global::<Confirm>().set_confirm_inputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.global::<Confirm>().set_confirm_outputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.global::<Ui>().set_status("".into());
        if kind == "psbt" {
            // Zero-trace for the PSBT path means discarding the loaded
            // signed PSBT too — nothing was recorded, and re-showing a
            // stale confirm screen next load would be wrong. The unsigned
            // built PSBT / UR export (screen 13) is untouched, so backing
            // further out and re-exporting still works.
            self.signed_psbt = None;
            w.global::<Ui>().set_psbt_signed(false);
        }
        w.global::<Ui>().set_screen(return_screen);
    }

pub(crate) fn on_account_cancel(&mut self, w: &AppWindow) {
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            // Abandon wallet consolidate: back to settings, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            self.wconsol = None;
            w.global::<Ui>().set_status("".into());
            w.global::<Ui>().set_screen(Screen::Settings);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Abandon create → back to the notebook list, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            w.global::<Ui>().set_status("".into());
            self.update_notebook_list(w);
            w.global::<Ui>().set_screen(Screen::Notebooks);
            return;
        }
        if self.pending_import.take().is_some() {
            w.global::<Ui>().set_screen(Screen::ImportKey); // abandon import → back to the import form
        } else {
            self.update_home(w);
            w.global::<Ui>().set_screen(Screen::Settings); // came from settings
        }
    }

pub(crate) fn on_reveal_hide(&mut self, w: &AppWindow) {
        self.clear_reveal(w);
        println!("cb: hide-reveal");
    }

pub(crate) fn on_pq_replace_confirm(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_pq_show_replace_confirm(false);
        match self.pq_pending_replace.take() {
            Some(PqReplaceKind::Generate) => self.do_pq_generate(w),
            Some(PqReplaceKind::Import) => self.do_pq_import(w),
            None => {}
        }
    }

pub(crate) fn on_pq_imported_hide_private(&mut self, w: &AppWindow) {
        w.global::<Modals>().set_pq_imported_private_value("".into());
        w.global::<Modals>().set_pq_imported_private_qr(slint::Image::default());
    }

pub(crate) fn on_copy_value(&mut self, w: &AppWindow, value: SharedString) {
        let ok = platform::set_clipboard_text(value.as_str());
        println!("cb: copy-value len={}", value.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }

pub(crate) fn on_go_home(&mut self, w: &AppWindow) {
        self.clear_reveal(w);
        self.go_home_or_list(w);
    }

pub(crate) fn on_open_notebooks(&mut self, w: &AppWindow) {
        // Leaving the open notebook: everything that was on screen counts
        // as read, so the list badge only flags what arrived since.
        if let Some(store) = self.store.as_mut() {
            if store.mark_seen() > 0 {
                self.save_store();
            }
        }
        w.global::<Ui>().set_status("".into());
        self.update_notebook_list(w);
        w.global::<Ui>().set_screen(Screen::Notebooks);
    }

pub(crate) fn on_nb_rename_cancel(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_nb_rename_index(-1);
        w.global::<Modals>().set_nb_rename_input("".into());
    }
}
