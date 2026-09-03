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
#[allow(unused_variables)]
pub(crate) fn on_dice_roll(&mut self, w: &AppWindow, face: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        if (1..=6).contains(&face) {
            s.dice_rolls.push(char::from_digit(face as u32, 10).expect("1..=6 is a digit"));
            s.update_dice_ui(w);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_dice_clear(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.dice_rolls = Zeroizing::new(String::new());
        println!("cb: dice-clear");
        s.update_dice_ui(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_set_icloud_backup(&mut self, w: &AppWindow, enabled: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        s.icloud_backup = enabled;
        println!("cb: set-icloud-backup {enabled}");
        if let Some(material) = s.material.clone() {
            match keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material.trim(), enabled) {
                Ok(()) => {
                    // Re-stored under a new sync mode — still a saved key.
                    s.saved_key_present = true;
                    w.global::<Onboarding>().set_saved_key_present(true);
                    w.global::<Ui>().set_status(
                        if enabled { "iCloud backup on" } else { "iCloud backup off" }.into(),
                    );
                }
                Err(e) => {
                    w.global::<Ui>().set_status(format!("iCloud: {e}").into());
                    s.icloud_backup = !enabled;
                    w.global::<Ui>().set_icloud_backup(!enabled);
                }
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_paste_compose(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        if let Some(text) = platform::clipboard_text() {
            let combined = format!("{}{}", w.global::<Compose>().get_compose_text(), text);
            let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                w.global::<Compose>().set_compose_text(combined.clone().into());
                w.global::<Ui>().invoke_compose_changed();
            });
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_refresh(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.refresh_async(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_refresh(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_refresh_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_compose(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_compose_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_act_retry(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_act_retry_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_rebroadcast_fetch(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_pending_rebroadcast_fetch_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_act_bump(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_act_bump_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_wallet_tx(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_pending_wallet_tx_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_spending_refresh(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_spending_refresh_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_wallet_stores_refresh(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_wallet_stores_refresh_results(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_icloud_contacts(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.apply_icloud_contacts_merge(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_picker_probe(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let results: Vec<PickerProbeResult> =
            PICKER_PROBE_RESULTS.lock().expect("picker probe mutex").drain(..).collect();
        for r in results {
            if s.account != r.account
                || w.global::<AccountPicker>().get_account_page() != r.page as i32
                || w.global::<Ui>().get_screen() != Screen::AccountPicker
            {
                println!("cb: picker-probe stale-drop");
                continue;
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
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_node_health(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let results: Vec<NodeHealthResult> =
            NODE_HEALTH_RESULTS.lock().expect("node health mutex").drain(..).collect();
        for r in results {
            if s.network != r.network || s.base_url().as_deref() != Some(r.base.as_str()) {
                println!("cb: node-health stale-drop");
                continue;
            }
            w.global::<Settings>().set_node_health_text(r.text);
            w.global::<Ui>().set_node_health_warn(r.warn);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_unlock(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let taken = UNLOCK_RESULT.lock().expect("unlock result mutex").take();
        match taken {
            // Boot path, not onboarding: never create a notebook here.
            Some(Ok(Some(m))) => s.activate_restored(w, m, false),
            Some(Ok(None)) => {
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
            Some(Err(e)) if e == "cancelled" => {
                // Left on onboarding with the door there, so a mis-tapped or
                // timed-out prompt is one tap from retrying.
                println!("cb: unlock cancelled");
                s.saved_key_present = true;
                w.global::<Onboarding>().set_saved_key_present(true);
                w.global::<Ui>().set_status("unlock cancelled — tap Restore to try again".into());
            }
            Some(Err(e)) => {
                println!("cb: unlock err={e}");
                s.saved_key_present = true;
                w.global::<Onboarding>().set_saved_key_present(true);
                w.global::<Ui>().set_status(format!("keychain: {e}").into());
            }
            None => {}
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_apply_pending_discovery(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let results: Vec<DiscoveryResult> =
            DISCOVERY_RESULTS.lock().expect("discovery results mutex").drain(..).collect();
        for r in results {
            if s.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
                || s.network != r.network
                || s.account != r.account
            {
                println!("cb: notebook-discovery stale-drop");
                continue;
            }
            let mut added = 0;
            for index in &r.found {
                if s.notebooks.as_ref().and_then(|ix| ix.get(r.account, *index)).is_none() {
                    s.ensure_notebook(*index);
                    added += 1;
                }
            }
            println!("cb: notebook-discovery found={} added={added}", r.found.len());
            if added > 0 {
                s.update_notebook_list(w);
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_copy_text(&mut self, w: &AppWindow, kind: SharedString, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
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

#[allow(unused_variables)]
pub(crate) fn on_set_coins_segment(&mut self, w: &AppWindow, seg: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        w.global::<Ui>().set_coins_segment(seg.clone());
        if seg.as_str() == "spending" && s.spending_capable && !s.spending_scanned {
            s.spending_refresh_async(w);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_open_activity(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: open-activity");
        w.global::<Ui>().set_return_screen(if w.global::<Ui>().get_screen() == Screen::Notebooks { Screen::Notebooks } else { Screen::Home });
        s.update_activity(w);
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Activity);
    }

#[allow(unused_variables)]
pub(crate) fn on_act_retry(&mut self, w: &AppWindow, ref_id: SharedString, is_note: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        if s.act_pending_ref.is_some() || s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        let (raw, last_txid) = if is_note {
            let n = s
                .store
                .as_ref()
                .and_then(|st| st.notes.iter().find(|n| n.note_id.as_str() == ref_id.as_str()));
            (n.and_then(|n| n.raw_hex.clone()), n.and_then(|n| n.txids.last().cloned()))
        } else {
            let t = s
                .store
                .as_ref()
                .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id.as_str())));
            (t.and_then(|t| t.raw_hex.clone()), t.and_then(|t| t.txids.last().cloned()))
        };
        let ref_id_s = ref_id.to_string();
        if let Some(r) = raw.filter(|r| !r.is_empty()) {
            // Case (a): raw hex cached locally — summarize + show_confirm
            // right now, no network round trip needed.
            s.enter_rebroadcast_confirm(w, ref_id_s, is_note, r);
            return;
        }
        // Case (b): chain-recovered record (watch mode, or any record with
        // no cached hex) — the node that already knows the tx is the
        // keyless rebroadcast source. Never block the UI thread on the
        // fetch; land on the confirm screen from the fetch-result
        // trampoline (mirrors `spending_refresh_async`).
        let Some(base) = s.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let net = s.network;
        let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let creds = s.core_rpc_creds_for(&base, net);
        s.act_pending_ref = Some(ref_id_s.clone());
        s.update_activity(w);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let client = open_client(&base, net, creds).map_err(|e| e.to_string());
            let result = last_txid
                .ok_or_else(|| "nothing to rebroadcast".to_string())
                .and_then(|t| client.and_then(|c| c.fetch_tx_hex(&t).map_err(|e| format!("{e}"))));
            REBROADCAST_FETCH_RESULTS.lock().expect("rebroadcast fetch results mutex").push(
                RebroadcastFetchResult { ref_id: ref_id_s, is_note, identity_addr, result },
            );
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_rebroadcast_fetch());
        });
    }

#[allow(unused_variables)]
pub(crate) fn on_act_explorer(&mut self, w: &AppWindow, url: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = platform::open_url(url.as_str());
    }

#[allow(unused_variables)]
pub(crate) fn on_consolidate_open(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.open_notebook_consolidate(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_start_rename(&mut self, w: &AppWindow, addr: SharedString, name: SharedString, synced: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        println!("cb: rename-start addr={addr}");
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_rename_address(addr.clone());
        w.global::<Modals>().set_rename_input(name);
        w.global::<Modals>().set_rename_synced(synced);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
        w.global::<Ui>().set_rename_pq_display(s.contact_pq_display_for(addr.as_str()).into());
    }

#[allow(unused_variables)]
pub(crate) fn on_cancel_rename(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Ui>().set_rename_address("".into());
        w.global::<Modals>().set_rename_input("".into());
        w.global::<Modals>().set_rename_synced(false);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Ui>().set_rename_pq_display("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
    }

#[allow(unused_variables)]
pub(crate) fn on_contact_pq_set(&mut self, w: &AppWindow, input: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = s.network.as_str().to_string();
        let Some(contact) = s
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        else {
            return;
        };
        match app_core::pqkeys::set_contact_pq_key(contact, input.trim()) {
            Ok(fp) => {
                s.save_contacts();
                println!("cb: contact-pq-key ok fp={fp}");
                w.global::<Modals>().set_rename_pq_error("".into());
                w.global::<Modals>().set_rename_pq_input("".into());
                w.global::<Ui>().set_rename_pq_display(s.contact_pq_display_for(&addr).into());
                s.refresh_contacts(w);
            }
            Err(e) => {
                println!("cb: contact-pq-key err={e}");
                w.global::<Modals>().set_rename_pq_error(e.to_string().into());
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_contact_pq_remove(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = s.network.as_str().to_string();
        if let Some(contact) = s
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        {
            contact.mlkem_ek = None;
            s.save_contacts();
            println!("cb: contact-pq-key removed");
            w.global::<Ui>().set_rename_pq_display("".into());
            s.refresh_contacts(w);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_cancel_remove(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Ui>().set_confirm_remove_address("".into());
    }

#[allow(unused_variables)]
pub(crate) fn on_compose_changed(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.refresh_compose(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_refresh_coins(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.wallet_stores_refresh_async(w, WalletStoresPurpose::Coins);
    }

#[allow(unused_variables)]
pub(crate) fn on_refresh_notebooks(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.wallet_stores_refresh_async(w, WalletStoresPurpose::Notebooks);
    }

#[allow(unused_variables)]
pub(crate) fn on_toggle_fund_external(&mut self, w: &AppWindow, on: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: fund-external {on}");
        if !on {
            s.funding_coins.clear();
        }
        w.global::<Ui>().set_status("".into());
        s.refresh_compose(w);
        // Turning it on with no wallet active → go to the saved-wallets list.
        if on && s.funding.is_none() {
            w.global::<Ui>().set_funding_return(Screen::Compose);
            s.refresh_funding_list(w);
            w.global::<Ui>().set_screen(Screen::FundingWallets);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_set_pay_from(&mut self, w: &AppWindow, kind: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: pay-from {kind}");
        s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
        s.apply_pay_from(w, kind.as_str());
        s.refresh_compose(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_open_funding(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: open-funding");
        w.global::<Ui>().set_status("".into());
        s.refresh_funding_list(w);
        w.global::<Ui>().set_screen(Screen::FundingWallets);
    }

#[allow(unused_variables)]
pub(crate) fn on_fund_rename_cancel(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Ui>().set_fund_rename_id("".into());
    }

#[allow(unused_variables)]
pub(crate) fn on_funding_import_ur(&mut self, w: &AppWindow, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        s.try_import_ur_account(w, text.as_str());
    }

#[allow(unused_variables)]
pub(crate) fn on_funding_clear(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.funding = None;
        s.funding_coins.clear();
        s.built_psbt = None;
        s.signed_psbt = None;
        w.global::<FundingWalletScreen>().set_funding_descriptor("".into());
        w.global::<FundingWalletScreen>().set_funding_feedback("".into());
        w.global::<FundingWalletScreen>().set_funding_valid(false);
        s.refresh_compose(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_psbt_copy(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let b64 = s.built_psbt.as_ref().map(|b| b.to_base64()).unwrap_or_default();
        if b64.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_text(&b64);
        if !ok {
            w.global::<Ui>().set_status("copy failed".into());
        }
        show_toast(w, if ok { "PSBT copied" } else { "Copy failed" });
    }

#[allow(unused_variables)]
pub(crate) fn on_psbt_loaded(&mut self, w: &AppWindow, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        s.load_signed_psbt(w, text.as_bytes());
    }

#[allow(unused_variables)]
pub(crate) fn on_psbt_broadcast(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        if s.wallet_tx_busy {
            return;
        }
        let Some(psbt) = s.signed_psbt.clone() else {
            w.global::<Ui>().set_status("no signed PSBT".into());
            return;
        };
        let Some(base) = s.base_url() else {
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
        let net = s.network;
        let snap = PsbtBroadcastSnapshot {
            identity_addr: s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
            txid,
            raw: raw.clone(),
            vsize,
        };
        s.wallet_tx_busy = true;
        w.global::<Confirm>().set_wallet_tx_busy(true);
        let creds = s.core_rpc_creds_for(&base, net);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let result = open_client(&base, net, creds)
                .map_err(|e| e.to_string())
                .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
            PSBT_BROADCAST_RESULTS
                .lock()
                .expect("psbt broadcast results mutex")
                .push(PsbtBroadcastResult { snap, result });
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
        });
    }

#[allow(unused_variables)]
pub(crate) fn on_confirm_cancel(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // Busy-guard: a broadcast already in flight can't be canceled out
        // from under itself (mirrors the Broadcast-tap guard above) — the
        // psbt kind in particular delegates to on_psbt_broadcast's own
        // wallet_tx_busy management, so this is the same flag either way.
        if s.wallet_tx_busy {
            return;
        }
        let kind = s.pending_broadcast.as_ref().map(|p| p.kind).unwrap_or("?");
        println!("cb: confirm cancel kind={kind}");
        let return_screen = s.pending_broadcast.take().map(|p| p.return_screen).unwrap_or(Screen::Home);
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
            s.signed_psbt = None;
            w.global::<Ui>().set_psbt_signed(false);
        }
        w.global::<Ui>().set_screen(return_screen);
    }

#[allow(unused_variables)]
pub(crate) fn on_account_cancel(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            // Abandon wallet consolidate: back to settings, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            s.wconsol = None;
            w.global::<Ui>().set_status("".into());
            w.global::<Ui>().set_screen(Screen::Settings);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Abandon create → back to the notebook list, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            w.global::<Ui>().set_status("".into());
            s.update_notebook_list(w);
            w.global::<Ui>().set_screen(Screen::Notebooks);
            return;
        }
        if s.pending_import.take().is_some() {
            w.global::<Ui>().set_screen(Screen::ImportKey); // abandon import → back to the import form
        } else {
            s.update_home(w);
            w.global::<Ui>().set_screen(Screen::Settings); // came from settings
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_reveal_hide(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.clear_reveal(w);
        println!("cb: hide-reveal");
    }

#[allow(unused_variables)]
pub(crate) fn on_pq_replace_confirm(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        w.global::<Ui>().set_pq_show_replace_confirm(false);
        match s.pq_pending_replace.take() {
            Some(PqReplaceKind::Generate) => s.do_pq_generate(w),
            Some(PqReplaceKind::Import) => s.do_pq_import(w),
            None => {}
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_pq_imported_hide_private(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Modals>().set_pq_imported_private_value("".into());
        w.global::<Modals>().set_pq_imported_private_qr(slint::Image::default());
    }

#[allow(unused_variables)]
pub(crate) fn on_copy_value(&mut self, w: &AppWindow, value: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        let ok = platform::set_clipboard_text(value.as_str());
        println!("cb: copy-value len={}", value.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }

#[allow(unused_variables)]
pub(crate) fn on_go_home(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.clear_reveal(w);
        s.go_home_or_list(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_open_notebooks(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // Leaving the open notebook: everything that was on screen counts
        // as read, so the list badge only flags what arrived since.
        if let Some(store) = s.store.as_mut() {
            if store.mark_seen() > 0 {
                s.save_store();
            }
        }
        w.global::<Ui>().set_status("".into());
        s.update_notebook_list(w);
        w.global::<Ui>().set_screen(Screen::Notebooks);
    }

#[allow(unused_variables)]
pub(crate) fn on_nb_rename_cancel(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Ui>().set_nb_rename_index(-1);
        w.global::<Modals>().set_nb_rename_input("".into());
    }
}
