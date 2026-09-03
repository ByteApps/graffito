//! Screen.activity — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Watch mode bump, step 1: fetch the pending tx from the node (chain-
/// recovered records carry no fee/vsize/raw hex), price it, open the dialog.
pub(crate) fn watch_bump_open(&mut self, w: &AppWindow, ref_id: String, is_note: bool) {
    let st = self;
    // The bump dialog prices the replacement off `st.fees.fastest` below —
    // lazily (re)fetch first (network-efficiency, 2026-07-23).
    st.refresh_fees_price(w);
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    let txid = {
        let Some(store) = st.store.as_ref() else { return };
        if is_note {
            store.notes.iter().find(|n| n.note_id == ref_id).and_then(|n| n.txids.last().cloned())
        } else {
            store
                .txs
                .iter()
                .find(|t| t.txids.contains(&ref_id))
                .and_then(|t| t.txids.last().cloned())
        }
    };
    let Some(txid) = txid else {
        w.global::<Ui>().set_status("transaction not found".into());
        return;
    };
    // Unit 6 defense-in-depth (mirrors keyed CHANGE 2's `mixed_inputs`
    // guard): a watch sweep/consolidate that included a chain-1 change coin
    // is recorded `mixed_inputs = true` and can't be bumped — the
    // `fetch_tx_io` rebuild below only resolves NOTEBOOK addresses, so it
    // can't safely reconstruct a chain-1 leaf's key origin.
    if !is_note
        && st
            .store
            .as_ref()
            .map(|s| s.txs.iter().any(|t| t.txids.contains(&ref_id) && t.mixed_inputs))
            .unwrap_or(false)
    {
        w.global::<Ui>().set_status(
            "this sweep included a change-chain coin — it can't be sped up (rebroadcast still works)"
                .into(),
        );
        return;
    }
    // Multi-notebook records: stamp each input's owning receive index by
    // its prevout address (fetch_tx_io alone can't know our leaves) — the
    // rebuild derives every input's spk/key-origin from that index.
    let index_by_addr: HashMap<String, u32> =
        st.nb_addrs.iter().map(|(i, a, _)| (a.clone(), *i)).collect();
    let creds = st.core_rpc_creds_for(&base, st.network);
    let client = match open_client(&base, st.network, creds) {
        Ok(c) => c,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    match client.fetch_tx_io(&txid, |a| index_by_addr.get(a).copied()) {
        Ok((coins, outputs, confirmed)) => {
            if confirmed {
                w.global::<Ui>().set_status("already confirmed — nothing to speed up".into());
                return;
            }
            let in_v: u64 = coins.iter().map(|c| c.value).sum();
            let out_v: u64 = outputs.iter().map(|(_, v)| *v).sum();
            let old_fee = in_v.saturating_sub(out_v);
            let vsize = predict_keyspend_vsize(coins.len(), outputs.iter().map(|(s, _)| s.len()));
            let old_rate = if vsize > 0 { old_fee as f64 / vsize as f64 } else { 0.0 };
            let min_rate = old_rate + 1.0;
            let fast = st.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
            let recommended = fast.max(min_rate);
            println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1} watch=1");
            w.global::<Ui>().set_bump_ref(ref_id.clone().into());
            w.global::<Ui>().set_bump_is_note(is_note);
            w.global::<Modals>().set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
            w.global::<Modals>().set_bump_current(format!("Currently {old_rate:.1} sat/vB · {old_fee} sats fee").into());
            w.global::<Modals>().set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
            w.global::<Modals>().set_bump_error("".into());
            w.global::<Modals>().set_bump_rate(format!("{recommended:.1}").into());
            w.global::<Modals>().set_bump_new_fee(new_fee_line(recommended, vsize, old_fee).into());
            st.watch_bump = Some(WatchBump { ref_id, is_note, txid, coins, outputs, old_fee, vsize });
            w.global::<Ui>().set_show_bump_dialog(true);
        }
        Err(e) => w.global::<Ui>().set_status(format!("can't fetch the pending tx: {}", friendly_net_err(&e.to_string())).into()),
    }
}

/// Watch mode bump, step 2: rebuild the replacement PSBT (same in/outs, fee
/// delta out of our own output) and open the external-sign screen.
pub(crate) fn watch_bump_confirm(&mut self, w: &AppWindow, new_rate: f64) {
    let st = self;
    let Some(wb) = st.watch_bump.take() else {
        w.global::<Modals>().set_bump_error("bump context lost — reopen the dialog".into());
        return;
    };
    let min_rate = (wb.old_fee as f64 / wb.vsize.max(1) as f64) + 1.0;
    if new_rate + 1e-9 < min_rate {
        w.global::<Modals>().set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
        st.watch_bump = Some(wb);
        return;
    }
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let self_spk = p2tr_script_pubkey(&st.ident.as_ref().map(|i| i.output_x()).unwrap_or_default());
    // Take the fee delta from our own output (largest), else the largest
    // non-OP_RETURN output (a sweep pays the fee out of the swept amount).
    let reduce = wb
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, (spk, _))| *spk == self_spk)
        .max_by_key(|(_, (_, v))| *v)
        .map(|(i, _)| i)
        .or_else(|| {
            wb.outputs
                .iter()
                .enumerate()
                .filter(|(_, (spk, _))| spk.first() != Some(&0x6a))
                .max_by_key(|(_, (_, v))| *v)
                .map(|(i, _)| i)
        });
    let Some(reduce) = reduce else {
        w.global::<Modals>().set_bump_error("no output can absorb the fee bump".into());
        return;
    };
    // Deliberately the DEVICE default, not `effective_lock_time()`: the
    // bump dialog (Activity screen) has no locktime panel and nothing
    // resets the compose/sweep override before it runs, so consulting it
    // here could silently leak a stale override from an earlier, unrelated
    // compose/sweep session into this replacement with no UI indication.
    match build_watch_bump_psbt(&src, &wb.coins, &wb.outputs, reduce, new_rate, st.lock_time()) {
        Ok(built) => {
            w.global::<Ui>().set_show_bump_dialog(false);
            let dest = st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let cost = format!(
                "speed-up · replaces {}… · new fee {} sats · sign with your external wallet",
                &wb.txid[..12.min(wb.txid.len())],
                built.fee
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind: "bump",
                dest,
                dest_spk_hex: hex::encode(&wb.outputs[reduce].0),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs: Vec::new(),
                input_indexes: Vec::new(),
                dest_index: None,
                bump_ref: Some((wb.ref_id.clone(), wb.is_note)),
                change_spent: Vec::new(),
            });
            println!("cb: watch-bump-build ref={} txid={} fee={}", wb.ref_id, built.txid, built.fee);
            st.show_psbt_sign_screen(w, built, cost);
        }
        Err(e) => {
            w.global::<Modals>().set_bump_error(format!("{e}").into());
            st.watch_bump = Some(wb);
        }
    }
}

/// Build the unified activity list (note txs + sweep/consolidate),
/// actionable (pending) first, then newest.
pub(crate) fn update_activity(&self, w: &AppWindow) {
    let st = self;
    let net = st.network;
    let exb = st.explorer_base();
    let ex = exb.as_deref();
    let mut items: Vec<(u64, bool, ActivityItem)> = Vec::new(); // (created, confirmed, item)

    // Wallet-wide: every ACTIVE notebook's notes + txs, tagged. Only the
    // active notebook's rows are actionable (bump/rebroadcast sign with
    // the live store + key); the rest keep the Explorer link.
    let current = st.ident.as_ref().map(|i| i.index);
    let mut sources: Vec<(String, bool, Store)> = Vec::new(); // (tag, actionable, store)
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = st.notebook_store(m.index) else { continue };
            sources.push((
                st.notebook_display_name(m.index),
                current == Some(m.index),
                store,
            ));
        }
    } else if let Some(store) = &st.store {
        sources.push((String::new(), true, store.clone()));
    }

    for (tag, actionable, store) in &sources {
    for n in &store.notes {
        let Some(txid) = n.txids.last() else { continue };
        let kind = format!(
            "Note · {}{}",
            if n.private { "private" } else { "public" },
            if n.received {
                " · received"
            } else if n.directed {
                " · sent"
            } else {
                ""
            }
        );
        let status = match n.status {
            // Task #14: a dropped PENDING note renders distinctly (amber
            // "dropped — bump fee to retry" in the UI) — Bump/Rebroadcast
            // stay available exactly like an ordinary pending row (`pending`
            // below is unaffected by `dropped`).
            NoteStatus::Pending if n.dropped => "dropped",
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        items.push((
            n.created_at.or(n.blocktime).unwrap_or(0),
            n.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: n.note_id.clone().into(),
                is_note: true,
                kind: kind.into(),
                title: n.text.clone().unwrap_or_else(|| "(encrypted)".into()).into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(n.fee, n.vsize).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: *actionable && n.status == NoteStatus::Pending && n.raw_hex.is_some(),
                replaced: replaced_label(n.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: funded_pill(n.funded_by.as_deref()).into(),
                busy: st.act_pending_ref.as_deref() == Some(n.note_id.as_str()),
                bumpable: true, // notes bump via bump_fee — never a mixed record
            },
        ));
    }

    for t in &store.txs {
        let Some(txid) = t.txids.last() else { continue };
        let status = match t.status {
            // Task #14 — see the identical note-row rule above.
            NoteStatus::Pending if t.dropped => "dropped",
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        let title = if t.dest == "self" {
            format!("Consolidate · {} sats arrived here", t.value)
        } else {
            format!("To {} · {} sats", t.dest, t.value)
        };
        items.push((
            t.created_at.unwrap_or(0),
            t.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: txid.clone().into(),
                is_note: false,
                kind: if t.kind == "consolidate" { "Consolidate" } else { "Sweep" }.into(),
                title: title.into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(Some(t.fee), Some(t.vsize)).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: *actionable && t.status == NoteStatus::Pending && t.raw_hex.is_some(),
                replaced: replaced_label(t.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: "".into(), // sweeps/consolidates aren't funded-note records
                busy: st.act_pending_ref.as_deref() == Some(txid.as_str()),
                bumpable: !t.mixed_inputs, // CHANGE 2: a mixed sweep can't RBF (see TxRecord.mixed_inputs)
            },
        ));
    }
    }

    // Actionable (unconfirmed) first, then newest created.
    items.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
    let list: Vec<ActivityItem> = items.into_iter().map(|(_, _, it)| it).collect();
    let pending = list.iter().filter(|i| i.pending).count();
    w.global::<Activity>().set_activity_summary(
        if list.is_empty() {
            "No transactions yet.".to_string()
        } else {
            format!("{} transaction{} · {pending} pending", list.len(), if list.len() == 1 { "" } else { "s" })
        }
        .into(),
    );
    w.global::<Ui>().set_activity(VecModel::from_slice(&list));
}
}

impl State {
pub(crate) fn on_act_bump_open(&mut self, w: &AppWindow, ref_id: SharedString, is_note: bool) {
        // The bump dialog prices off `st.fees.fastest` — lazily (re)fetch
        // before either branch below reads it (network-efficiency,
        // 2026-07-23). `watch_bump_open` also calls this — the 60s cache
        // makes the second call here-or-there free either way.
        self.refresh_fees_price(w);
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            self.watch_bump_open(w, ref_id.to_string(), is_note);
            return;
        }
        let Some(store) = &self.store else { return };
        // CHANGE 2 defense-in-depth: the UI already hides Speed-up for a
        // mixed record (`ActivityItem.bumpable`), but refuse here too
        // rather than trust the tap origin.
        if !is_note && store.txs.iter().any(|t| t.txids.iter().any(|x| x == ref_id.as_str()) && t.mixed_inputs) {
            w.global::<Ui>().set_status("this sweep mixed notebook + spending coins — it can't be sped up (rebroadcast still works)".into());
            return;
        }
        let Some((old_rate, fee, vsize)) = tx_rate(store, ref_id.as_str(), is_note) else {
            w.global::<Ui>().set_status("can't determine current fee rate".into());
            return;
        };
        // BIP-125: the replacement must add at least 1 sat/vB (incremental
        // relay) over the original, and pay a strictly higher total fee.
        let min_rate = old_rate + 1.0;
        let fast = self.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
        let recommended = fast.max(min_rate);
        println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1}");
        w.global::<Ui>().set_bump_ref(ref_id.clone());
        w.global::<Ui>().set_bump_is_note(is_note);
        w.global::<Modals>().set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
        w.global::<Modals>().set_bump_current(format!("Currently {old_rate:.1} sat/vB · {fee} sats fee").into());
        w.global::<Modals>().set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
        w.global::<Modals>().set_bump_error("".into());
        w.global::<Modals>().set_bump_rate(format!("{recommended:.1}").into());
        w.global::<Modals>().set_bump_new_fee(new_fee_line(recommended, vsize, fee).into());
        w.global::<Ui>().set_show_bump_dialog(true);
    }
}
