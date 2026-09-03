//! Screen.confirm — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// `ConfirmCtx.prevouts` for a notebook compose's spent coins — every input
/// is this notebook's own single address (coin control only ever selects
/// among this notebook's own UTXOs, so one address covers every entry).
/// `spent` is `NoteTx.spent_outpoints` — internal (non-reversed) txid
/// bytes, matching `compose::record_composed_note`'s own reversal.
pub(crate) fn notebook_prevouts(
    store: &Store,
    address: &str,
    name: &str,
    spent: &[([u8; 32], u32)],
) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    spent
        .iter()
        .map(|(txid, vout)| {
            let mut d = *txid;
            d.reverse();
            let txid_hex = hex::encode(d);
            let value =
                store.utxos.iter().find(|u| u.txid == txid_hex && u.vout == *vout).map(|u| u.value).unwrap_or(0);
            (
                format!("{txid_hex}:{vout}"),
                app_core::confirm::PrevoutInfo {
                    value,
                    address: Some(address.to_string()),
                    source: format!("Notebook · {name}"),
                },
            )
        })
        .collect()
}

/// `ConfirmCtx.prevouts` from already-known inputs whose value is already
/// in hand (gathered while building a sweep/consolidate tx, unlike
/// `notebook_prevouts`'s compose-path shape which must look values up) —
/// every entry gets the SAME address + source label. Multi-source flows
/// (wallet sweep, wconsol) build the map entry-by-entry themselves instead
/// (each input needs its OWN owning notebook's label).
pub(crate) fn labeled_prevouts(
    inputs: &[app_core::store::TxInput],
    address: Option<&str>,
    source: &str,
) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    inputs
        .iter()
        .map(|inp| {
            (
                format!("{}:{}", inp.txid, inp.vout),
                app_core::confirm::PrevoutInfo {
                    value: inp.value,
                    address: address.map(str::to_string),
                    source: source.to_string(),
                },
            )
        })
        .collect()
}

impl State {
/// Post-broadcast bookkeeping for a watch-mode compose: record the public
/// note as Pending with the same ledger effects as a keyed compose —
/// inputs locked, change (last vout) spendable unconfirmed, raw hex kept
/// for rebroadcast until confirmation.
pub(crate) fn record_watch_note(&mut self, wn: &WatchNote, txid: &str, raw: &str, vsize: u64) {
    let st = self;
    let Some(store) = st.store.as_mut() else { return };
    // A mixed-source compose (funding-unification UI rework) always carries
    // a dust-to-self output BEFORE change; a genuine watch compose never
    // does (it already spends from self) — shifts the change vout by one.
    // Multi-recipient (2+): as many recipient outputs as `wn.recipients`
    // carries, in place of the single 0/1 slot — everything else about the
    // vout arithmetic (dust-to-self, then change) is unaffected by count.
    let recipient_outputs =
        if wn.recipients.len() >= 2 { wn.recipients.len() } else { usize::from(wn.recipient.is_some()) };
    let change_vout = wn.chunks + recipient_outputs + usize::from(wn.dust_to_self);
    let change = (wn.change > 0).then(|| app_core::store::LedgerUtxo {
        txid: txid.to_string(),
        vout: change_vout as u32,
        value: wn.change,
        height: None,
        pending_spend: false,
    });
    store.record_signed(
        app_core::store::NoteRecord {
            // PLAN-pnte-redesign.md: the note id IS the txid.
            note_id: txid.to_string(),
            status: NoteStatus::Pending,
            text: Some(wn.text.clone()),
            private: wn.private,
            directed: wn.recipient.is_some(),
            received: false,
            sender: None,
            recipient: wn.recipient.clone(),
            recipients: wn.recipients.clone(),
            txids: vec![txid.to_string()],
            height: None,
            blocktime: None,
            created_at: Some(now()),
            spent: wn.spent.clone(),
            raw_hex: Some(raw.to_string()),
            fee: Some(wn.fee),
            vsize: Some(vsize),
            change_to: None,
            gift_amount: wn.recipient.is_some().then_some(wn.gift),
            funded_by: wn.funded.clone(),
            dropped: false,
            // Watch-mode compose never carries a pq layer — directed-
            // private (the only pq-eligible kind) needs the identity key
            // at compose time, which a watch identity never has.
            pq_flags: 0,
            locked: None,
        },
        change,
    );
    // Touch every recipient (multi: all of them; single: just the one) —
    // same "recents list reflects the whole To list" rule the notebook
    // path's `record_composed_note` follows. The chip-add flow already
    // touches contacts at PICK time (`on_add_recipient`), so this is a
    // redundant (idempotent — `touch_contact` just bumps recency) safety
    // net, not the only place it happens.
    if wn.recipients.is_empty() {
        if let Some(addr) = &wn.recipient {
            st.touch_contact(addr);
        }
    } else {
        for addr in &wn.recipients {
            st.touch_contact(addr);
        }
    }
    // Taproot CHANGE-chain coins (unit-5 follow-up): a keyed mixed compose
    // that ALSO pulled an external funding wallet signed its change inputs
    // in-app, then routed through this external-sign path — prune them from
    // the runtime cache on broadcast success (same treatment as
    // `record_watch_spend`/`WatchSpend.change_spent`), so the next compose
    // doesn't re-offer an already-spent coin before the next chain-1 rescan.
    if !wn.change_spent.is_empty() {
        st.change_coins
            .retain(|c| !wn.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout));
    }
    st.save_store();
    st.save_contacts();
}

/// Post-broadcast bookkeeping for a watch-mode external-sign spend: sweep/
/// consolidate become TxRecords (Activity lifecycle + rebroadcast/RBF), a
/// bump rides on the record it replaces; spent coins get pending-locked.
pub(crate) fn record_watch_spend(&mut self, ws: &WatchSpend, txid: &str, raw: &str, vsize: u64) {
    let st = self;
    if st.store.is_none() {
        return;
    }
    match &ws.bump_ref {
        Some((ref_id, is_note)) => {
            let store = st.store.as_mut().expect("checked above");
            if *is_note {
                if let Some(n) = store.notes.iter_mut().find(|n| n.note_id == *ref_id) {
                    if !n.txids.contains(&txid.to_string()) {
                        n.txids.push(txid.to_string());
                    }
                    n.fee = Some(ws.fee);
                    n.vsize = Some(vsize);
                }
            } else if let Some(t) =
                store.txs.iter_mut().find(|t| t.txids.iter().any(|x| x == ref_id))
            {
                if !t.txids.contains(&txid.to_string()) {
                    t.txids.push(txid.to_string());
                }
                t.fee = ws.fee;
                t.vsize = vsize;
                t.raw_hex = Some(raw.to_string());
            }
        }
        None => {
            // Wallet-level (rev 3): inputs may span notebooks — lock each
            // one in ITS OWN store (the active store in memory, siblings on
            // disk), mirroring the keyed sweep's bookkeeping.
            let active_index = st.ident.as_ref().map(|i| i.index);
            let mut owners: Vec<u32> = ws.input_indexes.clone();
            owners.sort_unstable();
            owners.dedup();
            if owners.is_empty() {
                owners.push(active_index.unwrap_or(0)); // legacy single-notebook shape
            }
            let lock = |store: &mut Store, index: u32| {
                for (i, input) in ws.inputs.iter().enumerate() {
                    let owner = ws.input_indexes.get(i).copied().unwrap_or(index);
                    if owner != index {
                        continue;
                    }
                    if let Some(u) =
                        store.utxos.iter_mut().find(|u| u.txid == input.txid && u.vout == input.vout)
                    {
                        u.pending_spend = true;
                    }
                }
            };
            for index in &owners {
                if active_index == Some(*index) {
                    if let Some(store) = st.store.as_mut() {
                        lock(store, *index);
                    }
                } else if let Some(mut store) = st.notebook_store(*index) {
                    lock(&mut store, *index);
                    if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                        save_store_file(&store, &st.store_path_for(fp8));
                    }
                }
            }
            // The TxRecord lands in the destination store for a consolidate-
            // to-notebook (plus its unconfirmed coin, so the balance shows
            // before the next scan); sweeps/legacy keep it in the ACTIVE
            // store — Activity is wallet-wide either way.
            let record = |store: &mut Store| {
                store.record_tx(
                    ws.kind,
                    txid.to_string(),
                    ws.value,
                    ws.fee,
                    vsize,
                    raw.to_string(),
                    ws.dest.clone(),
                    ws.inputs.clone(),
                    ws.dest_spk_hex.clone(),
                    now(),
                );
                if let Some(rec) = store.txs.last_mut() {
                    rec.input_indexes = ws.input_indexes.clone();
                    // Unit 6: a change-including watch spend is non-bumpable
                    // (see `WatchSpend.change_spent`'s doc comment) — same
                    // `mixed_inputs` flag keyed CHANGE 2 sweeps use, so the
                    // Activity screen's Speed-up affordance hides itself the
                    // same way (`ActivityItem.bumpable = !t.mixed_inputs`).
                    rec.mixed_inputs = !ws.change_spent.is_empty();
                }
            };
            match ws.dest_index {
                Some(dest) if active_index != Some(dest) => {
                    if let Some(mut dstore) = st.notebook_store(dest) {
                        record(&mut dstore);
                        dstore.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                        if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == dest) {
                            save_store_file(&dstore, &st.store_path_for(fp8));
                        }
                    }
                }
                Some(_) => {
                    // Destination IS the active notebook.
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                        store.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                    }
                }
                None => {
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                    }
                }
            }
            // Taproot CHANGE-chain coins (unit 6): pruned from the runtime
            // cache so they're not re-offered before the next wallet-stores
            // refresh re-scans chain 1 and finds them gone — same treatment
            // as the keyed sweep's `SweepSnapshot.change_spent`.
            if !ws.change_spent.is_empty() {
                st.change_coins.retain(|c| {
                    !ws.change_spent.iter().any(|(t, v)| t == &c.txid && *v == c.vout)
                });
            }
        }
    }
    st.save_store();
}

/// Every scriptPubKey this account controls: every ACTIVE notebook's own
/// address (not just the current one — a directed self-note from a sibling
/// notebook must still classify as "self", same rule `xacct_addrs`/
/// `sender_label` already follow) plus every spending-wallet address
/// handed out so far (`Store::spending_self_spks`). Feeds
/// `ConfirmCtx.self_spks`/`spending_spks` for every compose path; PSBT-path
/// callers reuse it too. A change output going to an address not yet
/// recorded as "used" (the spending wallet's NEXT receive/change index, or
/// a freshly discovered one) must be added by the caller on top of this —
/// see the spending/mixed compose call sites below.
pub(crate) fn confirm_self_spks(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let st = self;
    let mut self_spks: Vec<Vec<u8>> = Vec::new();
    if let (Some(ix), Some(material_str)) = (&st.notebooks, st.material.as_deref()) {
        if let Ok(material) = parse_key_material(material_str, st.network) {
            for m in ix.active(st.account) {
                if let Ok(ident) = realize(&material, st.network, st.account, m.index) {
                    self_spks.push(p2tr_script_pubkey(&ident.output_x()));
                }
            }
        }
    }
    let spending_spks = st.store.as_ref().map(|s| s.spending_self_spks()).unwrap_or_default();
    self_spks.extend(spending_spks.iter().cloned());
    (self_spks, spending_spks)
}

/// The DISPLAY-OWNER anchor set (notes-core rev 6e36a23) for the CURRENT
/// identity's account — every ACTIVE notebook's own spk, in index order,
/// fed to `Store::apply_bundle`/`apply_bundle_watch` alongside a scan.
/// Mirrors `confirm_self_spks`'s notebook enumeration exactly (same
/// `ix.active(account)` + `realize` walk via `active_notebook_spks`) but
/// omits the spending wallet's addresses, which must never be in this
/// set. Empty when there's no material/notebooks index yet (non-
/// hierarchical key material, or before the first notebook loads) —
/// `Store::apply_bundle*` treat an empty slice as a strict no-op.
pub(crate) fn notebook_spks_for(&self) -> Vec<Vec<u8>> {
    let st = self;
    match (&st.notebooks, st.material.as_deref()) {
        (Some(ix), Some(material_str)) => parse_key_material(material_str, st.network)
            .map(|material| active_notebook_spks(&material, st.network, st.account, ix))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The derived spending-address classification window (Unit A / RC1): both
/// chains' scriptPubKeys for indexes `0..max(SPENDING_WINDOW_MIN,
/// discovered_next_index + SPENDING_WINDOW_BUFFER)`, where
/// `discovered_next_index` is the account's spending section's
/// `next_receive`/`next_change` high-water mark
/// (`NotebookIndex::spending_for`, history-based and already correct — see
/// the PLAN's RC1 analysis). Fed to `Store::apply_bundle`/
/// `apply_bundle_watch` as `extra_spending_spks` alongside a scan, UNIONED
/// with (never replacing) the store's own recorded-`used` snapshot — this
/// is what fixes a spending-wallet-funded self-note classifying as
/// "Unknown" after a fresh install or on a disk-loaded non-active store,
/// where that snapshot is empty or stale.
///
/// Empty for watch-only or non-hierarchical material (`spending::
/// window_spks` mirrors `can_derive_spending`, so a watch identity — which
/// has no spending wallet — degrades to today's byte-identical behavior)
/// or when there's no notebooks index / material loaded yet.
pub(crate) fn spending_window_spks_for(&self) -> Vec<Vec<u8>> {
    let st = self;
    let (Some(ix), Some(material_str)) = (&st.notebooks, st.material.as_deref()) else {
        return Vec::new();
    };
    let Ok(material) = parse_key_material(material_str, st.network) else {
        return Vec::new();
    };
    let section = ix.spending_for(st.account);
    let discovered_next_index = section.next_receive.max(section.next_change);
    let upto = SPENDING_WINDOW_MIN.max(discovered_next_index.saturating_add(SPENDING_WINDOW_BUFFER));
    app_core::spending::window_spks(&material, st.network, st.account, upto).unwrap_or_default()
}

/// `ConfirmCtx.prevouts` for a STORED pending record's inputs — used by
/// Speed-up and Rebroadcast, where the tx was already built earlier (not
/// freshly composed this session, so there's no fresh coin list in hand).
/// A note spend is always this notebook's own single address (coin
/// control only ever spends one notebook's own UTXOs). A sweep/consolidate
/// record resolves each input's owning notebook from
/// `TxRecord.input_indexes`/`input_accounts` where available (multi-key
/// wallet ops); an input with no resolvable owner (a mixed notebook+
/// spending-wallet record has none at all — see `TxRecord.mixed_inputs`)
/// gets an empty source/no address — honest partial disclosure, never a
/// fabricated one; the confirm module renders that as "source unknown".
pub(crate) fn stored_record_prevouts(&self, ref_id: &str, is_note: bool) -> HashMap<String, app_core::confirm::PrevoutInfo> {
    let st = self;
    let Some(store) = st.store.as_ref() else { return HashMap::new() };
    if is_note {
        let Some(rec) = store.notes.iter().find(|n| n.note_id == ref_id) else { return HashMap::new() };
        let name = st.notebook_display_name(st.ident.as_ref().map(|i| i.index).unwrap_or(0));
        let addr = st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        return rec
            .spent
            .iter()
            .map(|op| {
                let value = store
                    .utxos
                    .iter()
                    .find(|u| u.txid == op.txid && u.vout == op.vout)
                    .map(|u| u.value)
                    .unwrap_or(0);
                (
                    format!("{}:{}", op.txid, op.vout),
                    app_core::confirm::PrevoutInfo {
                        value,
                        address: Some(addr.clone()),
                        source: format!("Notebook · {name}"),
                    },
                )
            })
            .collect();
    }
    let Some(rec) = store.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id)) else {
        return HashMap::new();
    };
    let material = st.material.as_deref().and_then(|m| parse_key_material(m, st.network).ok());
    rec.inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            let owner = if !rec.input_indexes.is_empty() {
                rec.input_indexes.get(i).map(|idx| (st.account, *idx))
            } else if !rec.input_accounts.is_empty() {
                rec.input_accounts.get(i).map(|acct| (*acct, 0u32))
            } else {
                None
            };
            let info = match (owner, material.as_ref()) {
                (Some((acct, idx)), Some(m)) => match realize(m, st.network, acct, idx) {
                    Ok(ident) => app_core::confirm::PrevoutInfo {
                        value: inp.value,
                        address: Some(ident.address.clone()),
                        source: if acct == st.account {
                            format!("Notebook · {}", st.notebook_display_name(idx))
                        } else {
                            format!("Notebook · account {acct}")
                        },
                    },
                    Err(_) => {
                        app_core::confirm::PrevoutInfo { value: inp.value, address: None, source: String::new() }
                    }
                },
                _ => app_core::confirm::PrevoutInfo { value: inp.value, address: None, source: String::new() },
            };
            (format!("{}:{}", inp.txid, inp.vout), info)
        })
        .collect()
}

/// `ConfirmCtx.expected_change` for a note's Speed-up/Rebroadcast: a note
/// composed with a custom (non-self) change address persists it on the
/// record (`NoteRecord.change_to`) specifically so RBF/rebroadcast keep
/// classifying it correctly — without this, a bumped/rebroadcast note's
/// custom-change output would wrongly read "other" (foreign) and trip the
/// paranoid warning on every legitimate replacement. Sweep/consolidate
/// records have no custom-change concept, so `None` for those.
pub(crate) fn stored_record_expected_change(&self, ref_id: &str, is_note: bool) -> Option<String> {
    let st = self;
    if !is_note {
        return None;
    }
    st.store.as_ref()?.notes.iter().find(|n| n.note_id == ref_id)?.change_to.clone()
}

/// Populate the universal confirm screen (26) from a signed raw tx +
/// [`app_core::confirm::ConfirmCtx`], and stash `pending` for the
/// Broadcast/Cancel taps. `summarize_signed_tx` decodes `pending.raw_hex`
/// itself (the paranoid byte-truth rule); `ctx` only supplies lookups. On a
/// decode error, sets `status` and does NOT navigate — the caller stays
/// wherever it was (compose/sign/etc).
pub(crate) fn show_confirm(&mut self, w: &AppWindow, pending: PendingBroadcast, ctx: app_core::confirm::ConfirmCtx) {
    let st = self;
    let sum = match app_core::confirm::summarize_signed_tx(&pending.raw_hex, &ctx) {
        Ok(s) => s,
        Err(e) => {
            println!("cb: confirm summarize err={e}");
            w.global::<Ui>().set_status(format!("confirm: {e}").into());
            return;
        }
    };
    let to_rows = |rows: &[app_core::confirm::SummaryRow]| -> Vec<PsbtRow> {
        rows.iter()
            .map(|r| PsbtRow {
                title: r.title.clone().into(),
                subtitle: r.subtitle.clone().into(),
                amount: r.amount.clone().into(),
                kind: r.kind.clone().into(),
            })
            .collect()
    };
    w.global::<Confirm>().set_confirm_inputs(VecModel::from_slice(&to_rows(&sum.inputs)));
    w.global::<Confirm>().set_confirm_outputs(VecModel::from_slice(&to_rows(&sum.outputs)));
    w.global::<Confirm>().set_confirm_note(ctx.note_preview.clone().unwrap_or_default().into());
    w.global::<Confirm>().set_confirm_fee_line(sum.fee_line.clone().into());
    w.global::<Confirm>().set_confirm_locktime_line(sum.lock_time_line.clone().into());
    w.global::<Ui>().set_confirm_warn(sum.warn.clone().unwrap_or_default().into());
    w.global::<Confirm>().set_confirm_txid(sum.txid.clone().into());
    w.global::<Confirm>().set_confirm_context(pending.context.clone().into());
    println!(
        "cb: confirm show kind={} txid={} fee={} vsize={} inputs={} outputs={} lock_time={} warn={}",
        pending.kind,
        sum.txid,
        sum.fee.map(|f| f.to_string()).unwrap_or_else(|| "?".to_string()),
        sum.vsize,
        sum.inputs.len(),
        sum.outputs.len(),
        sum.lock_time,
        i32::from(sum.warn.is_some()),
    );
    let return_screen = w.global::<Ui>().get_screen();
    w.global::<Ui>().set_status("".into());
    st.pending_broadcast = Some(PendingBroadcast { return_screen, ..pending });
    w.global::<Ui>().set_screen(Screen::Confirm);
}

/// Stage A for a Rebroadcast (`on_act_retry`), once the raw hex is in hand
/// (cached locally, or freshly fetched for a chain-recovered/watch record
/// with none cached — both sub-cases converge here): summarize + hand off
/// to the universal confirm screen. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Rebroadcast`) is the
/// pre-existing broadcast thread-spawn, moved verbatim.
pub(crate) fn enter_rebroadcast_confirm(&mut self, w: &AppWindow, ref_id: String, is_note: bool, raw_hex: String) {
    let st = self;
    let net = st.network;
    let (txid, vsize) = decode_txid_vsize(&raw_hex).unwrap_or_default();
    let prevouts = st.stored_record_prevouts(&ref_id, is_note);
    let expected_change = st.stored_record_expected_change(&ref_id, is_note);
    let (self_spks, spending_spks) = st.confirm_self_spks();
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
        tip_height: st.confirm_tip_height(),
    };
    let pending = PendingBroadcast {
        kind: "rebroadcast",
        raw_hex,
        txid,
        vsize,
        context: format!("Rebroadcast · {}", net.as_str()),
        return_screen: Screen::Activity, // overwritten by show_confirm
        payload: PendingPayload::Rebroadcast { ref_id },
    };
    st.show_confirm(w, pending, ctx);
}

/// Validate + summarize a signed PSBT into the confirmation screen.
/// Validate a signed PSBT, finalize it to raw broadcastable bytes, and hand
/// it to the universal confirm screen (kind "psbt" — external-wallet-funded
/// notes AND every watch-only spend share this path). `State.signed_psbt`/
/// `built_psbt`/`watch_note`/`watch_spend` are left exactly as before: they
/// already carry everything `on_psbt_broadcast`'s stage-B needs, untouched
/// by the confirm screen's navigation.
pub(crate) fn set_confirm_from_psbt(&mut self, w: &AppWindow, psbt: bitcoin::Psbt) {
    let st = self;
    let Some(built) = st.built_psbt.as_ref() else {
        w.global::<Ui>().set_status("build a transaction first".into());
        return;
    };
    if let Err(e) = validate_signed(&psbt, &built.txid) {
        w.global::<Ui>().set_status(format!("{e}").into());
        return;
    }
    let Some(output_x) = st.ident.as_ref().map(|i| i.output_x()) else { return };
    // Watch spends label their destination as the recipient; the funding
    // flow labels the compose recipient + the funding wallet's change.
    let recipient_addr = match &st.watch_spend {
        Some(ws) => Some(ws.dest.clone()),
        None => st.to_address.clone(),
    };
    let change_addr = match &st.watch_spend {
        Some(_) => None,
        None => st
            .funding
            .as_ref()
            .and_then(|src| src.derive(1, st.funding_change_index).ok())
            .map(|d| d.address),
    };
    // Only used here to pull the (public) note text back out / detect
    // whether this tx carries a note at all — the OUTPUTS list itself now
    // comes from the raw-hex decode below, not this PSBT-level summary.
    let sum_ctx = SummaryContext {
        identity_output_x: output_x,
        network: st.network,
        recipient_addr: recipient_addr.as_deref(),
        change_addr: change_addr.as_deref(),
    };
    let sum = match summarize(&psbt, &sum_ctx) {
        Ok(s) => s,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    let mut note_text = String::new();
    let mut has_note = false;
    for o in &sum.outputs {
        if let OutputRole::Note { text, .. } = &o.role {
            has_note = true;
            if let Some(t) = text {
                note_text = t.clone();
            }
        }
    }
    let note_preview = has_note.then(|| {
        if note_text.is_empty() { "Private note (encrypted)".to_string() } else { note_text.clone() }
    });
    // Sweep/consolidate/bump carry no OP_RETURN at all — label them from
    // `watch_spend` instead of the (note-shaped) public/private/directed
    // formula.
    let context = if has_note {
        note_context(recipient_addr.is_some(), note_text.is_empty(), st.network)
    } else {
        match &st.watch_spend {
            Some(ws) if ws.kind == "bump" => format!("Speed up · {}", st.network.as_str()),
            Some(ws) => {
                let label = match ws.kind {
                    "sweep" => "Sweep",
                    "consolidate" => "Consolidate",
                    other => other,
                };
                format!("{label} to {}", short_addr(&ws.dest))
            }
            None => format!("Transaction · {}", st.network.as_str()),
        }
    };

    // Prevout lookups straight from the PSBT's own witness_utxo — every
    // input here was funded externally (a watch identity's own coin,
    // signed off-device, or a separate funding wallet's coin), so there's
    // one source label for the whole tx: the active funding wallet's
    // label when known, else a generic "external signer".
    let source_label = st.active_funding_pill()
        .and_then(|s| s.strip_prefix("wallet:").map(str::to_string))
        .unwrap_or_else(|| "external signer".to_string());
    let btc_net = app_core::derive::btc_network(st.network);
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let wu = psbt.inputs.get(i).and_then(|pi| pi.witness_utxo.as_ref());
        let value = wu.map(|o| o.value.to_sat()).unwrap_or(0);
        let address = wu.and_then(|o| bitcoin::Address::from_script(&o.script_pubkey, btc_net).ok()).map(|a| a.to_string());
        prevouts.insert(
            format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout),
            app_core::confirm::PrevoutInfo { value, address, source: source_label.clone() },
        );
    }

    let (raw, txid, vsize) = match finalize_extract(psbt.clone()) {
        Ok(x) => x,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };

    let (self_spks, spending_spks) = st.confirm_self_spks();
    let recipient_name = recipient_addr.as_deref().and_then(|a| {
        st.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
    });
    let confirm_ctx = app_core::confirm::ConfirmCtx {
        network: btc_net,
        prevouts,
        self_spks,
        spending_spks,
        expected_change: change_addr,
        recipient: recipient_addr,
        recipient_name,
        recipients: Vec::new(),
        note_preview,
        tip_height: st.confirm_tip_height(),
    };

    st.signed_psbt = Some(psbt);
    w.global::<Ui>().set_psbt_signed(true);
    let pending = PendingBroadcast {
        kind: "psbt",
        raw_hex: raw,
        txid,
        vsize,
        context,
        return_screen: Screen::ImportSignedPsbt, // overwritten by show_confirm
        payload: PendingPayload::Psbt,
    };
    st.show_confirm(w, pending, confirm_ctx);
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_confirm_broadcast(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        if s.wallet_tx_busy {
            return;
        }
        let Some(pending) = s.pending_broadcast.clone() else { return };
        println!("cb: confirm broadcast kind={} txid={}", pending.kind, pending.txid);
        match pending.payload {
            PendingPayload::Psbt => {
                // Self-managed: reads State.signed_psbt directly, sets its
                // own wallet_tx_busy, posts its own PsbtBroadcastResult. Leaving
                // `pending_broadcast` in place lets a failed POST be retried
                // by tapping Broadcast again (re-invokes this same path).
                // U4: `on_psbt_broadcast` is a method now (not a fresh
                // `st.borrow_mut()`), so a direct call replaces the old
                // `drop(s); w.global::<Ui>().invoke_psbt_broadcast();` —
                // sequential method calls on the same `&mut self` need no
                // drop; that dance was only ever for the shared RefCell.
                s.on_psbt_broadcast(w);
            }
            PendingPayload::Compose { composed, text, private, change_to, created_at, to } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A: exactly what
                // `compose_and_record` used to do before its own broadcast
                // call. Recording is one-shot, so drop `pending_broadcast`
                // now — a failed POST is retried from Activity's
                // Rebroadcast (existing `apply_notebook_compose_result`
                // behavior, unchanged), never by re-tapping this button.
                if let Some(store) = s.store.as_mut() {
                    app_core::compose::record_composed_note(
                        store,
                        &text,
                        private,
                        change_to.as_deref(),
                        created_at,
                        &composed,
                    );
                }
                s.save_store();
                // Device-level contacts (iCloud-contacts feature): touch
                // every recipient here too — `record_composed_note` still
                // touches the per-notebook `Store.contacts` internally (kept
                // for serde back-compat; no longer read anywhere), but the
                // recents list the picker actually shows now lives on
                // `State.contacts`.
                if composed.recipients.is_empty() {
                    if let Some(addr) = &to {
                        s.touch_contact(addr);
                    }
                } else {
                    for addr in &composed.recipients {
                        s.touch_contact(addr);
                    }
                }
                s.save_contacts();
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let note_id = composed.note_id.clone();
                let fee = composed.tx.fee;
                let vsize = composed.tx.vsize;
                let pq_flags = composed.pq_flags;
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = NotebookComposeResult { note_id, fee, vsize, to, private, pq_flags, result };
                    post(&weak, move |w, st| {
                        st.clear_compose_busy(w);
                        st.apply_notebook_compose_result(w, r);
                    });
                });
            }
            PendingPayload::ComposeSpending {
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = SpendingComposeResult {
                        text,
                        private,
                        to,
                        recipients,
                        gift,
                        raw,
                        txid,
                        vsize,
                        built_fee,
                        built_change,
                        spent_outpoints,
                        change_index,
                        change_raw,
                        source,
                        result,
                    };
                    post(&weak, move |w, st| {
                        st.clear_compose_busy(w);
                        st.apply_spending_compose_result(w, r);
                    });
                });
            }
            PendingPayload::ComposeMixed {
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = MixedComposeResult {
                        text,
                        private,
                        to,
                        recipients,
                        gift,
                        raw,
                        txid,
                        vsize,
                        built_fee,
                        built_change,
                        change_default,
                        notebook_spent,
                        spent_spending,
                        change_spent,
                        payloads_len,
                        recipient_count,
                        change_index,
                        spending_source,
                        result,
                    };
                    post(&weak, move |w, st| {
                        st.clear_compose_busy(w);
                        st.apply_mixed_compose_result(w, r);
                    });
                });
            }
            // ---- sweep / consolidate / wconsol / spending-consolidate:
            // stage A already built + signed (see `build_sweep_confirm`
            // et al.); stage B synchronously returns to the ORIGIN screen
            // (`pending.return_screen`) — mirroring the removed confirm
            // modals, which closed in place while the broadcast ran in the
            // background — then spawns the pre-existing thread-spawn
            // verbatim, posting a job that clears the shared busy flag
            // (`State::clear_wallet_tx_busy`) and applies via their
            // (UNTOUCHED) `apply_*_broadcast_result`.
            PendingPayload::Sweep { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = SweepBroadcastResult { snap, result };
                    post(&weak, move |w, st| {
                        st.clear_wallet_tx_busy(w);
                        st.apply_sweep_broadcast_result(w, r);
                    });
                });
            }
            PendingPayload::Consolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = ConsolidateBroadcastResult { snap, result };
                    post(&weak, move |w, st| {
                        st.clear_wallet_tx_busy(w);
                        st.apply_consolidate_broadcast_result(w, r);
                    });
                });
            }
            PendingPayload::WConsol { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = snap.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = WConsolBroadcastResult { snap, result };
                    post(&weak, move |w, st| {
                        st.clear_wallet_tx_busy(w);
                        st.apply_wconsol_broadcast_result(w, r);
                    });
                });
            }
            PendingPayload::SpendingConsolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = SpendingConsolidateResult { snap, result };
                    post(&weak, move |w, st| {
                        st.clear_wallet_tx_busy(w);
                        st.apply_spending_consolidate_result(w, r);
                    });
                });
            }
            // ---- bump / rebroadcast: stage B re-arms `act_pending_ref`
            // (the Activity row's own busy guard — screen 26 briefly, then
            // back on the Activity screen while the POST runs) and spawns
            // the SAME broadcast worker their (UNTOUCHED) apply_act_*
            // functions already drain.
            PendingPayload::Bump { ref_id, fee, new_rate, bumped } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A (zero-trace
                // cancel fix): apply the exact mutation the one-shot
                // bump_* functions used to make — replacement txid append,
                // fee/vsize/raw_hex update, and (notes) the ledger change
                // swap — then save, exactly like the Compose arm. A failed
                // POST leaves a retryable record with the replacement hex
                // in hand (`apply_act_bump_result` behavior, unchanged).
                // PLAN-pnte-redesign.md: a note bump RENAMES the record's
                // id to the replacement's txid (the note id IS the txid),
                // so the busy-row marker below must follow the rename — a
                // sweep/consolidate bump keeps using `ref_id` (its identity
                // is the whole `txids` history, never renamed).
                let mut renamed_note_id: Option<String> = None;
                if let Some(store) = s.store.as_mut() {
                    match &bumped {
                        BumpedBuild::Note(c) => {
                            renamed_note_id = app_core::compose::record_bumped_note(store, &ref_id, c);
                        }
                        BumpedBuild::Tx(tx) => {
                            app_core::compose::record_bumped_tx(store, &ref_id, tx)
                        }
                    }
                }
                s.save_store();
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.act_pending_ref = Some(renamed_note_id.clone().unwrap_or_else(|| ref_id.clone()));
                s.update_activity(w);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = ActBumpResult { ref_id, txid, fee, new_rate, result };
                    post(&weak, move |w, st| st.apply_act_bump_result(w, r));
                });
            }
            PendingPayload::Rebroadcast { ref_id } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.act_pending_ref = Some(ref_id.clone());
                s.update_activity(w);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    let r = ActRetryResult { ref_id, result };
                    post(&weak, move |w, st| st.apply_act_retry_result(w, r));
                });
            }
        }
    }
}
