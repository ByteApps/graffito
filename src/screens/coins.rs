//! Screen.coins — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Every ACTIVE notebook's spendable coins (chain 0) PLUS the account's
/// taproot CHANGE-chain coins (chain 1, `State.change_coins`, unit 6) as
/// WatchCoins stamped with their owning chain+index — the gather behind
/// the watch wallet-level flows (rev-3 follow-up 1: sweep/consolidate span
/// notebooks in ONE externally-signed PSBT; unit 6 extends that ONE PSBT
/// to the account's own change coins too, so a hardware signer recognizes
/// them via their `.../1/{index}` key origin). Falls back to the active
/// store alone when no index is loaded. `State.change_coins` is empty for
/// any identity that hasn't scanned chain 1 yet (or a keyed identity — this
/// function is only ever called for watch), so appending it is a no-op
/// until unit 6's watch scan (`wallet_stores_refresh_async`) populates it.
pub(crate) fn watch_wallet_coins(&self) -> Vec<WatchCoin> {
    let st = self;
    let mut coins = Vec::new();
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = st.notebook_store(m.index) else { continue };
            coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
                txid: u.txid.clone(),
                vout: u.vout,
                value: u.value,
                chain: 0,
                index: m.index,
            }));
        }
    } else if let Some(store) = &st.store {
        let nb = st.ident.as_ref().map(|i| i.index).unwrap_or(0);
        coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
            txid: u.txid.clone(),
            vout: u.vout,
            value: u.value,
            chain: 0,
            index: nb,
        }));
    }
    coins.extend(st.change_coins.iter().map(|c| WatchCoin {
        txid: c.txid.clone(),
        vout: c.vout,
        value: c.value,
        chain: 1,
        index: c.index,
    }));
    coins
}

/// Watch mode: build the external-sign PSBT spending every ACTIVE
/// notebook's spendable coins into `dest_spk` and open the sign screen
/// (13) — wallet-level, like the keyed sweep (rev-3 follow-up 1). The
/// signed PSBT comes back through the same import paths external funding
/// uses.
pub(crate) fn watch_spend_build(&mut self, w: &AppWindow, kind: &'static str, dest: String, dest_spk: Vec<u8>, rate: f64) {
    let st = self;
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let coins = st.watch_wallet_coins();
    if coins.is_empty() || (kind == "consolidate" && coins.len() < 2) {
        w.global::<Ui>().set_status(
            if kind == "consolidate" { "nothing to consolidate (need 2+ coins)" } else { "nothing to sweep" }.into(),
        );
        return;
    }
    let notebooks = {
        let mut ids: Vec<u32> = coins.iter().filter(|c| c.chain == 0).map(|c| c.index).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    };
    // Unit 6: chain-1 (change) inputs riding along — pruned from
    // `State.change_coins` on success and marked non-bumpable (see
    // `WatchSpend.change_spent`'s doc comment).
    let change_spent: Vec<(String, u32)> =
        coins.iter().filter(|c| c.chain == 1).map(|c| (c.txid.clone(), c.vout)).collect();
    let inputs: Vec<app_core::store::TxInput> = coins
        .iter()
        .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
        .collect();
    let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
    match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), rate, st.effective_lock_time()) {
        Ok(built) => {
            let cost = format!(
                "{kind} · {} sats · fee {} sats · {} input{} · sign with your external wallet",
                built.sent_to_recipient,
                built.fee,
                coins.len(),
                if coins.len() == 1 { "" } else { "s" }
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind,
                dest,
                dest_spk_hex: hex::encode(&dest_spk),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs,
                input_indexes,
                dest_index: None,
                change_spent: change_spent.clone(),
                bump_ref: None,
            });
            println!(
                "cb: watch-spend-build kind={kind} txid={} fee={} inputs={} notebooks={notebooks}{}",
                built.txid,
                built.fee,
                coins.len(),
                if change_spent.is_empty() { String::new() } else { format!(" change={}", change_spent.len()) }
            );
            st.show_psbt_sign_screen(w, built, cost);
        }
        Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
    }
}

/// The per-notebook self-consolidate flow (screen 16, kind
/// "consolidate") — still the watch-only path, where signing happens on
/// an external wallet and one notebook is all there is.
pub(crate) fn open_notebook_consolidate(&mut self, w: &AppWindow) {
    let st = self;
    // Lands on screen 16 (fee tiers shown) — see the matching comment in
    // `set_sweep_dest` (network-efficiency, 2026-07-23).
    st.refresh_fees_price(w);
    let spendable = st
        .store
        .as_ref()
        .map(|s| s.utxos.iter().filter(|u| !u.pending_spend).count())
        .unwrap_or(0);
    if spendable < 2 {
        w.global::<Ui>().set_status("nothing to consolidate (need 2+ coins)".into());
        return;
    }
    let Some(addr) = st.ident.as_ref().map(|i| i.address.clone()) else { return };
    println!("cb: consolidate-open coins={spendable}");
    w.global::<Ui>().set_sweep_kind("consolidate".into());
    w.global::<Ui>().set_sweep_dest(addr.clone().into());
    w.global::<Sweep>().set_sweep_dest_note("".into());
    let nb_name = st
        .ident
        .as_ref()
        .map(|i| st.notebook_display_name(i.index))
        .unwrap_or_else(|| "this notebook".into());
    w.global::<Sweep>().set_sweep_to_label(format!("Consolidate within {nb_name} · {}", addr_short(&addr)).into());
    w.global::<Sweep>().set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.global::<Sweep>().set_sweep_rate_text(format!("{rate}").into());
    w.global::<Sweep>().set_sweep_fund_external(false);
    w.global::<Sweep>().set_sweep_inputs_expanded(false);
    // A fresh consolidate session — same reset rule as `set_sweep_dest`.
    st.reset_tx_lock_time_override();
    w.global::<Sweep>().set_sweep_locktime_expanded(false);
    st.refresh_sweep_locktime_panel(w);
    w.global::<Ui>().set_status("".into());
    st.update_sweep_screen(w);
    w.global::<Ui>().set_screen(Screen::Sweep);
}

/// The wallet-wide coins viewer (screen 10 + the Settings Coins card):
/// every ACTIVE notebook's spendable UTXOs, each tagged with its
/// notebook, plus the cross-wallet summary — data as of each notebook's
/// last scan (the ↻ on the coins screen rescans them all). Taproot
/// change-chain coins (`st.change_coins`, unit 3 — see
/// `../PLAN-chain-notes-app-taproot-change.md`) are folded into the SAME
/// list, each tagged "change" instead of a notebook name (Sal's decision:
/// one unified balance, not a separate segment) — they count toward the
/// total coin count and spendable sats but NOT toward the "M notebooks"
/// count below (they don't belong to any one notebook). The wallet Sweep
/// consumes them (unit 6) — this list is display-only for that; compose /
/// pay-from and watch-only still don't consume them (later units).
pub(crate) fn update_wallet_coins(&self, w: &AppWindow) {
    let st = self;
    let mut coins: Vec<CoinItem> = Vec::new();
    let mut spendable: u64 = 0;
    let mut notebooks = 0usize;
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = st.notebook_store(m.index) else { continue };
            let name = st.notebook_display_name(m.index);
            let mut any = false;
            for u in store.utxos.iter().filter(|u| !u.pending_spend) {
                coins.push(CoinItem {
                    outpoint: format!("{}:{}", u.txid, u.vout).into(),
                    value: u.value.to_string().into(),
                    status: if u.height.is_some() { "confirmed" } else { "unconfirmed" }.into(),
                    notebook: name.clone().into(),
                });
                spendable += u.value;
                any = true;
            }
            if any {
                notebooks += 1;
            }
        }
    }
    for c in &st.change_coins {
        coins.push(CoinItem {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            status: if c.confirmed { "confirmed" } else { "unconfirmed" }.into(),
            notebook: "change".into(),
        });
        spendable += c.value;
    }
    let n = coins.len();
    w.global::<Ui>().set_coins(VecModel::from_slice(&coins));
    // The aggregate (both pools) belongs ONLY on the Settings Coins card,
    // which has no segments of its own. The Coins SCREEN's notebook segment
    // and the notebook-consolidate confirm keep the notebook-only line —
    // Sal 2026-07-17: "spending: 2 coins" on a segment that shows no
    // spending coins is misleading (the spending segment is one tap away).
    let spending_state = if st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false) {
        if !st.spending_scanned {
            Some(app_core::mixed::SpendingSummaryState::NotScanned)
        } else {
            let sats: u64 = st.spending_coins.iter().map(|c| c.value).sum();
            Some(app_core::mixed::SpendingSummaryState::Scanned { n: st.spending_coins.len(), sats })
        }
    } else {
        None
    };
    w.global::<Ui>().set_coins_summary(app_core::mixed::coins_summary_line(n, spendable, notebooks, None).into());
    w.global::<Settings>().set_coins_summary_settings(
        app_core::mixed::coins_summary_line(n, spendable, notebooks, spending_state).into(),
    );
}

/// Stage A for a single-notebook consolidate (screen 16, `sweep-kind ==
/// "consolidate"`, keyed self-paid — `on_sweep_send`'s tail): build + sign
/// exactly as the old `on_consolidate` modal handler did, then hand off to
/// the universal confirm screen instead of broadcasting. The destination
/// is our own address (already in `confirm_self_spks`'s set), so no
/// `ConfirmCtx.recipient` is needed. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Consolidate`) is the
/// pre-existing thread-spawn, moved verbatim.
pub(crate) fn build_consolidate_confirm(&mut self, w: &AppWindow, rate: f64) {
    let s = self;
    let net = s.network;
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        return; // caller already routes watch identities to watch_spend_build
    }
    if s.base_url().is_none() {
        w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
        return;
    }
    let Some(self_addr) = s.ident.as_ref().map(|i| i.address.clone()) else { return };
    let Ok(me) = Recipient::parse(net, &self_addr) else { return };
    let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
        w.global::<Ui>().set_status("no identity".into());
        return;
    };
    let nb_index = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
    let name = s.notebook_display_name(nb_index);
    let Some(store) = s.store.as_mut() else { return };
    if store.available_utxos().len() < 2 {
        w.global::<Ui>().set_status("nothing to consolidate (need 2+ coins)".into());
        return;
    }
    let inputs = spendable_inputs(store);
    let dest_spk_hex = hex::encode(&me.spk);
    let tx = app_core::notes_core::tx::build_sweep_tx(
        &store.available_utxos(),
        &identity.output_x,
        me.spk.clone(),
        rate,
        s.effective_lock_time(),
        &identity.tweaked_seckey,
        app_core::notes_core::keys::generate_aux_rand,
    );
    match tx {
        Ok(tx) => {
            let snap = ConsolidateSnapshot {
                identity_addr: self_addr.clone(),
                value: tx.tx.outputs[0].value,
                fee: tx.fee,
                vsize: tx.vsize as u64,
                raw_hex: tx.raw_hex.clone(),
                dest_spk_hex,
                inputs: inputs.clone(),
            };
            let prevouts = labeled_prevouts(&inputs, Some(&self_addr), &format!("Notebook · {name}"));
            let (self_spks, spending_spks) = s.confirm_self_spks();
            let ctx = app_core::confirm::ConfirmCtx {
                network: app_core::derive::btc_network(net),
                prevouts,
                self_spks,
                spending_spks,
                expected_change: None,
                recipient: None,
                recipient_name: None,
                recipients: Vec::new(),
                note_preview: None,
                tip_height: s.confirm_tip_height(),
            };
            let pending = PendingBroadcast {
                kind: "consolidate",
                raw_hex: tx.raw_hex.clone(),
                txid: tx.txid_hex.clone(),
                vsize: tx.vsize,
                context: format!("Consolidate · {}", net.as_str()),
                return_screen: Screen::Sweep, // overwritten by show_confirm
                payload: PendingPayload::Consolidate { snap },
            };
            s.show_confirm(w, pending, ctx);
        }
        Err(e) => w.global::<Ui>().set_status(format!("consolidate: {e}").into()),
    }
}

/// Stage A for wallet-level consolidate (account picker "wconsol" mode —
/// picking a destination row IS the trigger now, no separate confirm
/// tap): keyed identities build + sign here and hand off to the universal
/// confirm screen; watch identities are UNCHANGED (external-sign PSBT,
/// screens 13/14, copied verbatim from the old `on_wallet_consolidate`).
/// The linkage-warning caption the old confirm modal carried
/// ("One transaction spends every notebook's coins…") moves onto
/// `PendingBroadcast.context`, appended after the base context. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::WConsol`) is the pre-existing
/// thread-spawn, moved verbatim.
///
/// Deliberately uses the plain DEVICE-DEFAULT `lock_time()` throughout,
/// never `effective_lock_time()`: this flow is reached from the account
/// picker (Settings → "Consolidate wallet…"), not compose (6) or
/// sweep/consolidate (16) — nothing resets the per-tx override before it
/// runs, so consulting it here could silently leak a stale override from
/// an earlier, unrelated compose/sweep session with no UI indication.
pub(crate) fn build_wconsol_confirm(&mut self, w: &AppWindow, wc: WConsol) {
    let s = self;
    // The picker's own job is done the moment a destination is picked —
    // reset its mode now (regardless of watch/keyed outcome below), same
    // as the old `on_wallet_consolidate` modal handler did unconditionally
    // at its top, so a later "Change account…" open isn't left in
    // "wconsol" mode.
    w.global::<AccountPicker>().set_account_pick_mode("switch".into());
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        // Watch: ONE external-sign PSBT over every source notebook's
        // coins — each input's key origin carries its own receive index,
        // so the signer recognizes them all in one pass. The cross-store
        // bookkeeping runs post-broadcast (record_watch_spend, dest_index
        // = the picked notebook). Unchanged from the old handler.
        let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else {
            return;
        };
        let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
            Ok(r) => r.spk,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let coins: Vec<WatchCoin> = wc
            .sources
            .iter()
            .flat_map(|(index, coins, _)| {
                coins.iter().map(move |u| {
                    let mut t = u.txid;
                    t.reverse();
                    WatchCoin { txid: hex::encode(t), vout: u.vout, value: u.value, chain: 0, index: *index }
                })
            })
            .collect();
        let inputs: Vec<app_core::store::TxInput> = coins
            .iter()
            .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
            .collect();
        let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), wc.rate, s.lock_time()) {
            Ok(built) => {
                let cost = format!(
                    "consolidate · {} sats · fee {} sats · {} input{} from {} notebook{} · sign with your external wallet",
                    built.sent_to_recipient,
                    built.fee,
                    coins.len(),
                    if coins.len() == 1 { "" } else { "s" },
                    wc.sources.len(),
                    if wc.sources.len() == 1 { "" } else { "s" }
                );
                s.watch_note = None;
                s.watch_spend = Some(WatchSpend {
                    kind: "consolidate",
                    dest: wc.dest_addr.clone(),
                    dest_spk_hex: hex::encode(&dest_spk),
                    value: built.sent_to_recipient,
                    fee: built.fee,
                    inputs,
                    input_indexes,
                    dest_index: Some(wc.dest_index),
                    bump_ref: None,
                    change_spent: Vec::new(), // wconsol sources are notebook coins only (chain 0)
                });
                println!(
                    "cb: wallet-consolidate build txid={} coins={} notebooks={} fee={}",
                    built.txid,
                    coins.len(),
                    wc.sources.len(),
                    built.fee
                );
                s.show_psbt_sign_screen(w, built, cost);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
        return;
    }
    let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
        return;
    };
    let Ok(material) = parse_key_material(&material_str, s.network) else { return };
    if s.base_url().is_none() {
        w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    }
    // Realize every source's full identity; a failure aborts cleanly.
    let mut idents = Vec::new();
    for (index, coins, _) in &wc.sources {
        let ident = match realize(&material, s.network, s.account, *index) {
            Ok(i) => i,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let addr = ident.address.clone();
        let Some(full) = ident.full().map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("wallet consolidate needs the full key".into());
            return;
        };
        idents.push((*index, full, coins.clone(), addr));
    }
    let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
        Ok(r) => r.spk,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    let sources: Vec<app_core::notes_core::tx::SweepSource> = idents
        .iter()
        .map(|(_, id, coins, _)| app_core::notes_core::tx::SweepSource {
            utxos: coins,
            output_x: id.output_x,
            tweaked_seckey: &id.tweaked_seckey,
        })
        .collect();
    let built = match app_core::notes_core::tx::build_sweep_tx_multi(
        &sources,
        dest_spk.clone(),
        wc.rate,
        s.lock_time(),
        app_core::notes_core::keys::generate_aux_rand,
    ) {
        Ok(t) => t,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    let mut all_inputs: Vec<app_core::store::TxInput> = Vec::new();
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    let source_locks: Vec<(u32, Vec<(String, u32)>)> = idents
        .iter()
        .map(|(index, _, coins, addr)| {
            let name = s.notebook_display_name(*index);
            let source = format!("Notebook · {name}");
            let locks: Vec<(String, u32)> = coins
                .iter()
                .map(|u| {
                    let mut t = u.txid;
                    t.reverse();
                    let txid_hex = hex::encode(t);
                    all_inputs.push(app_core::store::TxInput {
                        txid: txid_hex.clone(),
                        vout: u.vout,
                        value: u.value,
                    });
                    prevouts.insert(
                        format!("{txid_hex}:{}", u.vout),
                        app_core::confirm::PrevoutInfo {
                            value: u.value,
                            address: Some(addr.clone()),
                            source: source.clone(),
                        },
                    );
                    (txid_hex, u.vout)
                })
                .collect();
            (*index, locks)
        })
        .collect();
    let input_indexes: Vec<u32> =
        wc.sources.iter().flat_map(|(a, coins, _)| std::iter::repeat_n(*a, coins.len())).collect();
    let net = s.network;
    let snap = WConsolSnapshot {
        fp8: s.notebooks_fp8.clone().unwrap_or_default(),
        network: net,
        account: s.account,
        dest_index: wc.dest_index,
        dest_spk_hex: hex::encode(&dest_spk),
        value: built.tx.outputs[0].value,
        fee: built.fee,
        vsize: built.vsize as u64,
        raw_hex: built.raw_hex.clone(),
        source_locks,
        all_inputs,
        input_indexes,
        sources_n: wc.sources.len(),
    };
    let (mut self_spks, spending_spks) = s.confirm_self_spks();
    // The destination notebook may be freshly created (not yet an
    // "active" notebook `realize()` would find via `confirm_self_spks`)
    // — push its spk on top so it classifies "self", same rule a
    // compose's fresh change address follows.
    self_spks.push(dest_spk.clone());
    let ctx = app_core::confirm::ConfirmCtx {
        network: app_core::derive::btc_network(net),
        prevouts,
        self_spks,
        spending_spks,
        expected_change: None,
        recipient: None,
        recipient_name: None,
        recipients: Vec::new(),
        note_preview: None,
        tip_height: s.confirm_tip_height(),
    };
    let pending = PendingBroadcast {
        kind: "wconsol",
        raw_hex: built.raw_hex.clone(),
        txid: built.txid_hex.clone(),
        vsize: built.vsize,
        context: format!(
            "Consolidate wallet · {} — One transaction spends every notebook's coins — all their addresses become publicly linked on-chain.",
            net.as_str()
        ),
        return_screen: Screen::AccountPicker, // overwritten by show_confirm
        payload: PendingPayload::WConsol { snap },
    };
    s.show_confirm(w, pending, ctx);
}
}

impl State {
pub(crate) fn on_spending_scan_deep(&mut self, w: &AppWindow) {
        self.spending_scan_deep_async(w);
    }

pub(crate) fn on_spending_consolidate_open(&mut self, w: &AppWindow) {
        if self.wallet_tx_busy || self.pending_broadcast.is_some() {
            return;
        }
        // The fee rate used to build this tx comes from `s.fees.hour`
        // below — lazily (re)fetch first (network-efficiency, 2026-07-23).
        self.refresh_fees_price(w);
        self.ensure_spending_source();
        let Some(src) = self.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let coins = self.spending_coins.clone();
        if coins.len() < 2 {
            w.global::<Ui>().set_status("nothing to consolidate (need 2+ spending coins)".into());
            return;
        }
        if self.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
            return;
        }
        let Some(material_str) = self.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        let net = self.network;
        let Ok(material) = parse_key_material(&material_str, net) else { return };
        let Some(next_receive) = self.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(dest) = src.derive(0, next_receive) else {
            w.global::<Ui>().set_status("couldn't derive the destination address".into());
            return;
        };
        let rate = self.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        let account = self.account;
        // Deliberately the device default, not `effective_lock_time()`:
        // this is the Coins screen's direct "Consolidate spending coins…"
        // shortcut, not compose (6) or sweep/consolidate (16) — nothing
        // resets the per-tx override before it runs (see
        // `build_wconsol_confirm`'s doc comment for the same reasoning).
        let built = app_core::mixed::build_wallet_sweep_mixed(
            &[],
            Some((&material, net, account, &coins)),
            dest.spk.clone(),
            rate,
            self.lock_time(),
        );
        match built {
            Ok(tx) => {
                let spent: Vec<(String, u32, u64)> =
                    coins.iter().map(|c| (c.txid.clone(), c.vout, c.value)).collect();
                let snap = SpendingConsolidateSnapshot {
                    fp8: self.notebooks_fp8.clone().unwrap_or_default(),
                    network: net,
                    account,
                    dest_index: next_receive,
                    dest_addr: dest.address.clone(),
                    dest_spk_hex: hex::encode(&dest.spk),
                    value: tx.tx.outputs[0].value,
                    fee: tx.fee,
                    vsize: tx.vsize as u64,
                    raw_hex: tx.raw_hex.clone(),
                    spent,
                };
                let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
                for c in &coins {
                    prevouts.insert(
                        format!("{}:{}", c.txid, c.vout),
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(c.address.clone()),
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                let (mut self_spks, mut spending_spks) = self.confirm_self_spks();
                // Fresh spending receive address, not yet "used" bookkeeping
                // — push its spk on top so it classifies "self".
                self_spks.push(dest.spk.clone());
                spending_spks.push(dest.spk.clone());
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: None,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: self.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "spending-consolidate",
                    raw_hex: tx.raw_hex.clone(),
                    txid: tx.txid_hex.clone(),
                    vsize: tx.vsize,
                    context: format!("Consolidate spending coins · {}", net.as_str()),
                    return_screen: Screen::Coins, // overwritten by show_confirm
                    payload: PendingPayload::SpendingConsolidate { snap },
                };
                self.show_confirm(w, pending, ctx);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    }

pub(crate) fn on_consolidate_wallet_open(&mut self, w: &AppWindow) {
        // The destination-pick handler prices the tx off `s.fees.hour`
        // shortly after this opens the account picker — lazily (re)fetch
        // now so it's ready (network-efficiency, 2026-07-23).
        self.refresh_fees_price(w);
        // Keyed AND watch identities take the same wallet-level flow
        // (rev-3 follow-up 1): snapshot every active notebook's coins,
        // pick the destination notebook, confirm. Watch identities sign
        // the one resulting PSBT externally (screens 13/14).
        let Some(ix) = &self.notebooks else { return };
        let mut sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)> = Vec::new();
        let mut coins_total = 0usize;
        for m in ix.active(self.account) {
            let Some(store) = self.notebook_store(m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            coins_total += coins.len();
            let value: u64 = coins.iter().map(|u| u.value).sum();
            sources.push((m.index, coins, value));
        }
        if coins_total < 2 {
            w.global::<Ui>().set_status("nothing to consolidate (need 2+ coins across the wallet)".into());
            return;
        }
        println!(
            "cb: wallet-consolidate open coins={coins_total} notebooks={}",
            sources.len()
        );
        self.wconsol = Some(WConsol {
            sources,
            dest_index: 0,
            dest_addr: String::new(),
            rate: 0.0,
            fee: 0,
            vsize: 0,
        });
        w.global::<AccountPicker>().set_nb_create_name("".into());
        self.show_notebook_picker(w, 0, "wconsol");
    }
}
