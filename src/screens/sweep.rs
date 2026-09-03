//! Screen.sweep — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// The sweep screen's fee rate: tier pill (economy/hour/fastest) or the
/// custom sat/vB field — the compose mapping, mirrored.
pub(crate) fn resolve_sweep_rate(&self, w: &AppWindow) -> f64 {
    let st = self;
    let f = st.fees.clone().unwrap_or_default();
    match w.global::<Sweep>().get_sweep_tier() {
        0 => f.economy.max(1.0),
        2 => f.fastest.max(1.0),
        3 => w.global::<Sweep>().get_sweep_rate_text().trim().parse().unwrap_or(0.0),
        _ => f.hour.max(1.0),
    }
}

/// Refresh the sweep screen (16): read-only inputs list (a sweep spends
/// every spendable coin), inputs title, and the live cost line for the
/// current fee tier / funding mode.
pub(crate) fn update_sweep_screen(&mut self, w: &AppWindow) {
    let st = self;
    // Same freshness rule as `refresh_compose`'s locktime-panel repaint.
    st.refresh_sweep_locktime_panel(w);
    let net = st.network;
    let Some(store) = st.store.as_ref() else { return };
    let exb = st.explorer_base();
    // A SWEEP is wallet-level (leaving the wallet): every active
    // notebook's coins ride — scoped to the ACTIVE account, keyed AND
    // watch alike (rev-3 follow-up 1). Consolidate (kind) stays on the
    // active store (the legacy screen-16 flow).
    let wallet_mode = w.global::<Ui>().get_sweep_kind().as_str() == "sweep";
    let spendable: Vec<app_core::store::LedgerUtxo> = if wallet_mode {
        let mut v = Vec::new();
        if let Some(ix) = &st.notebooks {
            for m in ix.active(st.account) {
                if let Some(s2) = st.notebook_store(m.index) {
                    v.extend(s2.utxos.iter().filter(|u| !u.pending_spend).cloned());
                }
            }
        }
        v
    } else {
        store.utxos.iter().filter(|u| !u.pending_spend).cloned().collect()
    };
    // CHANGE 2: a WALLET sweep also gathers the spending wallet's coins —
    // UNLESS the destination IS the spending wallet's own next receive
    // address (`on_spending_sweep_here`; `pending_spending_sweep_index`),
    // where including them would sweep the spending wallet into itself.
    let spending_rows: Vec<FundingUtxo> = if wallet_mode
        && st.pending_spending_sweep_index.is_none()
        && st.spending_capable
        && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
    {
        st.spending_coins.clone()
    } else {
        Vec::new()
    };
    let nb_total: u64 = spendable.iter().map(|u| u.value).sum();
    let sp_total: u64 = spending_rows.iter().map(|c| c.value).sum();
    let total = nb_total + sp_total;
    let n = spendable.len();
    let sp_n = spending_rows.len();
    let mut rows: Vec<SpendCoin> = spendable
        .iter()
        .map(|u| SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected: true,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
            tag: "".into(),
        })
        .collect();
    rows.extend(spending_rows.iter().map(|c| SpendCoin {
        outpoint: format!("{}:{}", c.txid, c.vout).into(),
        value: c.value.to_string().into(),
        confirmed: c.confirmed,
        selected: true,
        txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
        explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
        tag: "".into(),
    }));
    rows.sort_by_key(|r| r.value.parse::<u64>().unwrap_or(0));
    w.global::<Sweep>().set_sweep_coins(VecModel::from_slice(&rows));
    let plural = if n == 1 { "" } else { "s" };
    w.global::<Sweep>().set_sweep_inputs_title(
        if sp_n > 0 {
            format!(
                "Inputs · {n} notebook coin{plural} + {sp_n} spending coin{} · {total} sats (all)",
                if sp_n == 1 { "" } else { "s" }
            )
        } else {
            format!("Inputs · {n} coin{plural} · {total} sats (all)")
        }
        .into(),
    );

    if n == 0 && sp_n == 0 {
        w.global::<Sweep>().set_sweep_cost_line("nothing to sweep — no spendable coins".into());
        return;
    }
    let rate = st.resolve_sweep_rate(w);
    if rate <= 0.0 {
        w.global::<Sweep>().set_sweep_cost_line("enter a fee rate".into());
        return;
    }
    let dest_spk_len = w
        .global::<Ui>()
        .get_sweep_dest()
        .to_string()
        .parse_dest_len(net)
        .unwrap_or(34);
    if w.global::<Sweep>().get_sweep_fund_external() {
        if st.funding.is_none() || st.funding_coins.is_empty() {
            w.global::<Sweep>().set_sweep_cost_line(format!("sweeps {total} sats in full — pick a funding wallet for the fee").into());
            return;
        }
        // notes inputs (taproot) + funding inputs + dest + funding change.
        use app_core::bitcoin::transaction::{predict_weight, InputWeightPrediction};
        let fund_kind = st.funding.as_ref().map(|f| f.kind);
        let fund_w = match fund_kind {
            Some(app_core::funding::FundingKind::Wpkh) => InputWeightPrediction::P2WPKH_MAX,
            _ => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        };
        let weights = std::iter::repeat_n(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, n)
            .chain(std::iter::repeat_n(fund_w, st.funding_coins.len()));
        let vsize = predict_weight(weights, [dest_spk_len, 34usize]).to_vbytes_ceil();
        let fee = (vsize as f64 * rate).ceil() as u64;
        let funding_total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
        if funding_total < fee {
            w.global::<Sweep>().set_sweep_cost_line(
                format!("funding wallet holds {funding_total} sats — fee needs ~{fee}").into(),
            );
            return;
        }
        w.global::<Sweep>().set_sweep_cost_line(
            format!(
                "destination receives {total} sats in full · fee ~{fee} sats from the funding wallet ({} sats change back)",
                funding_total.saturating_sub(fee)
            )
            .into(),
        );
    } else {
        // CHANGE 2: with spending coins riding along, size via
        // notes-core's mixed estimator (byte-exact — the same function
        // `build_wallet_sweep_mixed`/`build_sweep_tx_mixed` actually use
        // to build the tx); the all-taproot path is untouched.
        let vsize = if sp_n > 0 {
            use app_core::notes_core::tx::{estimate_vsize_mixed, InputKind};
            let kinds: Vec<InputKind> = std::iter::repeat_n(InputKind::Taproot, n)
                .chain(std::iter::repeat_n(InputKind::P2wpkh, sp_n))
                .collect();
            estimate_vsize_mixed(&kinds, &[], &[dest_spk_len]) as u64
        } else {
            predict_keyspend_vsize(n, std::iter::once(dest_spk_len))
        };
        let fee = (vsize as f64 * rate).ceil() as u64;
        if total <= fee {
            w.global::<Sweep>().set_sweep_cost_line(format!("balance {total} sats can't cover the ~{fee} sat fee").into());
            return;
        }
        let line = if w.global::<Ui>().get_sweep_kind().as_str() == "consolidate" {
            format!("combines {n} coins → 1 · fee ~{fee} sats · keeps {}", total - fee)
        } else {
            format!("sweeps {total} sats · fee ~{fee} sats · destination receives {}", total - fee)
        };
        w.global::<Sweep>().set_sweep_cost_line(line.into());
    }
}

/// Route a validated sweep destination to the compose-like sweep screen:
/// label (notebook name → contact name → bare address), the on-chain
/// linkage caveat when the destination is one of OUR notebooks (and no
/// contacts pollution for those), fee tier defaults, screen 16.
pub(crate) fn set_sweep_dest(&mut self, w: &AppWindow, a: String) {
    let st = self;
    // Lands on the sweep/consolidate screen (16), which shows fee tiers —
    // lazily (re)fetch before `update_sweep_screen` below reads `st.fees`
    // (network-efficiency, 2026-07-23).
    st.refresh_fees_price(w);
    let own_index = st.nb_addrs.iter().find(|(_, ad, _)| *ad == a).map(|(idx, ..)| *idx);
    match own_index {
        Some(acct) => {
            println!("cb: sweep-pick to={a} (notebook {acct})");
            w.global::<Sweep>().set_sweep_to_label(
                format!(
                    "Everything to: {} · {}",
                    st.notebook_display_name(acct),
                    addr_short(&a)
                )
                .into(),
            );
            w.global::<Sweep>().set_sweep_dest_note(
                "Heads up: sweeping between your own notebooks publicly links their addresses on-chain.".into(),
            );
        }
        None => {
            println!("cb: sweep-pick to={a}");
            st.touch_contact(&a);
            st.save_contacts();
            st.refresh_contacts(w);
            let name = st
                .contacts
                .iter()
                .find(|c| c.address == a)
                .map(|c| c.name.clone())
                .filter(|n| !n.is_empty());
            w.global::<Sweep>().set_sweep_to_label(
                match &name {
                    Some(n) => format!("Everything to: {n} · {a}"),
                    None => format!("Everything to: {a}"),
                }
                .into(),
            );
            w.global::<Sweep>().set_sweep_dest_note("".into());
        }
    }
    w.global::<Ui>().set_sweep_dest(a.into());
    w.global::<Sweep>().set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.global::<Sweep>().set_sweep_rate_text(format!("{rate}").into());
    w.global::<Sweep>().set_sweep_fund_external(false);
    w.global::<Sweep>().set_sweep_inputs_expanded(false);
    // A fresh sweep session — the locktime override never survives past
    // the screen it was set on (see `reset_tx_lock_time_override`'s doc
    // comment).
    st.reset_tx_lock_time_override();
    w.global::<Sweep>().set_sweep_locktime_expanded(false);
    st.refresh_sweep_locktime_panel(w);
    w.global::<Ui>().set_status("".into());
    st.update_sweep_screen(w);
    w.global::<Ui>().set_screen(Screen::Sweep);
}

/// Same as [`refresh_compose_locktime_panel`], for the sweep/consolidate
/// (screen 16) panel.
pub(crate) fn refresh_sweep_locktime_panel(&self, w: &AppWindow) {
    let st = self;
    let policy = st.tx_lock_time_override.unwrap_or(st.lock_time_policy);
    let tip = st.store.as_ref().map(|s| s.tip_height);
    let (mode, height, effective, warn) = locktime_panel_values(policy, tip);
    w.global::<Sweep>().set_sweep_locktime_mode(mode.into());
    w.global::<Sweep>().set_sweep_locktime_height(height.into());
    w.global::<Sweep>().set_sweep_locktime_effective(effective.into());
    w.global::<Sweep>().set_sweep_locktime_warn(warn.into());
}

/// Stage A for a wallet-level sweep (screen 16, `sweep-kind == "sweep"`,
/// keyed self-paid — `on_sweep_send`'s tail): gathers every active
/// notebook's coins (+ the spending wallet's, mixed-sweep style) exactly
/// as the old `on_sweep` modal handler did, builds + signs the multi-key
/// tx, then hands off to the universal confirm screen instead of
/// broadcasting immediately. The sweep destination is passed as
/// `ConfirmCtx.recipient` (no name) so it classifies "recipient" even
/// when it happens to be a foreign address — the paranoid "other"
/// tripwire is reserved for an address NOBODY chose, so a legitimate
/// sweep doesn't cry wolf on every tap. Stage B
/// (`on_confirm_broadcast`/`PendingPayload::Sweep`) is the pre-existing
/// `SWEEP_BROADCAST_RESULTS` thread-spawn, moved verbatim.
pub(crate) fn build_sweep_confirm(&mut self, w: &AppWindow, dest: String, rate: f64) {
    let s = self;
    let net = s.network;
    if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
        return; // caller already routes watch identities to watch_spend_build
    }
    if s.base_url().is_none() {
        w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
        return;
    }
    let Ok(recipient) = Recipient::parse(net, &dest) else {
        w.global::<Ui>().set_status(format!("not a valid {} address", net.as_str()).into());
        return;
    };
    let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
        return;
    };
    let Ok(material) = parse_key_material(&material_str, net) else { return };
    let mut idents: Vec<(
        u32,
        app_core::notes_core::bundle::Identity,
        Vec<app_core::notes_core::tx::Utxo>,
        String,
    )> = Vec::new();
    if let Some(ix) = &s.notebooks {
        for m in ix.active(s.account) {
            let Some(store) = s.notebook_store(m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            let Ok(ident) = realize(&material, net, s.account, m.index) else { continue };
            let addr = ident.address.clone();
            let Some(full) = ident.full().map(|i| i.clone_fields()) else { continue };
            idents.push((m.index, full, coins, addr));
        }
    }
    // CHANGE 2: gather the spending wallet's coins too — UNLESS this
    // sweep's destination IS the spending wallet's own next receive
    // address (`on_spending_sweep_here`), where including them would
    // sweep the spending wallet into itself.
    let spending_coins_for_sweep: Vec<FundingUtxo> = if s.pending_spending_sweep_index.is_none()
        && s.spending_capable
        && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
    {
        s.spending_coins.clone()
    } else {
        Vec::new()
    };
    // Taproot CHANGE-chain coins (unit 6, see
    // `../PLAN-chain-notes-app-taproot-change.md`): same account, chain 1
    // instead of the notebooks' chain 0. Grouped by unique chain-1 index
    // (mirrors the `idents` loop above) so each owner's OWN tweaked key
    // signs exactly its own inputs — `realize_change` is the chain-1
    // sibling of `realize`, same `output_x`/`full()` accessors. Each
    // coin's display-hex `txid` is decoded + reversed into notes-core's
    // internal byte order, the same conversion `Store::available_utxos`
    // does for notebook coins.
    let mut change_idents: Vec<(
        u32,
        app_core::notes_core::bundle::Identity,
        Vec<app_core::notes_core::tx::Utxo>,
        Vec<app_core::chain::ChangeCoin>,
    )> = Vec::new();
    {
        let mut seen_idx: Vec<u32> = Vec::new();
        for c in &s.change_coins {
            if seen_idx.contains(&c.index) {
                continue;
            }
            seen_idx.push(c.index);
            let Ok(owner) = realize_change(&material, net, s.account, c.index) else { continue };
            let Some(full) = owner.full().map(|i| i.clone_fields()) else { continue };
            let raw: Vec<app_core::chain::ChangeCoin> =
                s.change_coins.iter().filter(|x| x.index == c.index).cloned().collect();
            let utxos: Vec<app_core::notes_core::tx::Utxo> = raw
                .iter()
                .filter_map(|x| {
                    let mut txid = [0u8; 32];
                    hex::decode_to_slice(&x.txid, &mut txid).ok()?;
                    txid.reverse();
                    Some(app_core::notes_core::tx::Utxo { txid, vout: x.vout, value: x.value })
                })
                .collect();
            if utxos.is_empty() {
                continue; // a coin whose txid failed to decode — should not happen; skip defensively
            }
            change_idents.push((c.index, full, utxos, raw));
        }
    }
    if idents.is_empty() && spending_coins_for_sweep.is_empty() && change_idents.is_empty() {
        w.global::<Ui>().set_status("nothing to sweep".into());
        return;
    }
    let mut all_inputs: Vec<app_core::store::TxInput> = Vec::new();
    let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
    let notebook_locks: Vec<(u32, Vec<(String, u32)>)> = idents
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
    // Fold in the change-chain owners' inputs (unit 6): same all_inputs/
    // prevouts bookkeeping as the notebook loop above, tagged "Change"
    // instead of "Notebook · <name>" (change coins don't belong to any one
    // notebook — see `update_wallet_coins`). No lock-list is needed here:
    // like the notebook path, coins are only removed from the runtime
    // cache in `apply_sweep_broadcast_result` AFTER a successful
    // broadcast (see `change_spent` below), matching the existing
    // pre-confirm timing exactly.
    for (_, _, _, raw) in &change_idents {
        for c in raw {
            all_inputs.push(app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value });
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Change".to_string(),
                },
            );
        }
    }
    let change_spent: Vec<(String, u32)> = change_idents
        .iter()
        .flat_map(|(_, _, _, raw)| raw.iter().map(|c| (c.txid.clone(), c.vout)))
        .collect();
    let dest_spk_hex = hex::encode(&recipient.spk);
    // `spending_included` decides which notes-core builder runs (whether
    // spending-wallet P2WPKH coins ride along) — independent of change
    // coins, which are taproot key-path just like notebook coins and slot
    // into EITHER builder's all-taproot source list unchanged.
    let spending_included = !spending_coins_for_sweep.is_empty();
    let has_change = !change_idents.is_empty();
    // Mixed record: no per-input owner scheme covers notebook, change-
    // chain, AND spending-wallet inputs together, so it can't be
    // RBF-bumped — see CHANGE 2 / TxRecord.mixed_inputs. Change coins
    // ALSO force non-bumpable even with no spending-wallet coins involved:
    // `TxRecord.input_indexes` only carries chain-0 receive-notebook
    // indexes, so a bump could never re-derive a chain-1 leaf from it —
    // marking it non-bumpable is the safe v1 (rebroadcast still works). A
    // pure-notebook sweep (no change, no spending) keeps its owners
    // (bumpable, unchanged).
    let mixed = spending_included || has_change;
    let input_indexes: Vec<u32> = if mixed {
        Vec::new()
    } else {
        idents.iter().flat_map(|(a, _, coins, _)| std::iter::repeat_n(*a, coins.len())).collect()
    };
    let spending_spent: Vec<(String, u32)> =
        spending_coins_for_sweep.iter().map(|c| (c.txid.clone(), c.vout)).collect();
    if mixed {
        for c in &spending_coins_for_sweep {
            all_inputs.push(app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value });
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Spending wallet".to_string(),
                },
            );
        }
    }
    let sweep: Result<app_core::notes_core::tx::NoteTx, String> = if spending_included {
        let mut notebook_sources: Vec<app_core::mixed::NotebookSweepSource> = idents
            .iter()
            .map(|(_, id, coins, _)| app_core::mixed::NotebookSweepSource {
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
                utxos: coins,
            })
            .collect();
        notebook_sources.extend(change_idents.iter().map(|(_, id, utxos, _)| {
            app_core::mixed::NotebookSweepSource {
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
                utxos,
            }
        }));
        app_core::mixed::build_wallet_sweep_mixed(
            &notebook_sources,
            Some((&material, net, s.account, &spending_coins_for_sweep)),
            recipient.spk.clone(),
            rate,
            s.effective_lock_time(),
        )
        .map_err(|e| format!("{e}"))
    } else {
        let mut sources: Vec<app_core::notes_core::tx::SweepSource> = idents
            .iter()
            .map(|(_, id, coins, _)| app_core::notes_core::tx::SweepSource {
                utxos: coins,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            })
            .collect();
        sources.extend(change_idents.iter().map(|(_, id, utxos, _)| {
            app_core::notes_core::tx::SweepSource {
                utxos,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            }
        }));
        app_core::notes_core::tx::build_sweep_tx_multi(
            &sources,
            recipient.spk.clone(),
            rate,
            s.effective_lock_time(),
            app_core::notes_core::keys::generate_aux_rand,
        )
        .map_err(|e| format!("{e}"))
    };
    match sweep {
        Ok(tx) => {
            let snap = SweepSnapshot {
                identity_addr: s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
                dest: dest.clone(),
                dest_spk_hex,
                value: tx.tx.outputs[0].value,
                fee: tx.fee,
                vsize: tx.vsize as u64,
                raw_hex: tx.raw_hex.clone(),
                notebook_locks,
                all_inputs,
                input_indexes,
                mixed,
                spending_spent,
                pending_spending_sweep_index: s.pending_spending_sweep_index,
                notebooks_n: idents.len(),
                change_spent,
            };
            let (self_spks, spending_spks) = s.confirm_self_spks();
            let ctx = app_core::confirm::ConfirmCtx {
                network: app_core::derive::btc_network(net),
                prevouts,
                self_spks,
                spending_spks,
                expected_change: None,
                recipient: Some(dest.clone()),
                recipient_name: None,
                recipients: Vec::new(),
                note_preview: None,
                tip_height: s.confirm_tip_height(),
            };
            let pending = PendingBroadcast {
                kind: "sweep",
                raw_hex: tx.raw_hex.clone(),
                txid: tx.txid_hex.clone(),
                vsize: tx.vsize,
                context: format!("Sweep to {}… · {}", &dest[..14.min(dest.len())], net.as_str()),
                return_screen: Screen::Sweep, // overwritten by show_confirm
                payload: PendingPayload::Sweep { snap },
            };
            s.show_confirm(w, pending, ctx);
        }
        Err(e) => w.global::<Ui>().set_status(format!("sweep: {e}").into()),
    }
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_set_sweep_tier(&mut self, w: &AppWindow, tier: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        w.global::<Sweep>().set_sweep_tier(tier);
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        if tier != 3 {
            w.global::<Sweep>().set_sweep_rate_text(format!("{rate}").into());
        }
        println!("cb: sweep-tier {tier} rate={rate}");
        s.update_sweep_screen(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_sweep_rate_changed(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.update_sweep_screen(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_toggle_sweep_fund_external(&mut self, w: &AppWindow, on: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: sweep-fund-external {on}");
        w.global::<Ui>().set_status("".into());
        if on && s.funding.is_none() {
            // No funding wallet active yet — pick one; Back returns here.
            w.global::<Ui>().set_funding_return(Screen::Sweep);
            s.refresh_funding_list(w);
            w.global::<Ui>().set_screen(Screen::FundingWallets);
            return;
        }
        s.update_sweep_screen(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_sweep_send(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // Scan-freshness gate (belt to the UI button's braces — an e2e tap
        // or a race can land on a just-disabled button): never build a
        // sweep/consolidate off a coin cache a scan is about to replace.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=sweep");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let dest = w.global::<Ui>().get_sweep_dest().to_string();
        let net = s.network;
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.global::<Ui>().set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        let rate = s.resolve_sweep_rate(w);
        if rate <= 0.0 {
            w.global::<Ui>().set_status("enter a fee rate".into());
            return;
        }
        if w.global::<Sweep>().get_sweep_fund_external() {
            // Fee from the funding wallet: the FULL balance rides to the
            // destination, funding change returns to the funding wallet.
            let Some(fund_src) = s.funding.clone() else {
                w.global::<Ui>().set_status("set a funding wallet first".into());
                return;
            };
            if s.funding_coins.is_empty() {
                w.global::<Ui>().set_status("funding wallet has no spendable coins".into());
                return;
            }
            // Watch identities sweep the whole WALLET (every active
            // notebook's coins, per-index key origins); a keyed identity
            // signs its own inputs with the one active key, so it stays on
            // the active store.
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let notes_coins: Vec<WatchCoin> = if watch {
                s.watch_wallet_coins()
            } else {
                let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
                s.store
                    .as_ref()
                    .map(|store| {
                        store
                            .utxos
                            .iter()
                            .filter(|u| !u.pending_spend)
                            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            if notes_coins.is_empty() {
                w.global::<Ui>().set_status("nothing to sweep".into());
                return;
            }
            let inputs: Vec<app_core::store::TxInput> = notes_coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let input_indexes: Vec<u32> = notes_coins.iter().map(|c| c.index).collect();
            // Unit 6: the watch branch's `notes_coins` (from `watch_wallet_coins`)
            // may include chain-1 change coins riding in this fee-external-
            // funded sweep too — same non-bumpable + prune-on-success
            // treatment as the self-paid watch sweep.
            let change_spent: Vec<(String, u32)> =
                notes_coins.iter().filter(|c| c.chain == 1).map(|c| (c.txid.clone(), c.vout)).collect();
            let Some(ident) = s.ident.as_ref() else { return };
            let identity_spk = p2tr_script_pubkey(&ident.output_x());
            let identity_source = ident.watch_source().cloned();
            let fund_coins = s.funding_coins.clone();
            let plan = FundingPlan {
                source: &fund_src,
                coins: &fund_coins,
                change_index: s.funding_change_index,
                fee_rate: rate,
                change_override: None,
            };
            match build_funded_sweep_psbt(
                identity_spk,
                identity_source.as_ref(),
                &notes_coins,
                &plan,
                recipient.spk.clone(),
                s.effective_lock_time(),
            ) {
                Ok(mut built) => {
                    // Keyed identity: the app signs its own inputs here and
                    // now — only the funding wallet still needs to sign.
                    if let Some(id) = s.ident.as_ref().and_then(|i| i.full()) {
                        match sign_own_taproot_inputs(&mut built.psbt, &id.output_x, &id.tweaked_seckey) {
                            Ok(k) => println!("cb: sweep-own-signed inputs={k}"),
                            Err(e) => {
                                w.global::<Ui>().set_status(format!("{e}").into());
                                return;
                            }
                        }
                    }
                    let cost = format!(
                        "sweep · {} sats arrive in full · fee {} sats from the funding wallet",
                        built.sent_to_recipient, built.fee
                    );
                    s.watch_note = None;
                    s.watch_spend = Some(WatchSpend {
                        kind: if w.global::<Ui>().get_sweep_kind().as_str() == "consolidate" { "consolidate" } else { "sweep" },
                        dest: dest.clone(),
                        dest_spk_hex: hex::encode(&recipient.spk),
                        value: built.sent_to_recipient,
                        fee: built.fee,
                        inputs,
                        input_indexes,
                        dest_index: None,
                        bump_ref: None,
                        change_spent: change_spent.clone(),
                    });
                    println!(
                        "cb: sweep-build funded=1 txid={} fee={} notes_in={} fund_in={}{}",
                        built.txid,
                        built.fee,
                        notes_coins.len(),
                        fund_coins.len(),
                        if change_spent.is_empty() { String::new() } else { format!(" change={}", change_spent.len()) }
                    );
                    s.show_psbt_sign_screen(w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let consolidate = w.global::<Ui>().get_sweep_kind().as_str() == "consolidate";
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            let kind = if consolidate { "consolidate" } else { "sweep" };
            s.watch_spend_build(w, kind, dest, recipient.spk.clone(), rate);
            return;
        }
        // Keyed, self-paid: build + sign now (stage A) and hand off to the
        // universal confirm screen — the (removed) sweep/consolidate
        // confirm modals used to gate this; Broadcast on screen 26 is the
        // only way out now (`on_confirm_broadcast`, kind "sweep"/
        // "consolidate").
        if s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        if consolidate {
            s.build_consolidate_confirm(w, rate);
        } else {
            s.build_sweep_confirm(w, dest, rate);
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_set_sweep_locktime(&mut self, w: &AppWindow, mode: SharedString, height: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: sweep-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.tx_lock_time_override = Some(policy);
        let effective = s.effective_lock_time();
        println!("cb: sweep-locktime {} effective={effective} ok", policy.as_str());
        s.refresh_sweep_locktime_panel(w);
        w.global::<Ui>().set_status("".into());
    }
}
