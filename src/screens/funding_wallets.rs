//! Screen.funding-wallets — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// Load the device-level saved funding wallets (empty if the file is absent).
pub(crate) fn load_funding_wallets(dir: &std::path::Path) -> Vec<FundingWallet> {
    std::fs::read_to_string(dir.join("funding-wallets.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

impl State {
/// Populate the saved-wallet manager list (screen 15).
pub(crate) fn refresh_funding_list(&self, w: &AppWindow) {
    let st = self;
    let active = st.active_funding_id.clone();
    // Independent-expand rework (2026-07-18): each row carries its OWN
    // coins/title (from the shared `payfrom_panel_coins` helper — screen
    // 20's per-row panels bind directly to `fw.coins`, no more singular
    // `spend-coins`) and whether IT is the one open in the external-wallet
    // accordion slot (`payfrom_expanded_source`; Notebook/Spending have
    // their own independent booleans and never touch this).
    let rows: Vec<FundingWalletRow> = st
        .funding_wallets
        .iter()
        .map(|fw| {
            let meta = if fw.scanned {
                format!("{} · {} sats · {} coin{}", fw.kind, fw.balance, fw.coins, if fw.coins == 1 { "" } else { "s" })
            } else {
                format!("{} · tap to scan for funds", fw.kind)
            };
            let change_addr = fw
                .source(st.network)
                .ok()
                .and_then(|src| src.derive(1, fw.next_change_index).ok())
                .map(|d| addr_short(&d.address))
                .unwrap_or_default();
            let source_key = format!("wallet:{}", fw.id);
            let (coins, coin_title) = st.payfrom_panel_coins(&source_key);
            FundingWalletRow {
                id: fw.id.clone().into(),
                label: fw.label.clone().into(),
                meta: meta.into(),
                active: active.as_deref() == Some(fw.id.as_str()),
                change_addr: change_addr.into(),
                coins: VecModel::from_slice(&coins),
                coin_title: coin_title.into(),
                expanded: st.payfrom_expanded_source == source_key,
            }
        })
        .collect();
    w.global::<Ui>().set_funding_wallets(VecModel::from_slice(&rows));
}

/// Make a saved wallet the active funding source: scan it, cache its balance,
/// and return to compose in external-funding mode. Used by the screen-15
/// wallet list, the add-descriptor flow (12), and the sweep screen (16) —
/// NOT the Pay-from screen (20) anymore: independent-expand rework
/// (2026-07-18) split that header tap into `payfrom_scan_wallet_for_display`
/// (view only) + `promote_wallet_active` (on an actual coin tap), so
/// `stay_on_payfrom` below is effectively always false now — kept rather
/// than removed since this function's other callers still rely on the rest
/// of its behavior unchanged.
pub(crate) fn activate_funding_wallet(&mut self, w: &AppWindow, id: &str) {
    let st = self;
    // funding-unification UI rework: tapping a wallet row on the Pay-from
    // screen (20) selects + expands it IN PLACE — it must not navigate away
    // like the screen-15/16 entry points do.
    let stay_on_payfrom = w.global::<Ui>().get_screen() == Screen::PayFrom;
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    let descriptor = st.funding_wallets[idx].descriptor.clone();
    let src = match FundingSource::parse(&descriptor, net) {
        Ok(src) => src,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    w.global::<Ui>().set_status("scanning funding wallet…".into());
    let creds = st.core_rpc_creds_for(&base, net);
    let client = match open_client(&base, net, creds) {
        Ok(c) => c,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    match client.scan_funding(&src, 20) {
        Ok(scan) => {
            st.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            st.funding_wallets[idx].coins = scan.utxos.len();
            st.funding_wallets[idx].scanned = true;
            st.funding_wallets[idx].next_change_index = scan.next_change_index;
            st.save_funding_wallets();
            let empty = scan.utxos.is_empty();
            st.funding_coins = scan.utxos;
            st.funding_change_index = scan.next_change_index;
            st.funding = Some(src);
            st.active_funding_id = Some(id.to_string());
            // Seed the single-source scratch selection from this wallet's
            // coins (or its remembered cross-wallet selection), so
            // `sync_and_finalize_payfrom` mirrors the wallet into
            // `mixed_selected` — without this the change-default resolver
            // never saw an external wallet participating and kept
            // defaulting to the notebook (Sal's rule: external funding
            // defaults change to THAT wallet's change address).
            let remembered = st.mixed_coins_for(&format!("wallet:{id}"));
            st.selected_coins = if remembered.is_empty() {
                st.funding_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect()
            } else {
                remembered
            };
            w.global::<Ui>().set_status(if empty { "wallet has no spendable coins yet".to_string() } else { String::new() }.into());
            if stay_on_payfrom {
                w.global::<Ui>().set_fund_external(true);
                w.global::<Ui>().set_spend_from_wallet(false);
                let label = st.funding_wallets[idx].label.clone();
                w.global::<Ui>().set_pay_from(format!("wallet:{id}").into());
                w.global::<Compose>().set_pay_from_label(label.clone().into());
                w.global::<Ui>().set_pay_from_balance(format!("{} sats", commas(st.funding_wallets[idx].balance)).into());
                println!("cb: pay-from wallet:{label}");
                st.refresh_compose(w);
            } else if w.global::<Ui>().get_funding_return() == Screen::Sweep {
                // Came from the sweep screen — return there, funding armed.
                w.global::<Sweep>().set_sweep_fund_external(true);
                w.global::<Ui>().set_screen(Screen::Sweep);
                st.update_sweep_screen(w);
            } else {
                w.global::<Ui>().set_fund_external(true);
                w.global::<Ui>().set_spend_from_wallet(false);
                let label = st.funding_wallets[idx].label.clone();
                w.global::<Ui>().set_pay_from(format!("wallet:{id}").into());
                w.global::<Compose>().set_pay_from_label(label.clone().into());
                w.global::<Ui>().set_pay_from_balance(format!("{} sats", commas(st.funding_wallets[idx].balance)).into());
                println!("cb: pay-from wallet:{label}");
                w.global::<Ui>().set_spend_expanded(true);
                w.global::<Ui>().set_screen(Screen::Compose);
                st.refresh_compose(w);
            }
        }
        Err(e) => {
            println!("cb: funding-wallet scan err={e}");
            w.global::<Ui>().set_status(format!("scan failed: {}", friendly_net_err(&e.to_string())).into());
        }
    }
}

/// If `text` is a UR account/descriptor export (BCR crypto-account etc.),
/// decode it, save every supported descriptor as a funding wallet, and show the
/// manager list. Returns true if the input was a UR (handled — possibly with an
/// error message); false to fall through to plain descriptor handling.
pub(crate) fn try_import_ur_account(&mut self, w: &AppWindow, text: &str) -> bool {
    let st = self;
    let t = text.trim();
    if !t.to_lowercase().starts_with("ur:") {
        return false;
    }
    let net = st.network;
    let (ty, bytes) = match app_core::ur::decode_ur_string(t) {
        Ok(x) => x,
        Err(e) => {
            w.global::<Ui>().set_status(format!("UR: {e}").into());
            return true;
        }
    };
    if ty == "crypto-psbt" {
        w.global::<Ui>().set_status("that's a transaction QR, not a wallet".into());
        return true;
    }
    match app_core::ur_account::descriptors_from_ur(&ty, &bytes, net) {
        Ok(descs) if !descs.is_empty() => {
            let ds: Vec<String> = descs.iter().map(|d| d.descriptor.clone()).collect();
            let added = st.save_funding_descriptors(w, &ds);
            w.global::<Ui>().set_status(format!("imported {added} account(s) from {ty}").into());
            true
        }
        Ok(_) => {
            w.global::<Ui>().set_status("no taproot/segwit accounts in that export".into());
            true
        }
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            true
        }
    }
}

/// Create + persist a funding wallet for each descriptor (dedup by id), refresh
/// the manager list, and show it. Returns how many NEW wallets were added.
/// Shared by UR account import and multi-descriptor wallet files — the user
/// then picks which one to use from the list.
pub(crate) fn save_funding_descriptors(&mut self, w: &AppWindow, descriptors: &[String]) -> usize {
    let st = self;
    let net = st.network;
    let mut added = 0;
    for d in descriptors {
        if let Ok(fw) = FundingWallet::create(d, "", net) {
            if !st.funding_wallets.iter().any(|x| x.id == fw.id) {
                st.funding_wallets.push(fw);
                added += 1;
            }
        }
    }
    if added > 0 {
        st.save_funding_wallets();
    }
    st.refresh_funding_list(w);
    w.global::<Ui>().set_screen(Screen::FundingWallets);
    added
}
}
