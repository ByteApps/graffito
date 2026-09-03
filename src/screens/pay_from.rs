//! Screen.pay-from — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
#[allow(unused_variables)]
pub(crate) fn on_toggle_coin(&mut self, w: &AppWindow, source: SharedString, outpoint: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let source = source.to_string();
        let op = outpoint.as_str();
        if let Some((txid, vout)) = op.rsplit_once(':') {
            if let Ok(vout) = vout.parse::<u32>() {
                // Taproot CHANGE-chain coins (unit 5, see
                // `../PLAN-chain-notes-app-taproot-change.md`) render folded
                // into the "notebook" panel (`payfrom_panel_coins`), so the
                // slint call site always passes source="notebook" for their
                // rows too — resolve the TRUE source from the outpoint
                // itself (globally unique) rather than trusting the caller,
                // so a change coin is tracked under its own "change" key.
                let source = if s.change_coins.iter().any(|c| c.txid == txid && c.vout == vout) {
                    "change".to_string()
                } else {
                    source
                };
                let mut coins = s.mixed_coins_for(&source);
                let key = (txid.to_string(), vout);
                if let Some(i) = coins.iter().position(|c| c == &key) {
                    coins.remove(i);
                } else {
                    coins.push(key);
                }
                s.mixed_sync_source(&source, &coins);
                s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
                s.payfrom_active_source = source.clone();
                if source == "notebook" || source == "spending" {
                    s.selected_coins = coins.clone();
                    s.coins_overridden = true;
                    s.apply_pay_from(w, source.as_str());
                } else if let Some(id) = source.strip_prefix("wallet:") {
                    s.promote_wallet_active(w, id);
                }
                println!("cb: toggle-coin selected={}", coins.len());
                s.refresh_compose(w);
                s.update_payfrom_panels(w);
                s.refresh_funding_list(w);
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_set_coin_strategy(&mut self, w: &AppWindow, strategy: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        // 0 = fewest coins (largest-first), 1 = consolidate (smallest-first).
        // Re-applies the suggestion (clears any manual override).
        s.consolidate_coins = strategy == 1;
        s.coins_overridden = false;
        w.global::<PayFrom>().set_coin_strategy(strategy);
        println!("cb: coin-strategy {}", if strategy == 1 { "consolidate" } else { "fewest" });
        s.refresh_compose(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_payfrom_expand(&mut self, w: &AppWindow, source: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let key = source.to_string();
        match key.as_str() {
            "notebook" => {
                s.nb_expanded = !s.nb_expanded;
                w.global::<PayFrom>().set_nb_expanded(s.nb_expanded);
                println!("cb: payfrom expand wallet=notebook expanded={}", s.nb_expanded);
            }
            "spending" => {
                s.sp_expanded = !s.sp_expanded;
                w.global::<PayFrom>().set_sp_expanded(s.sp_expanded);
                println!("cb: payfrom expand wallet=spending expanded={}", s.sp_expanded);
                if s.sp_expanded && !s.spending_scanned {
                    s.spending_refresh_async(w);
                }
            }
            _ => {
                let collapsing = s.payfrom_expanded_source == key;
                s.payfrom_expanded_source = if collapsing { String::new() } else { key.clone() };
                w.global::<Ui>().set_payfrom_expanded_source(s.payfrom_expanded_source.clone().into());
                println!("cb: payfrom expand wallet={key} expanded={}", !collapsing);
                if !collapsing {
                    if let Some(id) = key.strip_prefix("wallet:") {
                        s.payfrom_scan_wallet_for_display(w, id);
                    }
                }
            }
        }
        s.update_payfrom_panels(w);
        s.refresh_funding_list(w);
    }

#[allow(unused_variables)]
pub(crate) fn on_funding_refresh(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        s.refresh_async(w);
        if s.spending_capable && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false) {
            s.spending_refresh_async(w);
        }
    }
}
