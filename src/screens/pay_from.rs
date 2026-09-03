//! Screen.pay-from — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn on_toggle_coin(&mut self, w: &AppWindow, source: SharedString, outpoint: SharedString) {
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
                let source = if self.change_coins.iter().any(|c| c.txid == txid && c.vout == vout) {
                    "change".to_string()
                } else {
                    source
                };
                let mut coins = self.mixed_coins_for(&source);
                let key = (txid.to_string(), vout);
                if let Some(i) = coins.iter().position(|c| c == &key) {
                    coins.remove(i);
                } else {
                    coins.push(key);
                }
                self.mixed_sync_source(&source, &coins);
                self.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
                self.payfrom_active_source = source.clone();
                if source == "notebook" || source == "spending" {
                    self.selected_coins = coins.clone();
                    self.coins_overridden = true;
                    self.apply_pay_from(w, source.as_str());
                } else if let Some(id) = source.strip_prefix("wallet:") {
                    self.promote_wallet_active(w, id);
                }
                println!("cb: toggle-coin selected={}", coins.len());
                self.refresh_compose(w);
                self.update_payfrom_panels(w);
                self.refresh_funding_list(w);
            }
        }
    }

pub(crate) fn on_set_coin_strategy(&mut self, w: &AppWindow, strategy: i32) {
        // 0 = fewest coins (largest-first), 1 = consolidate (smallest-first).
        // Re-applies the suggestion (clears any manual override).
        self.consolidate_coins = strategy == 1;
        self.coins_overridden = false;
        w.global::<PayFrom>().set_coin_strategy(strategy);
        println!("cb: coin-strategy {}", if strategy == 1 { "consolidate" } else { "fewest" });
        self.refresh_compose(w);
    }

pub(crate) fn on_payfrom_expand(&mut self, w: &AppWindow, source: SharedString) {
        let key = source.to_string();
        match key.as_str() {
            "notebook" => {
                self.nb_expanded = !self.nb_expanded;
                w.global::<PayFrom>().set_nb_expanded(self.nb_expanded);
                println!("cb: payfrom expand wallet=notebook expanded={}", self.nb_expanded);
            }
            "spending" => {
                self.sp_expanded = !self.sp_expanded;
                w.global::<PayFrom>().set_sp_expanded(self.sp_expanded);
                println!("cb: payfrom expand wallet=spending expanded={}", self.sp_expanded);
                if self.sp_expanded && !self.spending_scanned {
                    self.spending_refresh_async(w);
                }
            }
            _ => {
                let collapsing = self.payfrom_expanded_source == key;
                self.payfrom_expanded_source = if collapsing { String::new() } else { key.clone() };
                w.global::<Ui>().set_payfrom_expanded_source(self.payfrom_expanded_source.clone().into());
                println!("cb: payfrom expand wallet={key} expanded={}", !collapsing);
                if !collapsing {
                    if let Some(id) = key.strip_prefix("wallet:") {
                        self.payfrom_scan_wallet_for_display(w, id);
                    }
                }
            }
        }
        self.update_payfrom_panels(w);
        self.refresh_funding_list(w);
    }

pub(crate) fn on_funding_refresh(&mut self, w: &AppWindow) {
        self.refresh_async(w);
        if self.spending_capable && self.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false) {
            self.spending_refresh_async(w);
        }
    }
}
