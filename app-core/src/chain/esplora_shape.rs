//! Shared Esplora-shape synthesis, factored out of [`super::core_rpc`] so
//! [`super::electrum`] (the Electrum backend, `../../PLAN-graffito-electrum.md`)
//! can call the SAME code rather than duplicate it — both translators
//! receive a Core-shaped verbose tx (bitcoind's `getrawtransaction
//! verbosity=2`/electrs' `blockchain.transaction.get [txid, true]` answer
//! the identical shape) and must synthesize byte-identical Esplora JSON
//! from it. Nothing here does any I/O; every function is pure given its
//! inputs (plus, where noted, a caller-supplied prevout-resolving closure),
//! so this module is trivially unit-testable and carries no `Transport`
//! dependency of its own.
//!
//! **`CoreRpcTransport`'s behavior must stay byte-identical** — every
//! function below is a straight extraction of code that used to live
//! directly in `core_rpc.rs`, not a rewrite. Where the two backends'
//! *inputs* differ (Electrum's `listunspent`/`get_balance` values are
//! already in satoshis; Core's are BTC floats needing [`btc_to_sats`]),
//! that conversion stays at the call site, not in here.

use std::collections::HashMap;
use std::sync::Mutex;

/// `10^8` scale, rounded — bitcoind (and any RPC that mirrors its verbose-tx
/// shape) reports amounts in BTC (f64); every esplora shape in this crate is
/// sats (u64). Electrum-protocol calls (`listunspent`, `get_balance`) are
/// already in sats and must NOT be routed through this.
pub(super) fn btc_to_sats(btc: f64) -> u64 {
    (btc * 1e8).round() as u64
}

/// Does `tx` (an esplora-shaped JSON value, as built by
/// [`verbose_tx_to_esplora_json`]) touch `address` — an input prevout OR an
/// output? `CoreRpcTransport`'s watch wallet is SHARED across every address
/// ever queried, so its wallet-wide tx list needs this filter to find the
/// txs for one address; kept here (rather than private to `core_rpc.rs`) in
/// case a future caller needs the identical "does this esplora-shaped tx
/// touch this address" test.
pub(super) fn tx_touches(tx: &serde_json::Value, address: &str) -> bool {
    let touches_vin = tx.get("vin").and_then(|v| v.as_array()).is_some_and(|a| {
        a.iter().any(|i| {
            i.get("prevout").and_then(|p| p.get("scriptpubkey_address")).and_then(|x| x.as_str())
                == Some(address)
        })
    });
    if touches_vin {
        return true;
    }
    tx.get("vout").and_then(|v| v.as_array()).is_some_and(|a| {
        a.iter().any(|o| o.get("scriptpubkey_address").and_then(|x| x.as_str()) == Some(address))
    })
}

/// Whether an esplora-shaped tx (as built by [`verbose_tx_to_esplora_json`])
/// is confirmed — the one field every ordering/filtering helper below needs
/// to read back out of the JSON it was just given.
fn tx_confirmed(tx: &serde_json::Value) -> bool {
    tx.get("status").and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false)
}

/// A Core-shaped verbose tx (`getrawtransaction verbosity=2` / Electrum's
/// `blockchain.transaction.get [txid, true]` — both answer the identical
/// shape) → the esplora tx JSON [`super::esplora::EsploraTx`] deserializes.
/// Extracted verbatim from `CoreRpcTransport::esplora_tx_json`'s body (the
/// cache lookup/insert around it is transport-specific and stays at each
/// call site — see `TX_JSON_CACHE`/[`tx_json_cache_get`]/
/// [`tx_json_cache_maybe_insert`] below, which both transports now share
/// too).
///
/// `resolve_prevout(parent_txid, vout)` is called only when `raw`'s own
/// `vin[].prevout` is absent (a mempool input whose parent has no inlined
/// prevout — verified live for both bitcoind and electrs) — each transport
/// supplies its own version, backed by [`prevout_from_verbose_parent`] on
/// its own `transaction.get`/`getrawtransaction` fetch of the parent.
pub(super) fn verbose_tx_to_esplora_json(
    txid: &str,
    raw: &serde_json::Value,
    tip: u64,
    resolve_prevout: impl Fn(&str, u64) -> (Option<String>, u64),
) -> serde_json::Value {
    let confirmations = raw.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0);
    let confirmed = confirmations > 0;
    let mut status = serde_json::json!({"confirmed": confirmed});
    if confirmed {
        status["block_height"] = serde_json::json!(tip.saturating_sub(confirmations).saturating_add(1));
        if let Some(bt) = raw.get("blocktime") {
            status["block_time"] = bt.clone();
        }
    }
    let vin: Vec<serde_json::Value> = raw
        .get("vin")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|i| {
            let txid_v = i.get("txid").cloned().unwrap_or(serde_json::Value::Null);
            let vout_v = i.get("vout").cloned().unwrap_or(serde_json::Value::Null);
            let (address, value) = match i.get("prevout").filter(|p| !p.is_null()) {
                Some(p) => {
                    let addr = p
                        .get("scriptPubKey")
                        .and_then(|s| s.get("address"))
                        .and_then(|a| a.as_str())
                        .map(str::to_string);
                    let v = p.get("value").and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
                    (addr, v)
                }
                None => match (txid_v.as_str(), vout_v.as_u64()) {
                    // Coinbase inputs carry neither — nothing to resolve.
                    (Some(pt), Some(pv)) => resolve_prevout(pt, pv),
                    _ => (None, 0),
                },
            };
            serde_json::json!({
                "txid": txid_v,
                "vout": vout_v,
                "prevout": {"scriptpubkey_address": address, "value": value},
            })
        })
        .collect();
    let vout: Vec<serde_json::Value> = raw
        .get("vout")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|o| {
            let spk = o.get("scriptPubKey");
            let core_type = spk.and_then(|s| s.get("type")).and_then(|t| t.as_str());
            let esplora_type = if core_type == Some("nulldata") { Some("op_return") } else { core_type };
            let address = spk.and_then(|s| s.get("address")).and_then(|a| a.as_str());
            let hex = spk.and_then(|s| s.get("hex")).and_then(|h| h.as_str());
            let value = o.get("value").and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
            serde_json::json!({
                "scriptpubkey": hex,
                "scriptpubkey_type": esplora_type,
                "scriptpubkey_address": address,
                "value": value,
            })
        })
        .collect();
    serde_json::json!({"txid": txid, "status": status, "vin": vin, "vout": vout})
}

/// A verbose PARENT tx (same shape [`verbose_tx_to_esplora_json`] consumes)
/// → `(address, value_sats)` of its `vout[vout]` — the body shared by
/// `CoreRpcTransport::resolve_prevout` and `ElectrumTransport::resolve_prevout`,
/// each of which only differs in HOW it fetches the parent
/// (`getrawtransaction`/`transaction.get`).
pub(super) fn prevout_from_verbose_parent(parent: &serde_json::Value, vout: u64) -> (Option<String>, u64) {
    let out = parent.get("vout").and_then(|v| v.as_array()).and_then(|a| a.get(vout as usize));
    let address = out
        .and_then(|o| o.get("scriptPubKey"))
        .and_then(|s| s.get("address"))
        .and_then(|a| a.as_str())
        .map(str::to_string);
    let value = out.and_then(|o| o.get("value")).and_then(|v| v.as_f64()).map(btc_to_sats).unwrap_or(0);
    (address, value)
}

/// `GET /address/:a`'s funded/spent fold — extracted verbatim from
/// `CoreRpcTransport::address_stats_route`'s loop. `txs` is `address`'s full
/// esplora-shaped history (already touch/history-filtered by the caller);
/// this just buckets by confirmed/mempool and sums each side's own
/// outputs-to-`address` (funded) and inputs-from-`address` (spent).
pub(super) fn fold_address_stats(txs: &[serde_json::Value], address: &str) -> serde_json::Value {
    let (mut chain_n, mut chain_f, mut chain_s) = (0u64, 0u64, 0u64);
    let (mut mem_n, mut mem_f, mut mem_s) = (0u64, 0u64, 0u64);
    for tx in txs {
        let confirmed = tx_confirmed(tx);
        let mut funded = 0u64;
        let mut spent = 0u64;
        for o in tx.get("vout").and_then(|v| v.as_array()).into_iter().flatten() {
            if o.get("scriptpubkey_address").and_then(|a| a.as_str()) == Some(address) {
                funded += o.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
            }
        }
        for i in tx.get("vin").and_then(|v| v.as_array()).into_iter().flatten() {
            if i.get("prevout").and_then(|p| p.get("scriptpubkey_address")).and_then(|a| a.as_str()) == Some(address) {
                spent += i.get("prevout").and_then(|p| p.get("value")).and_then(|v| v.as_u64()).unwrap_or(0);
            }
        }
        if confirmed {
            chain_n += 1;
            chain_f += funded;
            chain_s += spent;
        } else {
            mem_n += 1;
            mem_f += funded;
            mem_s += spent;
        }
    }
    serde_json::json!({
        "chain_stats": {"tx_count": chain_n, "funded_txo_sum": chain_f, "spent_txo_sum": chain_s},
        "mempool_stats": {"tx_count": mem_n, "funded_txo_sum": mem_f, "spent_txo_sum": mem_s},
    })
}

/// `/address/:a/txs[/chain/:after]`'s pagination — extracted verbatim from
/// `CoreRpcTransport::txs_route`. `items` must already be newest-first
/// (mempool first, then descending height/confirmations — each transport's
/// own history-fetch produces that order); `chain_only` drops mempool
/// entries and paginates 25-at-a-time by cursor, otherwise the plain
/// `/txs` form caps at 50.
pub(super) fn paginate_txs(mut items: Vec<serde_json::Value>, after: Option<&str>, chain_only: bool) -> Vec<serde_json::Value> {
    if chain_only {
        items.retain(tx_confirmed);
    }
    if let Some(after_txid) = after {
        let idx = items.iter().position(|t| t.get("txid").and_then(|v| v.as_str()) == Some(after_txid));
        items = match idx {
            Some(i) => items.split_off(i + 1),
            None => Vec::new(),
        };
    }
    items.truncate(if chain_only { 25 } else { 50 });
    items
}

/// `/address/:a/utxo`'s `status` object — extracted from
/// `CoreRpcTransport::utxo_route`'s per-item shaping. `confirmed_height`
/// is `None` for a mempool coin; `block_time` is `None` when the caller has
/// no cheap way to get one (Core's `listunspent` doesn't carry it — this
/// preserves that transport's existing, unchanged shape) and `Some(t)` when
/// it does (Electrum resolves it from the coin's block header).
pub(super) fn confirmed_status(confirmed_height: Option<u64>, block_time: Option<u64>) -> serde_json::Value {
    match confirmed_height {
        Some(h) => {
            let mut s = serde_json::json!({"confirmed": true, "block_height": h});
            if let Some(t) = block_time {
                s["block_time"] = serde_json::json!(t);
            }
            s
        }
        None => serde_json::json!({"confirmed": false}),
    }
}

// ---- fee-tier helpers (extracted from core_rpc.rs's fee_estimates_route) ----

/// `10^8` sat/BTC ÷ `10^3` vB/kvB — see [`btc_per_kvb_to_sat_vb`]'s doc
/// comment for why this exact constant is the entire ballgame. `pub(super)`
/// so `core_rpc.rs`'s own `sat_vb_conversion_constant_is_exactly_100_000`
/// test (a direct trap for a 1000× mutation) can still pin the exact value.
pub(super) const SAT_VB_PER_BTC_PER_KVB: f64 = 100_000.0;

/// BTC/kvB (`estimatesmartfee`'s/`blockchain.estimatefee`'s and
/// `getmempoolinfo`'s/`blockchain.relayfee`'s native unit) → sat/vB (every
/// `FeeRates` field in this crate). Rounds UP (`.ceil()`) — rounding DOWN a
/// genuine 1.4 sat/vB estimate to 1 could compose a tx that pays less than
/// the rate it was estimated at, risking a slow confirmation or, at the
/// relay-floor boundary, outright rejection; overpaying by a fraction of a
/// sat/vB is the safe direction to round. `.max(1)` is a belt-and-braces
/// floor for a degenerate `0.0` input — the AUTHORITATIVE relay-minimum
/// floor is applied separately, from the live node, in [`clamp_fee_tiers`];
/// this local floor exists only so this function alone never returns a
/// nonsensical 0.
pub(super) fn btc_per_kvb_to_sat_vb(btc_per_kvb: f64) -> u64 {
    ((btc_per_kvb * SAT_VB_PER_BTC_PER_KVB).ceil() as u64).max(1)
}

/// Fallback sat/vB for the ~1-block tier when a real estimate is
/// unavailable (`estimatesmartfee`'s empty `errors` answer / Electrum's
/// `-1`). Deliberately just above the relay floor and the highest of the
/// four fallbacks — visibly "the urgent one" so the fallback shape alone
/// doesn't read as a flat, broken line.
pub(super) const FASTEST_FALLBACK_SAT_VB: u64 = 3;
/// Fallback sat/vB for the ~3-block tier — see [`FASTEST_FALLBACK_SAT_VB`].
pub(super) const HALF_HOUR_FALLBACK_SAT_VB: u64 = 2;
/// Fallback sat/vB for the ~6-block tier — the network's de-facto default
/// relay rate. See [`FASTEST_FALLBACK_SAT_VB`].
pub(super) const HOUR_FALLBACK_SAT_VB: u64 = 1;
/// Fallback sat/vB for the ~144-block (economy) tier — never below 1 (never
/// zero; a zero-fee tx does not relay at all). See
/// [`FASTEST_FALLBACK_SAT_VB`].
pub(super) const ECONOMY_FALLBACK_SAT_VB: u64 = 1;

/// Forces `fastest >= half_hour >= hour >= economy >= floor` — necessary
/// even though a single estimator is monotonic per confirmation target,
/// because each tier passed in here was chosen INDEPENDENTLY (real estimate
/// OR fallback), so a real, volatile value in one tier and a stale fallback
/// in an adjacent one can otherwise cross.
///
/// Order of operations matters and is deliberate: the descending clamp
/// (`half_hour.min(fastest)`, etc.) runs FIRST, then `floor` is applied via
/// `.max(floor)` to every already-ordered value — `max` is monotonic in its
/// first argument, so applying it independently to an already-descending
/// sequence cannot un-sort it.
pub(super) fn clamp_fee_tiers(fastest: u64, half_hour: u64, hour: u64, economy: u64, floor: u64) -> (u64, u64, u64, u64) {
    let half_hour = half_hour.min(fastest);
    let hour = hour.min(half_hour);
    let economy = economy.min(hour);
    (fastest.max(floor), half_hour.max(floor), hour.max(floor), economy.max(floor))
}

/// One block's worth of virtual bytes — the threshold below which a
/// mempool cannot fill the next block, so nothing in it competes for space
/// and next-block inclusion costs the relay floor.
pub(super) const BLOCK_VBYTES: u64 = 1_000_000;

/// Quiet-mempool sanity for a confirmed-history fee estimator (bitcoind's
/// `estimatesmartfee` / Electrum's `blockchain.estimatefee`): the estimator
/// answers from CONFIRMED-block fee history, not from what is waiting now,
/// so on a chain whose history is dominated by spam paid at high sat/vB
/// while the mempool holds almost nothing, the estimator's tiers repeat
/// that stale history. This applies one rule: every tier becomes `floor`
/// when the node/server reports a LOADED mempool (a node that just started
/// with an empty pool is not evidence of a quiet network) smaller than
/// [`BLOCK_VBYTES`]. Anything else (a busy mempool, an unknown size, an
/// unloaded pool) leaves the estimator's tiers as they are. Never raises a
/// tier.
pub(super) fn quiet_mempool_tiers(
    tiers: (u64, u64, u64, u64),
    mempool_vbytes: Option<u64>,
    mempool_loaded: bool,
    floor: u64,
) -> (u64, u64, u64, u64) {
    match mempool_vbytes {
        Some(vb) if mempool_loaded && vb < BLOCK_VBYTES => {
            let floor = floor.max(1);
            (tiers.0.min(floor), tiers.1.min(floor), tiers.2.min(floor), tiers.3.min(floor))
        }
        _ => tiers,
    }
}

// ---- shared confirmed-tx-JSON cache (was core_rpc.rs's TX_JSON_CACHE) ----

/// Process-global cache of fully-resolved esplora-shaped tx JSON, keyed by
/// (node identity, txid) — shared by every `Transport` backend that needs
/// to re-derive an Esplora tx from a verbose RPC/Electrum answer, so a
/// node/server queried through EITHER backend (or a harness that switches
/// between them) benefits from the same cache, and neither backend can
/// serve a stale hit for a DIFFERENT node's history (the key's first
/// element is each transport's own node-identity string, e.g.
/// `http://host:port` for Core or `electrum://host:port` for Electrum, so
/// the two families can never collide).
///
/// **Only a CONFIRMED transaction's fully-built JSON is ever inserted** —
/// see [`tx_json_cache_maybe_insert`]'s doc comment for why that is a
/// safety rule, not a stylistic choice.
static TX_JSON_CACHE: std::sync::LazyLock<Mutex<HashMap<(String, String), serde_json::Value>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Hard cap on [`TX_JSON_CACHE`]'s entry count, enforced at insert time by
/// [`tx_json_cache_maybe_insert`]. Left unbounded, the cache would trade an
/// O(wallet-history) NETWORK cost for an O(wallet-history) MEMORY cost, on a
/// platform (a phone) that can least afford it.
///
/// The policy on reaching the cap is deliberately the crudest one that is
/// still correct: **stop inserting.** Existing entries are never evicted, so
/// there is no thrashing and everything already cached keeps serving hits —
/// the cache just stops growing.
pub(super) const TX_JSON_CACHE_MAX_ENTRIES: usize = 5_000;

/// A cache hit for `key`, if any — skips the RPC/Electrum round trip (and
/// any prevout-resolving follow-ups) entirely.
pub(super) fn tx_json_cache_get(key: &(String, String)) -> Option<serde_json::Value> {
    TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned").get(key).cloned()
}

/// Inserts `value` under `key` ONLY when `confirmed` is true and the cache
/// has not yet reached [`TX_JSON_CACHE_MAX_ENTRIES`]. An UNCONFIRMED
/// (mempool) transaction's status can change on the very next call (mined,
/// dropped, replaced by a fee bump), so caching it would risk telling the
/// user a live transaction was dropped, or hiding a fresh confirmation — the
/// worst failure mode this crate treats specially elsewhere
/// (`TxLookupStatus::NotFound`'s own doc comment). A CONFIRMED transaction's
/// content — including its `status` object, computed once from an ABSOLUTE
/// block height, not a relative "N confirmations ago" — cannot change short
/// of a deep reorg.
pub(super) fn tx_json_cache_maybe_insert(key: (String, String), confirmed: bool, value: &serde_json::Value) {
    if !confirmed {
        return;
    }
    let mut cache = TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned");
    if cache.len() < TX_JSON_CACHE_MAX_ENTRIES {
        cache.insert(key, value.clone());
    }
}

/// Current entry count of [`TX_JSON_CACHE`] — test visibility only, proves
/// the cap in [`tx_json_cache_maybe_insert`] is genuinely enforced.
pub(super) fn tx_json_cache_len() -> usize {
    TX_JSON_CACHE.lock().expect("tx-json cache mutex poisoned").len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_per_kvb_to_sat_vb_matches_known_vectors() {
        assert_eq!(btc_per_kvb_to_sat_vb(0.00001), 1);
        assert_eq!(btc_per_kvb_to_sat_vb(0.00002), 2);
        assert_eq!(btc_per_kvb_to_sat_vb(0.000015), 2); // rounds UP
        assert_eq!(btc_per_kvb_to_sat_vb(0.0), 1); // degenerate floor
    }

    #[test]
    fn clamp_fee_tiers_sorts_descending_and_floors() {
        // hour (8) starts ABOVE half_hour (3) — must clamp down, not un-sort.
        let (f, hh, h, e) = clamp_fee_tiers(10, 3, 8, 1, 2);
        assert_eq!((f, hh, h, e), (10, 3, 3, 2)); // economy=1 floored to 2
        assert!(f >= hh && hh >= h && h >= e);
    }

    #[test]
    fn quiet_mempool_tiers_collapses_small_loaded_mempool() {
        let tiers = (376, 376, 376, 376);
        assert_eq!(quiet_mempool_tiers(tiers, Some(500), true, 1), (1, 1, 1, 1));
        // Unloaded or busy mempool: untouched.
        assert_eq!(quiet_mempool_tiers(tiers, Some(500), false, 1), tiers);
        assert_eq!(quiet_mempool_tiers(tiers, Some(2_000_000), true, 1), tiers);
        assert_eq!(quiet_mempool_tiers(tiers, None, true, 1), tiers);
    }

    #[test]
    fn paginate_txs_chain_only_filters_and_caps_at_25() {
        let mut items = Vec::new();
        for i in 0..30 {
            items.push(serde_json::json!({"txid": format!("t{i}"), "status": {"confirmed": i % 2 == 0}}));
        }
        let out = paginate_txs(items.clone(), None, true);
        assert!(out.len() <= 25);
        assert!(out.iter().all(|t| t["status"]["confirmed"].as_bool().unwrap()));

        let out_all = paginate_txs(items, None, false);
        assert_eq!(out_all.len(), 30.min(50));
    }

    #[test]
    fn paginate_txs_cursor_splits_after_match() {
        let items = vec![
            serde_json::json!({"txid": "a", "status": {"confirmed": true}}),
            serde_json::json!({"txid": "b", "status": {"confirmed": true}}),
            serde_json::json!({"txid": "c", "status": {"confirmed": true}}),
        ];
        let out = paginate_txs(items.clone(), Some("a"), true);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["txid"], "b");

        // Cursor not found -> empty.
        let out2 = paginate_txs(items, Some("zzz"), true);
        assert!(out2.is_empty());
    }
}
