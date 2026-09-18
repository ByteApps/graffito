//! Shared Esplora-shape synthesis, factored out of [`super::core_rpc`] so
//! [`super::electrum`] (the Electrum backend, `../../plans/PLAN-graffito-electrum.md`)
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
/// is confirmed. Test-only since `../../plans/PLAN-graffito-history-scaling.md`
/// item 1: no production caller materializes a full tx list and then
/// filters it anymore ([`paginate_txs`], the only caller, is itself
/// test-only now — see its own doc comment).
#[cfg(test)]
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

// `fold_address_stats` (the old `GET /address/:a` funded/spent fold, which
// needed `address`'s full esplora-shaped history materialized first) was
// REMOVED here by `../../plans/PLAN-graffito-history-scaling.md` U2 — both
// `CoreRpcTransport::address_stats_route` and `ElectrumTransport::
// address_stats_route` now compute their stats from cheap, address-scoped
// RPCs (`listunspent`/`getreceivedbyaddress` for Core,
// `get_history`/`get_balance` for Electrum) instead, with ZERO full-history
// fetch. See each transport's own doc comment for the consumer-visible
// field-definition changes this required.

/// `/address/:a/txs[/chain/:after]`'s pagination, STEP 2 of 2 (the
/// materialisation shape) — see [`paginate_window`] for STEP 1 (the window
/// SELECTION shape). `items` must already be newest-first (mempool first,
/// then descending height/confirmations — each transport's own
/// history-fetch produces that order); `chain_only` drops mempool entries
/// and paginates 25-at-a-time by cursor, otherwise the plain `/txs` form
/// caps at 50. This is a thin wrapper around [`paginate_window`] over
/// already-materialized esplora JSON — kept for callers that already have
/// the full list materialized (and for the existing tests below); a
/// page-aware caller uses [`paginate_order`] instead, over lightweight
/// `(txid, confirmed)` tuples, so it never materializes more than the page
/// it was asked for (`../../plans/PLAN-graffito-history-scaling.md`, "Where
/// the O(N) lives" item 1). Both go through the identical
/// [`paginate_window`] core so the two selections can never drift apart —
/// this is what makes page content/order provably byte-identical whether
/// computed the OLD way (fetch everything, then slice) or the NEW way
/// (slice the lightweight order, then fetch only that).
///
/// Test-only now (`../../plans/PLAN-graffito-history-scaling.md` item 1):
/// no production translator calls this anymore — both
/// `CoreRpcTransport::txs_route` and `ElectrumTransport::txs_route` now
/// window BEFORE materializing (via [`paginate_order`]), never after. Kept
/// (not deleted) as the independent "old shape" oracle the
/// byte-identical-page tests reconstruct against.
#[cfg(test)]
pub(super) fn paginate_txs(items: Vec<serde_json::Value>, after: Option<&str>, chain_only: bool) -> Vec<serde_json::Value> {
    paginate_window(items, after, chain_only, |t| t.get("txid").and_then(|v| v.as_str()).unwrap_or(""), tx_confirmed)
}

/// STEP 1 of 2: the window SELECTION shape, generic over anything that can
/// report its own txid + confirmed-ness — an already-materialized esplora
/// JSON value ([`paginate_txs`]) or a bare `(txid, confirmed)` tuple
/// ([`paginate_order`]). Filters to confirmed-only when `chain_only`, slices
/// from just after the `after` cursor (empty if the cursor isn't found —
/// same "cursor fell off, in practice from a reorg mid-page" tolerance the
/// old single-shot `paginate_txs` had), then caps at 25 (`chain_only`) or 50
/// (plain). Extracting this generic core is what lets a page-aware
/// translator apply the EXACT SAME selection to lightweight tuples that
/// `paginate_txs` applies to full JSON, instead of two hand-kept-in-sync
/// copies of the same three steps.
pub(super) fn paginate_window<T>(
    mut items: Vec<T>,
    after: Option<&str>,
    chain_only: bool,
    txid: impl Fn(&T) -> &str,
    confirmed: impl Fn(&T) -> bool,
) -> Vec<T> {
    if chain_only {
        items.retain(|t| confirmed(t));
    }
    if let Some(after_txid) = after {
        let idx = items.iter().position(|t| txid(t) == after_txid);
        items = match idx {
            Some(i) => items.split_off(i + 1),
            None => Vec::new(),
        };
    }
    items.truncate(if chain_only { 25 } else { 50 });
    items
}

/// STEP 1 alone, over lightweight `(txid, confirmed)` tuples in the same
/// newest-first order [`paginate_txs`] expects — what a page-aware
/// translator's `txs_route` calls BEFORE fetching any tx JSON, so it
/// materializes (`esplora_tx_json` + its prevout resolution) only the
/// txids the requested page actually needs, never the address's whole
/// history. Returns just the ordered txids for that page; the caller
/// fetches each one itself (so it can share its own `esplora_tx_json`/
/// cache plumbing) and serializes the result — see
/// `ElectrumTransport::txs_route` / `CoreRpcTransport::txs_route`.
pub(super) fn paginate_order(order: Vec<(String, bool)>, after: Option<&str>, chain_only: bool) -> Vec<String> {
    paginate_window(order, after, chain_only, |t| t.0.as_str(), |t| t.1).into_iter().map(|(txid, _)| txid).collect()
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

    /// Proves [`paginate_order`] (STEP 1 alone, over lightweight tuples)
    /// selects the EXACT SAME txids, in the EXACT SAME order, that
    /// [`paginate_txs`] (the old one-shot, fully-materialized shape)
    /// selects — over a history with mempool entries, several txs sharing
    /// one block (same `height`/confirmed-ness), and more than 50 confirmed
    /// txs, across every `chain_only`/`after` combination a real caller
    /// hits. This is the structural guarantee behind
    /// `../../plans/PLAN-graffito-history-scaling.md`'s "page JSON must stay
    /// byte-identical" invariant: a page-aware translator computes the page
    /// window from tuples BEFORE fetching any tx JSON, but only because
    /// this same core selects identically either way.
    #[test]
    fn paginate_order_matches_paginate_txs_across_mixed_history() {
        let mut items = Vec::new();
        let mut order = Vec::new();
        // Two mempool entries (unconfirmed), server order preserved.
        for i in 0..2 {
            let txid = format!("mem{i}");
            items.push(serde_json::json!({"txid": txid, "status": {"confirmed": false}}));
            order.push((txid, false));
        }
        // Three txs sharing one block (all confirmed, no height to break
        // ties by within this helper — relative order must survive as-is).
        for i in 0..3 {
            let txid = format!("blk{i}");
            items.push(serde_json::json!({"txid": txid, "status": {"confirmed": true}}));
            order.push((txid, true));
        }
        // 60 more confirmed txs — over both the chain_only cap (25) and the
        // plain cap (50).
        for i in 0..60 {
            let txid = format!("c{i}");
            items.push(serde_json::json!({"txid": txid, "status": {"confirmed": true}}));
            order.push((txid, true));
        }
        for chain_only in [false, true] {
            for after in [None, Some("blk1"), Some("c10"), Some("mem1"), Some("not-present")] {
                let full = paginate_txs(items.clone(), after, chain_only);
                let full_ids: Vec<&str> = full.iter().map(|t| t["txid"].as_str().unwrap()).collect();
                let windowed = paginate_order(order.clone(), after, chain_only);
                assert_eq!(
                    full_ids, windowed,
                    "chain_only={chain_only} after={after:?}: windowed selection diverged from the full-fetch one"
                );
            }
        }
    }
}
