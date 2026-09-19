//! Electrum protocol chain backend (`../../plans/PLAN-graffito-electrum.md`) — a
//! plain-TCP, newline-delimited JSON-RPC 2.0 client for a personal
//! `electrs`/ElectrumX server (romanz electrs, the same server Sparrow and
//! btc-rpc-explorer already use). Selected by the `electrum+tcp://host:port`
//! URL scheme in [`super::transport::AnyTransport::new`] — `electrum+ssl://`
//! is refused there with a clear error (TLS + cert pinning is a follow-up,
//! out of scope here).
//!
//! Same seam as [`super::core_rpc::CoreRpcTransport`]: [`Transport`]
//! receives Esplora-shaped PATHS and this translator synthesizes an
//! Esplora-shaped JSON body from Electrum RPC calls — `ChainClient`, the
//! scan functions, `netq`, `store`, `compose`, and the whole UI layer stay
//! untouched. Unlike Core RPC this needs NO credentials, NO watch wallet,
//! and NO descriptor imports/rescans — electrs already indexes every
//! scripthash, so an address lookup is a direct
//! `blockchain.scripthash.*` call with no import step.
//!
//! **Shared code, not copies**: the verbose-tx→Esplora conversion, the
//! funded/spent stats fold, the tx-list pagination, and the fee-tier
//! helpers all live in [`super::esplora_shape`] (extracted from
//! `core_rpc.rs`) and are called from here unchanged — a Core-shaped
//! verbose tx (bitcoind's `getrawtransaction verbosity=2` /
//! electrs' `blockchain.transaction.get [txid, true]`) is the SAME shape
//! either backend answers with.
//!
//! Wire facts this file encodes (probed live 2026-09-06 against the Pi's
//! mainnet electrs — see the plan doc's table): one TCP connection per
//! call (a fresh stream per request, reconnecting on any I/O error — v1
//! choice per the plan, simplest correct thing); a connect timeout of 10s
//! and a read/write timeout of 30s; missing-tx error code `2` maps to an
//! esplora-shaped `"404: …"` (so [`super::client::ChainClient::tx_lookup_status`]
//! reads it as [`super::transport::TxLookupStatus::NotFound`]); a broadcast
//! rejection maps to `"400: <reason>"` (so
//! `crate::friendly_broadcast_err` renders it identically to the other two
//! backends).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use bitcoin::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;

use super::esplora_shape;
use super::transport::Transport;

/// Connect timeout for a fresh Electrum TCP stream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Read/write timeout on an established Electrum stream — an electrs
/// query, including the pathological "fetch every parent for prevout
/// resolution" case, should never legitimately take anywhere near this
/// long; a dead/unreachable server should fail an operation, not hang it.
const RW_TIMEOUT: Duration = Duration::from_secs(30);

/// One JSON-RPC call's outcome, kept distinct from [`Error`] so
/// [`ElectrumTransport::transaction_get`] can pattern-match on the RPC
/// error CODE (electrs' code `2` = "no such transaction") before it
/// collapses down to the crate-wide [`Error`] shape everything else uses —
/// exactly the shape `core_rpc.rs`'s `RpcOutcome` already uses for the
/// identical reason.
enum ElectrumOutcome {
    Ok(serde_json::Value),
    /// A well-formed JSON-RPC error response — `code` is the server's own
    /// numeric error code (electrs mirrors bitcoind's negative/small-int
    /// codes for the calls this crate uses).
    RpcError { code: Option<i64>, message: String },
    /// The request never reached a server, or no full/parseable response
    /// came back — mirrors [`Error::Transport`]'s "safe to retry" class.
    Transport(String),
}

/// `server.features`'s `genesis_hash` + `server.version`'s server/protocol
/// strings + the current tip height, folded into one status the app can
/// render (and use for the network check — see [`network_matches_genesis`]
/// below, called with the network's own expected hash: this app's
/// `Network::Testnet4` intentionally does NOT share `bitcoin::Network`'s
/// testnet3 genesis, so the comparison is a plain string match the CALLER
/// supplies both sides of, never keyed off `bitcoin::Network` here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElectrumStatus {
    pub server_version: String,
    pub protocol: String,
    pub tip_height: u64,
    /// Hex genesis block hash, exactly as `server.features` reports it.
    pub genesis_hash: String,
}

/// Pure, case-insensitive genesis-hash comparison — deliberately NOT a
/// `bitcoin::Network`-keyed method (see [`ElectrumStatus`]'s doc comment):
/// this app's `Network::Testnet4` encodes addresses as `bitcoin::Network::
/// Testnet` (`derive.rs`), so keying a genesis check off `bitcoin::Network`
/// here would compare a testnet4 server's genesis against the WRONG
/// (testnet3) expected hash. The caller resolves `expected_genesis_hex`
/// from its own `Network` and hands both strings in.
pub fn network_matches_genesis(genesis_hash: &str, expected_genesis_hex: &str) -> bool {
    genesis_hash.trim().eq_ignore_ascii_case(expected_genesis_hex.trim())
}

/// Electrum protocol chain backend — see the module doc comment.
pub struct ElectrumTransport {
    host: String,
    port: u16,
    next_id: AtomicU64,
    /// U7 request counter — see
    /// [`super::transport::Transport::request_count`].
    request_count: AtomicU32,
}

impl std::fmt::Debug for ElectrumTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumTransport").field("host", &self.host).field("port", &self.port).finish()
    }
}

impl ElectrumTransport {
    /// `rest` is the base URL with the `electrum+` prefix already stripped
    /// by [`super::transport::AnyTransport::new`] — e.g. `tcp://host:port`.
    /// `electrum+ssl://` is refused one layer up, before this ever runs.
    pub fn new(rest: &str) -> Result<Self, Error> {
        let after = rest
            .strip_prefix("tcp://")
            .ok_or_else(|| Error::Http(format!("electrum+ URL must be tcp://host:port (got {rest:?})")))?;
        // Tolerate (and ignore) a stray trailing path/slash, same tolerance
        // `CoreRpcTransport::new` gives its own RPC endpoint.
        let authority = after.split('/').next().unwrap_or(after);
        let (host, port) =
            authority.rsplit_once(':').ok_or_else(|| Error::Http("electrum+tcp URL missing a port".into()))?;
        if host.is_empty() {
            return Err(Error::Http("electrum+tcp URL missing a host".into()));
        }
        let port: u16 =
            port.parse().map_err(|_| Error::Http(format!("electrum+tcp URL: invalid port {port:?}")))?;
        Ok(ElectrumTransport {
            host: host.to_string(),
            port,
            next_id: AtomicU64::new(1),
            request_count: AtomicU32::new(0),
        })
    }

    /// Identifies this node for the shared [`esplora_shape`] tx-JSON cache
    /// — distinct from `CoreRpcTransport::node_key`'s `http://…` shape, so
    /// the two backends' cache entries can never collide even if pointed
    /// at the same host:port (they never legitimately would be, but the
    /// cache key makes that moot).
    fn node_key(&self) -> String {
        format!("electrum://{}:{}", self.host, self.port)
    }

    /// One fresh TCP connection, per the plan's v1 choice ("a fresh stream
    /// per request is acceptable for v1; if you keep one stream, guard it
    /// with a Mutex and reconnect on any I/O error") — simplest correct
    /// thing, and it sidesteps ever having to distinguish an unsolicited
    /// notification arriving between calls from one arriving as a
    /// same-connection response (each connection carries exactly one
    /// request/response round trip in this implementation).
    fn connect(&self) -> Result<TcpStream, Error> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| Error::Transport(format!("electrum resolve {}:{}: {e}", self.host, self.port)))?
            .next()
            .ok_or_else(|| Error::Transport(format!("electrum: no address for {}:{}", self.host, self.port)))?;
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| Error::Transport(format!("electrum connect {}:{}: {e}", self.host, self.port)))?;
        // Best-effort — a platform that refuses to set these still gets a
        // working (if unbounded) connection rather than a hard failure.
        let _ = stream.set_read_timeout(Some(RW_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RW_TIMEOUT));
        Ok(stream)
    }

    /// One newline-delimited JSON-RPC 2.0 request/response round trip.
    /// Ignores any notification line (carries `"method"`, no `"id"`) that
    /// may arrive before the real response — a `blockchain.headers.
    /// subscribe` push, in servers that send one unprompted.
    fn call_raw(&self, method: &str, params: serde_json::Value) -> ElectrumOutcome {
        #[cfg(debug_assertions)]
        eprintln!("cb: electrum {method}");
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => return ElectrumOutcome::Transport(format!("electrum encode: {e}")),
        };
        line.push('\n');

        let stream = match self.connect() {
            Ok(s) => s,
            Err(Error::Transport(m)) => return ElectrumOutcome::Transport(m),
            Err(e) => return ElectrumOutcome::Transport(e.to_string()),
        };
        let mut writer = match stream.try_clone() {
            Ok(w) => w,
            Err(e) => return ElectrumOutcome::Transport(format!("electrum clone stream: {e}")),
        };
        if let Err(e) = writer.write_all(line.as_bytes()) {
            return ElectrumOutcome::Transport(format!("electrum write: {e}"));
        }

        let mut reader = BufReader::new(stream);
        loop {
            let mut resp_line = String::new();
            let n = match reader.read_line(&mut resp_line) {
                Ok(n) => n,
                Err(e) => return ElectrumOutcome::Transport(format!("electrum read: {e}")),
            };
            if n == 0 {
                return ElectrumOutcome::Transport("electrum: connection closed with no response".into());
            }
            let trimmed = resp_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => return ElectrumOutcome::Transport(format!("electrum response: {e}")),
            };
            // A line carrying "method" and no "id" is an unsolicited
            // notification (e.g. a headers-subscribe push) — never the
            // answer to what we just asked. Keep reading.
            if v.get("method").is_some() && v.get("id").is_none() {
                continue;
            }
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                let code = err.get("code").and_then(|c| c.as_i64());
                let message =
                    err.get("message").and_then(|m| m.as_str()).unwrap_or("electrum error").to_string();
                return ElectrumOutcome::RpcError { code, message };
            }
            return ElectrumOutcome::Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
    }

    /// [`Self::call_raw`] collapsed to the crate-wide [`Error`] shape —
    /// what every route below uses except [`Self::transaction_get`] (needs
    /// the raw code for the missing-tx → 404 mapping) and
    /// [`Self::broadcast`] (needs the raw message for the 400 mapping).
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Error> {
        match self.call_raw(method, params) {
            ElectrumOutcome::Ok(v) => Ok(v),
            ElectrumOutcome::RpcError { code, message } => {
                Err(Error::Http(format!("electrum [{}]: {message}", code.unwrap_or(-1))))
            }
            ElectrumOutcome::Transport(m) => Err(Error::Transport(m)),
        }
    }

    /// `blockchain.headers.subscribe` → tip height. Called with no params
    /// (protocol 1.4's shape — no callback id argument).
    fn tip_height(&self) -> Result<u64, Error> {
        let v = self.call("blockchain.headers.subscribe", serde_json::json!([]))?;
        v.get("height").and_then(|h| h.as_u64()).ok_or_else(|| Error::Json("headers.subscribe: missing height".into()))
    }

    /// `server.version` + `server.features` + the tip — everything the
    /// Settings health line (a later unit) needs.
    pub fn server_status(&self) -> Result<ElectrumStatus, Error> {
        let version = self.call("server.version", serde_json::json!(["graffito", "1.4"]))?;
        let arr = version.as_array().cloned().unwrap_or_default();
        let server_version = arr.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
        let protocol = arr.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let tip_height = self.tip_height()?;
        let features = self.call("server.features", serde_json::json!([]))?;
        let genesis_hash = features.get("genesis_hash").and_then(|g| g.as_str()).unwrap_or("").to_string();
        Ok(ElectrumStatus { server_version, protocol, tip_height, genesis_hash })
    }

    /// `blockchain.transaction.get [txid, verbose]`, mapping electrs' error
    /// code `2` ("No such mempool or blockchain transaction…") to an
    /// esplora-shaped `"404: …"` — unlike `CoreRpcTransport::
    /// getrawtransaction`'s `-5`, electrs only serves once bitcoind is out
    /// of IBD (plan doc), so code 2 IS positively-established absence,
    /// with no separate txindex/IBD/mempool cross-check needed. The
    /// `"404:"` prefix is load-bearing:
    /// `ChainClient::tx_lookup_status` matches on it verbatim.
    fn transaction_get(&self, txid: &str, verbose: bool) -> Result<serde_json::Value, Error> {
        match self.call_raw("blockchain.transaction.get", serde_json::json!([txid, verbose])) {
            ElectrumOutcome::Ok(v) => Ok(v),
            ElectrumOutcome::RpcError { code: Some(2), .. } => {
                Err(Error::Http(format!("404: no such transaction: {txid}")))
            }
            ElectrumOutcome::RpcError { code, message } => {
                Err(Error::Http(format!("electrum [{}]: {message}", code.unwrap_or(-1))))
            }
            ElectrumOutcome::Transport(m) => Err(Error::Transport(m)),
        }
    }

    /// A prevout not inlined on `vin[].prevout` (a mempool input) is
    /// resolved by fetching the parent tx directly — mirrors
    /// `CoreRpcTransport::resolve_prevout`, sharing its body via
    /// [`esplora_shape::prevout_from_verbose_parent`].
    fn resolve_prevout(&self, parent_txid: &str, vout: u64) -> (Option<String>, u64) {
        let Ok(parent) = self.transaction_get(parent_txid, true) else {
            return (None, 0);
        };
        esplora_shape::prevout_from_verbose_parent(&parent, vout)
    }

    /// `blockchain.transaction.get [txid, true]` → the esplora tx shape,
    /// through the shared [`esplora_shape::verbose_tx_to_esplora_json`] and
    /// the shared confirmed-tx cache (see that module's doc comment for
    /// the safety rule: only a CONFIRMED result is ever cached).
    fn esplora_tx_json(&self, txid: &str, tip: u64) -> Result<serde_json::Value, Error> {
        let cache_key = (self.node_key(), txid.to_string());
        if let Some(cached) = esplora_shape::tx_json_cache_get(&cache_key) {
            return Ok(cached);
        }
        let raw = self.transaction_get(txid, true)?;
        let result =
            esplora_shape::verbose_tx_to_esplora_json(txid, &raw, tip, |ptxid, v| self.resolve_prevout(ptxid, v));
        let confirmed = result.get("status").and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
        esplora_shape::tx_json_cache_maybe_insert(cache_key, confirmed, &result);
        Ok(result)
    }

    /// `blockchain.block.header [height]` → an 80-byte header hex, from
    /// which `block_time` is the little-endian u32 at bytes 68..72 (the
    /// block header's `nTime` field, per the standard 80-byte layout:
    /// version 0..4, prev-hash 4..36, merkle-root 36..68, time 68..72,
    /// bits 72..76, nonce 76..80). `None` on any failure — callers treat
    /// that as "no block_time available", never a hard error (matches
    /// `CoreRpcTransport::utxo_route`'s existing tolerance for a missing
    /// `block_time`).
    fn block_time(&self, height: u64) -> Option<u64> {
        let raw = self.call("blockchain.block.header", serde_json::json!([height])).ok()?;
        let hex_str = raw.as_str()?;
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() < 72 {
            return None;
        }
        let t = u32::from_le_bytes(bytes[68..72].try_into().ok()?);
        Some(t as u64)
    }

    /// `address`'s LIGHTWEIGHT history order via `scripthash` — ONE
    /// `blockchain.scripthash.get_history` call, no `transaction.get` at
    /// all: newest first, mempool entries (electrs reports `height <= 0`
    /// for these — 0 = mempool with a confirmed parent, -1 = mempool with
    /// an unconfirmed parent) in the server's own order, then confirmed
    /// entries descending by height (most-recently-mined first) — mirrors
    /// `CoreRpcTransport::wallet_tx_order`'s mempool-then-
    /// descending-confirmations shape (equivalent to descending height at
    /// a fixed tip). Each entry carries `confirmed` (`height > 0`) so a
    /// caller can run [`esplora_shape::paginate_order`] — the window
    /// SELECTION step — before fetching any tx JSON at all
    /// (`../../plans/PLAN-graffito-history-scaling.md`, "Where the O(N)
    /// lives" item 1: the old code fetched + prevout-resolved the
    /// address's ENTIRE history before slicing out the page the caller
    /// asked for). Backs `/address/:a/txs` and `/address/:a/txs/chain/
    /// :after`; `/address/:a` (stats) no longer walks this at all — see
    /// [`Self::address_stats_route`].
    fn address_order(&self, scripthash: &str) -> Result<Vec<(String, bool)>, Error> {
        let history = self.call("blockchain.scripthash.get_history", serde_json::json!([scripthash]))?;
        let mut entries: Vec<(String, i64)> = history
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                let txid = e.get("tx_hash").and_then(|t| t.as_str())?.to_string();
                let height = e.get("height").and_then(|h| h.as_i64()).unwrap_or(0);
                Some((txid, height))
            })
            .collect();
        entries.sort_by(|a, b| {
            let a_mem = a.1 <= 0;
            let b_mem = b.1 <= 0;
            match (a_mem, b_mem) {
                (true, true) => std::cmp::Ordering::Equal,
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                (false, false) => b.1.cmp(&a.1),
            }
        });
        Ok(entries.into_iter().map(|(txid, height)| (txid, height > 0)).collect())
    }

    /// `GET /address/:a` — U2 (`../../plans/PLAN-graffito-history-scaling.md`):
    /// counts come straight from `get_history` (EXACT — electrs' scripthash
    /// index already carries every tx that touches this address on EITHER
    /// side, input or output, so bucketing its entries by `height` needs no
    /// per-tx fetch at all), and the funded/spent SUMS come from
    /// `blockchain.scripthash.get_balance` — zero `transaction.get` calls,
    /// versus the old path's one full-history fetch (+ prevout resolution)
    /// per call, including on the quiet 60s refresh tick this route backs.
    ///
    /// **Consumer-visible change, reported per the plan's instructions**:
    /// `funded_txo_sum`/`spent_txo_sum` are no longer the old esplora-exact
    /// definition (lifetime sum of confirmed-tx outputs TO this address /
    /// lifetime sum of confirmed-tx inputs FROM this address, bucketed by
    /// the SPENDING tx's own confirmed-ness — see the removed
    /// `fold_address_stats` call this route used to make). They now report
    /// `get_balance`'s CURRENT net balance split: `chain_funded` = the
    /// confirmed balance, `mempool_funded`/`mempool_spent` = the
    /// unconfirmed balance (Electrum's protocol allows this to go
    /// negative — "spending confirmed funds via an unconfirmed tx" — which
    /// is reported as `mempool_spent` instead of a negative `funded`).
    /// `spent_txo_sum` under `chain_stats` is always `0` now (no cheap
    /// Electrum call gives a lifetime confirmed-spent sum without exactly
    /// the per-tx walk this unit removes).
    ///
    /// The only two consumers are `Store.addr_stats`'s equality-based
    /// change fingerprint and `ChainClient::address_used`'s `tx_count > 0`
    /// check (never a UI display — grepped repo-wide for this unit).
    /// `tx_count` keeps its EXACT old definition (one increment per tx in
    /// the address's history, same entries as before), so `address_used()`
    /// is byte-for-byte unaffected. The sums stay TRUTHFUL for
    /// fingerprinting: they change whenever the address's current balance
    /// changes, and `tx_count` alone already changes on every other kind of
    /// history event a same-value-swap could hide from a balance-only
    /// comparison (a new tx always adds one more `get_history` entry, in
    /// either bucket).
    fn address_stats_route(&self, scripthash: &str) -> Result<String, Error> {
        let history = self.call("blockchain.scripthash.get_history", serde_json::json!([scripthash]))?;
        let (chain_n, mem_n) = history.as_array().cloned().unwrap_or_default().into_iter().fold(
            (0u64, 0u64),
            |(chain, mem), e| {
                let height = e.get("height").and_then(|h| h.as_i64()).unwrap_or(0);
                if height > 0 { (chain + 1, mem) } else { (chain, mem + 1) }
            },
        );
        let balance = self.call("blockchain.scripthash.get_balance", serde_json::json!([scripthash]))?;
        let confirmed = balance.get("confirmed").and_then(|v| v.as_i64()).unwrap_or(0);
        let unconfirmed = balance.get("unconfirmed").and_then(|v| v.as_i64()).unwrap_or(0);
        let chain_funded = confirmed.max(0) as u64;
        let (mempool_funded, mempool_spent) =
            if unconfirmed >= 0 { (unconfirmed as u64, 0u64) } else { (0u64, (-unconfirmed) as u64) };
        Ok(serde_json::json!({
            "chain_stats": {"tx_count": chain_n, "funded_txo_sum": chain_funded, "spent_txo_sum": 0},
            "mempool_stats": {"tx_count": mem_n, "funded_txo_sum": mempool_funded, "spent_txo_sum": mempool_spent},
        })
        .to_string())
    }

    /// `GET /address/:a/utxo` → `blockchain.scripthash.listunspent` —
    /// values are already sats (the Electrum protocol convention, unlike
    /// Core's BTC-float RPC), and `block_time` is resolved per confirmed
    /// coin via [`Self::block_time`] (Core's own `utxo_route` has no cheap
    /// way to do this and stays without one — see
    /// [`esplora_shape::confirmed_status`]'s doc comment).
    fn utxo_route(&self, scripthash: &str) -> Result<String, Error> {
        let result = self.call("blockchain.scripthash.listunspent", serde_json::json!([scripthash]))?;
        let items: Vec<serde_json::Value> = result
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|u| {
                let txid = u.get("tx_hash").cloned().unwrap_or(serde_json::Value::Null);
                let vout = u.get("tx_pos").cloned().unwrap_or(serde_json::Value::Null);
                let value = u.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                let height = u.get("height").and_then(|h| h.as_i64()).unwrap_or(0);
                let confirmed_height = if height > 0 { Some(height as u64) } else { None };
                let block_time = confirmed_height.and_then(|h| self.block_time(h));
                let status = esplora_shape::confirmed_status(confirmed_height, block_time);
                serde_json::json!({"txid": txid, "vout": vout, "value": value, "status": status})
            })
            .collect();
        Ok(serde_json::to_string(&items).unwrap())
    }

    /// `GET /address/:a/txs[/chain/:after]` — page-aware
    /// (`../../plans/PLAN-graffito-history-scaling.md` item 1): computes the
    /// page's txids from [`Self::address_order`]'s lightweight tuples via
    /// [`esplora_shape::paginate_order`] FIRST, then calls
    /// [`Self::esplora_tx_json`] (with its cache + prevout resolution) only
    /// for the ≤ 25/50 txids that page actually needs — never the
    /// address's whole history, which is what the old
    /// fetch-everything-then-`paginate_txs` shape did.
    fn txs_route(&self, scripthash: &str, after: Option<&str>, chain_only: bool) -> Result<String, Error> {
        let tip = self.tip_height()?;
        let order = self.address_order(scripthash)?;
        let page_txids = esplora_shape::paginate_order(order, after, chain_only);
        let mut items = Vec::with_capacity(page_txids.len());
        for txid in page_txids {
            items.push(self.esplora_tx_json(&txid, tip)?);
        }
        Ok(serde_json::to_string(&items).unwrap())
    }

    /// `GET /v1/fees/recommended` → `blockchain.estimatefee` for 1/3/6/144
    /// blocks, floored to `blockchain.relayfee` and forced non-increasing
    /// via the SAME shared helpers `CoreRpcTransport::fee_estimates_route`
    /// uses, then the same quiet-mempool collapse from
    /// `mempool.get_fee_histogram`'s summed vsize.
    fn fee_estimates_route(&self) -> Result<String, Error> {
        let sat_vb = |blocks: u64| -> Option<u64> {
            let v = self.call("blockchain.estimatefee", serde_json::json!([blocks])).ok()?;
            let btc_per_kvb = v.as_f64()?;
            // `-1` is electrs' explicit "no estimate available" — never a
            // real (negative) fee rate.
            if btc_per_kvb < 0.0 {
                return None;
            }
            Some(esplora_shape::btc_per_kvb_to_sat_vb(btc_per_kvb))
        };
        let relay_min = self
            .call("blockchain.relayfee", serde_json::json!([]))
            .ok()
            .and_then(|v| v.as_f64())
            .map(esplora_shape::btc_per_kvb_to_sat_vb)
            .unwrap_or(1);
        let histogram = self.call("mempool.get_fee_histogram", serde_json::json!([])).ok();
        let mempool_vbytes: Option<u64> = histogram.as_ref().and_then(|h| h.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|pair| pair.as_array())
                .filter_map(|p| p.get(1))
                .filter_map(|v| v.as_u64())
                .sum()
        });
        let mempool_loaded = histogram.is_some();
        let fastest = sat_vb(1).unwrap_or(esplora_shape::FASTEST_FALLBACK_SAT_VB);
        let half_hour = sat_vb(3).unwrap_or(esplora_shape::HALF_HOUR_FALLBACK_SAT_VB);
        let hour = sat_vb(6).unwrap_or(esplora_shape::HOUR_FALLBACK_SAT_VB);
        let economy = sat_vb(144).unwrap_or(esplora_shape::ECONOMY_FALLBACK_SAT_VB);
        let (fastest, half_hour, hour, economy) =
            esplora_shape::clamp_fee_tiers(fastest, half_hour, hour, economy, relay_min);
        let (fastest, half_hour, hour, economy) = esplora_shape::quiet_mempool_tiers(
            (fastest, half_hour, hour, economy),
            mempool_vbytes,
            mempool_loaded,
            relay_min,
        );
        Ok(serde_json::json!({
            "fastestFee": fastest,
            "halfHourFee": half_hour,
            "hourFee": hour,
            "economyFee": economy,
            "minimumFee": relay_min,
        })
        .to_string())
    }

    /// `blockchain.transaction.broadcast [hex]` — a rejection maps to
    /// `"400: <reason>"`, matching the shape `crate::friendly_broadcast_err`
    /// already renders for the other two backends.
    fn broadcast(&self, hex: &str) -> Result<String, Error> {
        match self.call_raw("blockchain.transaction.broadcast", serde_json::json!([hex])) {
            ElectrumOutcome::Ok(v) => v
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| Error::Json("electrum broadcast: did not return a txid".into())),
            ElectrumOutcome::RpcError { message, .. } => Err(Error::Http(format!("400: {message}"))),
            ElectrumOutcome::Transport(m) => Err(Error::Transport(m)),
        }
    }
}

/// scripthash = sha256(scriptPubKey), byte-reversed, hex — the Electrum
/// protocol's addressing scheme. Parses `address` PERMISSIVELY
/// (`assume_checked`, plan doc): [`ElectrumTransport::new`] receives no
/// network at construction (same as `CoreRpcTransport`, which also never
/// validates network at the transport layer), so a wrong-network address
/// is not distinguishable here from a right-network one — only a
/// syntactically unparseable string is. `None` on parse failure is the
/// caller's signal to short-circuit to the same empty shapes
/// `CoreRpcTransport::ensure_address_watched` returns for an invalid
/// address.
fn scripthash_for_address(address: &str) -> Option<String> {
    let addr = Address::from_str(address.trim()).ok()?.assume_checked();
    let script = addr.script_pubkey();
    let digest = Sha256::digest(script.as_bytes());
    let mut bytes: Vec<u8> = digest.to_vec();
    bytes.reverse();
    Some(hex::encode(bytes))
}

impl Transport for ElectrumTransport {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        #[cfg(debug_assertions)]
        eprintln!("cb: http GET {path}");
        // Not debug-gated (U7) — see `HttpTransport::get_text`'s note.
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if path == "/blocks/tip/height" {
            return Ok(self.tip_height()?.to_string());
        }
        if path == "/v1/fees/recommended" {
            return self.fee_estimates_route();
        }
        if path == "/v1/prices" {
            // No server here knows the price — same as Core RPC; both
            // call sites already degrade via `if let Ok(...)`.
            return Err(Error::Http("electrum has no price oracle".into()));
        }
        if let Some(rest) = path.strip_prefix("/address/") {
            let mut parts = rest.splitn(2, '/');
            let address = parts.next().unwrap_or("");
            if address.is_empty() {
                return Err(Error::Http("404: address missing".into()));
            }
            let sub = parts.next();
            let Some(scripthash) = scripthash_for_address(address) else {
                // Syntactically invalid — same empty-shape short-circuit
                // `CoreRpcTransport` uses for the identical case.
                return match sub {
                    None => Ok(serde_json::json!({
                        "chain_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0},
                        "mempool_stats": {"tx_count": 0, "funded_txo_sum": 0, "spent_txo_sum": 0},
                    })
                    .to_string()),
                    Some("utxo") | Some("txs") => Ok("[]".to_string()),
                    Some(s) if s.starts_with("txs/chain/") => Ok("[]".to_string()),
                    Some(other) => Err(Error::Http(format!("404: no route /address/.../{other}"))),
                };
            };
            return match sub {
                None => self.address_stats_route(&scripthash),
                Some("utxo") => self.utxo_route(&scripthash),
                Some("txs") => self.txs_route(&scripthash, None, false),
                Some(s) if s.starts_with("txs/chain/") => {
                    let after = &s["txs/chain/".len()..];
                    self.txs_route(&scripthash, Some(after), true)
                }
                Some(other) => Err(Error::Http(format!("404: no route /address/.../{other}"))),
            };
        }
        if let Some(rest) = path.strip_prefix("/tx/") {
            if let Some(txid) = rest.strip_suffix("/hex") {
                let raw = self.transaction_get(txid, false)?;
                return raw
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::Json("transaction.get: hex not a string".into()));
            }
            let tip = self.tip_height()?;
            return self.esplora_tx_json(rest, tip).map(|v| v.to_string());
        }
        Err(Error::Http(format!("404: no route for {path}")))
    }

    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        #[cfg(debug_assertions)]
        eprintln!("cb: http POST {path}");
        // Not debug-gated (U7) — see `HttpTransport::get_text`'s note.
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if path != "/tx" {
            return Err(Error::Http(format!("404: no POST route for {path}")));
        }
        self.broadcast(body.trim())
    }

    fn request_count(&self) -> u32 {
        self.request_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::client::ChainClient;
    use super::super::transport::{AnyTransport, TxLookupStatus};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ---- in-process mock Electrum server ----------------------------

    /// A canned answer: `Ok(result)` or `Err((code, message))` for one
    /// `(method, params)` call.
    type Responder = dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, (i64, String)> + Send;

    /// One TCP listener on 127.0.0.1:0, ONE background thread (per the
    /// plan's spec) accepting connections serially and answering each with
    /// `responder`. Newline-delimited JSON-RPC 2.0, tolerant of multiple
    /// requests per connection (our own client never sends more than one,
    /// but nothing about the wire format requires that).
    ///
    /// `calls` (`../../plans/PLAN-graffito-history-scaling.md` item 3) is a
    /// per-method call counter — the load-bearing assertion surface for
    /// "page-aware costs O(page), not O(history)": a test asserts the exact
    /// number of `transaction.get` (etc.) calls a route made, not merely
    /// that it returned the right JSON.
    struct MockElectrumServer {
        addr: std::net::SocketAddr,
        calls: std::sync::Arc<Mutex<HashMap<String, usize>>>,
    }

    impl MockElectrumServer {
        fn start<F>(responder: F) -> Self
        where
            F: Fn(&str, &serde_json::Value) -> Result<serde_json::Value, (i64, String)> + Send + 'static,
        {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock electrum server");
            let addr = listener.local_addr().expect("local_addr");
            let responder: Box<Responder> = Box::new(responder);
            let calls: std::sync::Arc<Mutex<HashMap<String, usize>>> = std::sync::Arc::new(Mutex::new(HashMap::new()));
            let calls_thread = calls.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                    let mut writer = stream;
                    let mut line = String::new();
                    loop {
                        line.clear();
                        let n = match reader.read_line(&mut line) {
                            Ok(n) => n,
                            Err(_) => break,
                        };
                        if n == 0 {
                            break;
                        }
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let req: serde_json::Value = match serde_json::from_str(trimmed) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
                        let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);
                        *calls_thread.lock().expect("mock call-counter mutex poisoned").entry(method.clone()).or_insert(0) += 1;
                        let resp = match responder(&method, &params) {
                            Ok(result) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}),
                            Err((code, message)) => {
                                serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
                            }
                        };
                        let mut out = serde_json::to_string(&resp).expect("serialize mock response");
                        out.push('\n');
                        if writer.write_all(out.as_bytes()).is_err() {
                            break;
                        }
                    }
                }
            });
            MockElectrumServer { addr, calls }
        }

        fn url(&self) -> String {
            format!("tcp://{}", self.addr)
        }

        /// Real call count for one JSON-RPC method so far — the item-3 call-
        /// count assertion surface.
        fn call_count(&self, method: &str) -> usize {
            self.calls.lock().expect("mock call-counter mutex poisoned").get(method).copied().unwrap_or(0)
        }
    }

    /// A minimal Core-shaped verbose tx: one output paying `address` (BTC
    /// float, converted to sats by the shared conversion), empty vin,
    /// `confirmations` as given (0 = mempool). Good enough for every test
    /// below — none needs a real second input.
    fn verbose_tx(confirmations: u64, address: &str, value_btc: f64, script_type: &str) -> serde_json::Value {
        serde_json::json!({
            "confirmations": confirmations,
            "blocktime": 1_700_000_000u64,
            "vin": [],
            "vout": [{
                "value": value_btc,
                "scriptPubKey": {"address": address, "type": script_type, "hex": "deadbeef"},
            }],
        })
    }

    /// An 80-byte block header hex with `nTime` (LE u32 at bytes 68..72)
    /// set to `time`; every other byte is zero (irrelevant to
    /// `block_time`).
    fn header_hex_with_time(time: u32) -> String {
        let mut bytes = vec![0u8; 80];
        bytes[68..72].copy_from_slice(&time.to_le_bytes());
        hex::encode(bytes)
    }

    /// A real, checksum-valid P2WPKH address (via notes-core's own bech32
    /// encoder, not a hand-copied string) — `scripthash_for_address` must
    /// actually parse it for these tests to exercise the real routes
    /// rather than the invalid-address short-circuit.
    fn test_addr() -> String {
        notes_core::address::p2wpkh_address(notes_core::Network::Mainnet, &[0x11; 20])
    }

    fn test_addr2() -> String {
        notes_core::address::p2wpkh_address(notes_core::Network::Mainnet, &[0x22; 20])
    }

    // ---- server.version/features/tip + genesis compare ---------------

    #[test]
    fn server_status_and_genesis_compare() {
        let genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let srv = MockElectrumServer::start(move |method, _params| match method {
            "server.version" => Ok(serde_json::json!(["electrs/0.10.10", "1.4"])),
            "server.features" => Ok(serde_json::json!({"genesis_hash": genesis, "hosts": {"tcp_port": 50001}})),
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 900_000, "hex": "00"})),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let status = t.server_status().unwrap();
        assert_eq!(status.server_version, "electrs/0.10.10");
        assert_eq!(status.protocol, "1.4");
        assert_eq!(status.tip_height, 900_000);
        assert_eq!(status.genesis_hash, genesis);

        assert!(network_matches_genesis(&status.genesis_hash, genesis));
        assert!(network_matches_genesis(&status.genesis_hash, &genesis.to_uppercase()));
        assert!(!network_matches_genesis(
            &status.genesis_hash,
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
        ));
    }

    // ---- address stats: U2 — get_history counts + get_balance sums,
    // ZERO transaction.get (`../../plans/PLAN-graffito-history-scaling.md`) --

    #[test]
    fn address_stats_uses_get_balance_not_transaction_get() {
        let srv = MockElectrumServer::start(|method, _params| match method {
            "blockchain.scripthash.get_history" => Ok(serde_json::json!([
                {"tx_hash": "tx1", "height": 100},
                {"tx_hash": "tx2", "height": 0},
            ])),
            "blockchain.scripthash.get_balance" => Ok(serde_json::json!({"confirmed": 50_000, "unconfirmed": 20_000})),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["chain_stats"]["tx_count"], 1);
        assert_eq!(v["chain_stats"]["funded_txo_sum"], 50_000);
        assert_eq!(v["chain_stats"]["spent_txo_sum"], 0);
        assert_eq!(v["mempool_stats"]["tx_count"], 1);
        assert_eq!(v["mempool_stats"]["funded_txo_sum"], 20_000);
        assert_eq!(v["mempool_stats"]["spent_txo_sum"], 0);
        assert_eq!(srv.call_count("blockchain.transaction.get"), 0, "U2: stats must never fetch a tx");
        assert_eq!(srv.call_count("blockchain.scripthash.get_balance"), 1);
        assert_eq!(srv.call_count("blockchain.scripthash.get_history"), 1);
    }

    /// Electrum's `get_balance.unconfirmed` can go negative ("spending
    /// confirmed funds via an unconfirmed tx") — must map to
    /// `mempool_spent`, never panic on the `as u64` cast or silently clamp
    /// to a wrong-but-passing zero on both sides.
    #[test]
    fn address_stats_negative_unconfirmed_balance_becomes_mempool_spent() {
        let srv = MockElectrumServer::start(|method, _params| match method {
            "blockchain.scripthash.get_history" => Ok(serde_json::json!([{"tx_hash": "tx1", "height": 0}])),
            "blockchain.scripthash.get_balance" => Ok(serde_json::json!({"confirmed": 0, "unconfirmed": -1500})),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["mempool_stats"]["funded_txo_sum"], 0);
        assert_eq!(v["mempool_stats"]["spent_txo_sum"], 1500);
        assert_eq!(srv.call_count("blockchain.transaction.get"), 0);
    }

    /// Prevout resolution (a mempool-style input with no inlined
    /// `prevout`) still works — it moved from the old stats fold into
    /// `txs_route`'s per-tx materialization, and still costs exactly one
    /// extra `transaction.get` for the parent, on top of the tx itself.
    #[test]
    fn txs_route_resolves_prevout_for_missing_inline_data() {
        let addr = test_addr();
        let addr_for_mock = addr.clone();
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 105, "hex": "00"})),
            "blockchain.scripthash.get_history" => Ok(serde_json::json!([{"tx_hash": "tx1", "height": 100}])),
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                match txid {
                    "tx1" => {
                        let mut tx = verbose_tx(6, &addr_for_mock, 0.0005, "witness_v0_keyhash");
                        // No inlined prevout — forces resolution via a
                        // parent fetch (like a mempool input's parent).
                        tx["vin"] = serde_json::json!([{"txid": "parent1", "vout": 0}]);
                        Ok(tx)
                    }
                    "parent1" => Ok(verbose_tx(50, &addr_for_mock, 0.0003, "witness_v0_keyhash")),
                    other => Err((2, format!("no such tx {other}"))),
                }
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}/txs", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let items = v.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["vin"][0]["prevout"]["scriptpubkey_address"], addr);
        assert_eq!(items[0]["vin"][0]["prevout"]["value"], 30_000);
        // tx1 itself, plus one parent fetch for the unresolved prevout.
        assert_eq!(srv.call_count("blockchain.transaction.get"), 2);
    }

    // ---- utxo route: block_time from the header -----------------------

    #[test]
    fn utxo_route_resolves_block_time_from_header() {
        let time = 1_700_000_000u32;
        let header = header_hex_with_time(time);
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.scripthash.listunspent" => Ok(serde_json::json!([
                {"tx_hash": "u1", "tx_pos": 0, "height": 50, "value": 12_345},
                {"tx_hash": "u2", "tx_pos": 1, "height": 0, "value": 6_789},
            ])),
            "blockchain.block.header" => {
                let h = params.as_array().and_then(|a| a.first()).and_then(|v| v.as_u64());
                assert_eq!(h, Some(50));
                Ok(serde_json::json!(header))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}/utxo", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let items = v.as_array().unwrap();
        assert_eq!(items.len(), 2);
        let u1 = &items[0];
        assert_eq!(u1["value"], 12_345);
        assert_eq!(u1["status"]["confirmed"], true);
        assert_eq!(u1["status"]["block_height"], 50);
        assert_eq!(u1["status"]["block_time"], time as u64);
        let u2 = &items[1];
        assert_eq!(u2["value"], 6_789);
        assert_eq!(u2["status"]["confirmed"], false);
        assert!(u2["status"].get("block_time").is_none());
    }

    // ---- txs route ordering + pagination -----------------------------

    #[test]
    fn txs_route_orders_mempool_first_then_descending_height() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 1_000, "hex": "00"})),
            "blockchain.scripthash.get_history" => Ok(serde_json::json!([
                {"tx_hash": "c_low", "height": 10},
                {"tx_hash": "mem1", "height": 0},
                {"tx_hash": "c_high", "height": 900},
                {"tx_hash": "mem2", "height": -1},
            ])),
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let confirmations = match txid {
                    "c_low" => 991,   // tip 1000 - height 10 + 1
                    "c_high" => 101,  // tip 1000 - height 900 + 1
                    _ => 0,
                };
                Ok(verbose_tx(confirmations, &test_addr(), 0.0001, "witness_v0_keyhash"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}/txs", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v.as_array().unwrap().iter().map(|t| t["txid"].as_str().unwrap()).collect();
        // Mempool entries first (server order preserved: mem1 then mem2),
        // then confirmed descending by height: c_high (900) before c_low (10).
        assert_eq!(ids, vec!["mem1", "mem2", "c_high", "c_low"]);
    }

    #[test]
    fn txs_chain_pagination_confirmed_only_caps_at_25() {
        let heights: Vec<i64> = (1..=30).collect(); // 30 confirmed txs, heights 1..=30
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 1_000, "hex": "00"})),
            "blockchain.scripthash.get_history" => {
                let entries: Vec<serde_json::Value> = heights
                    .iter()
                    .map(|h| serde_json::json!({"tx_hash": format!("c{h}"), "height": h}))
                    .chain(std::iter::once(serde_json::json!({"tx_hash": "mem1", "height": 0})))
                    .collect();
                Ok(serde_json::json!(entries))
            }
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let confirmations = if let Some(h) = txid.strip_prefix('c').and_then(|s| s.parse::<u64>().ok()) {
                    1_000 - h + 1
                } else {
                    0
                };
                Ok(verbose_tx(confirmations, &test_addr(), 0.0001, "witness_v0_keyhash"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();

        // Plain /txs: mempool + confirmed, capped at 50 (31 total here).
        let json = t.get_text(&format!("/address/{}/txs", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 31);

        // /txs/chain/:after — confirmed only, 25 max, newest-first (c30 first).
        let json = t.get_text(&format!("/address/{}/txs/chain/c30", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v.as_array().unwrap().iter().map(|t| t["txid"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 25);
        assert_eq!(ids[0], "c29");
        assert!(!ids.contains(&"mem1"));
    }

    // ---- page-aware pagination: exact call counts + byte-identity
    // (`../../plans/PLAN-graffito-history-scaling.md`, "Where the O(N) lives"
    // items 1 + 3) --------------------------------------------------------

    /// A FRESH mock (own port -> its own `TX_JSON_CACHE` key namespace, so
    /// no cross-test cache carryover) with 60 confirmed txs + 2 mempool
    /// txs: the plain `/address/:a/txs` page (cap 50, mempool-first) must
    /// cost EXACTLY 50 `transaction.get` calls — the page's own txs, never
    /// the address's full 62-tx history. This is the direct measurement
    /// behind the "406 calls for N=162" defect this unit fixes.
    #[test]
    fn txs_route_plain_page_costs_exactly_the_page_not_the_history() {
        let heights: Vec<i64> = (1..=60).collect();
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 1_000, "hex": "00"})),
            "blockchain.scripthash.get_history" => {
                let entries: Vec<serde_json::Value> = heights
                    .iter()
                    .map(|h| serde_json::json!({"tx_hash": format!("c{h}"), "height": h}))
                    .chain([
                        serde_json::json!({"tx_hash": "mem0", "height": 0}),
                        serde_json::json!({"tx_hash": "mem1", "height": -1}),
                    ])
                    .collect();
                Ok(serde_json::json!(entries))
            }
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let confirmations = if let Some(h) = txid.strip_prefix('c').and_then(|s| s.parse::<u64>().ok()) {
                    1_000 - h + 1
                } else {
                    0
                };
                Ok(verbose_tx(confirmations, &test_addr(), 0.0001, "witness_v0_keyhash"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text(&format!("/address/{}/txs", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // 62 in history (2 mempool + 60 confirmed), plain /txs caps at 50 —
        // mempool-first, so 2 mempool + 48 confirmed.
        assert_eq!(v.as_array().unwrap().len(), 50);
        assert_eq!(srv.call_count("blockchain.transaction.get"), 50, "must materialize only the 50-item page");
        assert_eq!(srv.call_count("blockchain.scripthash.get_history"), 1);
    }

    /// Same history, but a FRESH mock and a single `/txs/chain/:after`
    /// call (as if this were the very first page a caller ever requested
    /// past some earlier cursor) — must cost exactly 25 `transaction.get`,
    /// never the other 34 confirmed txs beyond the cursor.
    #[test]
    fn txs_route_chain_page_costs_exactly_25_not_the_rest() {
        let heights: Vec<i64> = (1..=60).collect();
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 1_000, "hex": "00"})),
            "blockchain.scripthash.get_history" => {
                let entries: Vec<serde_json::Value> =
                    heights.iter().map(|h| serde_json::json!({"tx_hash": format!("c{h}"), "height": h})).collect();
                Ok(serde_json::json!(entries))
            }
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let confirmations = if let Some(h) = txid.strip_prefix('c').and_then(|s| s.parse::<u64>().ok()) {
                    1_000 - h + 1
                } else {
                    0
                };
                Ok(verbose_tx(confirmations, &test_addr(), 0.0001, "witness_v0_keyhash"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        // Cursor = c60 (the newest confirmed txid) — the next page is
        // c59..c35 (25 items), never touching c34..c1.
        let json = t.get_text(&format!("/address/{}/txs/chain/c60", test_addr())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v.as_array().unwrap().iter().map(|t| t["txid"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 25);
        assert_eq!(ids[0], "c59");
        assert_eq!(ids[24], "c35");
        assert_eq!(srv.call_count("blockchain.transaction.get"), 25, "must materialize only the 25-item page");
    }

    /// The quiet-tick shape: `/address/:a` twice in a row costs exactly the
    /// same 2 RPCs (`get_history` + `get_balance`) EACH time — no growth
    /// with history size, and no `transaction.get` ever.
    #[test]
    fn address_stats_quiet_tick_costs_two_rpcs_per_call() {
        let srv = MockElectrumServer::start(|method, _params| match method {
            "blockchain.scripthash.get_history" => Ok(serde_json::json!([
                {"tx_hash": "tx1", "height": 100},
                {"tx_hash": "tx2", "height": 0},
            ])),
            "blockchain.scripthash.get_balance" => Ok(serde_json::json!({"confirmed": 50_000, "unconfirmed": 20_000})),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let _ = t.get_text(&format!("/address/{}", test_addr())).unwrap();
        assert_eq!(srv.call_count("blockchain.scripthash.get_history"), 1);
        assert_eq!(srv.call_count("blockchain.scripthash.get_balance"), 1);
        let _ = t.get_text(&format!("/address/{}", test_addr())).unwrap();
        assert_eq!(srv.call_count("blockchain.scripthash.get_history"), 2);
        assert_eq!(srv.call_count("blockchain.scripthash.get_balance"), 2);
        assert_eq!(srv.call_count("blockchain.transaction.get"), 0);
    }

    /// Item 1's core invariant: the page-aware production route
    /// ([`ElectrumTransport::txs_route`], reached via `get_text`) returns
    /// content BYTE-IDENTICAL to the OLD shape — fetch the address's ENTIRE
    /// lightweight order, materialize all of it, then run the same generic
    /// [`esplora_shape::paginate_txs`] the pre-fix code called directly —
    /// across a history with mempool entries, three txs sharing one block,
    /// and more than 50 confirmed txs, for both the plain `/txs` page and
    /// the `/txs/chain/:after` continuation.
    #[test]
    fn txs_route_page_aware_matches_old_full_fetch_shape() {
        let heights: Vec<i64> = (4..=63).collect(); // 60 confirmed at distinct heights
        let srv = MockElectrumServer::start(move |method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 1_000, "hex": "00"})),
            "blockchain.scripthash.get_history" => {
                let mut entries = vec![
                    serde_json::json!({"tx_hash": "mem0", "height": 0}),
                    serde_json::json!({"tx_hash": "mem1", "height": -1}),
                    serde_json::json!({"tx_hash": "blk0", "height": 3}),
                    serde_json::json!({"tx_hash": "blk1", "height": 3}),
                    serde_json::json!({"tx_hash": "blk2", "height": 3}),
                ];
                entries.extend(heights.iter().map(|h| serde_json::json!({"tx_hash": format!("c{h}"), "height": h})));
                Ok(serde_json::json!(entries))
            }
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let txid = arr.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
                let confirmations: i64 = if txid.starts_with("blk") {
                    1_000 - 3 + 1
                } else if let Some(h) = txid.strip_prefix('c').and_then(|s| s.parse::<i64>().ok()) {
                    1_000 - h + 1
                } else {
                    0
                };
                Ok(verbose_tx(confirmations as u64, &test_addr(), 0.0001, "witness_v0_keyhash"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();

        // NEW page-aware production path, via the real `get_text` routes.
        let page1_json = t.get_text(&format!("/address/{}/txs", test_addr())).unwrap();
        let page1: Vec<serde_json::Value> = serde_json::from_str(&page1_json).unwrap();
        let last1 = page1.last().unwrap()["txid"].as_str().unwrap().to_string();
        let page2_json = t.get_text(&format!("/address/{}/txs/chain/{last1}", test_addr())).unwrap();
        let page2: Vec<serde_json::Value> = serde_json::from_str(&page2_json).unwrap();

        // OLD full-fetch shape, reconstructed independently: materialize
        // the WHOLE lightweight order (every txid, not just a page), then
        // paginate the fully-materialized list — exactly what the pre-fix
        // `address_history_json` + `paginate_txs` call used to do.
        let scripthash = scripthash_for_address(&test_addr()).unwrap();
        let order = t.address_order(&scripthash).unwrap();
        let tip = t.tip_height().unwrap();
        let full: Vec<serde_json::Value> =
            order.iter().map(|(txid, _)| t.esplora_tx_json(txid, tip).unwrap()).collect();
        let old_page1 = esplora_shape::paginate_txs(full.clone(), None, false);
        let old_page2 = esplora_shape::paginate_txs(full, Some(&last1), true);

        assert_eq!(page1, old_page1, "page 1 (plain /txs) diverged from the full-fetch shape");
        assert_eq!(page2, old_page2, "page 2 (/txs/chain) diverged from the full-fetch shape");
        assert!(!page1.is_empty() && !page2.is_empty(), "sanity: both pages must be non-trivial");
    }

    // ---- /tx/:id conversion (block_height, nulldata->op_return) -------

    #[test]
    fn tx_conversion_computes_block_height_and_maps_nulldata() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 200, "hex": "00"})),
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let verbose = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                assert!(verbose);
                Ok(verbose_tx(11, &test_addr(), 0.00012345, "nulldata"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text("/tx/sometx").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["status"]["confirmed"], true);
        // tip 200, confirmations 11 -> block_height = 200 - 11 + 1 = 190.
        assert_eq!(v["status"]["block_height"], 190);
        assert_eq!(v["vout"][0]["scriptpubkey_type"], "op_return");
        assert_eq!(v["vout"][0]["value"], 12_345);
    }

    #[test]
    fn tx_hex_route() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.transaction.get" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let verbose = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(true);
                assert!(!verbose);
                Ok(serde_json::json!("deadbeef"))
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let hex_out = t.get_text("/tx/sometx/hex").unwrap();
        assert_eq!(hex_out, "deadbeef");
    }

    // ---- missing tx -> 404 -> TxLookupStatus::NotFound ----------------

    #[test]
    fn missing_tx_maps_to_404_and_not_found() {
        let srv = MockElectrumServer::start(|method, _params| match method {
            "blockchain.headers.subscribe" => Ok(serde_json::json!({"height": 500, "hex": "00"})),
            "blockchain.transaction.get" => Err((2, "No such mempool or blockchain transaction".to_string())),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let transport = AnyTransport::Electrum(ElectrumTransport::new(&srv.url()).unwrap());
        let err = transport.get_text("/tx/missing").unwrap_err();
        match err {
            Error::Http(msg) => assert!(msg.starts_with("404"), "expected 404 prefix, got {msg}"),
            other => panic!("expected Error::Http, got {other:?}"),
        }

        let client = ChainClient::new(transport, notes_core::Network::Mainnet);
        assert_eq!(client.tx_lookup_status("missing"), TxLookupStatus::NotFound);
    }

    // ---- broadcast success + reject -----------------------------------

    #[test]
    fn broadcast_success_and_reject() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.transaction.broadcast" => {
                let arr = params.as_array().cloned().unwrap_or_default();
                let hex = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                if hex == "goodhex" {
                    Ok(serde_json::json!("txid123"))
                } else {
                    Err((1, "min relay fee not met".to_string()))
                }
            }
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let txid = t.post_text("/tx", "goodhex".to_string()).unwrap();
        assert_eq!(txid, "txid123");

        let err = t.post_text("/tx", "badhex".to_string()).unwrap_err();
        match err {
            Error::Http(msg) => assert!(msg.starts_with("400:"), "expected 400 prefix, got {msg}"),
            other => panic!("expected Error::Http, got {other:?}"),
        }
    }

    // ---- fee tiers ------------------------------------------------------

    #[test]
    fn fee_tiers_convert_units_and_floor_and_fallback() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.estimatefee" => {
                let blocks = params.as_array().and_then(|a| a.first()).and_then(|v| v.as_u64()).unwrap_or(0);
                match blocks {
                    1 => Ok(serde_json::json!(0.00002)),  // 2 sat/vB
                    3 => Ok(serde_json::json!(-1)),        // unavailable -> fallback
                    6 => Ok(serde_json::json!(0.00001)),  // 1 sat/vB
                    144 => Ok(serde_json::json!(-1)),      // unavailable -> fallback
                    _ => Err((1, "bad blocks".into())),
                }
            }
            "blockchain.relayfee" => Ok(serde_json::json!(0.00001)), // 1 sat/vB floor
            "mempool.get_fee_histogram" => Ok(serde_json::json!([])), // present, empty -> quiet
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text("/v1/fees/recommended").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Loaded, quiet (0 vsize < BLOCK_VBYTES) mempool -> every tier
        // collapses to the floor (1).
        assert_eq!(v["fastestFee"], 1);
        assert_eq!(v["halfHourFee"], 1);
        assert_eq!(v["hourFee"], 1);
        assert_eq!(v["economyFee"], 1);
        assert_eq!(v["minimumFee"], 1);
    }

    #[test]
    fn fee_tiers_untouched_without_histogram() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.estimatefee" => {
                let blocks = params.as_array().and_then(|a| a.first()).and_then(|v| v.as_u64()).unwrap_or(0);
                match blocks {
                    1 => Ok(serde_json::json!(0.0005)),  // 50 sat/vB
                    3 => Ok(serde_json::json!(0.0004)),  // 40 sat/vB
                    6 => Ok(serde_json::json!(0.0003)),  // 30 sat/vB
                    144 => Ok(serde_json::json!(0.0002)), // 20 sat/vB
                    _ => Err((1, "bad blocks".into())),
                }
            }
            "blockchain.relayfee" => Ok(serde_json::json!(0.00001)),
            // Server errors on the histogram call -> no histogram at all.
            "mempool.get_fee_histogram" => Err((1, "not supported".into())),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text("/v1/fees/recommended").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["fastestFee"], 50);
        assert_eq!(v["halfHourFee"], 40);
        assert_eq!(v["hourFee"], 30);
        assert_eq!(v["economyFee"], 20);
    }

    #[test]
    fn fee_tiers_busy_mempool_leaves_estimates_alone() {
        let srv = MockElectrumServer::start(|method, params| match method {
            "blockchain.estimatefee" => {
                let blocks = params.as_array().and_then(|a| a.first()).and_then(|v| v.as_u64()).unwrap_or(0);
                match blocks {
                    1 => Ok(serde_json::json!(0.0005)),
                    3 => Ok(serde_json::json!(0.0004)),
                    6 => Ok(serde_json::json!(0.0003)),
                    144 => Ok(serde_json::json!(0.0002)),
                    _ => Err((1, "bad blocks".into())),
                }
            }
            "blockchain.relayfee" => Ok(serde_json::json!(0.00001)),
            // A big histogram (>= 1_000_000 vsize) means a busy mempool —
            // must not collapse the tiers.
            "mempool.get_fee_histogram" => Ok(serde_json::json!([[50, 2_000_000]])),
            other => Err((99, format!("unexpected method {other}"))),
        });
        let t = ElectrumTransport::new(&srv.url()).unwrap();
        let json = t.get_text("/v1/fees/recommended").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["fastestFee"], 50);
        assert_eq!(v["economyFee"], 20);
    }

    // ---- invalid address -> empty shapes, no network call -------------

    #[test]
    fn invalid_address_short_circuits_to_empty_shapes() {
        // Deliberately no server running at this port — a call here would
        // fail loudly, proving the invalid-address path never touches the
        // network at all.
        let t = ElectrumTransport::new("tcp://127.0.0.1:1").unwrap();
        let garbage = "not-a-real-address";

        let stats = t.get_text(&format!("/address/{garbage}")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&stats).unwrap();
        assert_eq!(v["chain_stats"]["tx_count"], 0);

        assert_eq!(t.get_text(&format!("/address/{garbage}/utxo")).unwrap(), "[]");
        assert_eq!(t.get_text(&format!("/address/{garbage}/txs")).unwrap(), "[]");
        assert_eq!(t.get_text(&format!("/address/{garbage}/txs/chain/abc")).unwrap(), "[]");
    }

    // ---- construction / prefix parsing --------------------------------

    #[test]
    fn new_parses_tcp_host_port() {
        let t = ElectrumTransport::new("tcp://127.0.0.1:50001").unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 50_001);
    }

    #[test]
    fn new_rejects_missing_tcp_prefix() {
        assert!(ElectrumTransport::new("127.0.0.1:50001").is_err());
        assert!(ElectrumTransport::new("ssl://127.0.0.1:50002").is_err());
    }

    #[test]
    fn new_rejects_missing_port() {
        assert!(ElectrumTransport::new("tcp://127.0.0.1").is_err());
    }

    #[test]
    fn scripthash_is_reversed_sha256_hex() {
        let sh = scripthash_for_address(&test_addr()).expect("valid address");
        assert_eq!(sh.len(), 64);
        assert!(sh.chars().all(|c| c.is_ascii_hexdigit()));
        // A different address must hash differently.
        let sh2 = scripthash_for_address(&test_addr2()).expect("valid address");
        assert_ne!(sh, sh2);
    }
}
