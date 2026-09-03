use notes_core::address::address_to_script_pubkey;
use notes_core::bundle::{BundleUtxo, FeeRates, OnchainTx, SyncBundle};
use notes_core::tx::op_return_payload;
use notes_core::Network;

use crate::Error;

use super::esplora::{AddrStats, EsploraAddrStats, EsploraTx, EsploraUtxo};
use super::transport::{Transport, TxLookupStatus};

/// mempool.space bases per network. Regtest has no public instance —
/// callers supply a custom base (companion/server.py shape) instead.
pub fn default_base(network: Network) -> Option<&'static str> {
    match network {
        Network::Mainnet => Some("https://mempool.space/api"),
        Network::Testnet4 => Some("https://mempool.space/testnet4/api"),
        Network::Signet => Some("https://mempool.space/signet/api"),
        Network::Regtest => None,
    }
}

/// Named Bitcoin-node presets for the Settings dropdown (each is an Esplora/
/// mempool-compatible API base). `Some(url)` is an explicit base; `None` means
/// "network default" — stored as `node_url = None` so the choice keeps
/// tracking [`default_base`]. A trailing "Custom…"
/// entry (raw URL text field) is a UI concern and not listed here, so an empty
/// list (regtest) still yields a one-option dropdown of just Custom.
pub fn node_presets(network: Network) -> Vec<(&'static str, Option<&'static str>)> {
    match network {
        // Blockstream's Esplora is mainnet + testnet3 only — not testnet4 or
        // signet — so it's offered on mainnet alone.
        Network::Mainnet => vec![
            ("mempool.space", None),
            ("Blockstream", Some("https://blockstream.info/api")),
        ],
        Network::Testnet4 => vec![("mempool.space", None)],
        Network::Signet => vec![("mempool.space", None)],
        Network::Regtest => vec![],
    }
}

/// Default block-explorer website base — everything before `/tx/{txid}`. None
/// where there's no public explorer (regtest).
pub fn default_explorer_base(network: Network) -> Option<&'static str> {
    match network {
        Network::Mainnet => Some("https://mempool.space"),
        Network::Testnet4 => Some("https://mempool.space/testnet4"),
        Network::Signet => Some("https://mempool.space/signet"),
        Network::Regtest => None,
    }
}

/// Named block-explorer presets for the Settings dropdown (website base, i.e.
/// everything before `/tx/{txid}`). Same `None = network default` convention
/// as [`node_presets`]; Custom is a UI concern appended by the caller.
pub fn explorer_presets(network: Network) -> Vec<(&'static str, Option<&'static str>)> {
    match network {
        Network::Mainnet => vec![
            ("mempool.space", None),
            ("Blockstream", Some("https://blockstream.info")),
        ],
        Network::Testnet4 => vec![("mempool.space", None)],
        Network::Signet => vec![("mempool.space", None)],
        Network::Regtest => vec![],
    }
}

/// Block-explorer tx permalink. `explorer` = the custom website base from
/// Settings (None = network default). Returns "" when no explorer is available
/// (regtest with no custom base set), matching the "no link" UI convention.
pub fn explorer_tx_url(explorer: Option<&str>, network: Network, txid: &str) -> String {
    match explorer
        .map(str::to_string)
        .or_else(|| default_explorer_base(network).map(String::from))
    {
        Some(base) => format!("{}/tx/{txid}", base.trim_end_matches('/')),
        None => String::new(),
    }
}

fn is_taproot_addr(addr: &str) -> bool {
    addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
}

fn parse_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))
}

pub struct ChainClient<T: Transport> {
    pub transport: T,
    pub network: Network,
}

impl<T: Transport> ChainClient<T> {
    pub fn new(transport: T, network: Network) -> Self {
        ChainClient { transport, network }
    }

    pub fn tip_height(&self) -> Result<u64, Error> {
        let text = self.transport.get_text("/blocks/tip/height")?;
        text.trim().parse().map_err(|_| Error::Json("tip height not a number".into()))
    }

    pub fn fee_rates(&self) -> Result<FeeRates, Error> {
        parse_json(&self.transport.get_text("/v1/fees/recommended")?)
    }

    pub fn btc_usd(&self) -> Result<Option<f64>, Error> {
        let v: serde_json::Value = parse_json(&self.transport.get_text("/v1/prices")?)?;
        Ok(v.get("USD").and_then(|u| u.as_f64()))
    }

    pub fn utxos(&self, address: &str) -> Result<Vec<BundleUtxo>, Error> {
        let raw: Vec<EsploraUtxo> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/utxo"))?)?;
        Ok(raw
            .into_iter()
            .map(|u| BundleUtxo {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                height: u.status.block_height.filter(|_| u.status.confirmed),
                // None = "the bundle's scanned address" (this call scans
                // exactly one address's own UTXOs) — notes-core's documented
                // default, byte-identical to pre-bump behavior.
                owner_address: None,
            })
            .collect())
    }

    /// Full history, newest-first, deduped — the chain-scan.js loop:
    /// first `/txs` (mempool + ≤25 confirmed), then paginate
    /// `/txs/chain?after_txid=` while pages return a full 25.
    pub fn full_history(&self, address: &str) -> Result<Vec<EsploraTx>, Error> {
        let mut txs: Vec<EsploraTx> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/txs"))?)?;
        let mut seen: std::collections::HashSet<String> =
            txs.iter().map(|t| t.txid.clone()).collect();
        // Esplora paginates with the last-seen txid as a PATH segment
        // (`/txs/chain/:txid`). The `?after_txid=` query form is ignored by
        // mempool.space (returns the same page → would loop forever), and the
        // regtest companion only reads the query form — so pagesize/param
        // handling differs by backend. Guard on it: keep paging while a page
        // brings NEW txids; stop as soon as one adds nothing (empty, or a
        // backend that ignored the cursor and echoed a page we've seen).
        let mut last = txs.iter().filter(|t| t.status.confirmed).last().map(|t| t.txid.clone());
        while let Some(after) = last.take() {
            let page: Vec<EsploraTx> = parse_json(&self.transport.get_text(&format!(
                "/address/{address}/txs/chain/{after}"
            ))?)?;
            let fresh: Vec<EsploraTx> =
                page.into_iter().filter(|t| seen.insert(t.txid.clone())).collect();
            if fresh.is_empty() {
                break;
            }
            last = fresh.iter().filter(|t| t.status.confirmed).last().map(|t| t.txid.clone());
            txs.extend(fresh);
        }
        Ok(txs)
    }

    /// Scan a funding source's receive + change chains (gap-limited) for
    /// spendable UTXOs. An address counts as "used" if it has ANY history
    /// (so a spent-then-empty address doesn't prematurely end the gap walk);
    /// UTXOs are collected for used addresses. Also reports the first unused
    /// change index for a new change output.
    ///
    /// Network-efficiency merge (2026-07-23): this single walk ALSO collects
    /// every used address (either chain) plus the first unused RECEIVE index
    /// — exactly what a separate `chain::discover_spending` gap walk used to
    /// report, at zero extra request cost (this loop already visits every
    /// address and already calls `full_history` to decide "used"). Callers
    /// that only need coins (the external funding-wallet paths) simply don't
    /// read the new fields; the spending-wallet refresh path
    /// (`spending_refresh_async`) now needs only ONE `scan_funding` call
    /// instead of `discover_spending` + `scan_funding`.
    pub fn scan_funding(
        &self,
        src: &crate::funding::FundingSource,
        gap: u32,
    ) -> Result<crate::funding::FundingScan, Error> {
        use crate::funding::{FundingScan, FundingUtxo};
        use crate::notebooks::SpendingAddr;
        let mut utxos = Vec::new();
        let mut used = Vec::new();
        let mut seen_addr = std::collections::HashSet::new();
        let mut next_change_index = 0u32;
        let mut next_receive_index = 0u32;
        let ranged = src.is_ranged();

        for chain in [0usize, 1usize] {
            let mut consecutive_unused = 0u32;
            let mut index = 0u32;
            let mut first_unused: Option<u32> = None;
            loop {
                let d = src.derive(chain, index)?;
                // Fixed (non-multipath) descriptors can share an address
                // across chains — stop the chain once we revisit one.
                if !seen_addr.insert(d.address.clone()) {
                    break;
                }
                let is_used = !self.full_history(&d.address)?.is_empty();
                if is_used {
                    consecutive_unused = 0;
                    used.push(SpendingAddr {
                        chain: chain as u32,
                        index,
                        address: d.address.clone(),
                        script_pubkey_hex: hex::encode(&d.spk),
                    });
                    for u in self.utxos(&d.address)? {
                        utxos.push(FundingUtxo {
                            txid: u.txid,
                            vout: u.vout,
                            value: u.value,
                            address: d.address.clone(),
                            chain,
                            index,
                            confirmed: u.height.is_some(),
                        });
                    }
                } else {
                    if first_unused.is_none() {
                        first_unused = Some(index);
                    }
                    consecutive_unused += 1;
                }
                index += 1;
                if !ranged || consecutive_unused >= gap {
                    break;
                }
                // Backstop against a backend that reports history for EVERY
                // address (a server-side filter bug once walked this loop
                // forever): no sane wallet needs more indexes than this.
                if index >= 10_000 {
                    return Err(Error::Funding(
                        "descriptor scan ran away (backend reports every address as used?)".into(),
                    ));
                }
            }
            let next = first_unused.unwrap_or(0);
            if chain == 1 {
                next_change_index = next;
            } else {
                next_receive_index = next;
            }
        }
        Ok(FundingScan { utxos, next_change_index, used, next_receive_index })
    }

    /// One-page probe for the notebook picker: has this address ANY
    /// on-chain history (first /txs page non-empty), and what do its
    /// UTXOs sum to right now? Deliberately cheap — two requests, no
    /// history paging.
    pub fn address_probe(&self, address: &str) -> Result<(bool, u64), Error> {
        let txs: Vec<EsploraTx> =
            parse_json(&self.transport.get_text(&format!("/address/{address}/txs"))?)?;
        let balance = self.utxos(address)?.iter().map(|u| u.value).sum();
        Ok((!txs.is_empty(), balance))
    }

    /// `GET /address/:a` — esplora's per-address chain + mempool stats,
    /// flattened into [`AddrStats`]. The "did anything change since last
    /// scan" fingerprint: a later wiring pass compares this against the
    /// last-persisted value to short-circuit a refresh when nothing moved.
    pub fn address_stats(&self, address: &str) -> Result<AddrStats, Error> {
        let raw: EsploraAddrStats =
            parse_json(&self.transport.get_text(&format!("/address/{address}"))?)?;
        Ok(AddrStats {
            chain_tx_count: raw.chain_stats.tx_count,
            chain_funded: raw.chain_stats.funded_txo_sum,
            chain_spent: raw.chain_stats.spent_txo_sum,
            mempool_tx_count: raw.mempool_stats.tx_count,
            mempool_funded: raw.mempool_stats.funded_txo_sum,
            mempool_spent: raw.mempool_stats.spent_txo_sum,
        })
    }

    /// Network-efficiency (build-39): a ONE-request "does this address have
    /// ANY on-chain history" check for [`discover_indexes`]'s gap walk —
    /// cheaper than [`Self::address_probe`], which costs two requests
    /// (`/txs` + `/utxo`) to also compute a balance discovery never needs.
    /// Reuses [`Self::address_stats`]'s single `/address/:a` fetch; "used"
    /// means any tx at all, confirmed or still sitting in the mempool.
    pub fn address_used(&self, address: &str) -> Result<bool, Error> {
        let stats = self.address_stats(address)?;
        Ok(stats.chain_tx_count > 0 || stats.mempool_tx_count > 0)
    }

    /// Broadcast raw tx hex; returns the txid mempool.space echoes back.
    ///
    /// One automatic retry, TRANSPORT-class failures only (`Error::Transport`
    /// — the request never reached a server: connection reset, timeout, a
    /// dying cellular link; the exact shape a weak-connection broadcast hits,
    /// see the "note saved, retry from here" Activity path). A real server
    /// RESPONSE with an error status (`Error::Http` — 400 bad tx, 409, ...)
    /// is reported immediately, no retry: retrying a rejected tx can't help,
    /// and could even mask the real reason for a caller that only sees the
    /// final error. Sleeping ~2s between attempts is fine to block on: this
    /// always runs on a worker `std::thread` (every call site here spawns
    /// one for exactly this reason), never the UI/event-loop thread. A
    /// retried broadcast re-POSTs the SAME raw bytes, so it's idempotent —
    /// same tx, same computed txid — a duplicate submission after a timeout
    /// is a harmless no-op server-side, not a double-spend.
    pub fn broadcast(&self, raw_hex: &str) -> Result<String, Error> {
        match self.transport.post_text("/tx", raw_hex.to_string()) {
            Ok(txid) => Ok(txid.trim().to_string()),
            Err(Error::Transport(_)) => {
                std::thread::sleep(std::time::Duration::from_secs(2));
                self.transport
                    .post_text("/tx", raw_hex.to_string())
                    .map(|txid| txid.trim().to_string())
            }
            Err(e) => Err(e),
        }
    }

    /// Raw hex of an on-chain/mempool tx — the keyless rebroadcast source.
    pub fn fetch_tx_hex(&self, txid: &str) -> Result<String, Error> {
        Ok(self.transport.get_text(&format!("/tx/{txid}/hex"))?.trim().to_string())
    }

    /// Task #14 (dropped-pending detection): unlike [`Self::fetch_tx_status`]
    /// — which collapses "definitely doesn't exist" and "transient network
    /// error" into the same `None` — this distinguishes them, since a
    /// dropped-tx verdict must NEVER be based on a mere hiccup. `NotFound`
    /// requires a definitive esplora 404 (what real mempool.space/esplora
    /// returns for an unknown txid); anything else — a non-404 error status,
    /// a connection failure, an unparseable body — is `Unknown` and must
    /// leave the caller's state untouched. (companion/server.py's regtest
    /// shim currently answers an unknown txid with a 400 carrying the raw
    /// bitcoind RPC error, not a 404 — so `NotFound` is reachable against
    /// real esplora/mempool.space but not through the local shim; see the
    /// e2e suite's dropped-tx leg, which therefore stays host-unit-test-only.)
    pub fn tx_lookup_status(&self, txid: &str) -> TxLookupStatus {
        match self.transport.get_text(&format!("/tx/{txid}")) {
            Ok(text) => match parse_json::<EsploraTx>(&text) {
                Ok(t) => TxLookupStatus::Found(t.status.confirmed),
                Err(_) => TxLookupStatus::Unknown,
            },
            Err(Error::Http(msg)) if msg.trim_start().starts_with("404") => TxLookupStatus::NotFound,
            Err(_) => TxLookupStatus::Unknown,
        }
    }

    /// Task #14: is this specific outpoint still sitting spendable at
    /// `address`? Backs the dropped-tx detector's second condition — a
    /// `NotFound` tx whose funding coin is STILL unspent means the
    /// broadcast never really took (as opposed to Orphaned, where the coin
    /// was spent by something else). Uses the same `/address/:a/utxo`
    /// endpoint `Self::utxos` already calls (esplora-shape already
    /// supported by both real esplora and companion/server.py — no new
    /// endpoint needed). `None` on a transport/parse failure — the caller
    /// must treat that as "don't know", not "unspent".
    pub fn outpoint_unspent(&self, address: &str, txid: &str, vout: u32) -> Option<bool> {
        let utxos = self.utxos(address).ok()?;
        Some(utxos.iter().any(|u| u.txid == txid && u.vout == vout))
    }

    /// Real confirmation status of a txid: Some(true) = in a block,
    /// Some(false) = in the mempool, None = unknown there (evicted /
    /// replaced / transport error). Feeds `Store::resolve_spend_statuses`.
    pub fn fetch_tx_status(&self, txid: &str) -> Option<bool> {
        let text = self.transport.get_text(&format!("/tx/{txid}")).ok()?;
        parse_json::<EsploraTx>(&text).ok().map(|t| t.status.confirmed)
    }

    /// A pending tx's inputs (as spendable outpoints with values) and
    /// outputs (spk bytes + value) — what a watch-mode RBF bump rebuilds
    /// from. Input values come from the vin prevout when the backend sends
    /// one, else from fetching the parent tx. `index_of` maps a prevout
    /// address to its owning notebook's receive index (a multi-notebook
    /// record's inputs span several leaves); unknown addresses stamp 0.
    pub fn fetch_tx_io(
        &self,
        txid: &str,
        index_of: impl Fn(&str) -> Option<u32>,
    ) -> Result<(Vec<crate::psbt_build::WatchCoin>, Vec<(Vec<u8>, u64)>, bool), Error> {
        let t: EsploraTx = parse_json(&self.transport.get_text(&format!("/tx/{txid}"))?)?;
        let mut coins = Vec::with_capacity(t.vin.len());
        for vin in &t.vin {
            let (ptxid, pvout) = match (&vin.txid, vin.vout) {
                (Some(x), Some(v)) => (x.clone(), v),
                _ => return Err(Error::Json("vin without outpoint".into())),
            };
            let (value, address) = match vin.prevout.as_ref() {
                Some(p) if p.value > 0 => (p.value, p.scriptpubkey_address.clone()),
                _ => {
                    // Backend sent no prevout value — read the parent tx.
                    let parent: EsploraTx =
                        parse_json(&self.transport.get_text(&format!("/tx/{ptxid}"))?)?;
                    let o = parent
                        .vout
                        .get(pvout as usize)
                        .ok_or_else(|| Error::Json("parent vout missing".into()))?;
                    (o.value, o.scriptpubkey_address.clone())
                }
            };
            let index = address.as_deref().and_then(&index_of).unwrap_or(0);
            // `index_of` only resolves NOTEBOOK (chain-0) addresses — a
            // change-including watch spend is non-bumpable by design (unit
            // 6), so this reconstruction never needs to represent chain 1.
            coins.push(crate::psbt_build::WatchCoin { txid: ptxid, vout: pvout, value, chain: 0, index });
        }
        let mut outputs = Vec::with_capacity(t.vout.len());
        for o in &t.vout {
            let spk = o
                .scriptpubkey
                .as_deref()
                .and_then(|h| hex::decode(h).ok())
                .ok_or_else(|| Error::Json("vout without script".into()))?;
            outputs.push((spk, o.value));
        }
        Ok((coins, outputs, t.status.confirmed))
    }

    /// Assemble the in-memory SyncBundle notes-core's extract_notes eats —
    /// identical shape to what the companion emits as QR/file bundles.
    pub fn build_bundle(
        &self,
        address: &str,
        since_height: Option<u64>,
    ) -> Result<SyncBundle, Error> {
        let tip_height = self.tip_height()?;
        // Network-efficiency (2026-07-23): fee_rates + btc_usd are only READ by
        // the fee-showing screens (compose/sweep/consolidate/bump), which now
        // fetch them lazily (`refresh_fees_price`, session-cached). A scan no
        // longer fetches either — the notes-core SyncBundle fields are required,
        // so they're filled with defaults the app's apply path ignores.
        let fee_rates = FeeRates::default();
        // Network-efficiency (2026-07-23): btc_usd was fetched on every scan
        // but only ever READ by the fee-showing screens (compose/sweep/
        // consolidate/bump) — those now fetch it lazily themselves
        // (`refresh_fees_price`, session-cached). The field stays for serde
        // compat; a scan never populates it.
        let btc_usd = None;
        let utxos = self.utxos(address)?;
        let history = self.full_history(address)?;

        let notes_onchain = history
            .iter()
            .filter(|t| match since_height {
                Some(h) => !t.status.confirmed || t.status.block_height.unwrap_or(u64::MAX) > h,
                None => true,
            })
            .filter_map(|t| classify_tx_net(t, address, self.network))
            .collect();

        Ok(SyncBundle {
            network: self.network.as_str().to_string(),
            full: since_height.is_none(),
            since_height,
            tip_height,
            bundle_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            fee_rates,
            btc_usd,
            utxos,
            notes_onchain,
            ..SyncBundle::default()
        })
    }
}

/// Receive-chain notebook gap discovery (rev-3 follow-up 2): probe the
/// account's receive indexes in order and return every index with ANY
/// on-chain history, stopping after `gap` consecutive never-used indexes.
/// Best-effort by design — a transport error (offline, backend down) stops
/// the walk and returns what was found so far, so a re-import without a
/// node simply discovers nothing. The caller `ensure_notebook`s each hit;
/// this function only reads the chain.
///
/// Network-efficiency (build-39): `known` lists receive indexes already
/// confirmed to be notebooks (e.g. the freshly-ensured notebook 0 on a seed
/// re-import) — the walk treats each as PRESENT with NO network request at
/// all (the "notebook-0 double-scan" fix; `refresh_async` already scanned
/// it moments earlier) and resets the gap counter, since a present notebook
/// is never a gap. Every other index costs exactly one request via
/// [`ChainClient::address_used`] instead of the old two-request
/// [`ChainClient::address_probe`].
pub fn discover_indexes<T: Transport>(
    client: &ChainClient<T>,
    material: &crate::identity::KeyMaterial,
    network: Network,
    account: u32,
    known: &[u32],
    gap: u32,
) -> Vec<u32> {
    let mut found = Vec::new();
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    while consecutive_unused < gap {
        if known.contains(&index) {
            // Already a confirmed notebook — present by construction, so no
            // request is needed. It IS still counted in `found` (it's a used
            // index): callers report `found=<total used> added=<newly created>`
            // and re-`ensure_notebook` idempotently, so a known index must
            // appear in `found` or the total under-counts (broke S5's
            // `found=3 added=2` when index 0 was skipped AND dropped).
            found.push(index);
            consecutive_unused = 0;
        } else {
            // A fixed (non-ranged) watch descriptor only derives index 0 —
            // the realize error ends the walk cleanly after that one probe.
            let Ok(ident) = crate::identity::realize(material, network, account, index) else {
                break;
            };
            match client.address_used(&ident.address) {
                Ok(true) => {
                    found.push(index);
                    consecutive_unused = 0;
                }
                Ok(false) => consecutive_unused += 1,
                Err(_) => break,
            }
        }
        index += 1;
        // Same runaway backstop as scan_funding: no sane wallet needs more.
        if index >= 10_000 {
            break;
        }
    }
    found
}

/// A spendable coin found gap-walking a keyed identity's taproot CHANGE
/// chain (`m/86'/{coin}'/{account}'/1/{index}`, [`crate::identity::realize_change`]),
/// via [`scan_change_chain`]. Mirrors [`crate::funding::FundingUtxo`]'s
/// shape (txid/vout/value/address/index/confirmed) plus the leaf's own
/// script pubkey, so folding these into the wallet's coin set later (a
/// later unit — see `../PLAN-chain-notes-app-taproot-change.md`) is a
/// straight field copy, not a translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeCoin {
    /// Chain-1 index — the same `index` [`crate::identity::realize_change`]
    /// took to derive this coin's address; needed later to derive its
    /// signing leaf.
    pub index: u32,
    pub address: String,
    pub script_pubkey_hex: String,
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

/// Gap-walk a keyed (Mnemonic/Xprv) identity's taproot CHANGE chain
/// (chain 1, [`crate::identity::realize_change`]) for spendable coins — the
/// change-chain sibling of [`discover_indexes`]'s receive-chain (chain 0)
/// walk, same "used" test ([`ChainClient::address_used`], one request) and
/// same gap-stop shape as [`discover_indexes`]/[`ChainClient::scan_funding`].
/// A used index's UTXOs are collected via [`ChainClient::utxos`].
///
/// `gap` is a parameter, not hardcoded here: the notebook-folding call site
/// (a later unit) uses gap=1 — external taproot wallets allocate change
/// sequentially, so a notebook's own change usage has no gaps — but a
/// future "scan deeper" action can pass more, same shallow/deep split
/// `scan_funding`'s two gap constants already establish for the spending
/// wallet.
///
/// WIF/hex/watch-only material has no change chain: `realize_change` errors
/// on the very first index for that material, so the walk ends immediately
/// with an empty `Vec` — not an `Err` — matching "a non-hierarchical
/// identity simply has nothing to fold in" rather than treating it as a
/// scan failure. A transport error (`address_used`/`utxos`) IS propagated,
/// same as `scan_funding`.
pub fn scan_change_chain<T: Transport>(
    client: &ChainClient<T>,
    material: &crate::identity::KeyMaterial,
    network: Network,
    account: u32,
    gap: u32,
) -> Result<Vec<ChangeCoin>, Error> {
    let mut coins = Vec::new();
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    loop {
        let ident = match crate::identity::realize_change(material, network, account, index) {
            Ok(i) => i,
            // Non-hierarchical/watch material — no change chain to walk.
            Err(_) => break,
        };
        if client.address_used(&ident.address)? {
            consecutive_unused = 0;
            let spk = notes_core::address::p2tr_script_pubkey(&ident.output_x());
            for u in client.utxos(&ident.address)? {
                coins.push(ChangeCoin {
                    index,
                    address: ident.address.clone(),
                    script_pubkey_hex: hex::encode(&spk),
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                    confirmed: u.height.is_some(),
                });
            }
        } else {
            consecutive_unused += 1;
        }
        index += 1;
        if consecutive_unused >= gap {
            break;
        }
        // Same runaway backstop as scan_funding/discover_indexes: no sane
        // wallet needs more indexes than this.
        if index >= 10_000 {
            break;
        }
    }
    Ok(coins)
}

/// Watch-only sibling of [`scan_change_chain`] (taproot change-chain unit
/// 6): gap-walk a WATCH identity's account's taproot CHANGE chain (chain 1
/// of its `tr(.../<0;1>/*)` descriptor, [`crate::funding::FundingSource::derive`])
/// for spendable coins — `realize_change` (unit 1) errors on Xpub material,
/// so a watch identity's change chain must come from the descriptor's own
/// ranged `<0;1>` multipath instead. Same "used" test
/// ([`ChainClient::address_used`], one request), same gap-stop shape, and
/// the SAME `ChangeCoin` return type as `scan_change_chain` — folding these
/// into `State.change_coins` is identical for both identity kinds.
///
/// A FIXED (non-ranged) descriptor — a bare single key with no `*`
/// wildcard, which only derives index 0 — has no change chain either:
/// [`crate::funding::FundingSource::is_ranged`] gates the walk, so it
/// returns an empty `Vec` immediately, matching `scan_change_chain`'s own
/// "nothing to walk" shape for non-hierarchical keyed material rather than
/// treating it as a scan failure.
pub fn scan_change_chain_watch<T: Transport>(
    client: &ChainClient<T>,
    source: &crate::funding::FundingSource,
    gap: u32,
) -> Result<Vec<ChangeCoin>, Error> {
    let mut coins = Vec::new();
    if !source.is_ranged() {
        return Ok(coins);
    }
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    loop {
        let d = source.derive(1, index)?;
        if client.address_used(&d.address)? {
            consecutive_unused = 0;
            for u in client.utxos(&d.address)? {
                coins.push(ChangeCoin {
                    index,
                    address: d.address.clone(),
                    script_pubkey_hex: hex::encode(&d.spk),
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                    confirmed: u.height.is_some(),
                });
            }
        } else {
            consecutive_unused += 1;
        }
        index += 1;
        if consecutive_unused >= gap {
            break;
        }
        // Same runaway backstop as scan_change_chain/scan_funding.
        if index >= 10_000 {
            break;
        }
    }
    Ok(coins)
}

/// Spending-wallet analog of [`discover_indexes`] (funding-unification
/// M2): probe BOTH chains of the wallet's BIP-84 branch — receive (0) and
/// change (1) — for on-chain history, stopping each chain after `gap`
/// consecutive never-used indexes (the same rule `discover_indexes` and
/// `scan_funding` use). Returns every address found used (for the store's
/// persisted list and self-spk set, via `Store::spending_apply_discovery`)
/// plus each chain's next-unused index. Best-effort like `discover_indexes`:
/// a transport error stops the walk and returns what was found so far, so a
/// words-only restore without a node simply discovers nothing yet.
pub fn discover_spending<T: Transport>(
    client: &ChainClient<T>,
    source: &crate::funding::FundingSource,
    gap: u32,
) -> (Vec<crate::notebooks::SpendingAddr>, u32, u32) {
    let mut used = Vec::new();
    let mut next_receive = 0u32;
    let mut next_change = 0u32;
    for chain in [0usize, 1usize] {
        let mut consecutive_unused = 0u32;
        let mut index = 0u32;
        let mut first_unused: Option<u32> = None;
        let mut transport_error = false;
        loop {
            let Ok(d) = source.derive(chain, index) else { break };
            match client.address_probe(&d.address) {
                Ok((true, _)) => {
                    used.push(crate::notebooks::SpendingAddr {
                        chain: chain as u32,
                        index,
                        address: d.address.clone(),
                        script_pubkey_hex: hex::encode(&d.spk),
                    });
                    consecutive_unused = 0;
                }
                Ok((false, _)) => {
                    if first_unused.is_none() {
                        first_unused = Some(index);
                    }
                    consecutive_unused += 1;
                }
                Err(_) => {
                    transport_error = true;
                    break;
                }
            }
            index += 1;
            // Same runaway backstop as scan_funding/discover_indexes.
            if consecutive_unused >= gap || index >= 10_000 {
                break;
            }
        }
        let next = first_unused.unwrap_or(0);
        if chain == 0 {
            next_receive = next;
        } else {
            next_change = next;
        }
        if transport_error {
            break;
        }
    }
    (used, next_receive, next_change)
}

/// tx → OnchainTx iff it carries ≥1 OP_RETURN payload. Classification
/// rules mirror chain-scan.js; payload parsing is notes-core's own.
/// Kept exactly as shipped (no `input_prevout_spks`) — additive sibling is
/// [`classify_tx_net`], which also needs a network to decode addresses
/// that arrive with no raw script hex (the regtest server.py shape).
pub fn classify_tx(tx: &EsploraTx, address: &str) -> Option<OnchainTx> {
    classify_tx_inner(tx, address, None)
}

/// [`classify_tx`] plus `input_prevout_spks` (funding-unification M2's
/// self-spk-SET ownership rule): every input's raw prevout scriptPubKey,
/// hex-encoded. Uses the raw `scriptpubkey` hex when the backend sends one
/// (real esplora); when it sends only `scriptpubkey_address` (the regtest
/// server.py shape — see the module-level gotcha), the spk is derived from
/// the address instead of left empty.
pub fn classify_tx_net(tx: &EsploraTx, address: &str, network: Network) -> Option<OnchainTx> {
    classify_tx_inner(tx, address, Some(network))
}

fn classify_tx_inner(tx: &EsploraTx, address: &str, network: Option<Network>) -> Option<OnchainTx> {
    let payloads: Vec<String> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() == Some("op_return"))
        .filter_map(|o| {
            let script = hex::decode(o.scriptpubkey.as_deref()?).ok()?;
            op_return_payload(&script).map(hex::encode)
        })
        .collect();
    if payloads.is_empty() {
        return None;
    }

    let spends_from_self = tx
        .vin
        .iter()
        .any(|i| i.prevout.as_ref().and_then(|p| p.scriptpubkey_address.as_deref()) == Some(address));
    let pays_self = tx.vout.iter().any(|o| o.scriptpubkey_address.as_deref() == Some(address));

    // PLAN-pnte-redesign.md: the tx's FIRST input's prevout — display-order
    // `"<txid>:<vout>"`, matching notes-core's `bundle::format_outpoint`
    // convention. This is the outpoint every private body's AAD binds
    // (self-note or directed), so decrypting one requires it. Esplora and
    // server.py both carry `vin[i].txid`/`.vout` on every input regardless
    // of whether the prevout itself resolved, so this needs no `prevout`
    // lookup and degrades to `None` only when the tx somehow has zero
    // inputs (never true for a real signed tx).
    let first_input_outpoint =
        tx.vin.first().and_then(|i| Some(format!("{}:{}", i.txid.as_deref()?, i.vout?)));

    // FROZEN: prefer the first TAPROOT input prevout address — this is the
    // sender rule notes-core/contacts/reply-target logic keys off, since a
    // taproot address is the one that can double as a Graffito identity.
    // Do not change the taproot-first preference.
    //
    // DISPLAY-ONLY fallback: when the tx has no taproot input at all (e.g.
    // funded purely from a native-segwit P2WPKH wallet), fall back to the
    // first input prevout address of ANY type, just so the UI can name the
    // funder instead of bucketing the note under an anonymous "unknown"
    // sender row. This never feeds `author_candidates` (below, taproot-only)
    // or any ECDH/crypto path — it's scanner display metadata only, and it
    // only fires when the taproot search above finds nothing.
    let input_addrs_any: Vec<&str> = tx
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter_map(|p| p.scriptpubkey_address.as_deref())
        .collect();
    let sender = input_addrs_any
        .iter()
        .find(|a| is_taproot_addr(a))
        .or_else(|| input_addrs_any.first())
        .map(|a| a.to_string());

    let externals: Vec<&str> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() != Some("op_return"))
        .filter_map(|o| o.scriptpubkey_address.as_deref())
        .filter(|a| *a != address)
        .collect();
    let recipient = externals
        .iter()
        .find(|a| is_taproot_addr(a))
        .or(externals.first())
        .map(|a| a.to_string());

    // Every taproot address in the tx (input prevouts AND outputs) except our
    // own — candidate authors for a received directed-private note. Under
    // external funding the author's key rides on a dust-to-self output, not the
    // spending input, so the decoder tries each of these (see notes-core).
    let mut author_candidates: Vec<String> = Vec::new();
    let input_addrs = tx
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter_map(|p| p.scriptpubkey_address.as_deref());
    let output_addrs = tx.vout.iter().filter_map(|o| o.scriptpubkey_address.as_deref());
    for a in input_addrs.chain(output_addrs) {
        if is_taproot_addr(a) && a != address && !author_candidates.iter().any(|c| c == a) {
            author_candidates.push(a.to_string());
        }
    }

    // Raw prevout spks for the self-spk-SET ownership rule (funding-
    // unification M2): prefer the raw hex esplora sends; fall back to
    // decoding `scriptpubkey_address` (the regtest server.py shape, which
    // carries no script hex at all — the module-level gotcha). `None`
    // network (the legacy `classify_tx` entry point) leaves this empty,
    // matching the pre-M2 behavior byte-for-byte.
    let input_prevout_spks: Vec<String> = match network {
        Some(net) => tx
            .vin
            .iter()
            .filter_map(|i| {
                let p = i.prevout.as_ref()?;
                if let Some(hex) = p.scriptpubkey.as_deref().filter(|h| !h.is_empty()) {
                    Some(hex.to_string())
                } else {
                    let addr = p.scriptpubkey_address.as_deref()?;
                    address_to_script_pubkey(net, addr).ok().map(|spk| hex::encode(&spk))
                }
            })
            .collect(),
        None => Vec::new(),
    };

    // Addresses of every NON-OP_RETURN output, in ascending vout order
    // (multi-recipient directed notes, FLAG_MULTI: notes-core's decoder
    // slices `output_addrs[0..count]` as the recipient list — recipients
    // precede change by construction). Skips an output whose script
    // doesn't decode to an address (never happens for our own P2TR/P2WPKH
    // outputs; notes-core degrades gracefully — never crashes — if it
    // ever did).
    let output_addrs: Vec<String> = tx
        .vout
        .iter()
        .filter(|o| o.scriptpubkey_type.as_deref() != Some("op_return"))
        .filter_map(|o| o.scriptpubkey_address.clone())
        .collect();

    Some(OnchainTx {
        txid: tx.txid.clone(),
        height: tx.status.block_height.filter(|_| tx.status.confirmed),
        blocktime: tx.status.block_time.filter(|_| tx.status.confirmed),
        spends_from_self,
        payloads,
        pays_self,
        sender: if spends_from_self { None } else { sender },
        author_candidates,
        // Unconditional: ownership is no longer equivalent to
        // spends_from_self (a spending-wallet- or externally-funded own
        // note spends other inputs), and the sender needs this field to
        // re-derive its own directed-private DM key on rescan. notes-core
        // surfaces it only for directed notes (the envelope flag), so a
        // self-note's "first non-self output" (its change) stays hidden.
        recipient,
        input_prevout_spks,
        output_addrs,
        first_input_outpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{parse_key_material, realize, KeyMaterial};
    use super::super::core_rpc::CoreRpcTransport;

    // Official BIP-86 account xpub (m/86'/0'/0') — imports as ranged watch
    // material, so discovery walks its real receive chain deterministically.
    const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    fn material() -> KeyMaterial {
        parse_key_material(BIP86_ACCT_XPUB, Network::Mainnet).unwrap()
    }

    fn addr(i: u32) -> String {
        realize(&material(), Network::Mainnet, 0, i).unwrap().address
    }

    /// Canned esplora for address probes: history/utxos only at the listed
    /// addresses; `fail` simulates an offline backend. Also answers the
    /// plain `/address/:a` stats endpoint (`address_used`/`address_stats`)
    /// with a one-tx-or-zero chain_stats shape, matching the same `used`
    /// list — so `discover_indexes`'s one-request check exercises the same
    /// fixtures the old two-request `address_probe` tests did.
    struct ProbeTransport {
        used: Vec<String>,
        fail: bool,
    }

    impl Transport for ProbeTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            if self.fail {
                return Err(Error::Http("offline".into()));
            }
            let used = self.used.iter().any(|a| path.contains(a.as_str()));
            if path.contains("/utxo") {
                Ok(if used {
                    r#"[{"txid":"aa","vout":0,"value":700,"status":{"confirmed":true,"block_height":9,"block_time":1}}]"#.into()
                } else {
                    "[]".into()
                })
            } else if path.contains("/txs") {
                Ok(if used {
                    r#"[{"txid":"aa","vin":[],"vout":[],"status":{"confirmed":true,"block_height":9,"block_time":1}}]"#.into()
                } else {
                    "[]".into()
                })
            } else {
                // Plain `/address/:a` stats endpoint.
                Ok(format!(
                    r#"{{"chain_stats":{{"tx_count":{},"funded_txo_sum":0,"spent_txo_sum":0}},"mempool_stats":{{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}}}"#,
                    if used { 1 } else { 0 }
                ))
            }
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("probes never POST")
        }
    }

    #[test]
    fn discovery_finds_used_indexes_past_holes() {
        // Indexes 0 and 2 used, 1 is a hole — the gap walk must continue
        // past it and only stop after `gap` consecutive unused indexes.
        // known=&[] here: same result the old two-request address_probe
        // walk produced, now via the one-request address_used check.
        let client = ChainClient::new(
            ProbeTransport { used: vec![addr(0), addr(2)], fail: false },
            Network::Mainnet,
        );
        assert_eq!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5), vec![0, 2]);
    }

    #[test]
    fn discovery_on_fresh_seed_is_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5).is_empty());
    }

    #[test]
    fn discovery_offline_is_best_effort_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![addr(0)], fail: true }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, &[], 5).is_empty());
    }

    /// Same as `ProbeTransport` but records every path fetched, so a test
    /// can prove `known` indexes are skipped with NO request at all — the
    /// "notebook-0 double-scan" fix's core guarantee.
    struct LoggingProbeTransport {
        used: Vec<String>,
        log: std::cell::RefCell<Vec<String>>,
    }

    impl Transport for LoggingProbeTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            self.log.borrow_mut().push(path.to_string());
            let used = self.used.iter().any(|a| path.contains(a.as_str()));
            Ok(format!(
                r#"{{"chain_stats":{{"tx_count":{},"funded_txo_sum":0,"spent_txo_sum":0}},"mempool_stats":{{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}}}"#,
                if used { 1 } else { 0 }
            ))
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("probes never POST")
        }
    }

    #[test]
    fn discovery_skips_known_index_with_no_request() {
        // known=&[0]: index 0 must NOT be probed at all — yet the walk
        // still finds the higher used index (2) and the gap still
        // terminates correctly (index 0 being "present" resets the gap
        // counter, same as if it had been probed and found used).
        let a0 = addr(0);
        let transport =
            LoggingProbeTransport { used: vec![addr(2)], log: std::cell::RefCell::new(Vec::new()) };
        let client = ChainClient::new(transport, Network::Mainnet);
        let found = discover_indexes(&client, &material(), Network::Mainnet, 0, &[0], 5);
        // found INCLUDES the known index 0 (a used notebook — counted so the
        // caller's found=total/added=new stays right) plus the discovered 2 —
        // but index 0 was NOT probed (asserted below).
        assert_eq!(found, vec![0, 2]);
        let log = client.transport.log.borrow();
        assert!(
            !log.iter().any(|p| p.contains(&a0)),
            "index 0 must never be requested when it's already `known`: {log:?}"
        );
    }

    #[test]
    fn discovery_fresh_wallet_with_known_zero_terminates_empty() {
        // A fully-fresh wallet (nothing used anywhere) with known=&[0]:
        // index 0 is skipped (no request, but doesn't count toward the
        // gap), then the walk probes 1..=gap and finds nothing used —
        // `found` stays empty since a known index is never added to it.
        let transport =
            LoggingProbeTransport { used: vec![], log: std::cell::RefCell::new(Vec::new()) };
        let client = ChainClient::new(transport, Network::Mainnet);
        let found = discover_indexes(&client, &material(), Network::Mainnet, 0, &[0], 5);
        // Only the known index 0 is in `found` (counted, not probed); nothing
        // else on-chain, so no higher index is discovered.
        assert_eq!(found, vec![0]);
        let a0 = addr(0);
        let log = client.transport.log.borrow();
        assert!(!log.iter().any(|p| p.contains(&a0)), "index 0 must never be requested: {log:?}");
        // Exactly `gap` (5) requests — indexes 1..=5 — one per unused probe.
        assert_eq!(log.len(), 5);
    }

    /// Canned /tx/{txid}: two inputs with prevout addresses, one output.
    struct TxIoTransport;

    impl Transport for TxIoTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            assert!(path.starts_with("/tx/"), "unexpected fetch: {path}");
            Ok(r#"{"txid":"cc",
                "vin":[
                  {"txid":"aa","vout":0,"prevout":{"scriptpubkey_address":"bcrt1p-three","value":1000}},
                  {"txid":"bb","vout":1,"prevout":{"scriptpubkey_address":"bcrt1p-unknown","value":2000}}],
                "vout":[{"scriptpubkey":"51","value":2500}],
                "status":{"confirmed":false}}"#
                .into())
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!()
        }
    }

    #[test]
    fn fetch_tx_io_stamps_notebook_indexes_by_address() {
        let client = ChainClient::new(TxIoTransport, Network::Regtest);
        let (coins, outputs, confirmed) = client
            .fetch_tx_io("cc", |a| (a == "bcrt1p-three").then_some(3))
            .unwrap();
        assert!(!confirmed);
        assert_eq!(coins.len(), 2);
        assert_eq!((coins[0].index, coins[0].value), (3, 1000));
        // Unknown address (not one of our notebooks) stamps index 0.
        assert_eq!((coins[1].index, coins[1].value), (0, 2000));
        assert_eq!(outputs, vec![(vec![0x51], 2500)]);
    }

    const SPENDING_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                      abandon abandon abandon abandon about";

    #[test]
    fn discover_spending_finds_both_chains_past_holes() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r2 = src.derive(0, 2).unwrap().address; // index 1 is a hole
        let c0 = src.derive(1, 0).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r2.clone(), c0.clone()], fail: false },
            Network::Mainnet,
        );
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);

        assert_eq!(used.iter().filter(|a| a.chain == 0).count(), 2);
        assert!(used.iter().any(|a| a.chain == 0 && a.index == 0 && a.address == r0));
        assert!(used.iter().any(|a| a.chain == 0 && a.index == 2 && a.address == r2));
        // First unused receive index is the hole at 1 (same "first unused,
        // holes don't count as the frontier" rule scan_funding uses).
        assert_eq!(next_receive, 1);
        assert_eq!(used.iter().filter(|a| a.chain == 1).count(), 1);
        assert_eq!(next_change, 1);
        for a in &used {
            assert!(hex::decode(&a.script_pubkey_hex).is_ok(), "spk must be valid hex");
        }
    }

    #[test]
    fn discover_spending_on_fresh_wallet_is_empty() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);
        assert!(used.is_empty());
        assert_eq!(next_receive, 0);
        assert_eq!(next_change, 0);
    }

    #[test]
    fn discover_spending_offline_is_best_effort() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let client = ChainClient::new(ProbeTransport { used: vec![r0], fail: true }, Network::Mainnet);
        let (used, next_receive, next_change) = discover_spending(&client, &src, 5);
        assert!(used.is_empty());
        assert_eq!((next_receive, next_change), (0, 0));
    }

    /// Network-efficiency merge (2026-07-23), correctness proof #1: the
    /// extended `scan_funding`'s single walk must report the SAME used-
    /// address list + next-receive/next-change indexes that the OLD two-call
    /// shape (`discover_spending` + a plain `scan_funding`) produced — plus
    /// the same coins, since a missed coin is lost-funds visibility. Used at
    /// receive indexes {0,1} (a hole at neither) and change index 0.
    #[test]
    fn scan_funding_merge_matches_discover_spending() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r1 = src.derive(0, 1).unwrap().address;
        let c0 = src.derive(1, 0).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r1.clone(), c0.clone()], fail: false },
            Network::Mainnet,
        );

        let (disc_used, disc_next_receive, disc_next_change) = discover_spending(&client, &src, 20);
        let scan = client.scan_funding(&src, 20).unwrap();

        // Same used-address SET (chain, index, address, spk), order aside.
        let mut disc_keys: Vec<(u32, u32)> = disc_used.iter().map(|a| (a.chain, a.index)).collect();
        let mut scan_keys: Vec<(u32, u32)> = scan.used.iter().map(|a| (a.chain, a.index)).collect();
        disc_keys.sort();
        scan_keys.sort();
        assert_eq!(disc_keys, scan_keys, "used-address (chain,index) set must match exactly");
        for d in &disc_used {
            let s = scan
                .used
                .iter()
                .find(|a| a.chain == d.chain && a.index == d.index)
                .expect("every discover_spending hit must appear in the merged scan");
            assert_eq!(s.address, d.address);
            assert_eq!(s.script_pubkey_hex, d.script_pubkey_hex);
        }

        // Same next-unused indexes on both chains.
        assert_eq!(disc_next_receive, scan.next_receive_index);
        assert_eq!(disc_next_change, scan.next_change_index);

        // Same coins: one UTXO per used address (the ProbeTransport fixture's
        // fixed 700-sat coin), none missing/extra.
        assert_eq!(scan.utxos.len(), disc_used.len());
        for u in &scan.utxos {
            assert_eq!(u.value, 700);
        }
    }

    /// Correctness proof #2: the "shallow" gap the app's automatic scan now
    /// uses (3) catches sequential usage — indexes 0,1,2 used back-to-back,
    /// with three consecutive unused indexes after (3,4,5) ending the walk.
    #[test]
    fn scan_funding_shallow_gap3_catches_sequential_usage() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r0 = src.derive(0, 0).unwrap().address;
        let r1 = src.derive(0, 1).unwrap().address;
        let r2 = src.derive(0, 2).unwrap().address;
        let client = ChainClient::new(
            ProbeTransport { used: vec![r0.clone(), r1.clone(), r2.clone()], fail: false },
            Network::Mainnet,
        );
        let scan = client.scan_funding(&src, 3).unwrap();
        let mut receive_used: Vec<u32> =
            scan.used.iter().filter(|a| a.chain == 0).map(|a| a.index).collect();
        receive_used.sort();
        assert_eq!(receive_used, vec![0, 1, 2]);
        assert_eq!(scan.utxos.iter().filter(|u| u.chain == 0).count(), 3);
    }

    /// Correctness proof #3 (documents the shallow/deep tradeoff): usage at
    /// index 5 ONLY (0–4 all empty) is beyond a gap-3 walk's reach — it stops
    /// after 3 consecutive unused indexes (2,3,4) without ever reaching 5 —
    /// but a gap-20 walk (the manual "Scan for existing funds…" deep scan)
    /// finds it. This is exactly the gappy-externally-used-seed case the deep
    /// scan exists to cover.
    #[test]
    fn scan_funding_deep_gap20_catches_what_shallow_gap3_misses() {
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Mainnet).unwrap();
        let src = crate::spending::funding_source(&m, Network::Mainnet, 0).unwrap();
        let r5 = src.derive(0, 5).unwrap().address;
        let client =
            ChainClient::new(ProbeTransport { used: vec![r5.clone()], fail: false }, Network::Mainnet);

        let shallow = client.scan_funding(&src, 3).unwrap();
        assert!(shallow.used.is_empty(), "gap-3 must not reach index 5");
        assert!(shallow.utxos.is_empty());

        let deep = client.scan_funding(&src, 20).unwrap();
        assert!(deep.used.iter().any(|a| a.chain == 0 && a.index == 5 && a.address == r5));
        assert_eq!(deep.utxos.iter().filter(|u| u.chain == 0 && u.index == 5).count(), 1);
    }

    // --- scan_change_chain (taproot change-chain unit 2) ---------------

    const CHANGE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn change_addr(i: u32) -> String {
        crate::identity::realize_change(
            &parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap(),
            Network::Mainnet,
            0,
            i,
        )
        .unwrap()
        .address
    }

    /// Change-chain indexes 0 and 1 used (each with a UTXO via the
    /// `ProbeTransport` fixture's fixed 700-sat coin) — the walk must
    /// return exactly those two coins, each carrying the right chain-1
    /// `index`, its change address, and the fixture's value.
    #[test]
    fn scan_change_chain_finds_change_coins() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0), change_addr(1)], fail: false },
            Network::Mainnet,
        );

        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 5).unwrap();

        assert_eq!(coins.len(), 2, "one coin per used change index");
        let mut indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        indexes.sort();
        assert_eq!(indexes, vec![0, 1]);
        for c in &coins {
            assert_eq!(c.value, 700);
            assert!(c.confirmed);
            assert!(hex::decode(&c.script_pubkey_hex).is_ok(), "spk must be valid hex");
            assert_eq!(c.address, change_addr(c.index));
        }
    }

    /// Nothing used on the change chain — the walk stops after `gap`
    /// probes with an empty result (no panic, no runaway).
    #[test]
    fn scan_change_chain_stops_after_gap_on_fresh_wallet() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 3).unwrap();
        assert!(coins.is_empty());
    }

    /// Used at change indexes {0,2} (a hole at 1) — documents the
    /// notebook gap-1 tradeoff Sal chose (2026-07-23): gap>=2 reaches past
    /// the hole and finds both, but the shallow default gap=1 stops right
    /// after the hole and only finds index 0.
    #[test]
    fn scan_change_chain_gap_stops_the_walk() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let used = vec![change_addr(0), change_addr(2)];

        let client_deep =
            ChainClient::new(ProbeTransport { used: used.clone(), fail: false }, Network::Mainnet);
        let deep = scan_change_chain(&client_deep, &m, Network::Mainnet, 0, 2).unwrap();
        let mut deep_indexes: Vec<u32> = deep.iter().map(|c| c.index).collect();
        deep_indexes.sort();
        assert_eq!(deep_indexes, vec![0, 2], "gap>=2 must reach past the hole at 1");

        let client_shallow = ChainClient::new(ProbeTransport { used, fail: false }, Network::Mainnet);
        let shallow = scan_change_chain(&client_shallow, &m, Network::Mainnet, 0, 1).unwrap();
        let shallow_indexes: Vec<u32> = shallow.iter().map(|c| c.index).collect();
        assert_eq!(shallow_indexes, vec![0], "gap=1 (the notebook default) stops at the hole");
    }

    /// A returned coin's address must equal `realize_change`'s own output
    /// for that index — ties the scan to the verified derivation rather
    /// than some independent path that could silently drift from it.
    #[test]
    fn scan_change_chain_addresses_match_realize_change() {
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0)], fail: false },
            Network::Mainnet,
        );
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 3).unwrap();
        assert_eq!(coins.len(), 1);
        let expected =
            crate::identity::realize_change(&m, Network::Mainnet, 0, coins[0].index).unwrap();
        assert_eq!(coins[0].address, expected.address);
    }

    /// Non-hierarchical material (raw hex key) has no change chain —
    /// `realize_change` errors immediately, so the walk returns an empty
    /// result gracefully (no Err, no panic), never even reaching the
    /// transport (constructed with `fail: true` to prove no request is
    /// attempted).
    #[test]
    fn scan_change_chain_non_hierarchical_material_is_empty() {
        let m = KeyMaterial::Hex([7u8; 32]);
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: true }, Network::Mainnet);
        let coins = scan_change_chain(&client, &m, Network::Mainnet, 0, 5).unwrap();
        assert!(coins.is_empty());
    }

    // --- scan_change_chain_watch (taproot change-chain unit 6) ----------

    /// The account-level `tr([fp/86'/{coin}'/{account}']xpub/<0;1>/*)`
    /// descriptor for `CHANGE_MNEMONIC`'s seed — the SAME seed/network/
    /// account [`change_addr`] (above) uses, so a watch-only import of this
    /// seed sees the SAME chain-1 addresses as the keyed import.
    fn change_watch_source(network: Network, account: u32) -> crate::funding::FundingSource {
        use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        let mnemonic =
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, CHANGE_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(crate::derive::btc_network(network), &seed).unwrap();
        let coin = crate::derive::coin_type(network);
        let account_xpriv = master
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_hardened_idx(86).unwrap(),
                    ChildNumber::from_hardened_idx(coin).unwrap(),
                    ChildNumber::from_hardened_idx(account).unwrap(),
                ],
            )
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &account_xpriv);
        let fp = master.fingerprint(&secp);
        crate::funding::FundingSource::parse(
            &format!("tr([{fp}/86'/{coin}'/{account}']{xpub}/<0;1>/*)"),
            network,
        )
        .unwrap()
    }

    /// Money-critical parity (unit 6): a watch-only import of the SAME seed
    /// must see the SAME chain-1 change addresses a keyed import does — the
    /// descriptor's `<0;1>` multipath derivation and `realize_change`'s
    /// leaf derivation are two independent code paths that must agree, or a
    /// watch-only user's change coins would be invisible (or worse, an
    /// external signer would be handed the wrong key origin for them).
    #[test]
    fn watch_change_addr_matches_keyed_realize_change() {
        let src = change_watch_source(Network::Mainnet, 0);
        let m = parse_key_material(CHANGE_MNEMONIC, Network::Mainnet).unwrap();
        for j in [0u32, 1, 5, 41] {
            let watch = src.derive(1, j).unwrap();
            let keyed = crate::identity::realize_change(&m, Network::Mainnet, 0, j).unwrap();
            assert_eq!(watch.address, keyed.address, "index {j}: watch vs keyed address mismatch");
        }
    }

    /// [`scan_change_chain_watch`] finds the same coins [`scan_change_chain`]
    /// (the keyed walk) does, for the SAME seed/addresses — the watch-only
    /// scan sibling proven against the same `ProbeTransport` fixture unit 2
    /// already uses.
    #[test]
    fn scan_change_chain_watch_finds_coins() {
        let src = change_watch_source(Network::Mainnet, 0);
        let client = ChainClient::new(
            ProbeTransport { used: vec![change_addr(0), change_addr(1)], fail: false },
            Network::Mainnet,
        );
        let coins = scan_change_chain_watch(&client, &src, 5).unwrap();
        assert_eq!(coins.len(), 2, "one coin per used change index");
        let mut indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
        indexes.sort();
        assert_eq!(indexes, vec![0, 1]);
        for c in &coins {
            assert_eq!(c.value, 700);
            assert!(c.confirmed);
            assert!(hex::decode(&c.script_pubkey_hex).is_ok(), "spk must be valid hex");
            assert_eq!(c.address, change_addr(c.index));
        }
    }

    /// A fresh watch wallet (nothing used) stops after `gap` probes with an
    /// empty result — same shape as [`scan_change_chain_stops_after_gap_on_fresh_wallet`].
    #[test]
    fn scan_change_chain_watch_stops_after_gap_on_fresh_wallet() {
        let src = change_watch_source(Network::Mainnet, 0);
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        let coins = scan_change_chain_watch(&client, &src, 3).unwrap();
        assert!(coins.is_empty());
    }

    /// A FIXED (non-ranged, no `*` wildcard) descriptor has no change chain
    /// to walk — the same "nothing to walk" shape `scan_change_chain`
    /// returns for non-hierarchical keyed material, proven here with
    /// `fail: true` to confirm no request is even attempted.
    #[test]
    fn scan_change_chain_watch_fixed_descriptor_is_empty() {
        let src = change_watch_source(Network::Mainnet, 0);
        // A definite (index-fixed) descriptor is already a plain `tr(key)`
        // with no wildcard — re-parsing its own string form gives a FIXED
        // FundingSource (single key, `is_ranged() == false`).
        let fixed_desc = src.definite(0, 0).unwrap().to_string();
        let fixed_src = crate::funding::FundingSource::parse(&fixed_desc, Network::Mainnet).unwrap();
        assert!(!fixed_src.is_ranged());
        let client = ChainClient::new(ProbeTransport { used: vec![], fail: true }, Network::Mainnet);
        let coins = scan_change_chain_watch(&client, &fixed_src, 5).unwrap();
        assert!(coins.is_empty());
    }

    #[test]
    fn classify_tx_net_populates_input_prevout_spks_from_address_or_hex() {
        use notes_core::tx::op_return_script;
        let m = parse_key_material(SPENDING_MNEMONIC, Network::Regtest).unwrap();
        let key = crate::spending::derive_spending_key(&m, Network::Regtest, 0, 0, 0).unwrap();
        let payload_hex = hex::encode(op_return_script(b"hi"));
        let spk_hex = hex::encode(&key.script_pubkey);

        // Regtest server.py shape: only `scriptpubkey_address` on the
        // prevout, no raw script hex — the spk must be DERIVED from it.
        let json_addr_only = format!(
            r#"{{"txid":"t1","vin":[{{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"{}","value":1000}}}}],"vout":[{{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}}],"status":{{"confirmed":false}}}}"#,
            key.address
        );
        let tx: EsploraTx = serde_json::from_str(&json_addr_only).unwrap();
        let onchain = classify_tx_net(&tx, "not-our-address", Network::Regtest).unwrap();
        assert_eq!(onchain.input_prevout_spks, vec![spk_hex.clone()]);
        // The legacy no-network entry point stays empty — byte-identical
        // to pre-M2 behavior.
        assert!(classify_tx(&tx, "not-our-address").unwrap().input_prevout_spks.is_empty());

        // Real esplora shape: raw scriptpubkey hex present — used directly.
        let json_hex = format!(
            r#"{{"txid":"t2","vin":[{{"txid":"a","vout":0,"prevout":{{"scriptpubkey":"{spk_hex}","value":1000}}}}],"vout":[{{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}}],"status":{{"confirmed":false}}}}"#
        );
        let tx2: EsploraTx = serde_json::from_str(&json_hex).unwrap();
        let onchain2 = classify_tx_net(&tx2, "not-our-address", Network::Regtest).unwrap();
        assert_eq!(onchain2.input_prevout_spks, vec![spk_hex]);
    }

    // ---- Unit C: sender falls back to the first non-taproot input prevout
    // address when the tx has no taproot input at all (e.g. funded purely
    // from a native-segwit P2WPKH wallet) — display-only, so an "Unknown"
    // received note can show a real funder address instead. ----

    #[test]
    fn sender_falls_back_to_first_non_taproot_input() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1q-wpkh-funder","value":1000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender.as_deref(), Some("bcrt1q-wpkh-funder"));
    }

    #[test]
    fn sender_prefers_taproot_input_regardless_of_order() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // Taproot input is SECOND in vin order — proves the preference isn't
        // just "first input", it's "first taproot input" even when a
        // non-taproot input comes first.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1q-wpkh-funder","value":1000}}}},
                {{"txid":"b","vout":0,"prevout":{{"scriptpubkey_address":"bcrt1p-taproot-funder","value":2000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":2500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender.as_deref(), Some("bcrt1p-taproot-funder"));
    }

    #[test]
    fn sender_none_when_tx_spends_from_self() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // The tx spends OUR OWN address as an input — the return-site rule
        // (`sender: if spends_from_self { None } else { sender }`) must still
        // blank the sender, unaffected by the new fallback.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0,"prevout":{{"scriptpubkey_address":"our-address","value":1000}}}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender, None);
    }

    #[test]
    fn sender_none_when_no_resolvable_prevout_address() {
        use notes_core::tx::op_return_script;
        let payload_hex = hex::encode(op_return_script(b"hi"));
        // No inputs at all resolve to a prevout address (prevout missing
        // entirely) — must degrade to None, never panic.
        let json = format!(
            r#"{{"txid":"t1","vin":[
                {{"txid":"a","vout":0}}],
              "vout":[
                {{"scriptpubkey":"{payload_hex}","scriptpubkey_type":"op_return","value":0}},
                {{"scriptpubkey_address":"our-address","value":500}}],
              "status":{{"confirmed":false}}}}"#
        );
        let tx: EsploraTx = serde_json::from_str(&json).unwrap();
        let onchain = classify_tx(&tx, "our-address").unwrap();
        assert_eq!(onchain.sender, None);
    }

    // ---- task #14: dropped-pending detection — tx_lookup_status /
    // outpoint_unspent (the ChainClient half; the pure state machine that
    // consumes them, `store::resolve_dropped`, is tested in store.rs). ----

    /// Canned `/tx/:txid` transport: a 404 (real-esplora "definitely no
    /// such tx"), a non-404 error (transient), and a found tx, keyed by
    /// txid. `/address/:a/utxo` answers from a fixed outpoint list.
    struct TxLookupTransport {
        found_confirmed: Option<bool>, // Some(confirmed) for txid "found"
        utxos: Vec<(&'static str, u32)>, // (txid, vout) pairs deemed unspent
    }

    impl Transport for TxLookupTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            if path == "/tx/found" {
                let confirmed = self.found_confirmed.expect("found_confirmed must be set");
                return Ok(format!(
                    r#"{{"txid":"found","vin":[],"vout":[],"status":{{"confirmed":{confirmed}}}}}"#
                ));
            }
            if path == "/tx/missing" {
                return Err(Error::Http("404 Not Found: Transaction not found".into()));
            }
            if path == "/tx/flaky" {
                return Err(Error::Http("connection reset".into()));
            }
            if path == "/tx/bad-status" {
                // A non-404 HTTP error must NOT read as NotFound.
                return Err(Error::Http("500 Internal Server Error: oops".into()));
            }
            if path.starts_with("/address/") && path.ends_with("/utxo") {
                let items: Vec<String> = self
                    .utxos
                    .iter()
                    .map(|(t, v)| {
                        format!(
                            r#"{{"txid":"{t}","vout":{v},"value":1000,"status":{{"confirmed":true,"block_height":1}}}}"#
                        )
                    })
                    .collect();
                return Ok(format!("[{}]", items.join(",")));
            }
            Err(Error::Http(format!("unexpected path: {path}")))
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("dropped-detection never POSTs")
        }
    }

    #[test]
    fn tx_lookup_status_distinguishes_found_notfound_unknown() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: Some(true), utxos: vec![] },
            Network::Regtest,
        );
        assert_eq!(client.tx_lookup_status("found"), TxLookupStatus::Found(true));
        assert_eq!(client.tx_lookup_status("missing"), TxLookupStatus::NotFound);
        // A transport-level failure (no HTTP status at all) is Unknown, not
        // NotFound — a dropped verdict must never come from a network blip.
        assert_eq!(client.tx_lookup_status("flaky"), TxLookupStatus::Unknown);
        // A definite HTTP error that ISN'T a 404 is also Unknown, never
        // NotFound — only a real esplora 404 counts as definitive.
        assert_eq!(client.tx_lookup_status("bad-status"), TxLookupStatus::Unknown);
    }

    #[test]
    fn tx_lookup_status_found_reports_mempool_vs_confirmed() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: Some(false), utxos: vec![] },
            Network::Regtest,
        );
        assert_eq!(client.tx_lookup_status("found"), TxLookupStatus::Found(false));
    }

    #[test]
    fn outpoint_unspent_checks_the_address_utxo_set() {
        let client = ChainClient::new(
            TxLookupTransport { found_confirmed: None, utxos: vec![("aa", 0), ("bb", 1)] },
            Network::Regtest,
        );
        assert_eq!(client.outpoint_unspent("addr1", "aa", 0), Some(true));
        assert_eq!(client.outpoint_unspent("addr1", "aa", 1), Some(false));
        assert_eq!(client.outpoint_unspent("addr1", "cc", 0), Some(false));
    }

    // ---- broadcast: one retry, transport-class failures only ----

    /// Canned `/tx` POST transport whose first N attempts fail with a fixed
    /// error (transport- or response-shaped, caller's choice), then succeed
    /// — `attempts` counts every `post_text` call so tests can assert the
    /// retry fired exactly once (never more).
    struct BroadcastTransport {
        fail_first: std::cell::Cell<u32>,
        fail_err: Error,
        attempts: std::cell::Cell<u32>,
    }

    impl Transport for BroadcastTransport {
        fn get_text(&self, _path: &str) -> Result<String, Error> {
            unreachable!("broadcast never GETs")
        }
        fn post_text(&self, path: &str, _body: String) -> Result<String, Error> {
            assert_eq!(path, "/tx");
            self.attempts.set(self.attempts.get() + 1);
            let remaining = self.fail_first.get();
            if remaining > 0 {
                self.fail_first.set(remaining - 1);
                return Err(self.fail_err.clone());
            }
            Ok("deadbeef".into())
        }
    }

    #[test]
    fn broadcast_retries_once_after_a_transport_failure_then_succeeds() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(1),
            fail_err: Error::Transport("error sending request for url (...)".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        assert_eq!(client.broadcast("aabbcc").unwrap(), "deadbeef");
        assert_eq!(client.transport.attempts.get(), 2, "one retry after the transport failure");
    }

    #[test]
    fn broadcast_gives_up_after_two_transport_failures() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(99), // every attempt fails
            fail_err: Error::Transport("connection reset".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        let err = client.broadcast("aabbcc").unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
        assert_eq!(
            client.transport.attempts.get(),
            2,
            "exactly one retry, not an unbounded loop"
        );
    }

    #[test]
    fn broadcast_never_retries_a_server_rejection() {
        let transport = BroadcastTransport {
            fail_first: std::cell::Cell::new(99),
            fail_err: Error::Http("400 Bad Request: bad-txns-in-belowout".into()),
            attempts: std::cell::Cell::new(0),
        };
        let client = ChainClient::new(transport, Network::Testnet4);
        let err = client.broadcast("aabbcc").unwrap_err();
        assert!(matches!(err, Error::Http(_)));
        assert_eq!(
            client.transport.attempts.get(),
            1,
            "a real server response (even an error one) is reported immediately"
        );
    }

    // ---- address_stats: flattens esplora's nested chain/mempool shape ----

    struct AddrStatsTransport(&'static str);

    impl Transport for AddrStatsTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            assert!(path.starts_with("/address/"), "unexpected fetch: {path}");
            Ok(self.0.to_string())
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            unreachable!("address_stats never POSTs")
        }
    }

    #[test]
    fn address_stats_parses_nested_esplora_shape() {
        // Real-shaped esplora /address/:a response (extra fields present on
        // the wire — e.g. `address` itself — are ignored, not just absent).
        let json = r#"{
            "address": "tb1qdummy",
            "chain_stats": {
                "funded_txo_count": 3,
                "funded_txo_sum": 150000,
                "spent_txo_count": 1,
                "spent_txo_sum": 50000,
                "tx_count": 4
            },
            "mempool_stats": {
                "funded_txo_count": 1,
                "funded_txo_sum": 900,
                "spent_txo_count": 0,
                "spent_txo_sum": 0,
                "tx_count": 1
            }
        }"#;
        let client = ChainClient::new(AddrStatsTransport(json), Network::Testnet4);
        let stats = client.address_stats("tb1qdummy").unwrap();
        assert_eq!(
            stats,
            AddrStats {
                chain_tx_count: 4,
                chain_funded: 150000,
                chain_spent: 50000,
                mempool_tx_count: 1,
                mempool_funded: 900,
                mempool_spent: 0,
            }
        );
    }

    #[test]
    fn address_stats_tolerates_missing_stat_groups() {
        let client = ChainClient::new(AddrStatsTransport("{}"), Network::Testnet4);
        let stats = client.address_stats("tb1qdummy").unwrap();
        assert_eq!(
            stats,
            AddrStats {
                chain_tx_count: 0,
                chain_funded: 0,
                chain_spent: 0,
                mempool_tx_count: 0,
                mempool_funded: 0,
                mempool_spent: 0,
            }
        );
    }

    /// The `ChainClient::btc_usd()` layer above the transport must also see
    /// exactly this — an `Err`, not a fabricated `Ok(None)` or `Ok(Some(_))`
    /// — since `src/lib.rs`'s call sites degrade via `if let Ok(usd) = ...`
    /// and silently keep the PREVIOUS cached price on any `Err`. A Core
    /// backend must never look like a successful (if empty) price fetch.
    #[test]
    fn chain_client_btc_usd_surfaces_the_core_no_price_oracle_error() {
        let t = CoreRpcTransport::new("http://127.0.0.1:1", None).unwrap();
        let client = ChainClient::new(t, Network::Regtest);
        let err = client.btc_usd().unwrap_err();
        assert!(matches!(err, Error::Http(_)), "expected Error::Http, got {err:?}");
    }
}
