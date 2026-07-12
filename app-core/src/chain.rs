//! Esplora/mempool.space chain client → in-memory notes-core SyncBundle.
//!
//! Mirrors the companion's scan semantics exactly (chain-scan.js /
//! index.html in prime-chain-notes): full history = `/address/:a/txs`
//! then `/address/:a/txs/chain?after_txid=` while pages come back full
//! (25); a tx enters `notes_onchain` iff it carries ≥1 OP_RETURN payload;
//! `spends_from_self` = any input prevout is ours (the OWN-note rule),
//! `pays_self` = any output is ours, sender = first taproot input
//! prevout, recipient = first non-self non-OP_RETURN output (taproot
//! preferred). Payload extraction reuses notes-core's own script parser.
//!
//! The `Transport` trait isolates HTTP so tests inject canned JSON.

use notes_core::bundle::{BundleUtxo, FeeRates, OnchainTx, SyncBundle};
use notes_core::tx::op_return_payload;
use notes_core::Network;
use serde::Deserialize;

use crate::Error;

pub trait Transport {
    fn get_text(&self, path: &str) -> Result<String, Error>;
    fn post_text(&self, path: &str, body: String) -> Result<String, Error>;
}

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

pub struct HttpTransport {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpTransport {
    pub fn new(base: impl Into<String>) -> Self {
        HttpTransport {
            base: base.into(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("client config is static"),
        }
    }
}

impl Transport for HttpTransport {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        let resp = self
            .client
            .get(format!("{}{}", self.base, path))
            .send()
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Http(format!("{status}: {text}")));
        }
        Ok(text)
    }

    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        let resp = self
            .client
            .post(format!("{}{}", self.base, path))
            .body(body)
            .send()
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Http(format!("{status}: {text}")));
        }
        Ok(text)
    }
}

// ---- esplora JSON shapes (only the fields we consume) ----

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// Field-tolerant: real esplora sends script hex + `v1_p2tr` types, the
/// regtest server.py sends only addresses on prevouts and Core-style
/// type names — taproot detection therefore goes by address prefix
/// (chain-scan.js's P2TR_RE rule), never by type string.
#[derive(Debug, Clone, Deserialize)]
pub struct EsploraOut {
    #[serde(default)]
    pub scriptpubkey: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    #[serde(default)]
    pub value: u64,
}

fn is_taproot_addr(addr: &str) -> bool {
    addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraVin {
    /// Outpoint being spent (present on real esplora and server.py alike).
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vout: Option<u32>,
    #[serde(default)]
    pub prevout: Option<EsploraOut>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraTx {
    pub txid: String,
    pub vin: Vec<EsploraVin>,
    pub vout: Vec<EsploraOut>,
    pub status: EsploraStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: EsploraStatus,
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
    pub fn scan_funding(
        &self,
        src: &crate::funding::FundingSource,
        gap: u32,
    ) -> Result<crate::funding::FundingScan, Error> {
        use crate::funding::{FundingScan, FundingUtxo};
        let mut utxos = Vec::new();
        let mut seen_addr = std::collections::HashSet::new();
        let mut next_change_index = 0u32;
        let ranged = src.is_ranged();

        for chain in [0usize, 1usize] {
            let mut consecutive_unused = 0u32;
            let mut index = 0u32;
            let mut first_unused_change: Option<u32> = None;
            loop {
                let d = src.derive(chain, index)?;
                // Fixed (non-multipath) descriptors can share an address
                // across chains — stop the chain once we revisit one.
                if !seen_addr.insert(d.address.clone()) {
                    break;
                }
                let used = !self.full_history(&d.address)?.is_empty();
                if used {
                    consecutive_unused = 0;
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
                    if chain == 1 && first_unused_change.is_none() {
                        first_unused_change = Some(index);
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
            if chain == 1 {
                next_change_index = first_unused_change.unwrap_or(0);
            }
        }
        Ok(FundingScan { utxos, next_change_index })
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

    /// Broadcast raw tx hex; returns the txid mempool.space echoes back.
    pub fn broadcast(&self, raw_hex: &str) -> Result<String, Error> {
        Ok(self.transport.post_text("/tx", raw_hex.to_string())?.trim().to_string())
    }

    /// Raw hex of an on-chain/mempool tx — the keyless rebroadcast source.
    pub fn fetch_tx_hex(&self, txid: &str) -> Result<String, Error> {
        Ok(self.transport.get_text(&format!("/tx/{txid}/hex"))?.trim().to_string())
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
            coins.push(crate::psbt_build::WatchCoin { txid: ptxid, vout: pvout, value, index });
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
        let fee_rates = self.fee_rates()?;
        let btc_usd = self.btc_usd().unwrap_or(None);
        let utxos = self.utxos(address)?;
        let history = self.full_history(address)?;

        let notes_onchain = history
            .iter()
            .filter(|t| match since_height {
                Some(h) => !t.status.confirmed || t.status.block_height.unwrap_or(u64::MAX) > h,
                None => true,
            })
            .filter_map(|t| classify_tx(t, address))
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
pub fn discover_indexes<T: Transport>(
    client: &ChainClient<T>,
    material: &crate::identity::KeyMaterial,
    network: Network,
    account: u32,
    gap: u32,
) -> Vec<u32> {
    let mut found = Vec::new();
    let mut consecutive_unused = 0u32;
    let mut index = 0u32;
    while consecutive_unused < gap {
        // A fixed (non-ranged) watch descriptor only derives index 0 — the
        // realize error ends the walk cleanly after that one probe.
        let Ok(ident) = crate::identity::realize(material, network, account, index) else {
            break;
        };
        match client.address_probe(&ident.address) {
            Ok((used, _)) => {
                if used {
                    found.push(index);
                    consecutive_unused = 0;
                } else {
                    consecutive_unused += 1;
                }
            }
            Err(_) => break,
        }
        index += 1;
        // Same runaway backstop as scan_funding: no sane wallet needs more.
        if index >= 10_000 {
            break;
        }
    }
    found
}

/// tx → OnchainTx iff it carries ≥1 OP_RETURN payload. Classification
/// rules mirror chain-scan.js; payload parsing is notes-core's own.
pub fn classify_tx(tx: &EsploraTx, address: &str) -> Option<OnchainTx> {
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

    let sender = tx
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter_map(|p| p.scriptpubkey_address.as_deref())
        .find(|a| is_taproot_addr(a))
        .map(String::from);

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

    Some(OnchainTx {
        txid: tx.txid.clone(),
        height: tx.status.block_height.filter(|_| tx.status.confirmed),
        blocktime: tx.status.block_time.filter(|_| tx.status.confirmed),
        spends_from_self,
        payloads,
        pays_self,
        sender: if spends_from_self { None } else { sender },
        author_candidates,
        recipient: if spends_from_self { recipient } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{parse_key_material, realize, KeyMaterial};

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
    /// addresses; `fail` simulates an offline backend.
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
                Ok(String::new())
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
        let client = ChainClient::new(
            ProbeTransport { used: vec![addr(0), addr(2)], fail: false },
            Network::Mainnet,
        );
        assert_eq!(discover_indexes(&client, &material(), Network::Mainnet, 0, 5), vec![0, 2]);
    }

    #[test]
    fn discovery_on_fresh_seed_is_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![], fail: false }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, 5).is_empty());
    }

    #[test]
    fn discovery_offline_is_best_effort_empty() {
        let client =
            ChainClient::new(ProbeTransport { used: vec![addr(0)], fail: true }, Network::Mainnet);
        assert!(discover_indexes(&client, &material(), Network::Mainnet, 0, 5).is_empty());
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
}
