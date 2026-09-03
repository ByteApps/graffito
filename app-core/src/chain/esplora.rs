use serde::{Deserialize, Serialize};

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

/// Private mirror of esplora's `{chain_stats, mempool_stats}` nesting for
/// `GET /address/:a` — flattened into [`AddrStats`] on the way out so
/// callers don't have to reach through two levels for the fields they
/// need. All fields `#[serde(default)]`-tolerant like every other esplora
/// shape in this file.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct EsploraAddrStatsGroup {
    #[serde(default)]
    pub(super) tx_count: u64,
    #[serde(default)]
    pub(super) funded_txo_sum: u64,
    #[serde(default)]
    pub(super) spent_txo_sum: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct EsploraAddrStats {
    #[serde(default)]
    pub(super) chain_stats: EsploraAddrStatsGroup,
    #[serde(default)]
    pub(super) mempool_stats: EsploraAddrStatsGroup,
}

impl Default for EsploraAddrStatsGroup {
    fn default() -> Self {
        EsploraAddrStatsGroup { tx_count: 0, funded_txo_sum: 0, spent_txo_sum: 0 }
    }
}

/// Flat "did anything change since last scan" fingerprint for one address —
/// esplora's `GET /address/:a` chain + mempool stats, flattened. A later
/// wiring pass compares this against the last-persisted value ([`Store`]'s
/// `addr_stats` field) to short-circuit a refresh when nothing moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrStats {
    pub chain_tx_count: u64,
    pub chain_funded: u64,
    pub chain_spent: u64,
    pub mempool_tx_count: u64,
    pub mempool_funded: u64,
    pub mempool_spent: u64,
}
