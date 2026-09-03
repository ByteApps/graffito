//! Esplora/mempool.space chain client → in-memory notes-core SyncBundle.
//!
//! Mirrors the companion's scan semantics exactly (chain-scan.js /
//! index.html in prime-graffito): full history = `/address/:a/txs`
//! then `/address/:a/txs/chain?after_txid=` while pages come back full
//! (25); a tx enters `notes_onchain` iff it carries ≥1 OP_RETURN payload;
//! `spends_from_self` = any input prevout is ours (the OWN-note rule),
//! `pays_self` = any output is ours, sender = first taproot input
//! prevout, recipient = first non-self non-OP_RETURN output (taproot
//! preferred). Payload extraction reuses notes-core's own script parser.
//!
//! The `Transport` trait isolates HTTP so tests inject canned JSON.
//!
//! `HttpTransport` also owns two request-shaping behaviors that only make
//! sense against a real server, never against the canned-transport tests:
//! a global inter-request pacer (throttles bursty scans so mempool.space
//! stops handing back 429s in the first place) and a bounded 429
//! retry-with-backoff (for the 429s that get through anyway). See the
//! comment on `Transport for HttpTransport` below for the exact rules.
//!
//! U6 (`../../PLAN-graffito-app-arch.md`, "chain.rs split") broke this
//! module up into files, purely a move — no behavior changed and every
//! `app_core::chain::<Item>` path below still resolves:
//! [`transport`] owns the `Transport` seam (`HttpTransport`/
//! `AnyTransport`/`TxLookupStatus`); [`core_rpc`] owns the Bitcoin Core
//! JSON-RPC backend (`CoreRpcTransport`/`WatchDescriptor`/`NodeStatus`);
//! [`esplora`] owns the esplora wire shapes; [`client`] owns `ChainClient`
//! plus the scan/discover/classify free functions.

mod client;
mod core_rpc;
mod esplora;
mod transport;

pub use client::{
    classify_tx, classify_tx_net, default_base, default_explorer_base, discover_indexes,
    discover_spending, explorer_presets, explorer_tx_url, node_presets, scan_change_chain,
    scan_change_chain_watch, ChainClient, ChangeCoin,
};
pub use core_rpc::{
    core_rpc_import_descriptors_call_count, core_rpc_tx_json_cache_len,
    core_rpc_tx_json_cache_max_entries, identity_watch_descriptors, CoreRpcTransport, NodeStatus,
    WatchDescriptor,
};
pub use esplora::{AddrStats, EsploraOut, EsploraStatus, EsploraTx, EsploraUtxo, EsploraVin};
pub use transport::{node_backend_label, AnyTransport, HttpTransport, Transport, TxLookupStatus};
