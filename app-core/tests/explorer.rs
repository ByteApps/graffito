//! Pure URL/preset helpers for the Settings node + explorer dropdowns.

use app_core::chain::{
    default_explorer_base, explorer_presets, explorer_tx_url, node_presets,
};
use app_core::notes_core::Network;

const TXID: &str = "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66";

#[test]
fn explorer_default_matches_legacy_mempool_urls() {
    // Byte-identical to the old hardcoded explorer_tx_url behavior.
    assert_eq!(
        explorer_tx_url(None, Network::Mainnet, TXID),
        format!("https://mempool.space/tx/{TXID}")
    );
    assert_eq!(
        explorer_tx_url(None, Network::Testnet4, TXID),
        format!("https://mempool.space/testnet4/tx/{TXID}")
    );
    assert_eq!(
        explorer_tx_url(None, Network::Signet, TXID),
        format!("https://mempool.space/signet/tx/{TXID}")
    );
    // Regtest had no public explorer → empty link.
    assert_eq!(explorer_tx_url(None, Network::Regtest, TXID), "");
}

#[test]
fn explorer_custom_base_builds_tx_path() {
    // Self-hosted open-source mempool (any host) → <base>/tx/<txid>.
    assert_eq!(
        explorer_tx_url(Some("http://localhost:8080"), Network::Regtest, TXID),
        format!("http://localhost:8080/tx/{TXID}")
    );
    // A custom base makes regtest links non-empty.
    assert_ne!(explorer_tx_url(Some("http://localhost:8080"), Network::Regtest, TXID), "");
    // Blockstream preset base.
    assert_eq!(
        explorer_tx_url(Some("https://blockstream.info"), Network::Mainnet, TXID),
        format!("https://blockstream.info/tx/{TXID}")
    );
}

#[test]
fn explorer_custom_base_trailing_slash_tolerated() {
    assert_eq!(
        explorer_tx_url(Some("http://localhost:8080/"), Network::Regtest, TXID),
        format!("http://localhost:8080/tx/{TXID}")
    );
}

#[test]
fn presets_first_is_default_and_regtest_is_custom_only() {
    for net in [Network::Mainnet, Network::Testnet4, Network::Signet] {
        // First preset is always mempool.space = network default (url None).
        assert_eq!(node_presets(net)[0], ("mempool.space", None));
        assert_eq!(explorer_presets(net)[0], ("mempool.space", None));
    }
    // Regtest offers no public preset (dropdown = just "Custom…").
    assert!(node_presets(Network::Regtest).is_empty());
    assert!(explorer_presets(Network::Regtest).is_empty());
    // Blockstream is offered on mainnet only.
    assert!(node_presets(Network::Mainnet)
        .iter()
        .any(|(l, u)| *l == "Blockstream" && u.is_some()));
    assert!(!node_presets(Network::Testnet4).iter().any(|(l, _)| *l == "Blockstream"));
}

#[test]
fn default_explorer_base_pairs_with_default_node_base() {
    // Explorer website base + "/api" is the node base on mempool.space nets.
    assert_eq!(default_explorer_base(Network::Mainnet), Some("https://mempool.space"));
    assert_eq!(default_explorer_base(Network::Testnet4), Some("https://mempool.space/testnet4"));
    assert_eq!(default_explorer_base(Network::Regtest), None);
}
