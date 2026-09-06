//! Electrum backend against a REAL electrs (PLAN-graffito-electrum.md §
//! Verification 2) — read-only, so it may run against the Pi's MAINNET
//! instance through the SSH tunnel. The server is taken from the
//! environment ONLY (`CN_ELECTRUM_HOST`, default 127.0.0.1 — the tunnel;
//! `CN_ELECTRUM_PORT`, default 50001) and its absence is a HARD FAILURE
//! with instructions, never a silent skip (silent-green-test-hazards).
//!
//! Nothing here spends, imports, or writes: `server.features`, the tip,
//! fee tiers, one address's history/utxos/stats, one tx by id, and the
//! established-absence answer for a txid that cannot exist.

use app_core::chain::{AnyTransport, ChainClient, EsploraTx, Transport, TxLookupStatus};
use app_core::notes_core::Network;
use std::net::TcpStream;
use std::time::Duration;

fn server() -> (String, u16) {
    let host = std::env::var("CN_ELECTRUM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("CN_ELECTRUM_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(50001);
    let addr = format!("{host}:{port}");
    let reachable = addr
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).is_ok())
        .unwrap_or(false);
    assert!(
        reachable,
        "no Electrum server at {addr} — this test needs the Pi's electrs through the SSH tunnel:\n  \
         ssh -f -N -o ExitOnForwardFailure=yes -L 50001:127.0.0.1:50001 satoshi@raspberrypi.local\n  \
         (or CN_ELECTRUM_HOST/CN_ELECTRUM_PORT for another server)"
    );
    (host, port)
}

fn client() -> ChainClient<AnyTransport> {
    let (host, port) = server();
    let base = format!("electrum+tcp://{host}:{port}");
    let transport = AnyTransport::new(&base, None).expect("electrum+tcp base parses");
    assert!(matches!(transport, AnyTransport::Electrum(_)), "{base} must select the Electrum backend");
    ChainClient::new(transport, Network::Mainnet)
}

/// The BIP-173 reference address (`bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`)
/// — a real, quiet mainnet address with a small confirmed history.
const KNOWN_ADDRESS: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
/// The first mainnet coinbase after genesis (block 1) — always present,
/// never in a mempool, no prevouts to resolve.
const BLOCK1_COINBASE: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

#[test]
fn electrum_server_status_and_tip_are_consistent() {
    let client = client();
    let AnyTransport::Electrum(t) = &client.transport else { unreachable!() };
    let status = t.server_status().expect("server.version/features/headers");
    assert!(status.server_version.to_lowercase().contains("electrs"), "{status:?}");
    assert!(status.tip_height > 900_000, "mainnet tip must be past 900k: {}", status.tip_height);
    assert!(
        app_core::chain::network_matches_genesis(
            &status.genesis_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        ),
        "the Pi's electrs indexes mainnet: {}",
        status.genesis_hash
    );
    let tip = client.tip_height().expect("tip via the transport");
    assert!(tip >= status.tip_height && tip - status.tip_height <= 2, "tip {tip} vs status {}", status.tip_height);
    eprintln!("electrum_server_status_and_tip_are_consistent: PASS ({status:?})");
}

#[test]
fn electrum_fee_tiers_are_ordered_and_floored() {
    let fees = client().fee_rates().expect("fee_rates");
    assert!(fees.fastest >= fees.half_hour && fees.half_hour >= fees.hour && fees.hour >= fees.economy, "{fees:?}");
    assert!(fees.economy >= 1.0 && fees.minimum >= 1.0, "{fees:?}");
    assert!(fees.fastest < 10_000.0, "a sane mainnet tier: {fees:?}");
    eprintln!("electrum_fee_tiers_are_ordered_and_floored: PASS ({fees:?})");
}

#[test]
fn electrum_known_address_history_stats_and_utxos_agree() {
    let client = client();
    let stats = client.address_stats(KNOWN_ADDRESS).expect("/address/:a");
    assert!(stats.chain_tx_count >= 1, "the BIP-173 address has confirmed history: {stats:?}");
    let txs = client.full_history(KNOWN_ADDRESS).expect("/address/:a/txs (+ /txs/chain/:after pages)");
    assert!(!txs.is_empty());
    for tx in &txs {
        let touches = tx.vout.iter().any(|o| o.scriptpubkey_address.as_deref() == Some(KNOWN_ADDRESS))
            || tx.vin.iter().any(|i| {
                i.prevout.as_ref().and_then(|p| p.scriptpubkey_address.as_deref()) == Some(KNOWN_ADDRESS)
            });
        assert!(touches, "every listed tx touches the address: {}", tx.txid);
        assert_eq!(tx.txid.len(), 64);
    }
    let confirmed = txs.iter().filter(|t| t.status.confirmed).count();
    assert_eq!(confirmed as u64, stats.chain_tx_count, "history count matches chain_stats.tx_count");
    // Confirmed-only pagination cursor: the page after the FIRST confirmed
    // tx must not contain it and must be a strict suffix.
    if let Some(first) = txs.iter().find(|t| t.status.confirmed) {
        let body = client
            .transport
            .get_text(&format!("/address/{KNOWN_ADDRESS}/txs/chain/{}", first.txid))
            .expect("/txs/chain/:after");
        let page: Vec<EsploraTx> = serde_json::from_str(&body).expect("page parses");
        assert!(page.iter().all(|t| t.txid != first.txid && t.status.confirmed));
        assert!(page.len() < confirmed);
    }
    let utxos = client.utxos(KNOWN_ADDRESS).expect("/address/:a/utxo");
    let funded_minus_spent = stats.chain_funded.saturating_sub(stats.chain_spent);
    let utxo_sum: u64 = utxos.iter().filter(|u| u.height.is_some()).map(|u| u.value).sum();
    assert_eq!(utxo_sum, funded_minus_spent, "confirmed utxo sum equals funded − spent: {stats:?} {utxos:?}");
    eprintln!(
        "electrum_known_address_history_stats_and_utxos_agree: PASS (txs={}, utxos={}, stats={stats:?})",
        txs.len(),
        utxos.len()
    );
}

#[test]
fn electrum_tx_lookup_found_and_established_absence() {
    let client = client();
    let body = client.transport.get_text(&format!("/tx/{BLOCK1_COINBASE}")).expect("/tx/:id");
    let tx: EsploraTx = serde_json::from_str(&body).expect("tx parses");
    assert_eq!(tx.txid, BLOCK1_COINBASE);
    assert!(tx.status.confirmed);
    assert_eq!(tx.status.block_height, Some(1), "block 1 coinbase: {:?}", tx.status);
    assert_eq!(tx.vout.len(), 1);
    assert_eq!(tx.vout[0].value, 5_000_000_000);
    assert_eq!(client.tx_lookup_status(BLOCK1_COINBASE), TxLookupStatus::Found(true));
    let hex = client.fetch_tx_hex(BLOCK1_COINBASE).expect("/tx/:id/hex");
    assert!(hex.starts_with("01000000") && hex.len() == 268, "raw block-1 coinbase: {hex}");
    // A txid that cannot exist: electrs answers with its "No such mempool
    // or blockchain transaction" error, which the transport maps to the
    // 404 shape — established absence, never Unknown.
    let absent = "0000000000000000000000000000000000000000000000000000000000000001";
    assert_eq!(client.tx_lookup_status(absent), TxLookupStatus::NotFound);
    eprintln!("electrum_tx_lookup_found_and_established_absence: PASS");
}
