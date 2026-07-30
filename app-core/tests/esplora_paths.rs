//! U1 (`PLAN-chain-notes-app-core-rpc.md` §3 step 1): the Esplora-ONLY half
//! of the contract work — exact request-path strings, in order, for every
//! `ChainClient` method. This is `HttpTransport`'s contract, not
//! `ChainClient`'s, so unlike `tests/chain_contract.rs`'s
//! `assert_chain_contract` these assertions are NOT meant to survive the
//! upcoming `Transport` refactor or a Core RPC backend unmodified — they
//! exist to catch an ACCIDENTAL url/path change during that refactor.

mod common;

use app_core::chain::ChainClient;
use app_core::notes_core::Network;

use common::{EsploraFake, InSpec, OutSpec, ScenarioBuilder};

#[test]
fn tip_height_hits_one_path() {
    let sc = ScenarioBuilder::new(Network::Regtest, 42).build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.tip_height().unwrap();
    assert_eq!(client.transport.drain_requests(), vec!["/blocks/tip/height"]);
}

#[test]
fn fee_rates_hits_one_path() {
    let sc = ScenarioBuilder::new(Network::Regtest, 1).build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.fee_rates().unwrap();
    assert_eq!(client.transport.drain_requests(), vec!["/v1/fees/recommended"]);
}

#[test]
fn btc_usd_hits_one_path() {
    let sc = ScenarioBuilder::new(Network::Regtest, 1).build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.btc_usd().unwrap();
    assert_eq!(client.transport.drain_requests(), vec!["/v1/prices"]);
}

#[test]
fn utxos_hits_one_path() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.utxos(&addr).unwrap();
    assert_eq!(client.transport.drain_requests(), vec![format!("/address/{addr}/utxo")]);
}

#[test]
fn address_stats_and_address_used_hit_one_path() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    client.address_stats(&addr).unwrap();
    assert_eq!(client.transport.drain_requests(), vec![format!("/address/{addr}")]);

    client.address_used(&addr).unwrap();
    assert_eq!(client.transport.drain_requests(), vec![format!("/address/{addr}")]);
}

#[test]
fn address_probe_hits_txs_then_utxo() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.address_probe(&addr).unwrap();
    assert_eq!(
        client.transport.drain_requests(),
        vec![format!("/address/{addr}/txs"), format!("/address/{addr}/utxo")]
    );
}

#[test]
fn full_history_always_probes_one_continuation_past_a_short_page() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 100);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
        Some(50),
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    client.full_history(&addr).unwrap();
    // The first page can't prove history is complete on its own — the client
    // always probes one continuation page after the last CONFIRMED txid it
    // saw, even when the first page was short.
    assert_eq!(
        client.transport.drain_requests(),
        vec![format!("/address/{addr}/txs"), format!("/address/{addr}/txs/chain/{txid}")]
    );
}

#[test]
fn full_history_paginates_the_exact_request_sequence_past_25() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1000);
    let addr = b.taproot_addr("pager");
    let funder = b.taproot_addr("pager-funder");
    let mut txids = Vec::new();
    for i in 0..30u64 {
        let txid = b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
            Some(500 + i),
        );
        txids.push(txid);
    }
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    let history = client.full_history(&addr).unwrap();
    assert_eq!(history.len(), 30);

    // Newest-first ordering (descending confirmed height): txids[29] is the
    // most recent (height 529), txids[0] the oldest (height 500). Page 1
    // carries the 25 most recent (txids[29..=5]); the cursor after page 1 is
    // its OLDEST entry, txids[5]; page 2 then returns the remaining 5
    // (txids[4..=0]), cursor txids[0]; page 3 (after txids[0]) is empty and
    // ends the walk.
    let after1 = &txids[5];
    let after2 = &txids[0];
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{after1}"),
            format!("/address/{addr}/txs/chain/{after2}"),
        ]
    );
}

#[test]
fn broadcast_posts_to_slash_tx() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr, value: 5_000 }],
        Some(1),
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    let (raw_hex, _txid) = common::build_unsigned_spend_hex(sc.network, &sc.txs[0].txid, 0, 5_000);
    client.broadcast(&raw_hex).unwrap();
    assert_eq!(client.transport.drain_requests(), vec!["/tx".to_string()]);
    assert_eq!(client.transport.posts.borrow().as_slice(), &[("/tx".to_string(), raw_hex)]);
}

#[test]
fn fetch_tx_hex_and_status_and_lookup_hit_expected_paths() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr, value: 5_000 }],
        Some(1),
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    client.fetch_tx_hex(&txid).unwrap();
    assert_eq!(client.transport.drain_requests(), vec![format!("/tx/{txid}/hex")]);

    client.fetch_tx_status(&txid);
    assert_eq!(client.transport.drain_requests(), vec![format!("/tx/{txid}")]);

    client.tx_lookup_status(&txid);
    assert_eq!(client.transport.drain_requests(), vec![format!("/tx/{txid}")]);
}

#[test]
fn outpoint_unspent_hits_the_utxo_path() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
        Some(1),
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.outpoint_unspent(&addr, &txid, 0);
    assert_eq!(client.transport.drain_requests(), vec![format!("/address/{addr}/utxo")]);
}

#[test]
fn fetch_tx_io_hits_the_single_tx_path_when_prevout_values_are_present() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr, value: 5_000 }],
        None,
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.fetch_tx_io(&txid, |_| None).unwrap();
    // Every ScenarioIn already carries its prevout value — no parent-tx
    // lookup is needed.
    assert_eq!(client.transport.drain_requests(), vec![format!("/tx/{txid}")]);
}

#[test]
fn build_bundle_hits_tip_then_utxo_then_history_in_order() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 77);
    let addr = b.taproot_addr("a");
    let funder = b.taproot_addr("funder");
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
        Some(50),
    );
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);
    client.build_bundle(&addr, None).unwrap();
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{txid}"),
        ]
    );
}
