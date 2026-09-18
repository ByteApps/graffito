//! U1 (`plans/PLAN-graffito-app-core-rpc.md` §3 step 1): the Esplora-ONLY half
//! of the contract work — exact request-path strings, in order, for every
//! `ChainClient` method. This is `HttpTransport`'s contract, not
//! `ChainClient`'s, so unlike `tests/chain_contract.rs`'s
//! `assert_chain_contract` these assertions are NOT meant to survive the
//! upcoming `Transport` refactor or a Core RPC backend unmodified — they
//! exist to catch an ACCIDENTAL url/path change during that refactor.

mod common;

use std::collections::HashSet;

use app_core::chain::{ChainClient, ScanCursor};
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
    client.build_bundle(&addr).unwrap();
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

/// U1 (`plans/PLAN-graffito-history-scaling.md`): [`ChainClient::scan_history`]'s
/// request-path contract. 60 confirmed txs at addr, one OP_RETURN output
/// each (heights 1..=60, oldest→newest by construction order — `txids[0]`
/// is the oldest); a page-1 fetch (`/txs`) always returns the NEWEST 25
/// (`txids[35..60]`), and a chain continuation after `txids[35]` returns
/// the next 25 (`txids[10..35]`), then `txids[0..10]` (short).
fn build_60_tx_scenario(role: &str) -> (common::Scenario, String, Vec<String>) {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1000);
    let addr = b.taproot_addr(role);
    let funder = b.taproot_addr(&format!("{role}-funder"));
    let mut txids = Vec::new();
    for i in 0..60u64 {
        let txid = b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![
                OutSpec::Pay { address: addr.clone(), value: 5_000 },
                OutSpec::OpReturn { payload: format!("note{i}").into_bytes() },
            ],
            Some(i + 1),
        );
        txids.push(txid);
    }
    (b.build(), addr, txids)
}

#[test]
fn full_scan_stops_at_known_confirmed_txid() {
    let (sc, addr, txids) = build_60_tx_scenario("scan");
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    // Part 1: cursor already knows EVERY confirmed txid — page 1 alone (25
    // known-confirmed txids, a FULL page) already crosses
    // HISTORY_REORG_MARGIN, so the walk never even probes a continuation
    // page: exactly 3 paths.
    let cursor_all = ScanCursor {
        known_confirmed: txids.iter().cloned().collect(),
        must_see: HashSet::new(),
        tip_height: 0,
    };
    let bundle = client.scan_history(&addr, &cursor_all, &mut |_| {}).unwrap();
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
        ]
    );
    assert!(bundle.full);
    let page1_expected: HashSet<String> = txids[35..60].iter().cloned().collect();
    let got: HashSet<String> = bundle.notes_onchain.iter().map(|t| t.txid.clone()).collect();
    assert_eq!(got, page1_expected, "an all-known cursor's bundle is exactly page 1's 25 txs");

    // Part 2: cursor knows only the OLDEST 30 — page 1 (the newest 25)
    // matches none of them, so the walk continues past it; page 2 then
    // contains 20 of the known txids (≥ HISTORY_REORG_MARGIN), so the walk
    // stops there — exactly ONE continuation.
    let cursor_old30 = ScanCursor {
        known_confirmed: txids[0..30].iter().cloned().collect(),
        must_see: HashSet::new(),
        tip_height: 0,
    };
    client.scan_history(&addr, &cursor_old30, &mut |_| {}).unwrap();
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", txids[35]),
        ]
    );
}

#[test]
fn scan_history_streams_one_partial_bundle_per_page_then_a_full_one() {
    let (sc, addr, txids) = build_60_tx_scenario("stream");
    let expected_utxo_count = sc.utxos_for(&addr).len();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    let mut page_sizes = Vec::new();
    let bundle = client
        .scan_history(&addr, &ScanCursor::empty(), &mut |page| {
            assert!(!page.full, "a streamed page must be partial");
            assert_eq!(
                page.utxos.len(),
                expected_utxo_count,
                "every streamed page carries the complete utxo set"
            );
            page_sizes.push(page.notes_onchain.len());
        })
        .unwrap();

    // Page 1 = newest 25, page 2 (chain) = next 25, page 3 (chain) = final
    // 10 (short — ends the walk without a 4th, empty-confirming request).
    assert_eq!(page_sizes, vec![25, 25, 10]);
    assert!(bundle.full);
    assert_eq!(bundle.notes_onchain.len(), 60);
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", txids[35]),
            format!("/address/{addr}/txs/chain/{}", txids[10]),
        ]
    );
}

#[test]
fn reorg_below_cursor_tip_walks_to_the_end() {
    let (sc, addr, txids) = build_60_tx_scenario("reorg");
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    // Cursor claims EVERY txid as known-confirmed (would otherwise stop
    // after page 1 alone, per `full_scan_stops_at_known_confirmed_txid`'s
    // part 1) but records a tip HIGHER than the live one — the chain moved
    // backward under us, so `known_confirmed` must be ignored entirely and
    // the walk goes to the end, byte-identical to the empty-cursor run.
    let cursor = ScanCursor {
        known_confirmed: txids.iter().cloned().collect(),
        must_see: HashSet::new(),
        tip_height: (sc.tip_height + 1000) as u32,
    };
    let bundle = client.scan_history(&addr, &cursor, &mut |_| {}).unwrap();
    assert!(bundle.full);
    assert_eq!(bundle.notes_onchain.len(), 60, "a reorg-guarded scan still walks to the end");
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", txids[35]),
            format!("/address/{addr}/txs/chain/{}", txids[10]),
        ]
    );
}

#[test]
fn mempool_txs_never_satisfy_the_stop() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1000);
    let addr = b.taproot_addr("mempool-stop");
    let funder = b.taproot_addr("mempool-stop-funder");
    // 30 confirmed txs (page 1 = newest 25, one chain continuation = the
    // oldest 5 — the classic pagination shape) plus 6 still-UNCONFIRMED
    // txs paying the same address. EsploraFake's `/txs` page always lists
    // mempool txs before confirmed ones (real esplora ordering), so all 6
    // land in page 1 alongside the newest 25 confirmed.
    let mut confirmed_txids = Vec::new();
    for i in 0..30u64 {
        let txid = b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
            Some(i + 1),
        );
        confirmed_txids.push(txid);
    }
    let mut mempool_txids = Vec::new();
    for _ in 0..6u64 {
        let txid = b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![OutSpec::Pay { address: addr.clone(), value: 5_000 }],
            None,
        );
        mempool_txids.push(txid);
    }
    let sc = b.build();
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    // A store bug: these 6 txids are recorded as CONFIRMED in the cursor,
    // but the chain still shows them unconfirmed. If mempool status were
    // ignored, page 1 alone would already show 6 "known-confirmed" matches
    // (≥ HISTORY_REORG_MARGIN) on a full page and the walk would stop with
    // ZERO continuation requests.
    let cursor =
        ScanCursor { known_confirmed: mempool_txids.into_iter().collect(), must_see: HashSet::new(), tip_height: 0 };
    let bundle = client.scan_history(&addr, &cursor, &mut |_| {}).unwrap();

    // Instead the walk behaves exactly like an empty cursor over 30
    // confirmed txs: ONE continuation (the oldest 5), proving the 6
    // mempool "matches" never counted toward the stop.
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", confirmed_txids[5]),
        ]
    );
    assert!(bundle.full);
}

/// U1 pending-txid follow-up (`plans/PLAN-graffito-history-scaling.md`): a
/// `must_see` txid the store still holds pending/unconfirmed must block the
/// early stop even when `known_confirmed` alone would already satisfy it —
/// the store's dropped-pending detector needs a full walk to positively
/// establish absence. `txids[5]` sits deep in the OLDEST page (page 3, the
/// short 10-tx tail): with `known_confirmed` claiming every txid confirmed
/// (which alone would stop after page 1, per
/// `full_scan_stops_at_known_confirmed_txid`'s part 1), the walk must
/// instead continue all the way to page 3, where `txids[5]` finally turns
/// up — at which point the page is short anyway and the walk ends
/// naturally.
#[test]
fn pending_txid_deep_in_history_blocks_the_early_stop() {
    let (sc, addr, txids) = build_60_tx_scenario("pending-deep");
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    let cursor = ScanCursor {
        known_confirmed: txids.iter().cloned().collect(),
        must_see: [txids[5].clone()].into_iter().collect(),
        tip_height: 0,
    };
    let bundle = client.scan_history(&addr, &cursor, &mut |_| {}).unwrap();
    assert!(bundle.full);
    assert_eq!(bundle.notes_onchain.len(), 60, "must_see forces a full walk to reach txids[5]");
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", txids[35]),
            format!("/address/{addr}/txs/chain/{}", txids[10]),
        ]
    );
}

/// U1 pending-txid follow-up: a `must_see` txid that never appears on any
/// page (the store thinks it's pending, but it's genuinely gone — the
/// "dropped from the mempool" case) costs exactly one full walk to the
/// end — same path list as an empty cursor, never an infinite/extra probe.
#[test]
fn must_see_txid_absent_from_chain_walks_to_the_end() {
    let (sc, addr, txids) = build_60_tx_scenario("pending-absent");
    let fake = EsploraFake::new(&sc);
    let client = ChainClient::new(fake, sc.network);

    let cursor = ScanCursor {
        known_confirmed: HashSet::new(),
        must_see: ["ff".repeat(32)].into_iter().collect(),
        tip_height: 0,
    };
    let bundle = client.scan_history(&addr, &cursor, &mut |_| {}).unwrap();
    assert!(bundle.full);
    assert_eq!(bundle.notes_onchain.len(), 60);
    assert_eq!(
        client.transport.drain_requests(),
        vec![
            "/blocks/tip/height".to_string(),
            format!("/address/{addr}/utxo"),
            format!("/address/{addr}/txs"),
            format!("/address/{addr}/txs/chain/{}", txids[35]),
            format!("/address/{addr}/txs/chain/{}", txids[10]),
        ]
    );
}
