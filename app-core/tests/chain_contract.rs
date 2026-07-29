//! U1 (`PLAN-chain-notes-app-core-rpc.md` §3 step 1): the backend-agnostic
//! contract battery, run against TODAY's Esplora `ChainClient` through
//! `EsploraFake`. Locks in current `ChainClient`/free-scan-function
//! behavior so the upcoming `Transport` refactor (U2) and the Core RPC
//! backend (U3) can both be proven not to change it — this same
//! `assert_chain_contract` call will later run, unmodified, against
//! `ChainClient<CoreRpcTransport>` pointed at a real `bitcoind -regtest`
//! holding the same scenario.
//!
//! Three scenarios, per the plan's suggestion:
//!   1. a simple funded address (confirmed + mempool coins on one address),
//!   2. a spend-and-change history with a self-authored note (exercises
//!      classify_tx/build_bundle, spent+unspent outpoints, fetch_tx_io),
//!   3. a >25-tx paginated address (with a mempool tx) alongside an HD
//!      wallet with gap-limited holes on both the notebook and spending
//!      trees (exercises pagination AND the free scan functions' gap-limit
//!      termination).

mod common;

use app_core::chain::ChainClient;
use app_core::notes_core::Network;

use common::{assert_chain_contract, attach_wallet, EsploraFake, InSpec, OutSpec, ScenarioBuilder};

/// The canonical all-zeroes BIP-39 test mnemonic — already used elsewhere in
/// this crate (`app-core/src/chain.rs`'s `SPENDING_MNEMONIC`,
/// `keyexport.rs`'s tests) as a public, well-known test vector.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn contract_simple_funded_address() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 200);
    let addr_a = b.taproot_addr("addr-a");
    let funder1 = b.taproot_addr("funder1");
    let funder2 = b.taproot_addr("funder2");

    // Confirmed coin.
    b.add_tx(
        vec![InSpec::External { address: funder1, value: 150_000 }],
        vec![OutSpec::Pay { address: addr_a.clone(), value: 80_000 }],
        Some(150),
    );
    // Mempool coin on the SAME address — mixed chain/mempool stats.
    b.add_tx(
        vec![InSpec::External { address: funder2, value: 60_000 }],
        vec![OutSpec::Pay { address: addr_a, value: 20_000 }],
        None,
    );

    let sc = b.build();
    let client = ChainClient::new(EsploraFake::new(&sc), sc.network);
    assert_chain_contract(&client, &sc);
}

#[test]
fn contract_spend_and_change_with_self_note() {
    let mut b = ScenarioBuilder::new(Network::Regtest, 300);
    let addr_a = b.taproot_addr("addr-a");
    let addr_b_external = b.taproot_addr("addr-b-external-recipient");
    let funder = b.taproot_addr("funder");
    let funder3 = b.taproot_addr("funder3");

    // addr_a receives its first coin.
    let fund_txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 150_000 }],
        vec![OutSpec::Pay { address: addr_a.clone(), value: 100_000 }],
        Some(100),
    );
    // addr_a spends that coin: pays an external recipient + change back to
    // itself — the original outpoint becomes SPENT, the change output is a
    // fresh UNSPENT one at the same address.
    let spend_txid = b.add_tx(
        vec![InSpec::Prior { txid: fund_txid, vout: 0 }],
        vec![
            OutSpec::Pay { address: addr_b_external.clone(), value: 40_000 },
            OutSpec::Pay { address: addr_a.clone(), value: 55_000 },
        ],
        Some(150),
    );
    // A self-authored note: spends the change coin, carries an OP_RETURN
    // payload, and pays change back to self again (spends_from_self AND
    // pays_self both true — the OWN-note rule).
    b.add_tx(
        vec![InSpec::Prior { txid: spend_txid, vout: 1 }],
        vec![
            OutSpec::OpReturn { payload: b"hello from the contract battery".to_vec() },
            OutSpec::Pay { address: addr_a, value: 54_800 },
        ],
        Some(200),
    );
    // A mempool tx touching the external recipient too, for mixed stats.
    b.add_tx(
        vec![InSpec::External { address: funder3, value: 5_000 }],
        vec![OutSpec::Pay { address: addr_b_external, value: 2_000 }],
        None,
    );

    let sc = b.build();
    let client = ChainClient::new(EsploraFake::new(&sc), sc.network);
    assert_chain_contract(&client, &sc);
}

#[test]
fn contract_paginated_address_with_gap_limited_wallet() {
    const TIP: u64 = 1000;
    let mut b = ScenarioBuilder::new(Network::Regtest, TIP);
    let pager_addr = b.taproot_addr("pager");
    let pager_funder = b.taproot_addr("pager-funder");

    // 30 confirmed txs on one address — strictly more than esplora's 25-per-
    // page limit, so `full_history` must page via `/txs/chain/:after_txid`.
    for i in 0..30u64 {
        b.add_tx(
            vec![InSpec::External { address: pager_funder.clone(), value: 10_000 }],
            vec![OutSpec::Pay { address: pager_addr.clone(), value: 5_000 }],
            Some(500 + i),
        );
    }
    // Plus one mempool tx on the same address.
    b.add_tx(
        vec![InSpec::External { address: pager_funder, value: 3_000 }],
        vec![OutSpec::Pay { address: pager_addr, value: 1_000 }],
        None,
    );

    // A gap-limited HD wallet: index 1 is a hole on the notebook receive
    // chain (0 and 2 used) — the walk must skip past it and still find 2,
    // then stop after `gap` (3) consecutive unused indexes past it.
    let wallet = attach_wallet(
        &mut b,
        TEST_MNEMONIC,
        Network::Regtest,
        0,
        3,
        vec![0, 2],
        vec![0],
        vec![0, 1],
        vec![0],
        TIP,
    );
    let sc = b.with_wallet(wallet).build();
    let client = ChainClient::new(EsploraFake::new(&sc), sc.network);
    assert_chain_contract(&client, &sc);
}
