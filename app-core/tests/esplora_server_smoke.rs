//! U1 (`plans/PLAN-graffito-history-scaling.md`) step 3: proves
//! `common::esplora_server::EsploraFakeServer` (a REAL socket) serves the
//! exact same content and exact same request-path sequence
//! `common::EsploraFake` (in-process) does — the load-bearing assumption
//! the history-scaling flow test (`src/tests/ui_flow_history_streaming.rs`)
//! makes when it drives the real app shell against this server instead of
//! a canned in-process transport. Two independently-built `Scenario`s (the
//! builder is deterministic — same role strings + call order always
//! produce the same hash-derived addresses/txids) stand in for "the same
//! scenario, served two ways" without needing `Scenario: Clone`.

mod common;

use std::sync::{Arc, Mutex};

use app_core::chain::{AnyTransport, ChainClient, Transport};
use app_core::notes_core::Network;

use common::esplora_server::EsploraFakeServer;
use common::{EsploraFake, InSpec, OutSpec, Scenario, ScenarioBuilder};

/// The same 60-confirmed-OP_RETURN-tx shape `esplora_paths.rs`'s private
/// `build_60_tx_scenario` uses (that helper isn't reachable from this test
/// binary) — enough history to exercise the full tip/utxo/txs/chain/chain
/// pagination sequence, not just a single-page scan.
fn build_60_tx_scenario() -> (Scenario, String) {
    let mut b = ScenarioBuilder::new(Network::Regtest, 1000);
    let addr = b.taproot_addr("smoke");
    let funder = b.taproot_addr("smoke-funder");
    for i in 0..60u64 {
        b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![
                OutSpec::Pay { address: addr.clone(), value: 5_000 },
                OutSpec::OpReturn { payload: format!("note{i}").into_bytes() },
            ],
            Some(i + 1),
        );
    }
    (b.build(), addr)
}

#[test]
fn http_transport_matches_in_process_fake_for_60_tx_scenario() {
    let (sc_in_process, addr_in_process) = build_60_tx_scenario();
    let (sc_server, addr_server) = build_60_tx_scenario();
    assert_eq!(addr_in_process, addr_server, "the builder must be deterministic");

    // Ground truth: ChainClient<EsploraFake>, in-process.
    let fake = EsploraFake::new(&sc_in_process);
    let in_process_client = ChainClient::new(fake, sc_in_process.network);
    let expected_bundle = in_process_client.build_bundle(&addr_in_process).unwrap();
    let expected_paths = in_process_client.transport.drain_requests();
    assert!(!expected_paths.is_empty(), "sanity: the in-process walk must issue requests");

    // Same scenario, served over a real socket — the app never contacts
    // anything but loopback here (127.0.0.1, unpaced — see
    // `HttpTransport::is_loopback_base`).
    let server = EsploraFakeServer::start(Arc::new(Mutex::new(sc_server)));
    let transport = AnyTransport::new(&server.base_url(), None).expect("plain http(s) base must parse as Esplora");
    let http_client = ChainClient::new(transport, Network::Regtest);
    let got_bundle = http_client.build_bundle(&addr_server).unwrap();
    let got_paths = server.drain_requests();

    assert_eq!(got_paths, expected_paths, "HttpTransport must issue the exact same request-path sequence");
    assert!(got_bundle.full);
    assert_eq!(got_bundle.tip_height, expected_bundle.tip_height);
    let mut got_utxos: Vec<(String, u32, u64, Option<u64>)> =
        got_bundle.utxos.iter().map(|u| (u.txid.clone(), u.vout, u.value, u.height)).collect();
    let mut expected_utxos: Vec<(String, u32, u64, Option<u64>)> =
        expected_bundle.utxos.iter().map(|u| (u.txid.clone(), u.vout, u.value, u.height)).collect();
    got_utxos.sort();
    expected_utxos.sort();
    assert_eq!(got_utxos, expected_utxos, "the real-socket transport must yield the same utxo set");
    let mut got_notes: Vec<String> = got_bundle.notes_onchain.iter().map(|t| t.txid.clone()).collect();
    let mut expected_notes: Vec<String> = expected_bundle.notes_onchain.iter().map(|t| t.txid.clone()).collect();
    got_notes.sort();
    expected_notes.sort();
    assert_eq!(got_notes, expected_notes, "the real-socket transport must yield the same notes_onchain set");
}

/// U7 (`plans/PLAN-graffito-history-scaling.md`): `AnyTransport::Esplora`'s
/// `request_count()` must track every `get_text`/`post_text` call it makes,
/// success or failure, so `refresh_async` can snapshot it into
/// `cb: refresh paths=<n> pages=<p>` without relying on the fake server's
/// own (test-only) request log. A real loopback server stands in for "a
/// stub" here — no new dependency, same server this file already proves
/// matches the in-process fake byte-for-byte.
#[test]
fn any_transport_request_count_tracks_every_call() {
    let (sc, addr) = build_60_tx_scenario();
    let server = EsploraFakeServer::start(Arc::new(Mutex::new(sc)));
    let transport = AnyTransport::new(&server.base_url(), None).expect("plain http(s) base must parse as Esplora");
    assert_eq!(transport.request_count(), 0, "a fresh transport starts at zero");

    transport.get_text("/blocks/tip/height").expect("tip route");
    transport.get_text(&format!("/address/{addr}")).expect("stats route");
    transport.get_text(&format!("/address/{addr}/utxo")).expect("utxo route");
    assert_eq!(transport.request_count(), 3, "three successful get_text calls");

    // A call that comes back an error still counts — the counter measures
    // requests MADE, not requests that succeeded (a hostile/offline node
    // making every call fail must not read as "zero network cost").
    let _ = transport.get_text("/no/such/route");
    assert_eq!(transport.request_count(), 4, "a failing call still counts as one request");

    // Matches the server's own independent request log, proving the two
    // counters agree rather than one merely mirroring the other's math.
    assert_eq!(server.drain_requests().len(), 4, "sanity: the server saw exactly the same 4 requests");
}
