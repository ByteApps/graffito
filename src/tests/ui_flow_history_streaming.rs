// ---------------------------------------------------------------------------
// In-process UI-flow test, U1 (plans/PLAN-graffito-history-scaling.md): the
// full streaming-scan pipeline — `refresh_async`'s worker paging through
// `ChainClient::scan_history` against a REAL loopback HTTP server
// (`common::esplora_server::EsploraFakeServer`, not the in-process
// `EsploraFake` every other `app-core` test uses) instead of a canned
// transport. Proves, end to end through the real production code path:
//   (a) the FIRST partial page paints before the walk finishes,
//   (b) the FINAL bundle lands with the right totals and exactly the
//       expected number of HTTP requests for a from-scratch scan,
//   (c) a second refresh with nothing changed short-circuits to ONE
//       request (the `/address/:a` stats fingerprint),
//   (d) adding one CONFIRMED tx costs 4 requests and zero chain pages
//       (the ScanCursor's known_confirmed early stop),
//   (e) a MEMPOOL tx costs the same 4 requests, and confirming it still
//       does — the store's `must_see` set (built from PENDING records)
//       is what makes the confirm transition observable without a full
//       rescan, per the fingerprint-short-circuit review fix in
//       `refresh_async` (a Core-RPC-backend stats shape can't tell a
//       pending tx confirmed on its own — see the comment there).
//
// `QUEUE`/`SCAN_LANE` are process-global (`pending.rs`), so this test
// acquires `QUEUE_TEST_LOCK` for its whole body, same as the two tests in
// `pending`'s own module that also touch those statics directly — see
// that lock's doc comment.
//
// Draining note: `apply_pending` drains the ENTIRE queue in one call, so
// polling it in a loop cannot reliably catch "exactly after the first
// partial landed" — a fast local worker can post several pages before the
// test thread gets to call it even once. This test instead pops and runs
// jobs ONE AT A TIME straight from the shared `QUEUE` (same primitive
// `apply_pending` itself uses to drain, just not batched), which is what
// makes step (a)'s exact assertions deterministic regardless of how far
// ahead the background thread races.
// ---------------------------------------------------------------------------

use crate::*;

#[path = "../../app-core/tests/common/mod.rs"]
mod common;

use common::esplora_server::EsploraFakeServer;
use common::{InSpec, OutSpec, Scenario, ScenarioBuilder};
use std::sync::{Arc, Mutex};

/// A REAL, minimal PNTE envelope payload (flags=0: public, non-directed,
/// single output) wrapping `text` — `store::apply_bundle`'s
/// `extract_notes_pq` -> `envelope::decode_note` rejects anything that
/// doesn't parse as a valid envelope (`Some(decoded) = envelope::decode_note(...)
/// else { continue }`, notes-core/src/bundle.rs), silently dropping the tx
/// from `store.notes` entirely — plain ASCII bytes (as `esplora_paths.rs`'s
/// `build_60_tx_scenario` uses, since it only asserts on `bundle.notes_onchain`,
/// never the store) look like a note to `classify_tx` (any OP_RETURN
/// qualifies) but are NOT one to the store. `text` must stay well under one
/// output's payload budget.
fn pnte_payload(text: &str) -> Vec<u8> {
    app_core::notes_core::envelope::encode_outputs(0, None, text.as_bytes(), 200)
        .expect("text fits in one PNTE output")
        .remove(0)
}

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon about";

/// Pop and run exactly one already-queued job against live `(app, st)` —
/// the same `Job` shape/order `apply_pending`'s `take_all` drains, just one
/// at a time. `None`/`false` when the queue was empty at the moment of the
/// check (the worker hasn't posted yet).
fn run_one_pending_job(app: &AppWindow, st: &mut State) -> bool {
    let job = {
        let mut q = QUEUE.lock().expect("pending queue mutex");
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    };
    match job {
        Some(j) => {
            j(app, st);
            true
        }
        None => false,
    }
}

/// Runs jobs one at a time (see `run_one_pending_job`) until `done` reports
/// true (checked BEFORE every job and once more after each), or the
/// iteration cap is hit — bounded exactly like the FIFO test's join-based
/// determinism, just polling instead of joining since the work happens on
/// a real background thread this test doesn't own. A short sleep only
/// when the queue is momentarily empty (the worker is still mid-request).
fn drain_until(app: &AppWindow, st: &mut State, mut done: impl FnMut(&AppWindow, &State) -> bool) -> bool {
    for _ in 0..20_000u32 {
        if done(app, st) {
            return true;
        }
        if !run_one_pending_job(app, st) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    done(app, st)
}

/// Runs every job CURRENTLY queued or that shows up within the deadline,
/// without an early-exit condition — used once the test wants to fully
/// settle (e.g. after triggering a second scan) before reading final
/// state. Distinct from `drain_until`: this keeps going until an entire
/// `idle_polls` streak sees nothing to run, not until a specific total is
/// reached (used for the short-circuit/incremental steps, whose paths are
/// asserted from the recorder rather than a UI count).
fn drain_settle(app: &AppWindow, st: &mut State) {
    let mut idle = 0u32;
    for _ in 0..20_000u32 {
        if run_one_pending_job(app, st) {
            idle = 0;
        } else {
            idle += 1;
            if idle > 50 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

/// Adds one tx to a LIVE shared scenario (mutating it between scans) via a
/// throwaway one-shot `ScenarioBuilder` — reuses the builder's real
/// tx-construction machinery (address derivation, consensus encoding,
/// txid computation) instead of hand-rolling a `ScenarioTx`. Always
/// carries an OP_RETURN payload, so it always classifies as a note.
fn add_tx(scenario: &Arc<Mutex<Scenario>>, pay_to: &str, height: Option<u64>, tag: &str) -> String {
    let mut b = ScenarioBuilder::new(Network::Regtest, height.unwrap_or(1000));
    let funder = b.taproot_addr(&format!("extra-funder-{tag}"));
    let txid = b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![
            OutSpec::Pay { address: pay_to.to_string(), value: 5_000 },
            OutSpec::OpReturn { payload: pnte_payload(&format!("extra-{tag}")) },
        ],
        height,
    );
    let mut one = b.build();
    let tx = one.txs.remove(0);
    scenario.lock().expect("scenario mutex").txs.push(tx);
    txid
}

#[test]
fn thousand_tx_history_streams_then_scales_incrementally() {
    let _queue_lock = QUEUE_TEST_LOCK.lock().expect("queue test lock");
    i_slint_backend_testing::init_no_event_loop();

    // The identity's receive address is a pure function of the mnemonic —
    // derive it BEFORE building the scenario/server so the scenario can pay
    // it directly (no dependency on activate() having run first).
    let material = app_core::identity::parse_key_material(MNEMONIC, Network::Regtest).expect("parse material");
    let address = app_core::identity::realize(&material, Network::Regtest, 0, 0).expect("realize").address;

    const N: u32 = 1000;
    let build_started = std::time::Instant::now();
    let mut b = ScenarioBuilder::new(Network::Regtest, 10_000);
    let funder = b.taproot_addr("thousand-funder");
    for i in 0..N {
        b.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 10_000 }],
            vec![
                OutSpec::Pay { address: address.clone(), value: 5_000 },
                OutSpec::OpReturn { payload: pnte_payload(&format!("note{i}")) },
            ],
            Some((i + 1) as u64),
        );
    }
    let sc = b.build();
    let build_elapsed = build_started.elapsed();
    eprintln!("cb: test-build-scenario n={N} elapsed_ms={}", build_elapsed.as_millis());
    assert!(
        build_elapsed.as_secs() < 60,
        "building {N} txs took {:?} — over budget, the brief says fall back to 500 and say so",
        build_elapsed
    );

    let scenario = Arc::new(Mutex::new(sc));
    let server = EsploraFakeServer::start(scenario.clone());

    let node_urls = HashMap::from([("regtest".to_string(), server.base_url())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-history-streaming-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    assert_eq!(st.ident.as_ref().unwrap().address, address, "sanity: identity address matches the scenario payee");
    // A fresh multi-notebook mnemonic import flags gap discovery, which
    // `refresh_async` would ALSO kick off (a separate worker probing OTHER
    // receive indexes) — this test's path-count assertions are about the
    // notebook scan alone, so discovery is switched off here rather than
    // asserting around its noise.
    st.discovery_pending = false;

    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);

    // ---- (a) first partial paints before the walk finishes -------------
    // A hard breakpoint (not a sleep) after request #4 (stats, tip, utxo,
    // the `/txs` page-1 fetch) — the walk PHYSICALLY cannot make request
    // #5 until `resume()` is called, so this is race-free regardless of
    // how this test thread happens to get scheduled (a fixed sleep-based
    // delay was tried first and still let the walk race ~17 requests
    // ahead under a loaded test run — see `pause_after`'s doc comment).
    server.pause_after(4);
    st.refresh_async(&app);
    let landed = drain_until(&app, &mut st, |_app, _st| app.global::<Ui>().get_notes().row_count() > 0);
    assert!(landed, "the first partial page must land within the poll budget");
    assert_eq!(
        app.global::<Ui>().get_notes().row_count(),
        25,
        "the first partial page carries exactly ESPLORA_PAGE_SIZE notes"
    );
    assert_eq!(
        server.drain_requests(),
        vec![
            format!("/address/{address}"),
            "/blocks/tip/height".to_string(),
            format!("/address/{address}/utxo"),
            format!("/address/{address}/txs"),
        ],
        "exactly the stats precheck + tip + utxo + the first history page so far"
    );

    // ---- (b) the final bundle lands with the right totals --------------
    server.resume();
    drain_settle(&app, &mut st);
    assert!(!st.scan_gate.busy(), "the scan must have fully drained by now");
    assert_eq!(app.global::<Home>().get_notes_total(), N as i32);
    assert_eq!(app.global::<Ui>().get_notes().row_count(), 200, "the shown window caps at NOTES_WINDOW");
    assert_eq!(st.store.as_ref().unwrap().notes.len(), N as usize);

    // Path count for a from-scratch walk of N=1000 (an EXACT multiple of
    // ESPLORA_PAGE_SIZE=25): stats + tip + utxo + the initial `/txs` page
    // (4) + 39 further FULL chain pages consuming the remaining 975 txs
    // (39*25=975) + one more chain fetch that comes back EMPTY (a full
    // page can't tell "that was the end" from "there's more" without one
    // more probe — see `scan_history`'s own doc comment) = 4 + 39 + 1 = 44.
    // Recorded here from the FIRST run of this test and pinned — if this
    // ever changes, it means the pagination math changed, not that the
    // number was wrong before.
    let rest_paths = server.drain_requests();
    let total_paths = 4 + rest_paths.len();
    assert_eq!(total_paths, 44, "exact request count for a from-scratch 1000-tx scan: {rest_paths:?}");
    assert!(
        rest_paths.iter().all(|p| p.contains("/txs/chain/") || p == &format!("/address/{address}/txs")),
        "every request after the first 4 is a history page: {rest_paths:?}"
    );

    // ---- (c) nothing changed — the fingerprint short-circuits -----------
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    assert_eq!(server.drain_requests(), vec![format!("/address/{address}")], "unchanged: only the stats precheck");
    assert!(!st.scan_gate.busy());

    // ---- (d) one CONFIRMED tx — cheap incremental catch-up --------------
    // The scenario's tip started at 10_000 (well above N=1000 confirmation
    // heights) — the new tx's height/tip must stay ABOVE that, or the
    // reorg guard (`scan_history`: a tip that moved BACKWARD makes
    // `known_confirmed` untrusted, forcing a full walk) fires and this
    // step accidentally re-tests (b) instead of the incremental path.
    add_tx(&scenario, &address, Some(10_001), "confirmed");
    scenario.lock().expect("scenario mutex").tip_height = 10_001;
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    assert_eq!(
        server.drain_requests(),
        vec![format!("/address/{address}"), "/blocks/tip/height".to_string(), format!("/address/{address}/utxo"), format!("/address/{address}/txs")],
        "known_confirmed lets page 1 alone satisfy the early stop"
    );
    assert_eq!(app.global::<Home>().get_notes_total(), N as i32 + 1);

    // ---- (e) a MEMPOOL tx, then confirming it — must_see stays cheap ----
    let pending_txid = add_tx(&scenario, &address, None, "mempool");
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    assert_eq!(
        server.drain_requests(),
        vec![format!("/address/{address}"), "/blocks/tip/height".to_string(), format!("/address/{address}/utxo"), format!("/address/{address}/txs")],
        "a mempool tx never blocks the confirmed-only early stop"
    );
    {
        let store = st.store.as_ref().unwrap();
        let n = store.notes.iter().find(|n| n.txids.contains(&pending_txid)).expect("mempool note recorded");
        assert_eq!(n.status, NoteStatus::Pending, "not yet confirmed on chain");
    }

    {
        let mut sc = scenario.lock().expect("scenario mutex");
        let tx = sc.txs.iter_mut().find(|t| t.txid == pending_txid).expect("pending tx in scenario");
        tx.confirmed_height = Some(10_002);
        sc.tip_height = 10_002;
    }
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    assert_eq!(
        server.drain_requests(),
        vec![format!("/address/{address}"), "/blocks/tip/height".to_string(), format!("/address/{address}/utxo"), format!("/address/{address}/txs")],
        "must_see re-saw the pending txid on page 1 — still no chain pages needed"
    );
    let store = st.store.as_ref().unwrap();
    let n = store.notes.iter().find(|n| n.txids.contains(&pending_txid)).expect("note still present");
    assert_eq!(n.status, NoteStatus::Confirmed, "the badge must flip to confirmed");
}

/// U1 review fix: the `/address/:a` fingerprint short-circuit must NEVER
/// fire while the store holds a pending/unconfirmed record — on the Core
/// RPC backend that stats shape can't distinguish "still pending" from
/// "just confirmed" (see `refresh_async`'s comment above the check), so
/// gating purely on the FINGERPRINT being unchanged would hide a
/// confirmation forever. This drives the same worker against the fake
/// Esplora server (whose stats DO move on confirm, unlike Core's) but with
/// the fingerprint pinned unchanged by construction — the point is to
/// prove `refresh_async` doesn't even LOOK at the fingerprint match while
/// something is pending, which is backend-agnostic.
#[test]
fn pending_record_blocks_the_fingerprint_short_circuit() {
    let _queue_lock = QUEUE_TEST_LOCK.lock().expect("queue test lock");
    i_slint_backend_testing::init_no_event_loop();

    let material = app_core::identity::parse_key_material(MNEMONIC, Network::Regtest).expect("parse material");
    let address = app_core::identity::realize(&material, Network::Regtest, 0, 0).expect("realize").address;

    let mut b = ScenarioBuilder::new(Network::Regtest, 100);
    let funder = b.taproot_addr("pending-gate-funder");
    b.add_tx(
        vec![InSpec::External { address: funder, value: 10_000 }],
        vec![
            OutSpec::Pay { address: address.clone(), value: 5_000 },
            OutSpec::OpReturn { payload: pnte_payload("seed") },
        ],
        Some(1),
    );
    let sc = b.build();
    let scenario = Arc::new(Mutex::new(sc));
    let server = EsploraFakeServer::start(scenario.clone());

    let node_urls = HashMap::from([("regtest".to_string(), server.base_url())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-pending-gate-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.discovery_pending = false; // see the other test's comment on this field

    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);

    // Establish a stamped fingerprint with nothing pending: the SECOND
    // refresh (first is never short-circuited — `prev_stats` starts None)
    // must be the classic 1-path short circuit.
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    server.drain_requests();
    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    assert_eq!(
        server.drain_requests(),
        vec![format!("/address/{address}")],
        "baseline: nothing pending, unchanged fingerprint -> exactly 1 path"
    );

    // Now inject a PENDING record directly into the store (simulating a
    // just-composed, not-yet-confirmed note) WITHOUT touching the
    // scenario at all — the fingerprint the next scan reads back is
    // BYTE-IDENTICAL to the one just stamped.
    st.store.as_mut().unwrap().notes.push(app_core::store::NoteRecord {
        note_id: "1".repeat(64),
        status: NoteStatus::Pending,
        text: Some("pending".into()),
        private: false,
        directed: false,
        received: false,
        sender: None,
        recipient: None,
        recipients: Vec::new(),
        txids: vec!["1".repeat(64)],
        height: None,
        blocktime: None,
        created_at: Some(0),
        spent: Vec::new(),
        raw_hex: None,
        fee: None,
        vsize: None,
        change_to: None,
        gift_amount: None,
        funded_by: None,
        dropped: false,
        pq_flags: 0,
        locked: None,
        locked_multi: None,
    });

    st.refresh_async(&app);
    drain_settle(&app, &mut st);
    let paths = server.drain_requests();
    assert!(
        paths.len() > 1,
        "a pending record must fall through to the incremental scan even with an unchanged fingerprint: {paths:?}"
    );
}
