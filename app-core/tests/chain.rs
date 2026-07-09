//! M2 gate: the chain client reproduces, from recorded live testnet4
//! fixtures, exactly what viewer.html shows for the standing identities —
//! the sim's own PRIVATE note surfaces with text=None under a foreign
//! key, the throwaway's own PUBLIC note reads with no key at all.

use std::cell::RefCell;
use std::collections::HashMap;

use app_core::chain::{default_base, ChainClient, Transport};
use app_core::derive::identity_from_leaf;
use app_core::notes_core::bundle::{extract_notes, extract_notes_watch};
use app_core::notes_core::Network;
use app_core::Error;

const SIM_ADDR: &str = "tb1p548gt356p9jrhr6p5hfvd83km5zus936hlcfyzl0xhmtg5av2arquy4wpk";
const SIM_PRIVATE_TXID: &str = "25c3046f9c8ce3b7e305498fbcf97a6c1bcc2d4880b8033412cfa9a67a882179";
const THROWAWAY_ADDR: &str = "tb1p4nmywn3zrs9n6ugzlez32urjejln52t07gnqd2pkk3sq20t6wugsdyezke";
const THROWAWAY_PUBLIC_TXID: &str =
    "9097778ec53b2b5b9f8270a7e404487643bdbdccaa81bf8af7aafb3b0404b8bc";

struct Fixture {
    routes: HashMap<String, String>,
    posts: RefCell<Vec<(String, String)>>,
    requests: RefCell<Vec<String>>,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            routes: HashMap::new(),
            posts: RefCell::new(Vec::new()),
            requests: RefCell::new(Vec::new()),
        }
    }

    fn file(mut self, path: &str, fixture: &str) -> Self {
        let body = std::fs::read_to_string(format!(
            "{}/tests/fixtures/{fixture}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|_| panic!("fixture {fixture}"));
        self.routes.insert(path.to_string(), body);
        self
    }

    fn body(mut self, path: &str, body: &str) -> Self {
        self.routes.insert(path.to_string(), body.to_string());
        self
    }

    fn for_address(addr: &str, txs_fixture: &str, utxo_fixture: &str) -> Self {
        let fx = Fixture::new()
            .file(&format!("/address/{addr}/txs"), txs_fixture)
            .file(&format!("/address/{addr}/utxo"), utxo_fixture)
            .file("/v1/fees/recommended", "fees.json")
            .file("/v1/prices", "prices.json")
            .file("/blocks/tip/height", "tip.txt");
        // The client always probes one continuation page after the last
        // confirmed txid (the first page can't prove history is complete)
        // — serve it an empty page, as live testnet4 would.
        let txs: Vec<serde_json::Value> =
            serde_json::from_str(fx.routes.get(&format!("/address/{addr}/txs")).unwrap())
                .unwrap();
        let last_confirmed = txs
            .iter()
            .filter(|t| t["status"]["confirmed"].as_bool() == Some(true))
            .last()
            .and_then(|t| t["txid"].as_str().map(String::from));
        match last_confirmed {
            Some(txid) => fx.body(&format!("/address/{addr}/txs/chain/{txid}"), "[]"),
            None => fx,
        }
    }
}

impl Transport for Fixture {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        self.requests.borrow_mut().push(path.to_string());
        self.routes
            .get(path)
            .cloned()
            .ok_or_else(|| Error::Http(format!("no fixture for {path}")))
    }

    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        self.posts.borrow_mut().push((path.to_string(), body));
        Ok("a".repeat(64))
    }
}

fn foreign_identity() -> app_core::notes_core::bundle::Identity {
    identity_from_leaf(&[0x33u8; 32]).unwrap()
}

#[test]
fn sim_identity_private_note_surfaces_undecrypted() {
    let fx = Fixture::for_address(SIM_ADDR, "sim-txs.json", "sim-utxo.json");
    let client = ChainClient::new(fx, Network::Testnet4);
    let bundle = client.build_bundle(SIM_ADDR, None).unwrap();

    assert!(bundle.full);
    assert_eq!(bundle.network, "testnet4");
    assert_eq!(bundle.tip_height, 143129);
    assert_eq!(bundle.fee_rates.fastest, 1.0);
    assert!(bundle.btc_usd.is_some());
    assert!(bundle.utxos.is_empty(), "sim funds were swept");

    let notes = extract_notes(&bundle, &foreign_identity(), Network::Testnet4);
    let private = notes
        .iter()
        .find(|n| n.txids.contains(&SIM_PRIVATE_TXID.to_string()))
        .expect("the standing private note");
    assert!(private.private);
    assert!(!private.received, "spends_from_self ⇒ own note");
    assert_eq!(private.text, None, "foreign key must not decrypt it");
    assert!(private.height.is_some());
}

#[test]
fn throwaway_public_note_reads_without_any_key() {
    let fx = Fixture::for_address(THROWAWAY_ADDR, "throwaway-txs.json", "throwaway-utxo.json");
    let client = ChainClient::new(fx, Network::Testnet4);
    let bundle = client.build_bundle(THROWAWAY_ADDR, None).unwrap();

    let notes = extract_notes(&bundle, &foreign_identity(), Network::Testnet4);
    let public = notes
        .iter()
        .find(|n| n.txids.contains(&THROWAWAY_PUBLIC_TXID.to_string()))
        .expect("the 224-byte relay-probe note");
    assert!(!public.private);
    assert!(!public.received);
    let text = public.text.as_ref().expect("public notes decode with no key");
    assert!(!text.is_empty());

    // Funding/sweep txs carry no OP_RETURN — they must not appear.
    assert_eq!(bundle.notes_onchain.len(), 1);
}

#[test]
fn incremental_bundle_filters_by_height() {
    let fx = Fixture::for_address(SIM_ADDR, "sim-txs.json", "sim-utxo.json");
    let client = ChainClient::new(fx, Network::Testnet4);

    let full = client.build_bundle(SIM_ADDR, None).unwrap();
    let heights: Vec<u64> =
        full.notes_onchain.iter().filter_map(|t| t.height).collect();
    let max = *heights.iter().max().expect("confirmed notes exist");

    // since = max ⇒ nothing new; since = max-1 ⇒ only the newest remain.
    let none_new = client.build_bundle(SIM_ADDR, Some(max)).unwrap();
    assert!(!none_new.full);
    assert!(none_new.notes_onchain.iter().all(|t| t.height.is_none()));

    let some = client.build_bundle(SIM_ADDR, Some(max - 1)).unwrap();
    assert!(some
        .notes_onchain
        .iter()
        .all(|t| t.height.map_or(true, |h| h > max - 1)));
}

#[test]
fn pagination_follows_full_pages() {
    let addr = "tb1qdummy";
    let mk_tx = |i: u32| {
        serde_json::json!({
            "txid": format!("{i:064x}"),
            "vin": [],
            "vout": [],
            "status": {"confirmed": true, "block_height": 100 + i, "block_time": 1}
        })
    };
    let page1: Vec<_> = (0..25).map(mk_tx).collect();
    let last1 = format!("{:064x}", 24);
    let page2: Vec<_> = (25..30).map(mk_tx).collect();
    let last2 = format!("{:064x}", 29);

    let fx = Fixture::new()
        .body(&format!("/address/{addr}/txs"), &serde_json::to_string(&page1).unwrap())
        .body(
            &format!("/address/{addr}/txs/chain/{last1}"),
            &serde_json::to_string(&page2).unwrap(),
        )
        // Completion isn't inferred from a short page (backends disagree on
        // page size) — the client probes once more and stops on an empty page.
        .body(&format!("/address/{addr}/txs/chain/{last2}"), "[]");
    let client = ChainClient::new(fx, Network::Testnet4);
    let history = client.full_history(addr).unwrap();
    assert_eq!(history.len(), 30);
    // Two continuation probes: after page1 (→ page2) and after page2 (→ empty).
    assert_eq!(
        client
            .transport
            .requests
            .borrow()
            .iter()
            .filter(|p| p.contains("/txs/chain/"))
            .count(),
        2
    );
}

#[test]
fn broadcast_posts_raw_hex() {
    let fx = Fixture::new();
    let client = ChainClient::new(fx, Network::Testnet4);
    let txid = client.broadcast("02000000beef").unwrap();
    assert_eq!(txid.len(), 64);
    let posts = client.transport.posts.borrow();
    assert_eq!(posts.as_slice(), &[("/tx".to_string(), "02000000beef".to_string())]);
}

#[test]
fn default_bases() {
    assert_eq!(default_base(Network::Mainnet), Some("https://mempool.space/api"));
    assert_eq!(
        default_base(Network::Testnet4),
        Some("https://mempool.space/testnet4/api")
    );
    assert!(default_base(Network::Regtest).is_none());
}

/// The stage-1 watch-only story on real recorded chain data: a key-less
/// scan of the sim identity sees the standing private note's metadata
/// with its body sealed — identical shape to the foreign-key view.
#[test]
fn watch_scan_of_sim_identity_seals_private_note() {
    let fx = Fixture::for_address(SIM_ADDR, "sim-txs.json", "sim-utxo.json");
    let client = ChainClient::new(fx, Network::Testnet4);
    let bundle = client.build_bundle(SIM_ADDR, None).unwrap();

    let notes = extract_notes_watch(&bundle, Network::Testnet4);
    let private = notes
        .iter()
        .find(|n| n.txids.contains(&SIM_PRIVATE_TXID.to_string()))
        .expect("the standing private note");
    assert!(private.private);
    assert!(!private.received, "spends_from_self ⇒ own note");
    assert_eq!(private.text, None, "watch scan must not decrypt");

    // And the throwaway's public note still reads keylessly.
    let fx = Fixture::for_address(THROWAWAY_ADDR, "throwaway-txs.json", "throwaway-utxo.json");
    let client = ChainClient::new(fx, Network::Testnet4);
    let bundle = client.build_bundle(THROWAWAY_ADDR, None).unwrap();
    let public = extract_notes_watch(&bundle, Network::Testnet4)
        .into_iter()
        .find(|n| n.txids.contains(&THROWAWAY_PUBLIC_TXID.to_string()))
        .expect("the relay-probe note");
    assert!(public.text.is_some(), "public notes decode with no key");
}
