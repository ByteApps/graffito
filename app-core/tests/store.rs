//! M3 gate: the store round-trips the whole note lifecycle with no
//! network — compose (pending, inputs locked, change chains), confirm
//! via a synthetic bundle, idempotent re-apply, wipe-recovery from bare
//! key material (private text decrypts back), cross-identity directed
//! private notes, and orphan detection.

use app_core::compose::{compose_and_record, compose_note, ComposeRequest};
use app_core::derive::identity_from_leaf;
use app_core::identity::{parse_key_material, realize};
use app_core::notes_core::bundle::{BundleUtxo, Identity, OnchainTx, SyncBundle};
use app_core::notes_core::envelope::{FLAG_MLKEM, FLAG_PW};
use app_core::notes_core::pq::MlKemAlg;
use app_core::notes_core::tx::{op_return_payload, NoteTx};
use app_core::notes_core::Network;
use app_core::pqkeys;
use app_core::spending;
use app_core::store::{LedgerUtxo, NoteRecord, NoteStatus, Store};
use app_core::Error;

const NET: Network = Network::Regtest;

// Official BIP-84/86 test-vector mnemonic — used only for the
// spending-self-notes fix tests below (Unit A/B), which need HD material
// that CAN derive a spending wallet (`identity_from_leaf`'s single-leaf
// identities can't — `spending::can_derive_spending` gates on it).
const SPENDING_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon about";

fn alice() -> Identity {
    identity_from_leaf(&[0x33u8; 32]).unwrap()
}

fn bob() -> Identity {
    identity_from_leaf(&[0x44u8; 32]).unwrap()
}

fn funded_store(identity: &Identity) -> Store {
    let mut store = Store::new(&identity.output_x, NET);
    store.utxos.push(LedgerUtxo {
        txid: "aa".repeat(32),
        vout: 0,
        value: 100_000,
        height: Some(100),
        pending_spend: false,
    });
    store
}

/// PLAN-pnte-redesign.md: the tx's FIRST input's outpoint, display-order
/// `"<txid>:<vout>"` — every private body's AAD binds this, so a bundle
/// fixture must carry it for `extract_notes*` to decrypt anything. Shared
/// by every `OnchainTx` fixture builder below; independent of which
/// identity is viewing the tx (own or received), since the outpoint is a
/// property of the tx itself.
fn first_input_outpoint_of(tx: &NoteTx) -> Option<String> {
    tx.spent_outpoints
        .first()
        .map(|(txid, vout)| app_core::notes_core::bundle::format_outpoint(txid, *vout))
}

/// Synthetic chain view of a signed note tx, as the chain client would
/// report it after confirmation.
fn onchain(tx: &NoteTx, height: u64, from_self: bool, sender: Option<&str>, recipient: Option<&str>) -> OnchainTx {
    OnchainTx {
        txid: tx.txid_hex.clone(),
        height: Some(height),
        blocktime: Some(1_700_000_000 + height),
        spends_from_self: from_self,
        payloads: tx
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey).map(hex::encode))
            .collect(),
        pays_self: true,
        sender: sender.map(String::from),
        author_candidates: sender.map(|s| vec![String::from(s)]).unwrap_or_default(),
        recipient: recipient.map(String::from),
        input_prevout_spks: Vec::new(),
        output_addrs: Vec::new(),
        first_input_outpoint: first_input_outpoint_of(tx),
    }
}

fn bundle(txs: Vec<OnchainTx>, utxos: Vec<BundleUtxo>, tip: u64) -> SyncBundle {
    SyncBundle {
        network: NET.as_str().to_string(),
        full: true,
        since_height: None,
        tip_height: tip,
        bundle_time: 1_700_000_500,
        utxos,
        notes_onchain: txs,
        ..SyncBundle::default()
    }
}

fn change_utxo(tx: &NoteTx, height: Option<u64>) -> BundleUtxo {
    BundleUtxo {
        txid: tx.txid_hex.clone(),
        vout: (tx.tx.outputs.len() - 1) as u32,
        value: tx.change,
        height,
        owner_address: None,
    }
}

#[test]
fn compose_confirm_recover_lifecycle() {
    let a = alice();
    let mut store = funded_store(&a);

    // Note 1: public. Note 2: private, spending note 1's unconfirmed
    // change (queueing between scans).
    let n1 = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "first, public", private: false, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1000, pq_password: None, pq_mlkem: None },
    )
    .unwrap();
    assert_eq!(store.notes.len(), 1);
    assert_eq!(store.notes[0].status, NoteStatus::Pending);
    assert!(store.utxos[0].pending_spend, "funding input locked");

    let n2 = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "second, private", private: true, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 2000, pq_password: None, pq_mlkem: None },
    )
    .unwrap();
    assert_eq!(
        hex::encode({ let mut t = n2.tx.spent_outpoints[0].0; t.reverse(); t }),
        n1.tx.txid_hex,
        "note 2 chains off note 1's change"
    );

    // Chain confirms both.
    let b = bundle(
        vec![onchain(&n1.tx, 101, true, None, None), onchain(&n2.tx, 102, true, None, None)],
        vec![change_utxo(&n2.tx, Some(102))],
        102,
    );
    let stats = store.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(stats.orphaned, 0);
    assert!(store.notes.iter().all(|n| n.status == NoteStatus::Confirmed));
    assert_eq!(store.balance(), n2.tx.change);
    assert_eq!(store.tip_height, 102);

    // Idempotency: re-applying the identical bundle changes nothing.
    let snapshot = serde_json::to_string(&store).unwrap();
    store.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(serde_json::to_string(&store).unwrap(), snapshot);

    // Wipe recovery: fresh store + bare key + full bundle = notebook
    // back, INCLUDING the private note's plaintext.
    let mut fresh = Store::new(&a.output_x, NET);
    fresh.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(fresh.notes.len(), 2);
    let recovered_private = fresh.notes.iter().find(|n| n.private).unwrap();
    assert_eq!(recovered_private.text.as_deref(), Some("second, private"));
    assert_eq!(recovered_private.note_id, n2.note_id);
    let recovered_public = fresh.notes.iter().find(|n| !n.private).unwrap();
    assert_eq!(recovered_public.text.as_deref(), Some("first, public"));
    assert_eq!(fresh.balance(), n2.tx.change);
}

#[test]
fn directed_private_note_both_sides() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let alice_addr = a.address(NET);

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "for bob only",
            private: true,
            recipient: Some(&bob_addr), extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None, lock_time: None, now: 3000, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(sent.tx.sent, 330, "dust delivery output");
    assert_eq!(store.contacts[0].address, bob_addr, "recipient becomes a recent contact");

    // Alice's view after confirmation: own directed note, text re-derived
    // via the dust-output recipient (open_sent) even from a fresh store.
    let alice_bundle = bundle(
        vec![onchain(&sent.tx, 105, true, None, Some(&bob_addr))],
        vec![change_utxo(&sent.tx, Some(105))],
        105,
    );
    let mut alice_fresh = Store::new(&a.output_x, NET);
    alice_fresh.apply_bundle(&alice_bundle, &a, NET, &[], &[], &[]).unwrap();
    let note = &alice_fresh.notes[0];
    assert!(note.directed && note.private && !note.received);
    assert_eq!(note.recipient.as_deref(), Some(bob_addr.as_str()));
    assert_eq!(note.text.as_deref(), Some("for bob only"));

    // Bob's view: a pays-me PNTE tx from Alice — received, attributed,
    // decrypted via reciprocal ECDH (open_received).
    let bob_bundle = bundle(
        vec![onchain(&sent.tx, 105, false, Some(&alice_addr), None)],
        vec![BundleUtxo { txid: sent.tx.txid_hex.clone(), vout: 1, value: 330, height: Some(105), owner_address: None }],
        105,
    );
    let mut bob_store = Store::new(&b.output_x, NET);
    bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &[], &[]).unwrap();
    let received = &bob_store.notes[0];
    assert!(received.received && received.private && received.directed);
    assert_eq!(received.sender.as_deref(), Some(alice_addr.as_str()));
    assert_eq!(received.text.as_deref(), Some("for bob only"));
}

fn carol() -> Identity {
    identity_from_leaf(&[0x55u8; 32]).unwrap()
}

/// An `OnchainTx` for an OWN multi-recipient note tx, with `output_addrs`
/// populated the way `app_core::chain::classify_tx_inner` populates it in
/// the real client (every NON-OP_RETURN output's address, in vout order —
/// recipients precede change by construction) — the field notes-core's
/// scanner needs to reconstruct `RecoveredNote.recipients` for a
/// FLAG_MULTI note.
fn onchain_own_multi(tx: &NoteTx, height: u64) -> OnchainTx {
    let output_addrs: Vec<String> = tx
        .tx
        .outputs
        .iter()
        .filter(|o| op_return_payload(&o.script_pubkey).is_none())
        .filter_map(|o| app_core::notes_core::address::address_from_spk(&o.script_pubkey, NET))
        .collect();
    OnchainTx {
        txid: tx.txid_hex.clone(),
        height: Some(height),
        blocktime: Some(1_700_000_000 + height),
        spends_from_self: true,
        payloads: tx
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey).map(hex::encode))
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: Vec::new(),
        output_addrs,
        first_input_outpoint: first_input_outpoint_of(tx),
    }
}

/// A multi-recipient directed note (2 recipients) round-trips through
/// scan: the store's OWN view recovers the plural `recipients` list (both
/// addresses, in order) via `output_addrs`, proving the app's
/// `classify_tx_inner`-shaped bundle producer feeds notes-core's
/// `extract_notes_multi` correctly end to end — not just at the notes-core
/// unit-test layer.
#[test]
fn multi_recipient_note_recovers_recipients_on_rescan() {
    let a = alice();
    let bob_addr = bob().address(NET);
    let carol_addr = carol().address(NET);
    let mut store = funded_store(&a);

    let composed = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "group note",
            private: false,
            recipient: Some(&bob_addr),
            extra_recipients: &[&carol_addr],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(composed.recipients, vec![bob_addr.clone(), carol_addr.clone()]);

    let b = bundle(vec![onchain_own_multi(&composed.tx, 105)], vec![change_utxo(&composed.tx, Some(105))], 105);
    let mut fresh = Store::new(&a.output_x, NET);
    fresh.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    let note = &fresh.notes[0];
    assert!(note.directed && !note.received);
    assert_eq!(note.recipient.as_deref(), Some(bob_addr.as_str()), "singular field keeps the first recipient");
    assert_eq!(note.recipients, vec![bob_addr, carol_addr], "plural field carries the full list");
    assert_eq!(note.text.as_deref(), Some("group note"));
}

#[test]
fn unconfirmed_scanned_utxo_is_spendable() {
    let a = alice();
    let mut store = Store::new(&a.output_x, NET);
    // A scan that returns one UNCONFIRMED utxo (height None) paying us.
    let b = bundle(
        vec![],
        vec![BundleUtxo { txid: "ab".repeat(32), vout: 0, value: 50_000, height: None, owner_address: None }],
        100,
    );
    store.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    // Counts toward balance and is spendable (0-conf), not filtered out.
    assert_eq!(store.balance(), 50_000);
    assert_eq!(store.available_utxos().len(), 1);
    // A note composes against it.
    let n = compose_and_record(
        &mut store, &a, NET,
        &ComposeRequest {
            text: "spend unconfirmed", private: false, recipient: None, extra_recipients: &[],
            change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(n.tx.spent_outpoints.len(), 1);
}

#[test]
fn coin_control_spends_exactly_selected() {
    let a = alice();
    let mut store = Store::new(&a.output_x, NET);
    // Three coins.
    for (i, v) in [(0u32, 60_000u64), (1, 40_000), (2, 20_000)] {
        store.utxos.push(LedgerUtxo {
            txid: format!("{i:02x}").repeat(32), vout: i, value: v,
            height: Some(100), pending_spend: false,
        });
    }
    // Select only coins #0 (60k) and #2 (20k) — skip the 40k.
    let picks = vec![
        (store.utxos[0].txid.clone(), 0u32),
        (store.utxos[2].txid.clone(), 2u32),
    ];
    let n = compose_and_record(
        &mut store, &a, NET,
        &ComposeRequest {
            text: "coin control", private: false, recipient: None, extra_recipients: &[],
            change_to: None, coins: Some(&picks), fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    // Spent exactly the two selected coins (not the 40k).
    assert_eq!(n.tx.spent_outpoints.len(), 2);
    let spent_vouts: std::collections::HashSet<u32> =
        n.tx.spent_outpoints.iter().map(|(_, v)| *v).collect();
    assert!(spent_vouts.contains(&0) && spent_vouts.contains(&2));
    assert!(!spent_vouts.contains(&1), "unselected coin not spent");
    // The 40k coin stays spendable; the selected two are pending-locked.
    let spendable: Vec<_> = store.utxos.iter().filter(|u| !u.pending_spend).collect();
    // change (to self) added + the untouched 40k.
    assert!(spendable.iter().any(|u| u.value == 40_000));
}

#[test]
fn custom_change_address_not_tracked_as_own_coin() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let mut store = funded_store(&a);
    let n = compose_and_record(
        &mut store, &a, NET,
        &ComposeRequest {
            text: "change goes to bob", private: false, recipient: None, extra_recipients: &[],
            change_to: Some(&bob_addr), coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    // The note records the custom change destination...
    assert_eq!(store.notes[0].change_to.as_deref(), Some(bob_addr.as_str()));
    // ...and the change is NOT a spendable coin (it left the wallet):
    // only the funding input remains, now pending-locked.
    assert!(n.tx.change > 0, "there was change");
    let spendable: Vec<_> = store.utxos.iter().filter(|u| !u.pending_spend).collect();
    assert!(spendable.is_empty(), "custom change must not be tracked");
    // Sanity: the same note with default change WOULD track the change.
    let mut store2 = funded_store(&a);
    compose_and_record(
        &mut store2, &a, NET,
        &ComposeRequest {
            text: "change to self", private: false, recipient: None, extra_recipients: &[],
            change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(store2.utxos.iter().filter(|u| !u.pending_spend).count(), 1);
}

/// PLAN-pnte-redesign.md: the note id IS the txid, so an RBF bump — a
/// DIFFERENT tx (same inputs, higher fee) — gets a DIFFERENT id, and the
/// stored record is renamed/rekeyed to it (superseding the old
/// `bump_fee_same_note_id_same_inputs_higher_fee`'s "identity survives
/// RBF" assumption, which was true only under the old synthetic-4-byte-id
/// scheme). The id only stabilizes once the note confirms.
#[test]
fn bump_fee_renames_note_id_to_replacement_txid_same_inputs_higher_fee() {
    use app_core::compose::bump_fee;
    let a = alice();
    let mut store = funded_store(&a);
    let n1 = compose_and_record(
        &mut store, &a, NET,
        &ComposeRequest { text: "bump me", private: true, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None },
    )
    .unwrap();
    assert!(store.notes[0].raw_hex.is_some(), "raw kept for rebroadcast");
    assert_eq!(n1.note_id, n1.tx.txid_hex, "the note id IS the just-built tx's txid");

    let bumped = bump_fee(&mut store, &a, NET, &n1.note_id, 5.0).unwrap();
    assert_ne!(bumped.note_id, n1.note_id, "a fee-bump is a DIFFERENT tx, so a DIFFERENT id");
    assert_eq!(bumped.note_id, bumped.tx.txid_hex, "the new id IS the replacement's txid");
    assert_ne!(bumped.tx.txid_hex, n1.tx.txid_hex, "txid changes");
    assert!(bumped.tx.fee > n1.tx.fee, "fee actually higher");
    assert_eq!(bumped.tx.spent_outpoints, n1.tx.spent_outpoints, "same inputs");
    let rec = &store.notes[0];
    assert_eq!(rec.note_id, bumped.note_id, "the stored record was RENAMED to the replacement's txid");
    assert_eq!(rec.txids, vec![n1.tx.txid_hex.clone(), bumped.tx.txid_hex.clone()]);
    assert_eq!(rec.raw_hex.as_deref(), Some(bumped.tx.raw_hex.as_str()));
    // Old change gone from the ledger, new change present.
    assert!(!store.utxos.iter().any(|u| u.txid == n1.tx.txid_hex));
    assert!(store.utxos.iter().any(|u| u.txid == bumped.tx.txid_hex));

    // Confirmation of the bumped tx clears raw_hex and confirms the note
    // under the RENAMED id — post-confirmation ids never change again.
    let b = bundle(
        vec![onchain(&bumped.tx, 120, true, None, None)],
        vec![change_utxo(&bumped.tx, Some(120))],
        120,
    );
    store.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(store.notes[0].status, NoteStatus::Confirmed);
    assert_eq!(store.notes[0].note_id, bumped.tx.txid_hex);
    assert!(store.notes[0].raw_hex.is_none());
}

#[test]
fn orphaned_when_inputs_spent_elsewhere() {
    let a = alice();
    let mut store = funded_store(&a);
    compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "never broadcast", private: false, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1, pq_password: None, pq_mlkem: None },
    )
    .unwrap();

    // Full rescan: the funding UTXO is gone (spent by another wallet
    // holding the same key) and our txid never appeared.
    let empty = bundle(vec![], vec![], 110);
    let stats = store.apply_bundle(&empty, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(stats.orphaned, 1);
    assert_eq!(store.notes[0].status, NoteStatus::Orphaned);
    assert_eq!(store.balance(), 0);
}

#[test]
fn sweep_tx_record_bump_and_confirm() {
    use app_core::compose::bump_raw_tx;
    use app_core::store::TxInput;
    let a = alice();
    let mut store = funded_store(&a);
    // Two coins so a self-send has inputs.
    store.utxos.push(LedgerUtxo {
        txid: "bb".repeat(32), vout: 1, value: 40_000, height: Some(100), pending_spend: false,
    });
    let me = app_core::notes_core::address::Recipient::parse(NET, &a.address(NET)).unwrap();
    let inputs: Vec<TxInput> = store.utxos.iter()
        .map(|u| TxInput { txid: u.txid.clone(), vout: u.vout, value: u.value }).collect();
    let tx = app_core::notes_core::tx::build_sweep_tx(
        &store.available_utxos(), &a.output_x, me.spk.clone(), 1.0, 0, &a.tweaked_seckey,
        app_core::notes_core::keys::generate_aux_rand).unwrap();
    for u in &mut store.utxos { u.pending_spend = true; }
    store.record_tx("consolidate", tx.txid_hex.clone(), tx.tx.outputs[0].value, tx.fee,
        tx.vsize as u64, tx.raw_hex.clone(), "self".into(), inputs, hex::encode(&me.spk), 1000);
    assert_eq!(store.txs.len(), 1);
    assert_eq!(store.txs[0].status, NoteStatus::Pending);

    // RBF bump: same inputs, higher fee, new txid appended.
    let bumped = bump_raw_tx(&mut store, &a, &tx.txid_hex, 8.0).unwrap();
    assert_ne!(bumped.txid_hex, tx.txid_hex);
    assert!(bumped.fee > tx.fee);
    assert_eq!(store.txs[0].txids, vec![tx.txid_hex.clone(), bumped.txid_hex.clone()]);
    assert_eq!(store.txs[0].raw_hex.as_deref(), Some(bumped.raw_hex.as_str()));

    // A full scan alone no longer confirms (inputs vanishing only proves
    // mempool acceptance); the record settles when the node reports the
    // REPLACEMENT txid in a block.
    let b = bundle(vec![], vec![change_utxo(&bumped, Some(120))], 120);
    store.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(store.txs[0].status, NoteStatus::Pending);
    let winner = bumped.txid_hex.clone();
    store.resolve_spend_statuses(|t| if t == winner { Some(true) } else { None });
    assert_eq!(store.txs[0].status, NoteStatus::Confirmed);
    assert!(store.txs[0].raw_hex.is_none());
}

#[test]
fn identity_mismatch_rejected_and_persistence_roundtrip() {
    let a = alice();
    let mut store = funded_store(&a);
    let err = store.apply_bundle(&bundle(vec![], vec![], 1), &bob(), NET, &[], &[], &[]);
    assert!(err.is_err(), "bundle for a different identity must be refused");

    store.touch_contact("bcrt1qsomeone");
    store.name_contact("bcrt1qsomeone", "someone");
    store.touch_contact("bcrt1qother");
    assert_eq!(store.contacts[0].address, "bcrt1qother", "touch puts newest first");
    store.remove_contact("bcrt1qother");
    assert_eq!(store.contacts.len(), 1);
    assert_eq!(store.contacts[0].name, "someone", "remove leaves others intact");
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("store-roundtrip.json");
    store.save(&path).unwrap();
    let loaded = Store::load(&path).unwrap();
    assert_eq!(serde_json::to_string(&store).unwrap(), serde_json::to_string(&loaded).unwrap());
    assert_eq!(loaded.contacts[0].name, "someone");
}

/// Back-compat: stores written before the node choice moved to device-level
/// config used a bare `"esplora"` key. The serde `alias` must keep those
/// loading into `node_url` — the field the app reads once, on load, to migrate
/// the value into config.json — so upgrading never silently drops a custom node.
#[test]
fn legacy_esplora_key_loads_into_node_url() {
    let json = r#"{
        "version": 1,
        "network": "regtest",
        "identity_fingerprint": "00",
        "address": "bcrt1p",
        "esplora": "http://127.0.0.1:3002"
    }"#;
    let store: Store = serde_json::from_str(json).unwrap();
    assert_eq!(store.node_url.as_deref(), Some("http://127.0.0.1:3002"));
    // And it re-serializes under the new key.
    assert!(serde_json::to_string(&store).unwrap().contains("node_url"));
}

#[test]
fn directed_gift_amount_plumbs_through() {
    let a = alice();
    let bob_addr = bob().address(NET);
    let gift = 25_000u64;

    // A custom gift reaches the recipient output and is recorded.
    let mut store = funded_store(&a);
    let n = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "happy birthday",
            private: false,
            recipient: Some(&bob_addr), extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: Some(gift),
            lock_time: None,
            now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(n.tx.sent, gift, "gift reaches the recipient output");
    assert!(store.notes[0].directed);
    assert_eq!(store.notes[0].gift_amount, Some(gift), "gift stored on the record");

    // RBF fee-bump keeps the same gift (not reset to dust).
    let id = store.notes[0].note_id.clone();
    let bumped = app_core::compose::bump_fee(&mut store, &a, NET, &id, 5.0).unwrap();
    assert_eq!(bumped.tx.sent, gift, "fee-bump preserves the gift");

    // A None gift defaults to dust.
    let mut store2 = funded_store(&a);
    let d = compose_and_record(
        &mut store2,
        &a,
        NET,
        &ComposeRequest {
            text: "hi",
            private: false,
            recipient: Some(&bob_addr), extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(d.tx.sent, app_core::notes_core::DUST_LIMIT, "default gift is dust");
    assert_eq!(store2.notes[0].gift_amount, Some(app_core::notes_core::DUST_LIMIT));
}

/// Watch-only recovery: a key-less store rebuilds the same notebook from
/// the same bundle — public text readable, private bodies sealed, balance
/// identical — idempotently, and the fingerprint guard still holds.
#[test]
fn watch_store_recovers_notebook_without_keys() {
    let a = alice();
    let mut store = funded_store(&a);
    let n1 = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "first, public", private: false, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 1000, pq_password: None, pq_mlkem: None },
    )
    .unwrap();
    let n2 = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "second, private", private: true, recipient: None, extra_recipients: &[], change_to: None, coins: None, fee_rate: 1.0, gift_amount: None, lock_time: None, now: 2000, pq_password: None, pq_mlkem: None },
    )
    .unwrap();
    let b = bundle(
        vec![onchain(&n1.tx, 101, true, None, None), onchain(&n2.tx, 102, true, None, None)],
        vec![change_utxo(&n2.tx, Some(102))],
        102,
    );

    let mut keyed = Store::new(&a.output_x, NET);
    keyed.apply_bundle(&b, &a, NET, &[], &[], &[]).unwrap();
    let mut watch = Store::new(&a.output_x, NET);
    let stats = watch.apply_bundle_watch(&b, &a.output_x, NET, &[], &[]).unwrap();
    assert_eq!(stats.notes_new, 2);
    assert_eq!(watch.address, keyed.address);
    assert_eq!(watch.balance(), keyed.balance());

    let wpub = watch.notes.iter().find(|n| !n.private).unwrap();
    assert_eq!(wpub.text.as_deref(), Some("first, public"));
    let wpriv = watch.notes.iter().find(|n| n.private).unwrap();
    assert!(wpriv.text.is_none(), "watch store must hold ciphertext only");
    assert_eq!(wpriv.note_id, n2.note_id);
    assert_eq!(keyed.notes.iter().find(|n| n.private).unwrap().text.as_deref(), Some("second, private"));

    // Idempotent re-apply: private stays sealed, nothing duplicates.
    let snapshot = serde_json::to_string(&watch).unwrap();
    watch.apply_bundle_watch(&b, &a.output_x, NET, &[], &[]).unwrap();
    assert_eq!(serde_json::to_string(&watch).unwrap(), snapshot);

    // Fingerprint guard works keyless too.
    assert!(watch.apply_bundle_watch(&b, &bob().output_x, NET, &[], &[]).is_err());
}

/// Spend records settle on REAL confirmation, not on their inputs
/// vanishing: mempool-only keeps them Pending (Speed-up/Rebroadcast
/// stay possible), a block-confirmed RBF replacement settles via ANY
/// txid in the record, and unknown txids alone never confirm.
#[test]
fn spend_records_confirm_by_tx_status_not_utxo_disappearance() {
    let a = alice();
    let mut store = funded_store(&a);
    store.record_tx(
        "sweep",
        "aa".repeat(32),
        90_000,
        500,
        110,
        "raw".into(),
        "tb1qdest".into(),
        vec![app_core::store::TxInput { txid: "aa".repeat(32), vout: 0, value: 100_000 }],
        "0014".into(),
        1_000,
    );

    // Full bundle WITHOUT the spent coin: the old inference would have
    // confirmed here. It must stay Pending now.
    let empty = bundle(vec![], vec![], 200);
    store.apply_bundle(&empty, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(store.txs[0].status, NoteStatus::Pending, "mempool-spent is not finality");
    assert!(store.txs[0].raw_hex.is_some(), "rebroadcast must stay possible");

    // Node says: original in mempool only → still pending.
    assert_eq!(store.resolve_spend_statuses(|_| Some(false)), 0);
    assert_eq!(store.txs[0].status, NoteStatus::Pending);

    // RBF bump replaced it: original unknown, bump txid confirmed.
    let bump = "bb".repeat(32);
    store.txs[0].txids.push(bump.clone());
    assert_eq!(store.resolve_spend_statuses(|t| if t == bump { Some(true) } else { None }), 1);
    assert_eq!(store.txs[0].status, NoteStatus::Confirmed);
    assert!(store.txs[0].raw_hex.is_none());

    // All-unknown never confirms (node outage ≠ mined).
    store.record_tx("consolidate", "cc".repeat(32), 1, 1, 1, "r".into(), "self".into(), vec![], "51".into(), 2_000);
    assert_eq!(store.resolve_spend_statuses(|_| None), 0);
    assert_eq!(store.txs[1].status, NoteStatus::Pending);
}

// ---------------------------------------------------------------------
// DISPLAY-OWNER dedup for multi-notebook own notes (notes-core rev
// 6e36a23, 2026-07-18 design decision — a protocol DISPLAY rule, not an
// ownership change): a tx that spends from MULTIPLE of a wallet's
// notebook addresses must display in only ONE notebook's store — the
// scan of the notebook whose spk is the FIRST notebook input in tx
// order. `Store::apply_bundle`'s new `notebook_spks` argument threads
// straight into `extract_notes_multi_deduped`; these tests prove that
// plumbing at the store level (notes-core's own tests already cover the
// extraction rule itself byte-for-byte). `alice`/`bob` stand in for two
// sibling notebooks of the same wallet — their derivation path is
// irrelevant here, only their distinct notebook spks matter.
// ---------------------------------------------------------------------

fn notebook_spk(identity: &Identity) -> Vec<u8> {
    app_core::notes_core::address::p2tr_script_pubkey(&identity.output_x)
}

/// A crafted `OnchainTx` for `tx` whose `input_prevout_spks` claims it
/// spends from every notebook in `input_notebooks`, in that order —
/// never a shape our own composers produce (they only ever spend from
/// one notebook), but exactly what a foreign wallet could craft, which
/// is what `extract_notes_multi_deduped` disambiguates.
fn onchain_multi_notebook_input(tx: &NoteTx, height: u64, input_notebooks: &[&Identity]) -> OnchainTx {
    OnchainTx {
        txid: tx.txid_hex.clone(),
        height: Some(height),
        blocktime: Some(1_700_000_000 + height),
        spends_from_self: false,
        payloads: tx
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey).map(hex::encode))
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: input_notebooks.iter().map(|id| hex::encode(notebook_spk(id))).collect(),
        output_addrs: Vec::new(),
        first_input_outpoint: first_input_outpoint_of(tx),
    }
}

/// The core rule: notebook A's input comes first in the crafted tx, so
/// scanning the SAME tx independently as both notebook A's and notebook
/// B's store keeps the note only in A's — never-zero across the pair,
/// never doubled either.
#[test]
fn display_owner_dedup_keeps_note_only_in_first_notebook_input_scan() {
    let a = alice();
    let b = bob();
    let spk_a = notebook_spk(&a);
    let spk_b = notebook_spk(&b);

    let mut store = funded_store(&a);
    let n = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "owned by two notebooks",
            private: false,
            recipient: None, extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 4000, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    // Crafted: the tx's input_prevout_spks claims A's input first, B's second.
    let tx = onchain_multi_notebook_input(&n.tx, 700, &[&a, &b]);
    let scan_bundle = bundle(vec![tx], vec![], 700);
    let notebook_spks = vec![spk_a.clone(), spk_b.clone()];

    let mut store_a = Store::new(&a.output_x, NET);
    let stats_a = store_a.apply_bundle(&scan_bundle, &a, NET, &notebook_spks, &[], &[]).unwrap();
    let mut store_b = Store::new(&b.output_x, NET);
    let stats_b = store_b.apply_bundle(&scan_bundle, &b, NET, &notebook_spks, &[], &[]).unwrap();

    assert_eq!(store_a.notes.len(), 1, "notebook A (first notebook input) keeps the note");
    assert_eq!(stats_a.notes_seen, 1);
    assert_eq!(store_b.notes.len(), 0, "notebook B must not also display it");
    assert_eq!(stats_b.notes_seen, 0);
}

/// EDGE RULE (review): an ARCHIVED notebook must be excluded from the
/// `notebook_spks` set fed to `apply_bundle` (see
/// `identity::active_notebook_spks`), so its input can never anchor —
/// and therefore never suppress — a note that also touches an ACTIVE
/// notebook. Same crafted shape, but B's input is now FIRST in tx order
/// while the caller's `notebook_spks` (standing in for "B is archived,
/// only A is active") omits B entirely. The anchor search must skip
/// straight past B to A's (later) input, so A still keeps the note
/// despite not being first in the tx.
#[test]
fn display_owner_dedup_archived_notebook_input_never_anchors() {
    let a = alice();
    let b = bob();
    let spk_a = notebook_spk(&a);

    let mut store = funded_store(&a);
    let n = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "b archived, a active",
            private: false,
            recipient: None, extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 4100, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    // B's input FIRST, A's SECOND — but notebook_spks (the archived-
    // exclusion caller contract) omits B, as if it were archived.
    let tx = onchain_multi_notebook_input(&n.tx, 701, &[&b, &a]);
    let scan_bundle = bundle(vec![tx], vec![], 701);
    let notebook_spks = vec![spk_a.clone()]; // B deliberately excluded

    let mut store_a = Store::new(&a.output_x, NET);
    let stats_a = store_a.apply_bundle(&scan_bundle, &a, NET, &notebook_spks, &[], &[]).unwrap();

    assert_eq!(
        store_a.notes.len(),
        1,
        "active notebook A must keep the note even though the (archived) B input came first"
    );
    assert_eq!(stats_a.notes_seen, 1);
}

// ---------------------------------------------------------------------
// spending-self-notes fix (PLAN-chain-notes-app-spending-self-notes.md),
// Units A + B: a note composed by the app but funded purely from the
// spending wallet (BIP-84, P2WPKH inputs, dust change back to the
// notebook) has no notebook input and no taproot input — the old
// snapshot-only self-spk set can't recognize it as own, so it scans
// RECEIVED with `sender = None` → sender_key "unknown" (RC1), and a
// prior bad scan's record lingers forever even after a corrected rescan
// (RC2).
// ---------------------------------------------------------------------

/// A scan result for a note tx funded ENTIRELY from the spending wallet:
/// no notebook input (`spends_from_self: false`), no taproot input to
/// name a sender (`sender: None`) — only a 330-sat dust change output
/// back to the notebook (`pays_self: true`) and the spending address's
/// scriptPubKey as the sole input prevout. This is the exact shape RC1
/// describes.
fn onchain_spending_funded(tx: &NoteTx, height: u64, spending_spk: &[u8]) -> OnchainTx {
    OnchainTx {
        txid: tx.txid_hex.clone(),
        height: Some(height),
        blocktime: Some(1_700_000_000 + height),
        spends_from_self: false,
        payloads: tx
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey).map(hex::encode))
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: vec![hex::encode(spending_spk)],
        output_addrs: Vec::new(),
        first_input_outpoint: first_input_outpoint_of(tx),
    }
}

/// A stale `received`/"unknown" twin, exactly as a pre-fix scan (running
/// with an empty/stale self-spk snapshot) would have stored it — for
/// seeding a store as if a bad scan already ran once.
fn stale_received_twin(note_id: &str, txid: &str, height: u64) -> NoteRecord {
    NoteRecord {
        note_id: note_id.to_string(),
        status: NoteStatus::Confirmed,
        text: None,
        private: false,
        directed: false,
        received: true,
        sender: None,
        recipient: None,
        recipients: Vec::new(),
        txids: vec![txid.to_string()],
        height: Some(height),
        blocktime: Some(1_700_000_000 + height),
        created_at: None,
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
    }
}

/// Unit A / RC1: a spent-empty spending address that is NOT in the
/// recorded-`used` snapshot, but IS within the derived window, flips
/// classification from received/"unknown" to own — proving the window
/// (not the recorded snapshot) is what fixes it.
#[test]
fn spending_window_spk_makes_funded_note_own() {
    let material = parse_key_material(SPENDING_MNEMONIC, NET).unwrap();
    let ident = realize(&material, NET, 0, 0).unwrap();
    let a = ident.full().unwrap();

    let mut store = funded_store(a);
    let n1 = compose_and_record(
        &mut store,
        a,
        NET,
        &ComposeRequest {
            text: "spending-funded self note",
            private: false,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 9000, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    // Index 7 — never recorded `used`, but comfortably inside a 100-wide
    // window (WINDOW_MIN in lib.rs).
    let spending_spk =
        spending::derive_spending_key(&material, NET, 0, 0, 7).unwrap().script_pubkey;
    let window = spending::window_spks(&material, NET, 0, 100).unwrap();
    assert!(window.contains(&spending_spk), "index 7 must fall inside a 100-wide window");

    let b = bundle(
        vec![onchain_spending_funded(&n1.tx, 900, &spending_spk)],
        vec![change_utxo(&n1.tx, Some(900))],
        900,
    );

    // Empty window (today's bug reproduced): no notebook input, no
    // taproot input to name a sender — RECEIVED, sender "unknown".
    let mut without_window = Store::new(&a.output_x, NET);
    without_window.apply_bundle(&b, a, NET, &[], &[], &[]).unwrap();
    assert_eq!(without_window.notes.len(), 1);
    assert!(without_window.notes[0].received, "no window: classifies received (the bug)");
    assert_eq!(without_window.sender_key(&without_window.notes[0]), "unknown");

    // Widened window: the SAME bundle now classifies OWN.
    let mut with_window = Store::new(&a.output_x, NET);
    with_window.apply_bundle(&b, a, NET, &[], &window, &[]).unwrap();
    assert_eq!(with_window.notes.len(), 1);
    assert!(!with_window.notes[0].received, "widened window: classifies OWN");
    assert_eq!(with_window.sender_key(&with_window.notes[0]), with_window.address);
}

/// Unit B / RC2: a store already carrying the stale `received`/"unknown"
/// twin, re-scanned (full bundle) with the widened window, ends with
/// exactly ONE note — own — and the stale twin is gone.
#[test]
fn stale_received_twin_pruned_on_full_scan() {
    let material = parse_key_material(SPENDING_MNEMONIC, NET).unwrap();
    let ident = realize(&material, NET, 0, 0).unwrap();
    let a = ident.full().unwrap();

    let mut store = funded_store(a);
    let n1 = compose_and_record(
        &mut store,
        a,
        NET,
        &ComposeRequest {
            text: "spending-funded self note",
            private: false,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 9100, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    let spending_spk =
        spending::derive_spending_key(&material, NET, 0, 0, 3).unwrap().script_pubkey;
    let window = spending::window_spks(&material, NET, 0, 100).unwrap();

    let mut fresh = Store::new(&a.output_x, NET);
    fresh.notes.push(stale_received_twin(&n1.note_id, &n1.tx.txid_hex, 899));

    let b = bundle(
        vec![onchain_spending_funded(&n1.tx, 900, &spending_spk)],
        vec![change_utxo(&n1.tx, Some(900))],
        900,
    );
    let stats = fresh.apply_bundle(&b, a, NET, &[], &window, &[]).unwrap();

    assert_eq!(stats.reclassified, 1, "the stale received twin must be pruned");
    assert_eq!(fresh.notes.len(), 1, "exactly one note remains");
    assert!(!fresh.notes[0].received, "the surviving note is OWN");
    assert!(
        fresh.notes.iter().all(|n| fresh.sender_key(n) != "unknown"),
        "no record left keyed under the unknown bucket"
    );
}

/// REGRESSION: a genuinely third-party received note (its tx does NOT
/// spend any of our self-spks, however wide that set gets) must never be
/// pruned — the pays-me-can't-hijack-an-own-note guard, preserved in the
/// direction Unit B does NOT touch.
#[test]
fn third_party_received_note_never_pruned() {
    let a = alice();
    let b = bob();
    let alice_addr = a.address(NET);

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "for bob only",
            private: true,
            recipient: Some(&b.address(NET)),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 9200, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    // Bob's view: a genuine pays-me tx from Alice. Its input is Alice's
    // own coin — it never spends any of Bob's self-spks, however wide
    // that set gets (a large decoy set stands in for a maximally widened
    // window, to prove the guard holds even then).
    let bob_bundle = bundle(
        vec![onchain(&sent.tx, 950, false, Some(&alice_addr), None)],
        vec![BundleUtxo {
            txid: sent.tx.txid_hex.clone(),
            vout: 1,
            value: 330,
            height: Some(950),
            owner_address: None,
        }],
        950,
    );
    let decoy_spks: Vec<Vec<u8>> = (0u8..50).map(|i| vec![i; 22]).collect();

    let mut bob_store = Store::new(&b.output_x, NET);
    let stats = bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &decoy_spks, &[]).unwrap();
    assert_eq!(stats.reclassified, 0);
    assert_eq!(bob_store.notes.len(), 1);
    assert!(bob_store.notes[0].received);
    assert_eq!(bob_store.notes[0].sender.as_deref(), Some(alice_addr.as_str()));

    // A second full scan (idempotency) must not prune it either.
    let stats2 = bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &decoy_spks, &[]).unwrap();
    assert_eq!(stats2.reclassified, 0);
    assert_eq!(bob_store.notes.len(), 1);
    assert!(bob_store.notes[0].received);
}

/// Unit B is gated on `bundle.full`: an incremental bundle must never
/// prune, even when it independently recovers the same note as own.
#[test]
fn stale_received_twin_not_pruned_on_incremental_bundle() {
    let material = parse_key_material(SPENDING_MNEMONIC, NET).unwrap();
    let ident = realize(&material, NET, 0, 0).unwrap();
    let a = ident.full().unwrap();

    let mut store = funded_store(a);
    let n1 = compose_and_record(
        &mut store,
        a,
        NET,
        &ComposeRequest {
            text: "spending-funded self note",
            private: false,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 9300, pq_password: None, pq_mlkem: None,
        },
    )
    .unwrap();

    let spending_spk =
        spending::derive_spending_key(&material, NET, 0, 0, 5).unwrap().script_pubkey;
    let window = spending::window_spks(&material, NET, 0, 100).unwrap();

    let mut fresh = Store::new(&a.output_x, NET);
    fresh.notes.push(stale_received_twin(&n1.note_id, &n1.tx.txid_hex, 899));

    let mut incremental = bundle(
        vec![onchain_spending_funded(&n1.tx, 900, &spending_spk)],
        vec![change_utxo(&n1.tx, Some(900))],
        900,
    );
    incremental.full = false;

    let stats = fresh.apply_bundle(&incremental, a, NET, &[], &window, &[]).unwrap();
    assert_eq!(stats.reclassified, 0, "an incremental bundle must never prune");
    assert_eq!(fresh.notes.len(), 2, "the stale twin AND the freshly-own note both exist");
    assert!(fresh.notes.iter().any(|n| n.received), "the stale twin survives the incremental apply");
    assert!(fresh.notes.iter().any(|n| !n.received), "the new own note was still added");
}

// ---------------------------------------------------------------------------
// Post-quantum notes (pq.rs hybrid layers): compose e2e through canned
// bundles for password-only, ML-KEM-only, and both together, plus the
// store's locked-note lifecycle (scan -> locked, unlock -> cached,
// re-scan -> cache preserved).
// ---------------------------------------------------------------------------

// `bob()`'s notes identity leaf (matches `identity_from_leaf(&[0x44u8; 32])`
// above) — `pqkeys::derive_keypair`/`derive_secrets` need the raw leaf
// bytes directly (not the derived `Identity`), same "same leaf as the
// notebook" contract `pqkeys`'s module doc describes.
const BOB_LEAF: [u8; 32] = [0x44u8; 32];

/// Bob's derived ML-KEM-768 receive keypair — same leaf secret `bob()`
/// derives its notes identity from, matching `pqkeys`' "same leaf as the
/// notebook" contract.
fn bob_pq_keypair() -> app_core::notes_core::pq::MlKemKeypair {
    pqkeys::derive_keypair(&BOB_LEAF, MlKemAlg::MlKem768)
}

/// A received-note fixture: Bob's view of `tx` (Alice -> Bob, dust output
/// at vout 1) — mirrors `directed_private_note_both_sides`'s `bob_bundle`
/// construction exactly.
fn bob_receives(tx: &NoteTx, alice_addr: &str, height: u64) -> SyncBundle {
    bundle(
        vec![onchain(tx, height, false, Some(alice_addr), None)],
        vec![BundleUtxo {
            txid: tx.txid_hex.clone(),
            vout: 1,
            value: 330,
            height: Some(height),
            owner_address: None,
        }],
        height,
    )
}

/// Alice's own view of her just-sent `tx` — mirrors
/// `directed_private_note_both_sides`'s `alice_bundle` construction.
fn alice_own_view(tx: &NoteTx, bob_addr: &str, height: u64) -> SyncBundle {
    bundle(
        vec![onchain(tx, height, true, None, Some(bob_addr))],
        vec![change_utxo(tx, Some(height))],
        height,
    )
}

/// Structural validation: a pq layer on anything other than a single-
/// recipient directed PRIVATE note, or a private SELF-note, is refused
/// loudly, never silently dropped. Covers: a public note and a multi-
/// recipient pick — one representative failure each is enough (the guard
/// is a single `if` in `compose_note`, not per-shape logic). A self-note
/// pq layer is NOT in this list since PLAN-graffito-self-pw.md (2026-08-22)
/// — see `pq_self_note_with_password_is_stored_locked_and_never_cached`
/// and the ML-KEM case in `pq_self_note_with_mlkem_layer_composes`.
#[test]
fn pq_layers_require_single_recipient_directed_private_or_self() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let store = funded_store(&a);

    // Public note (private: false) + a password layer.
    let err = compose_note(
        &store,
        &a,
        NET,
        &ComposeRequest {
            text: "nope",
            private: false,
            recipient: Some(&bob_addr),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some("hunter2hunter2hunter2".into()),
            pq_mlkem: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Store(_)));

    // A public SELF-note (private: false, no recipient) + a password layer
    // — private is required regardless of recipient shape.
    let err = compose_note(
        &store,
        &a,
        NET,
        &ComposeRequest {
            text: "nope",
            private: false,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some("hunter2hunter2hunter2".into()),
            pq_mlkem: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Store(_)));

    // Multi-recipient (extra_recipients adds a distinct address) + a
    // password layer.
    let carol_addr = carol().address(NET);
    let err = compose_note(
        &store,
        &a,
        NET,
        &ComposeRequest {
            text: "nope",
            private: true,
            recipient: Some(&bob_addr),
            extra_recipients: &[&carol_addr],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some("hunter2hunter2hunter2".into()),
            pq_mlkem: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Store(_)));
}

/// Self-note pq compose routing (PLAN-graffito-self-pw.md): a private
/// SELF-note (no recipient) with an ML-KEM layer alone is accepted and
/// carries JUST `FLAG_MLKEM` — a self-note pq layer is no longer refused
/// the way it was before this feature (see the previous test's doc
/// comment). The recipient/multi-recipient bookkeeping stays empty, same
/// as any other self-note.
#[test]
fn pq_self_note_with_mlkem_layer_composes() {
    let a = alice();
    let store = funded_store(&a);
    let kp = bob_pq_keypair(); // stand-in for an imported (non-seed-derived) key
    let composed = compose_note(
        &store,
        &a,
        NET,
        &ComposeRequest {
            text: "self note, quantum-sealed",
            private: true,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: None,
            pq_mlkem: Some((MlKemAlg::MlKem768, kp.ek().to_vec())),
        },
    )
    .unwrap();
    assert_eq!(composed.pq_flags, FLAG_MLKEM);
    assert!(composed.recipient_address.is_none());
    assert!(composed.recipients.is_empty());
}

/// Password-only pq note: recoverable by EITHER party who knows the
/// password (the module doc's "no asymmetric secret" property) — neither
/// side auto-unlocks on scan (passwords are never stored/guessed), both
/// unlock explicitly via `Store::unlock_note`, and Bob's own re-scan after
/// unlocking must never clobber the cached plaintext back to locked.
#[test]
fn pq_password_only_note_round_trips_both_sides_and_survives_rescan() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let alice_addr = a.address(NET);
    let password = "correct horse battery staple extra";

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "pw only, for bob",
            private: true,
            recipient: Some(&bob_addr),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some(password.into()),
            pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(sent.pq_flags, FLAG_PW);
    // The sender's OWN store cached the plaintext directly at compose time
    // (no decryption needed — they just typed it).
    assert_eq!(store.notes[0].text.as_deref(), Some("pw only, for bob"));
    assert_eq!(store.notes[0].pq_flags, FLAG_PW);
    assert!(store.notes[0].locked.is_none(), "the composer's own copy is never locked");

    // Alice, wipe-recovered: her own pq note comes back LOCKED (auto-
    // unlock never runs for an own note or a password-involving one).
    let alice_bundle = alice_own_view(&sent.tx, &bob_addr, 105);
    let mut alice_fresh = Store::new(&a.output_x, NET);
    alice_fresh.apply_bundle(&alice_bundle, &a, NET, &[], &[], &[]).unwrap();
    assert_eq!(alice_fresh.notes.len(), 1);
    assert!(alice_fresh.notes[0].text.is_none(), "no auto-unlock for an own pq note");
    assert!(alice_fresh.notes[0].locked.is_some());
    assert_eq!(alice_fresh.notes[0].pq_flags, FLAG_PW);
    let note_id = alice_fresh.notes[0].note_id.clone();
    // Wrong password fails cleanly and never mutates the record.
    assert!(alice_fresh.unlock_note(&note_id, &a, &[], Some("wrong password")).is_err());
    assert!(alice_fresh.notes[0].locked.is_some(), "a failed unlock must not clear locked");
    // Right password re-opens via unlock_sent (sender-reopen — password-
    // only is the ONE pq shape a sender can ever recover this way).
    let text = alice_fresh.unlock_note(&note_id, &a, &[], Some(password)).unwrap();
    assert_eq!(text, "pw only, for bob");
    assert_eq!(alice_fresh.notes[0].text.as_deref(), Some("pw only, for bob"));
    assert!(alice_fresh.notes[0].locked.is_none(), "unlocking clears locked");

    // Bob's view: received, locked (password-only never auto-unlocks even
    // though he's the recipient), then explicitly unlocked.
    let bob_bundle = bob_receives(&sent.tx, &alice_addr, 105);
    let mut bob_store = Store::new(&b.output_x, NET);
    bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &[], &[]).unwrap();
    assert_eq!(bob_store.notes.len(), 1);
    assert!(bob_store.notes[0].received);
    assert!(bob_store.notes[0].text.is_none());
    assert_eq!(bob_store.notes[0].pq_flags, FLAG_PW);
    let bob_note_id = bob_store.notes[0].note_id.clone();
    let text = bob_store.unlock_note(&bob_note_id, &b, &[], Some(password)).unwrap();
    assert_eq!(text, "pw only, for bob");
    assert!(bob_store.notes[0].locked.is_none());

    // Re-scan (idempotent full-bundle re-apply, no secrets supplied this
    // time): Bob's already-unlocked cache must survive untouched — the
    // "fresh success wins, a still-locked re-derivation never clobbers a
    // good cache" rule from `fresh_decode_corrects_stale_text_cache`,
    // extended to pq notes.
    bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &[], &[]).unwrap();
    assert_eq!(bob_store.notes[0].text.as_deref(), Some("pw only, for bob"));
    assert!(bob_store.notes[0].locked.is_none(), "a re-scan must not re-lock an unlocked note");
}

/// ML-KEM-only pq note: Bob AUTO-unlocks on scan when his derived secret
/// is supplied to `apply_bundle` (the only auto-unlock case — received +
/// KEM-only); without it he stays locked and must call `unlock_note`
/// explicitly. Alice, the sender, can NEVER reopen it — no asymmetric
/// secret was ever hers to begin with (`SenderCannotReopen`).
#[test]
fn pq_kem_only_note_auto_unlocks_for_recipient_with_derived_secret() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let alice_addr = a.address(NET);
    let bob_kp = bob_pq_keypair();

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "kem only, for bob",
            private: true,
            recipient: Some(&bob_addr),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: None,
            pq_mlkem: Some((MlKemAlg::MlKem768, bob_kp.ek().to_vec())),
        },
    )
    .unwrap();
    assert_eq!(sent.pq_flags, FLAG_MLKEM);

    let bob_bundle = bob_receives(&sent.tx, &alice_addr, 200);

    // Without any secret: stays locked.
    let mut bob_locked = Store::new(&b.output_x, NET);
    bob_locked.apply_bundle(&bob_bundle, &b, NET, &[], &[], &[]).unwrap();
    assert!(bob_locked.notes[0].text.is_none());
    assert!(bob_locked.notes[0].locked.is_some());

    // With the WRONG level's secret (512, not the 768 this was sealed
    // to): still locked — cryptographically indistinguishable from
    // tampering, never a crash.
    let wrong_level = pqkeys::derive_secrets(&BOB_LEAF)
        .into_iter()
        .next() // MlKem512, per derive_secrets' documented [512, 768, 1024] order
        .unwrap();
    let mut bob_wrong = Store::new(&b.output_x, NET);
    bob_wrong.apply_bundle(&bob_bundle, &b, NET, &[], &[], std::slice::from_ref(&wrong_level)).unwrap();
    assert!(bob_wrong.notes[0].text.is_none(), "wrong-level secret must not authenticate");

    // With Bob's FULL derived secret set (all three levels — the same
    // union `apply_bundle`'s doc comment describes): auto-unlocks.
    let secrets = pqkeys::derive_secrets(&BOB_LEAF);
    let mut bob_auto = Store::new(&b.output_x, NET);
    bob_auto.apply_bundle(&bob_bundle, &b, NET, &[], &[], &secrets).unwrap();
    assert_eq!(bob_auto.notes[0].text.as_deref(), Some("kem only, for bob"));
    assert!(bob_auto.notes[0].locked.is_none());

    // Re-scan with an EMPTY secret set this time: the auto-unlocked cache
    // must survive (never re-locked by a weaker follow-up scan).
    bob_auto.apply_bundle(&bob_bundle, &b, NET, &[], &[], &[]).unwrap();
    assert_eq!(bob_auto.notes[0].text.as_deref(), Some("kem only, for bob"));
    assert!(bob_auto.notes[0].locked.is_none());

    // Explicit unlock_note path (no auto-unlock) also works, given the
    // right secret.
    let bob_note_id = bob_locked.notes[0].note_id.clone();
    let secret_only = pqkeys::derive_keypair(&BOB_LEAF, MlKemAlg::MlKem768).secret();
    let text =
        bob_locked.unlock_note(&bob_note_id, &b, std::slice::from_ref(&secret_only), None).unwrap();
    assert_eq!(text, "kem only, for bob");

    // Alice, the sender, structurally CANNOT reopen a KEM-layered note —
    // she never held the ML-KEM secret (it was encapsulated to Bob's key).
    let alice_bundle = alice_own_view(&sent.tx, &bob_addr, 200);
    let mut alice_fresh = Store::new(&a.output_x, NET);
    alice_fresh.apply_bundle(&alice_bundle, &a, NET, &[], &[], &[]).unwrap();
    let alice_note_id = alice_fresh.notes[0].note_id.clone();
    let err = alice_fresh.unlock_note(&alice_note_id, &a, &[], None).unwrap_err();
    assert!(
        matches!(err, Error::Notes(app_core::notes_core::Error::SenderCannotReopen)),
        "expected SenderCannotReopen, got {err:?}"
    );
}

/// Hybrid (both layers): unlocking needs the ML-KEM secret AND the
/// password TOGETHER — the sealing key is one HKDF over both shared
/// secrets combined, so a partial credential (only one of the two)
/// authenticates nothing (implicit-rejection/AEAD-failure territory,
/// not a distinct "which one was wrong" error).
#[test]
fn pq_hybrid_note_needs_both_layers_together() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);
    let alice_addr = a.address(NET);
    let bob_kp = bob_pq_keypair();
    let password = "hybrid layer password, quite long";

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "hybrid, for bob",
            private: true,
            recipient: Some(&bob_addr),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some(password.into()),
            pq_mlkem: Some((MlKemAlg::MlKem768, bob_kp.ek().to_vec())),
        },
    )
    .unwrap();
    assert_eq!(sent.pq_flags, FLAG_PW | FLAG_MLKEM);

    let bob_bundle = bob_receives(&sent.tx, &alice_addr, 300);
    let secrets = pqkeys::derive_secrets(&BOB_LEAF);

    // Auto-unlock never runs for a hybrid note (pq_flags != FLAG_MLKEM
    // exactly) — locked regardless of secrets supplied to apply_bundle.
    let mut bob_store = Store::new(&b.output_x, NET);
    bob_store.apply_bundle(&bob_bundle, &b, NET, &[], &[], &secrets).unwrap();
    assert!(bob_store.notes[0].text.is_none());
    let note_id = bob_store.notes[0].note_id.clone();

    // Secret alone, no password: fails.
    assert!(bob_store.unlock_note(&note_id, &b, &secrets, None).is_err());
    assert!(bob_store.notes[0].locked.is_some());
    // Password alone, no secret: fails.
    assert!(bob_store.unlock_note(&note_id, &b, &[], Some(password)).is_err());
    assert!(bob_store.notes[0].locked.is_some());
    // Both together: succeeds.
    let text = bob_store.unlock_note(&note_id, &b, &secrets, Some(password)).unwrap();
    assert_eq!(text, "hybrid, for bob");
    assert!(bob_store.notes[0].locked.is_none());
}

/// A fee-bump attempt on a pq note is refused loudly (its layers can't be
/// re-sealed without the original password/ek, which `bump_fee_build`'s
/// signature doesn't carry) rather than silently rebuilding a plain v1
/// replacement that drops both layers.
#[test]
fn pq_note_refuses_fee_bump() {
    let a = alice();
    let b = bob();
    let bob_addr = b.address(NET);

    let mut store = funded_store(&a);
    let sent = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "pq, don't bump me",
            private: true,
            recipient: Some(&bob_addr),
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some("some reasonably long password".into()),
            pq_mlkem: None,
        },
    )
    .unwrap();

    let err =
        app_core::compose::bump_fee_build(&store, &a, NET, &sent.note_id, 5.0, None).unwrap_err();
    assert!(matches!(err, Error::Store(_)));
}

// ---------------------------------------------------------------------------
// Self-note pq layers (PLAN-graffito-self-pw.md, 2026-08-22): password and/or
// ML-KEM on a private SELF-note. Unlike a directed pq note (which the
// composer caches plaintext for immediately — see the tests above), a
// self-pq note is stored LOCKED from the moment it's signed and only ever
// unlocked VIEW-ONLY: `Store::unlock_note_view` never writes into `text`
// and never clears `locked`.
// ---------------------------------------------------------------------------

/// Compose routing: a self-note (no recipient) with a password layer
/// produces a tx whose FIRST OP_RETURN header carries
/// `FLAG_PRIVATE | FLAG_PW` (decoded independently via
/// `envelope::decode_note`, not trusted from `composed.pq_flags` alone),
/// and the recorded store entry has NO cached plaintext and
/// `locked.is_self()` — the store never gets a chance to hold the
/// plaintext next to the password-protected note, unlike a directed pq
/// note (whose composer already had the text in hand with nothing to
/// decrypt).
#[test]
fn pq_self_note_with_password_is_stored_locked_and_never_cached() {
    use app_core::notes_core::envelope::FLAG_PRIVATE;

    let a = alice();
    let password = "a genuinely long self-note passphrase";
    let mut store = funded_store(&a);
    let composed = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: "my private diary entry",
            private: true,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some(password.into()),
            pq_mlkem: None,
        },
    )
    .unwrap();
    assert_eq!(composed.pq_flags, FLAG_PW);
    assert!(composed.recipient_address.is_none());

    // Byte-truth check on the wire header itself, independent of anything
    // the compose path claims about itself.
    let payloads: Vec<Vec<u8>> = composed
        .tx
        .tx
        .outputs
        .iter()
        .filter(|o| o.script_pubkey.first() == Some(&0x6a))
        .filter_map(|o| op_return_payload(&o.script_pubkey).map(<[u8]>::to_vec))
        .collect();
    let decoded = app_core::notes_core::envelope::decode_note(&payloads).unwrap();
    assert_eq!(decoded.flags, FLAG_PRIVATE | FLAG_PW, "no FLAG_DIRECTED on a self-note");

    // The store record: empty text, a self-scoped locked body.
    assert_eq!(store.notes.len(), 1);
    let rec = &store.notes[0];
    assert!(rec.text.is_none(), "a self-pq note must never cache plaintext, even for the composer");
    assert_eq!(rec.pq_flags, FLAG_PW);
    let locked = rec.locked.as_ref().expect("self-pq note must be recorded locked");
    assert!(locked.is_self(), "not a directed locked body");
    assert!(!rec.directed);
    assert!(!rec.received);
}

/// View-only unlock (PLAN-graffito-self-pw.md): `Store::unlock_note_view`
/// returns the plaintext for display, but — unlike `Store::unlock_note` —
/// never persists it: the record's `text` stays `None`, `locked` survives
/// untouched, and a round-trip through `Store::save`/`Store::load` (a real
/// file on disk) proves the plaintext was never written anywhere, not even
/// transiently. Every future open must ask again.
#[test]
fn pq_self_note_unlock_is_view_only_and_never_persists() {
    let a = alice();
    let password = "another self-note passphrase, plenty long";
    let plaintext = "only readable with the password";
    let mut store = funded_store(&a);
    let composed = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest {
            text: plaintext,
            private: true,
            recipient: None,
            extra_recipients: &[],
            change_to: None,
            coins: None,
            fee_rate: 1.0,
            gift_amount: None,
            lock_time: None,
            now: 1,
            pq_password: Some(password.into()),
            pq_mlkem: None,
        },
    )
    .unwrap();
    let note_id = composed.note_id.clone();

    // Wrong password fails cleanly and never mutates the record.
    let err = store.unlock_note_view(&note_id, &a, None, Some("wrong password")).unwrap_err();
    assert!(matches!(err, Error::Notes(_)));
    assert!(store.notes[0].locked.is_some(), "a failed unlock must not clear locked");
    assert!(store.notes[0].text.is_none());

    // `unlock_note` (the directed-note fn) must refuse a self locked body —
    // the two paths never cross.
    let cross_err = store.unlock_note(&note_id, &a, &[], Some(password)).unwrap_err();
    assert!(matches!(cross_err, Error::Notes(_)), "got: {cross_err:?}");
    assert!(store.notes[0].locked.is_some(), "the wrong-path attempt must not mutate either");

    // Right password: returns the plaintext, but the STORE stays untouched.
    let text = store.unlock_note_view(&note_id, &a, None, Some(password)).unwrap();
    assert_eq!(text, plaintext);
    assert!(store.notes[0].text.is_none(), "view-only must never cache the plaintext");
    assert!(store.notes[0].locked.is_some(), "view-only must never clear locked");

    // Persist to a real file and reload — the disk copy must carry neither
    // the plaintext nor any trace of it, and `locked` must survive the
    // round-trip byte-identically.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("self-pq-view-only-store.json");
    store.save(&path).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        !on_disk.contains(plaintext),
        "the plaintext must never reach disk, not even transiently"
    );
    let loaded = Store::load(&path).unwrap();
    let loaded_rec = loaded.notes.iter().find(|n| n.note_id == note_id).unwrap();
    assert!(loaded_rec.text.is_none());
    assert!(loaded_rec.locked.is_some());
    assert_eq!(loaded_rec.locked, store.notes[0].locked, "locked body survives the round-trip");

    // Unlocking the RELOADED store still works — the locked body alone is
    // enough to recover the note (no session-only state was needed).
    let text_again = loaded.unlock_note_view(&note_id, &a, None, Some(password)).unwrap();
    assert_eq!(text_again, plaintext);
}

/// `CLASSIFY_VERSION` bump pin (PLAN-graffito-self-pw.md): a `PW|PRIVATE`
/// (no `FLAG_DIRECTED`) header was UNDECODABLE before this feature — an
/// older build's scan recorded no note at all for such a tx, own or
/// otherwise. Bumping this constant is what forces one full rescan per
/// store so those notes stop being invisible on an already-quiet wallet
/// (the `addr_stats` short-circuit otherwise never triggers one on its
/// own). This test pins the exact value so a future bump (for an unrelated
/// reason) doesn't accidentally undo this one, and a missing bump doesn't
/// silently ship.
#[test]
fn classify_version_bumped_for_self_pw_notes() {
    assert_eq!(app_core::store::CLASSIFY_VERSION, 5);
}
