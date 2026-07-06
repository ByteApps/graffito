//! M3 gate: the store round-trips the whole note lifecycle with no
//! network — compose (pending, inputs locked, change chains), confirm
//! via a synthetic bundle, idempotent re-apply, wipe-recovery from bare
//! key material (private text decrypts back), cross-identity directed
//! private notes, and orphan detection.

use app_core::compose::{compose_and_record, ComposeRequest};
use app_core::derive::identity_from_leaf;
use app_core::notes_core::bundle::{BundleUtxo, Identity, OnchainTx, SyncBundle};
use app_core::notes_core::tx::{op_return_payload, NoteTx};
use app_core::notes_core::Network;
use app_core::store::{LedgerUtxo, NoteStatus, Store};

const NET: Network = Network::Regtest;

fn alice() -> Identity {
    identity_from_leaf(&[0x33u8; 32]).unwrap()
}

fn bob() -> Identity {
    identity_from_leaf(&[0x44u8; 32]).unwrap()
}

fn funded_store(identity: &Identity) -> Store {
    let mut store = Store::new(identity, NET);
    store.utxos.push(LedgerUtxo {
        txid: "aa".repeat(32),
        vout: 0,
        value: 100_000,
        height: Some(100),
        pending_spend: false,
    });
    store
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
        recipient: recipient.map(String::from),
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
        &ComposeRequest { text: "first, public", private: false, recipient: None, fee_rate: 1.0, now: 1000 },
    )
    .unwrap();
    assert_eq!(store.notes.len(), 1);
    assert_eq!(store.notes[0].status, NoteStatus::Pending);
    assert!(store.utxos[0].pending_spend, "funding input locked");

    let n2 = compose_and_record(
        &mut store,
        &a,
        NET,
        &ComposeRequest { text: "second, private", private: true, recipient: None, fee_rate: 1.0, now: 2000 },
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
    let stats = store.apply_bundle(&b, &a, NET).unwrap();
    assert_eq!(stats.orphaned, 0);
    assert!(store.notes.iter().all(|n| n.status == NoteStatus::Confirmed));
    assert_eq!(store.balance(), n2.tx.change);
    assert_eq!(store.tip_height, 102);

    // Idempotency: re-applying the identical bundle changes nothing.
    let snapshot = serde_json::to_string(&store).unwrap();
    store.apply_bundle(&b, &a, NET).unwrap();
    assert_eq!(serde_json::to_string(&store).unwrap(), snapshot);

    // Wipe recovery: fresh store + bare key + full bundle = notebook
    // back, INCLUDING the private note's plaintext.
    let mut fresh = Store::new(&a, NET);
    fresh.apply_bundle(&b, &a, NET).unwrap();
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
            recipient: Some(&bob_addr),
            fee_rate: 1.0,
            now: 3000,
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
    let mut alice_fresh = Store::new(&a, NET);
    alice_fresh.apply_bundle(&alice_bundle, &a, NET).unwrap();
    let note = &alice_fresh.notes[0];
    assert!(note.directed && note.private && !note.received);
    assert_eq!(note.recipient.as_deref(), Some(bob_addr.as_str()));
    assert_eq!(note.text.as_deref(), Some("for bob only"));

    // Bob's view: a pays-me PNTE tx from Alice — received, attributed,
    // decrypted via reciprocal ECDH (open_received).
    let bob_bundle = bundle(
        vec![onchain(&sent.tx, 105, false, Some(&alice_addr), None)],
        vec![BundleUtxo { txid: sent.tx.txid_hex.clone(), vout: 1, value: 330, height: Some(105) }],
        105,
    );
    let mut bob_store = Store::new(&b, NET);
    bob_store.apply_bundle(&bob_bundle, &b, NET).unwrap();
    let received = &bob_store.notes[0];
    assert!(received.received && received.private && received.directed);
    assert_eq!(received.sender.as_deref(), Some(alice_addr.as_str()));
    assert_eq!(received.text.as_deref(), Some("for bob only"));
}

#[test]
fn bump_fee_same_note_id_same_inputs_higher_fee() {
    use app_core::compose::bump_fee;
    let a = alice();
    let mut store = funded_store(&a);
    let n1 = compose_and_record(
        &mut store, &a, NET,
        &ComposeRequest { text: "bump me", private: true, recipient: None, fee_rate: 1.0, now: 1 },
    )
    .unwrap();
    assert!(store.notes[0].raw_hex.is_some(), "raw kept for rebroadcast");

    let bumped = bump_fee(&mut store, &a, NET, &n1.note_id, 5.0).unwrap();
    assert_eq!(bumped.note_id, n1.note_id, "note identity survives RBF");
    assert_ne!(bumped.tx.txid_hex, n1.tx.txid_hex, "txid changes");
    assert!(bumped.tx.fee > n1.tx.fee, "fee actually higher");
    assert_eq!(bumped.tx.spent_outpoints, n1.tx.spent_outpoints, "same inputs");
    let rec = &store.notes[0];
    assert_eq!(rec.txids, vec![n1.tx.txid_hex.clone(), bumped.tx.txid_hex.clone()]);
    assert_eq!(rec.raw_hex.as_deref(), Some(bumped.tx.raw_hex.as_str()));
    // Old change gone from the ledger, new change present.
    assert!(!store.utxos.iter().any(|u| u.txid == n1.tx.txid_hex));
    assert!(store.utxos.iter().any(|u| u.txid == bumped.tx.txid_hex));

    // Confirmation of the bumped tx clears raw_hex and confirms the note.
    let b = bundle(
        vec![onchain(&bumped.tx, 120, true, None, None)],
        vec![change_utxo(&bumped.tx, Some(120))],
        120,
    );
    store.apply_bundle(&b, &a, NET).unwrap();
    assert_eq!(store.notes[0].status, NoteStatus::Confirmed);
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
        &ComposeRequest { text: "never broadcast", private: false, recipient: None, fee_rate: 1.0, now: 1 },
    )
    .unwrap();

    // Full rescan: the funding UTXO is gone (spent by another wallet
    // holding the same key) and our txid never appeared.
    let empty = bundle(vec![], vec![], 110);
    let stats = store.apply_bundle(&empty, &a, NET).unwrap();
    assert_eq!(stats.orphaned, 1);
    assert_eq!(store.notes[0].status, NoteStatus::Orphaned);
    assert_eq!(store.balance(), 0);
}

#[test]
fn identity_mismatch_rejected_and_persistence_roundtrip() {
    let a = alice();
    let mut store = funded_store(&a);
    let err = store.apply_bundle(&bundle(vec![], vec![], 1), &bob(), NET);
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
