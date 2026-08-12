//! M0 gate: notes-core works as an external git dependency, outside its
//! own workspace — Identity constructed from app-supplied key material
//! (public fields, no from_app_seed), compose_note over fake UTXOs,
//! deterministic signed tx with injected aux randomness.

use app_core::notes_core::bundle::{compose_note, Identity};
use app_core::notes_core::keys::xonly_pubkey;
use app_core::notes_core::taproot::{taproot_tweak_pubkey, taproot_tweak_seckey};
use app_core::notes_core::tx::Utxo;
use app_core::notes_core::Network;

fn identity_from_secret(secret: &[u8; 32]) -> Identity {
    let (internal_x, _) = xonly_pubkey(secret).unwrap();
    let (output_x, _) = taproot_tweak_pubkey(&internal_x, None).unwrap();
    let tweaked_seckey = taproot_tweak_seckey(secret, None).unwrap();
    Identity { internal_x, output_x, tweaked_seckey, enc_key: [0x42; 32] }
}

#[test]
fn compose_note_standalone() {
    let ident = identity_from_secret(&[7u8; 32]);

    let addr = ident.address(Network::Regtest);
    assert!(addr.starts_with("bcrt1p"), "not a regtest taproot address: {addr}");

    let utxos = vec![Utxo { txid: [1u8; 32], vout: 0, value: 100_000 }];
    let build = |private: bool| {
        compose_note(
            &ident,
            &utxos,
            "hello from chain-notes-app (M0 smoke)",
            private,
            80, // chunked path
            1.0,
            0,
            || Ok([0u8; 32]), // fixed aux → deterministic BIP340 signature
        )
        .unwrap()
    };

    let note = build(false);
    assert_eq!(note.txid_hex.len(), 64);
    assert!(!note.raw_hex.is_empty());
    assert!(note.fee > 0 && note.change > 0 && note.sent == 0);
    assert_eq!(note.spent_outpoints, vec![([1u8; 32], 0)]);

    // Public + fixed aux ⇒ byte-identical tx on a second build.
    let again = build(false);
    assert_eq!(note.raw_hex, again.raw_hex);
    assert_eq!(note.txid_hex, again.txid_hex);

    // Private notes must NOT be deterministic even with fixed aux: seal()
    // draws a fresh random nonce per build (host OS randomness — also
    // proves the KeyOS TRNG [patch] did not leak through the git dep).
    let p1 = build(true);
    let p2 = build(true);
    assert_ne!(p1.raw_hex, p2.raw_hex);
}
