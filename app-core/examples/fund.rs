//! One-off test-funding tool: spend from a P2WPKH WIF (FUND_WIF env) to
//! a destination address. Testnet plumbing for the M7 live pass — NOT
//! part of the shipped app.
//!
//! usage: fund <network> <base-url> <dest-address> <amount-sats> <fee-sats>

use app_core::chain::{ChainClient, HttpTransport, Transport};
use app_core::notes_core::Network as CnNetwork;
use bitcoin::hashes::Hash;
use bitcoin::key::CompressedPublicKey;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute, transaction, Address, Amount, OutPoint, PrivateKey, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use std::str::FromStr;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let net = CnNetwork::from_str_opt(&a[1]).expect("network");
    let btc_net = app_core::derive::btc_network(net);
    let wif = PrivateKey::from_wif(std::env::var("FUND_WIF").expect("FUND_WIF").trim())
        .expect("WIF");
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pk = CompressedPublicKey::from_private_key(&secp, &wif).expect("compressed");
    let source = Address::p2wpkh(&pk, btc_net);
    let dest = Address::from_str(&a[3]).expect("dest").require_network(btc_net).expect("net");
    let amount: u64 = a[4].parse().expect("amount");
    let fee: u64 = a[5].parse().expect("fee");

    let client = ChainClient::new(HttpTransport::new(&a[2]), net);
    let mut utxos = client.utxos(&source.to_string()).expect("utxos");
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
    let mut selected = Vec::new();
    let mut in_value = 0u64;
    for u in utxos {
        in_value += u.value;
        selected.push(u);
        if in_value >= amount + fee {
            break;
        }
    }
    assert!(in_value >= amount + fee, "insufficient funds: {in_value}");

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: dest.script_pubkey(),
    }];
    let change = in_value - amount - fee;
    if change > 294 {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: source.script_pubkey(),
        });
    }
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: selected
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&u.txid).expect("txid"),
                    vout: u.vout,
                },
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };

    let spk = source.script_pubkey();
    let values: Vec<u64> = selected.iter().map(|u| u.value).collect();
    let mut cache = SighashCache::new(&mut tx);
    for (i, value) in values.iter().enumerate() {
        let sighash = cache
            .p2wpkh_signature_hash(i, &spk, Amount::from_sat(*value), EcdsaSighashType::All)
            .expect("sighash");
        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        let sig = bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &wif.inner),
            sighash_type: EcdsaSighashType::All,
        };
        *cache.witness_mut(i).expect("witness") = Witness::p2wpkh(&sig, &pk.0);
    }
    let raw = bitcoin::consensus::encode::serialize_hex(&tx);
    let txid = client.transport.post_text("/tx", raw).expect("broadcast");
    println!("fund: sent {amount} sats to {} txid={}", a[3], txid.trim());
}
