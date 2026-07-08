//! Host CLI over app-core for the regtest e2e — plays the APP role the
//! Slint shell will play later: identity from key material, scan via a
//! live esplora-shaped endpoint, compose+broadcast, list notes, and emit
//! sync-bundle JSON for ANY address (feeds prime's notes_cli — the two
//! cores share the SyncBundle serde). NOT part of the shipped app.
//!
//! Key material comes from APP_KEY (any accepted format: mnemonic /
//! xprv / WIF / 32-byte hex), so secrets never sit in argv.

use std::str::FromStr;

use app_core::chain::{ChainClient, HttpTransport};
use app_core::compose::{compose_and_record, ComposeRequest};
use app_core::funding::FundingSource;
use app_core::identity::{parse_key_material, realize, AppIdentity};
use app_core::notes_core::address::Recipient;
use app_core::notes_core::Network;
use app_core::psbt_build::{build_funding_psbt, FundingPlan, NoteParams};
use app_core::psbt_finalize::{finalize_extract, parse_psbt};
use app_core::store::{NoteStatus, Store};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;

fn identity(network: Network) -> AppIdentity {
    let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | xprv | WIF | hex32");
    let account = std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
    let material = parse_key_material(&key, network).expect("APP_KEY parse");
    realize(&material, network, account).expect("APP_KEY realize")
}

fn network(s: &str) -> Network {
    Network::from_str_opt(s).expect("network: mainnet|testnet4|signet|regtest")
}

fn load(path: &str) -> Store {
    Store::load(std::path::Path::new(path)).expect("store load")
}

fn save(store: &Store, path: &str) {
    store.save(std::path::Path::new(path)).expect("store save");
}

fn status_str(s: NoteStatus) -> &'static str {
    match s {
        NoteStatus::Pending => "pending",
        NoteStatus::Confirmed => "confirmed",
        NoteStatus::Orphaned => "orphaned",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("address") => {
            // address <network>
            let net = network(&args[2]);
            println!("{}", identity(net).address);
        }
        Some("init") => {
            // init <store.json> <network>
            let net = network(&args[3]);
            let ident = identity(net);
            let store = Store::new(&ident.identity, net);
            save(&store, &args[2]);
            println!(
                "cli: init kind={} network={} address={}",
                ident.kind,
                net.as_str(),
                ident.address
            );
        }
        Some("scan") => {
            // scan <store.json> <base-url>
            let mut store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let bundle = client.build_bundle(&store.address, None).expect("build bundle");
            let stats = store.apply_bundle(&bundle, &ident.identity, net).expect("apply");
            save(&store, &args[2]);
            println!(
                "cli: scan notes={} new={} orphaned={} balance={} tip={}",
                stats.notes_seen,
                stats.notes_new,
                stats.orphaned,
                store.balance(),
                store.tip_height
            );
        }
        Some("notes") => {
            // notes <store.json>
            let store = load(&args[2]);
            for n in &store.notes {
                println!(
                    "note id={} status={} private={} directed={} received={} from={} to={} text={}",
                    n.note_id,
                    status_str(n.status),
                    n.private,
                    n.directed,
                    n.received,
                    n.sender.as_deref().unwrap_or("-"),
                    n.recipient.as_deref().unwrap_or("-"),
                    n.text.as_deref().unwrap_or("-"),
                );
            }
        }
        Some("compose") => {
            // compose <store.json> <base-url> <public|private> <fee_rate> <text> [to_addr]
            let mut store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let private = match args[4].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[5].parse().expect("fee rate");
            let to = args.get(7).map(String::as_str);
            let composed = compose_and_record(
                &mut store,
                &ident.identity,
                net,
                &ComposeRequest {
                    text: &args[6],
                    private,
                    recipient: to,
                    change_to: None,
                    coins: None,
                    fee_rate,
                    now: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                },
            )
            .expect("compose");
            save(&store, &args[2]);
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let txid = client.broadcast(&composed.tx.raw_hex).expect("broadcast");
            assert_eq!(txid, composed.tx.txid_hex, "endpoint echoed a different txid");
            println!(
                "cli: compose id={} txid={} fee={} vsize={} to={} private={} broadcast=ok",
                composed.note_id,
                composed.tx.txid_hex,
                composed.tx.fee,
                composed.tx.vsize,
                to.unwrap_or("self"),
                private,
            );
        }
        Some("sweep") => {
            // sweep <store.json> <base-url> <dest-address> <fee_rate>
            let mut store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let dest = app_core::notes_core::address::Recipient::parse(net, &args[4])
                .expect("dest address");
            let rate: f64 = args[5].parse().expect("fee rate");
            let sweep = app_core::notes_core::tx::build_sweep_tx(
                &store.available_utxos(),
                &ident.identity.output_x,
                dest.spk,
                rate,
                &ident.identity.tweaked_seckey,
                app_core::notes_core::keys::generate_aux_rand,
            )
            .expect("sweep build");
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let txid = client.broadcast(&sweep.raw_hex).expect("broadcast");
            for u in &mut store.utxos { u.pending_spend = true; }
            save(&store, &args[2]);
            println!("cli: sweep txid={} value={} fee={}", txid.trim(), sweep.tx.outputs[0].value, sweep.fee);
        }
        Some("bundle") => {
            // bundle <address> <network> <base-url> <out.json|->
            let net = network(&args[3]);
            let client = ChainClient::new(HttpTransport::new(&args[4]), net);
            let bundle = client.build_bundle(&args[2], None).expect("build bundle");
            let json = serde_json::to_string_pretty(&bundle).expect("serialize");
            if args[5] == "-" {
                println!("{json}");
            } else {
                std::fs::write(&args[5], json).expect("write bundle");
                println!(
                    "cli: bundle address={} txs={} utxos={} -> {}",
                    args[2],
                    bundle.notes_onchain.len(),
                    bundle.utxos.len(),
                    args[5]
                );
            }
        }
        // ---- external funding (PSBT) — simulates a hardware/software signer ----
        Some("fund-keygen") => {
            // fund-keygen <network> <seed-hex> → "<watch-descriptor>\t<xprv>\t<addr0/0>"
            let net = network(&args[2]);
            let seed = hex::decode(&args[3]).expect("seed hex");
            let master = Xpriv::new_master(app_core::derive::btc_network(net), &seed).expect("master");
            let secp = Secp256k1::new();
            let xpub = Xpub::from_priv(&secp, &master);
            let desc = format!("tr({xpub}/<0;1>/*)");
            let src = FundingSource::parse(&desc, net).expect("descriptor");
            let addr0 = src.derive(0, 0).expect("derive").address;
            println!("{desc}\t{master}\t{addr0}");
        }
        Some("fund-build") => {
            // fund-build <base> <network> <descriptor> <public|private> <rate> <text> [to]
            let net = network(&args[3]);
            let ident = identity(net);
            let src = FundingSource::parse(&args[4], net).expect("descriptor");
            let private = match args[5].as_str() {
                "private" => true,
                "public" => false,
                o => panic!("visibility must be public|private, got {o}"),
            };
            let fee_rate: f64 = args[6].parse().expect("fee rate");
            let text = args[7].clone();
            let to = args.get(8).cloned();
            let client = ChainClient::new(HttpTransport::new(&args[2]), net);
            // Gap limit (CN_FUND_GAP overrides; the e2e uses a small gap since a
            // per-address genesis rescan on the regtest shim is expensive).
            let gap: u32 =
                std::env::var("CN_FUND_GAP").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
            let scan = client.scan_funding(&src, gap).expect("scan funding");
            if scan.utxos.is_empty() {
                panic!("no spendable coins at the funding descriptor");
            }
            let recipient = to.as_deref().map(|a| Recipient::parse(net, a).expect("recipient"));
            let r = app_core::notes_core::keys::generate_aux_rand().expect("rng");
            let note_id = [r[0], r[1], r[2], r[3]];
            let plan = FundingPlan {
                source: &src,
                coins: &scan.utxos,
                change_index: scan.next_change_index,
                fee_rate,
                change_override: None,
            };
            let np = NoteParams {
                identity: &ident.identity,
                text: &text,
                private,
                recipient: recipient.as_ref(),
                note_id,
                max_op_return_bytes: 100_000,
                network: net,
            };
            let built = build_funding_psbt(&plan, &np).expect("build funding psbt");
            eprintln!(
                "cli: fund-build txid={} fee={} change={} coins={} to={} private={}",
                built.txid,
                built.fee,
                built.change,
                scan.utxos.len(),
                to.as_deref().unwrap_or("self"),
                private,
            );
            println!("{}", built.to_base64());
        }
        Some("fund-build-fake") => {
            // fund-build-fake <network> <descriptor> <public|private> <rate> <text> [to]
            // OFFLINE: fabricate one UTXO at receive index 0 (witness_utxo only),
            // for feeding a signer that never touches the chain (the stock KeyOS
            // Bitcoin Wallet). No node, no real funding.
            let net = network(&args[2]);
            let ident = identity(net);
            let src = FundingSource::parse(&args[3], net).expect("descriptor");
            let private = match args[4].as_str() {
                "private" => true,
                "public" => false,
                o => panic!("visibility must be public|private, got {o}"),
            };
            let fee_rate: f64 = args[5].parse().expect("fee rate");
            let text = args[6].clone();
            let to = args.get(7).cloned();
            let d0 = src.derive(0, 0).expect("derive 0/0");
            let coins = vec![app_core::funding::FundingUtxo {
                txid: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b".into(),
                vout: 0,
                value: 200_000,
                address: d0.address.clone(),
                chain: 0,
                index: 0,
                confirmed: true,
            }];
            let recipient = to.as_deref().map(|a| Recipient::parse(net, a).expect("recipient"));
            let r = app_core::notes_core::keys::generate_aux_rand().expect("rng");
            let note_id = [r[0], r[1], r[2], r[3]];
            let plan = FundingPlan {
                source: &src,
                coins: &coins,
                change_index: 0,
                fee_rate,
                change_override: None,
            };
            let np = NoteParams {
                identity: &ident.identity,
                text: &text,
                private,
                recipient: recipient.as_ref(),
                note_id,
                max_op_return_bytes: 100_000,
                network: net,
            };
            let built = build_funding_psbt(&plan, &np).expect("build funding psbt");
            eprintln!(
                "cli: fund-build-fake txid={} fee={} change={} addr={} to={} private={}",
                built.txid,
                built.fee,
                built.change,
                d0.address,
                to.as_deref().unwrap_or("self"),
                private,
            );
            println!("{}", built.to_base64());
        }
        Some("ur-decode") => {
            // ur-decode <file>  → reassemble UR part lines; print "<type>\t<msg>".
            let parts = std::fs::read_to_string(&args[2]).expect("read ur parts");
            let (ty, bytes) = app_core::ur::decode_ur_string(&parts).expect("decode ur");
            eprintln!("cli: ur-decode type={ty} bytes={}", bytes.len());
            match String::from_utf8(bytes.clone()) {
                Ok(s) => println!("{ty}\t{s}"),
                Err(_) => println!("{ty}\t{}", hex::encode(&bytes)),
            }
        }
        Some("ur-encode-psbt") => {
            // ur-encode-psbt <psbt-base64> [frag] → crypto-psbt UR frames (test QR)
            let psbt = parse_psbt(&args[2]).expect("psbt");
            let frag: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(200);
            for f in app_core::ur::encode_psbt(&psbt.serialize(), frag) {
                println!("{f}");
            }
        }
        Some("ur-encode-account") => {
            // ur-encode-account <account|outdesc|hdkey> <tr()/wpkh() descriptor> [frag]
            // Build the BCR CBOR from the descriptor's xpub + origin and emit UR
            // frames — for generating hardware-wallet account-export test QRs.
            use bitcoin::bip32::Xpub;
            use ciborium::value::Value;
            let kind = args[2].as_str();
            let desc = args[3].as_str();
            let frag: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(200);
            let tag: u64 = if desc.starts_with("tr(") { 409 } else { 404 };
            let origin = desc.split('[').nth(1).and_then(|s| s.split(']').next()).expect("[origin]");
            let mut it = origin.split('/');
            let fp = u32::from_str_radix(it.next().expect("fp"), 16).expect("fp hex");
            let path: Vec<(u32, bool)> = it
                .map(|c| {
                    let hard = c.ends_with('h') || c.ends_with('\'');
                    (c.trim_end_matches(['h', '\'']).parse::<u32>().expect("idx"), hard)
                })
                .collect();
            let xpub_str = desc.split(']').nth(1).and_then(|s| s.split('/').next()).expect("xpub");
            let xpub = Xpub::from_str(xpub_str).expect("xpub");
            let mut comps = Vec::new();
            for (idx, hard) in &path {
                comps.push(Value::from(*idx as u64));
                comps.push(Value::Bool(*hard));
            }
            let keypath = Value::Map(vec![
                (Value::from(1u64), Value::Array(comps)),
                (Value::from(2u64), Value::from(fp as u64)),
                (Value::from(3u64), Value::from(path.len() as u64)),
            ]);
            let parent_fp = u32::from_be_bytes(xpub.parent_fingerprint.to_bytes());
            let hdkey = Value::Map(vec![
                (Value::from(3u64), Value::Bytes(xpub.public_key.serialize().to_vec())),
                (Value::from(4u64), Value::Bytes(xpub.chain_code.to_bytes().to_vec())),
                (Value::from(6u64), keypath),
                (Value::from(8u64), Value::from(parent_fp as u64)),
            ]);
            let (ur_type, value): (&str, Value) = match kind {
                "hdkey" => ("crypto-hdkey", hdkey),
                "outdesc" => (
                    "crypto-output-descriptor",
                    Value::Tag(tag, Box::new(Value::Tag(303, Box::new(hdkey)))),
                ),
                _ => (
                    "crypto-account",
                    Value::Map(vec![
                        (Value::from(1u64), Value::from(fp as u64)),
                        (
                            Value::from(2u64),
                            Value::Array(vec![Value::Tag(tag, Box::new(Value::Tag(303, Box::new(hdkey))))]),
                        ),
                    ]),
                ),
            };
            let mut cbor = Vec::new();
            ciborium::into_writer(&value, &mut cbor).expect("cbor");
            for f in app_core::ur::encode_ur(ur_type, &cbor, frag) {
                println!("{f}");
            }
        }
        Some("fund-sign") => {
            // fund-sign <psbt-base64> <xprv>   (the "external wallet")
            let mut psbt = parse_psbt(&args[2]).expect("psbt");
            let xprv = Xpriv::from_str(&args[3]).expect("xprv");
            let secp = Secp256k1::new();
            let signed = match psbt.sign(&xprv, &secp) {
                Ok(keys) => keys.len(),
                Err((keys, errs)) => {
                    eprintln!("cli: fund-sign partial errs={errs:?}");
                    keys.len()
                }
            };
            eprintln!("cli: fund-sign inputs_signed={signed}");
            println!("{psbt}");
        }
        Some("wif-pubkey") => {
            // wif-pubkey <wif> → compressed pubkey hex (for wpkh(<pubkey>) descriptor)
            let sk = bitcoin::PrivateKey::from_wif(&args[2]).expect("wif");
            let secp = Secp256k1::new();
            println!("{}", sk.public_key(&secp).inner);
        }
        Some("fund-sign-wif") => {
            // fund-sign-wif <psbt-base64> <wif>  (single-key p2wpkh external wallet)
            use bitcoin::hashes::Hash;
            use bitcoin::sighash::{EcdsaSighashType, SighashCache};
            use bitcoin::{ecdsa, PrivateKey, ScriptBuf};
            let mut psbt = parse_psbt(&args[2]).expect("psbt");
            let sk = PrivateKey::from_wif(&args[3]).expect("wif");
            let secp = Secp256k1::new();
            let pk = sk.public_key(&secp);
            let wpkh = pk.wpubkey_hash().expect("compressed key");
            let spk = ScriptBuf::new_p2wpkh(&wpkh);
            let tx = psbt.unsigned_tx.clone();
            let mut cache = SighashCache::new(&tx);
            let mut signed = 0usize;
            for i in 0..psbt.inputs.len() {
                let Some(wu) = psbt.inputs[i].witness_utxo.clone() else { continue };
                if wu.script_pubkey != spk {
                    continue;
                }
                let sighash = cache
                    .p2wpkh_signature_hash(i, &wu.script_pubkey, wu.value, EcdsaSighashType::All)
                    .expect("sighash");
                let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                let sig = secp.sign_ecdsa(&msg, &sk.inner);
                psbt.inputs[i]
                    .partial_sigs
                    .insert(pk, ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All });
                signed += 1;
            }
            eprintln!("cli: fund-sign-wif inputs_signed={signed}");
            println!("{psbt}");
        }
        Some("fund-finalize") => {
            // fund-finalize <base> <network> <signed-psbt-base64>
            let net = network(&args[3]);
            let psbt = parse_psbt(&args[4]).expect("psbt");
            let (raw, txid, vsize) = finalize_extract(psbt).expect("finalize");
            let client = ChainClient::new(HttpTransport::new(&args[2]), net);
            let got = client.broadcast(&raw).expect("broadcast");
            eprintln!("cli: fund-finalize txid={txid} vsize={vsize} broadcast=ok");
            println!("{}", got.trim());
        }
        _ => {
            eprintln!(
                "usage: cli address <net> | init <store> <net> | scan <store> <base> | \
                 notes <store> | compose <store> <base> <public|private> <rate> <text> [to] | \
                 bundle <addr> <net> <base> <out> | \
                 fund-keygen <net> <seed-hex> | \
                 fund-build <base> <net> <desc> <public|private> <rate> <text> [to] | \
                 fund-sign <psbt> <xprv> | fund-finalize <base> <net> <psbt>   \
                 (identity from APP_KEY)"
            );
            std::process::exit(2);
        }
    }
}
