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
use app_core::identity::{parse_key_material, realize, AppIdentity, KeyMaterial};
use app_core::notebooks::{NotebookIndex, SpendingAddr};
use app_core::notes_core::address::Recipient;
use app_core::notes_core::Network;
use app_core::psbt_build::{
    build_funded_sweep_psbt, build_watch_note_psbt,    build_funding_psbt, build_watch_bump_psbt, build_watch_spend_psbt, FundingPlan, NoteParams,
    WatchCoin,
};
use app_core::psbt_finalize::{finalize_extract, parse_psbt, validate_signed};
use app_core::store::{NoteStatus, Store};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;

fn identity(network: Network) -> AppIdentity {
    let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | xprv | WIF | hex32");
    let account = std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
    // Rev 3: APP_INDEX picks the notebook (receive-chain address index).
    let index = std::env::var("APP_INDEX").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
    let material = parse_key_material(&key, network).expect("APP_KEY parse");
    realize(&material, network, account, index).expect("APP_KEY realize")
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

/// The per-identity notebooks index file NEXT TO `store_path` — the
/// spending wallet's section (funding-unification M3.1) is ACCOUNT-level
/// now, shared by every notebook of the account, so it lives here rather
/// than in the store the caller happened to load. Mirrors the app's own
/// `notebooks-<net>-<fp8>.json` naming/co-location (`src/lib.rs`
/// `State::notebooks_path`).
fn spending_index_path(store_path: &str, network: Network, material: &KeyMaterial) -> std::path::PathBuf {
    let fp8 = app_core::identity::index_fp8(material, network).expect("index_fp8 (need mnemonic/xprv APP_KEY)");
    let dir = std::path::Path::new(store_path).parent().filter(|p| !p.as_os_str().is_empty());
    dir.unwrap_or_else(|| std::path::Path::new(".")).join(format!("notebooks-{}-{}.json", network.as_str(), fp8))
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
        Some("xpub") => {
            // xpub <network> — the account-level xpub for hierarchical
            // APP_KEY material (APP_ACCOUNT selects the account): the
            // string a watch-only import takes.
            let net = network(&args[2]);
            let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | xprv");
            let account: u32 =
                std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
            let material = parse_key_material(&key, net).expect("APP_KEY parse");
            let secp = Secp256k1::new();
            let master = match material {
                app_core::identity::KeyMaterial::Mnemonic(m) => {
                    Xpriv::new_master(app_core::derive::btc_network(net), &m.to_seed(""))
                        .expect("master xprv")
                }
                app_core::identity::KeyMaterial::Xprv(x) if x.depth == 0 => x,
                app_core::identity::KeyMaterial::Xprv(x) => {
                    // Already account-level: just neuter it.
                    println!("{}", Xpub::from_priv(&secp, &x));
                    return;
                }
                _ => panic!("xpub needs hierarchical material (mnemonic or xprv)"),
            };
            let path = [
                bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
                bitcoin::bip32::ChildNumber::from_hardened_idx(app_core::derive::coin_type(net))
                    .unwrap(),
                bitcoin::bip32::ChildNumber::from_hardened_idx(account).unwrap(),
            ];
            let acct = master.derive_priv(&secp, &path).expect("derive account");
            println!("{}", Xpub::from_priv(&secp, &acct));
        }
        Some("init") => {
            // init <store.json> <network>
            let net = network(&args[3]);
            let ident = identity(net);
            let store = Store::new(&ident.output_x(), net);
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
            // Funding-unification M3.1: stamp the RUNTIME spending cache
            // from the account-level notebooks index (mirrors
            // `State::activate` in src/lib.rs) so `apply_bundle`'s
            // self-spk SET recognizes spending-wallet-funded notes as
            // OWN. Best-effort and additive: non-hierarchical APP_KEY
            // (WIF/hex/account-xprv) has no notebooks index at all, and a
            // never-enabled spending wallet leaves an empty section
            // either way — both leave `store.spending` at its byte-
            // identical pre-M2 default.
            let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | xprv | WIF | hex32");
            let account: u32 =
                std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
            // DISPLAY-OWNER anchor set (notes-core rev 6e36a23): every
            // ACTIVE notebook's own spk, best-effort from the same
            // notebooks index loaded above for the spending section —
            // empty (no-op) for non-hierarchical APP_KEY or no index yet.
            let mut notebook_spks: Vec<Vec<u8>> = Vec::new();
            if let Ok(material) = parse_key_material(&key, net) {
                let ix_path = spending_index_path(&args[2], net, &material);
                if let Ok(ix) = NotebookIndex::load(&ix_path) {
                    store.spending = ix.spending_for(account);
                    notebook_spks =
                        app_core::identity::active_notebook_spks(&material, net, account, &ix);
                }
            }
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let bundle = client.build_bundle(&store.address, None).expect("build bundle");
            let stats = match ident.full() {
                Some(id) => store.apply_bundle(&bundle, id, net, &notebook_spks).expect("apply"),
                None => store
                    .apply_bundle_watch(&bundle, &ident.output_x(), net, &notebook_spks)
                    .expect("apply"),
            };
            store.resolve_spend_statuses(|t| client.fetch_tx_status(t));
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
        Some("spend-build") => {
            // spend-build <store.json> <sweep|consolidate> <rate> <out.psbt> [dest]
            // Watch identity: unsigned PSBT spending every spendable coin to
            // dest (default = self). Sign it externally, then spend-broadcast.
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let src = ident
                .watch_source()
                .expect("spend-build needs watch-only APP_KEY (xpub / descriptor)")
                .clone();
            let kind = args[3].as_str();
            let rate: f64 = args[4].parse().expect("fee rate");
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend)
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: ident.index })
                .collect();
            let dest_addr = args.get(6).cloned().unwrap_or_else(|| ident.address.clone());
            let dest = Recipient::parse(net, &dest_addr).expect("dest address");
            let built = build_watch_spend_psbt(&src, &coins, dest.spk, rate).expect("build");
            std::fs::write(&args[5], built.to_bytes()).expect("write psbt");
            println!(
                "cli: spend-build kind={kind} txid={} fee={} value={} inputs={} -> {}",
                built.txid,
                built.fee,
                built.sent_to_recipient,
                coins.len(),
                args[5]
            );
        }
        Some("wallet-spend-build") => {
            // wallet-spend-build <sweep|consolidate> <rate> <out.psbt> <dest> <store:index> [...]
            // Watch identity, WALLET-level (rev 3): ONE unsigned PSBT
            // spending every listed notebook store's spendable coins to
            // dest — each input's key origin carries its own receive
            // index, so an external signer recognizes every notebook's
            // coins in one pass. Sign externally, then spend-broadcast.
            let kind = args[2].as_str();
            let rate: f64 = args[3].parse().expect("fee rate");
            let sources: Vec<(Store, u32)> = args[6..]
                .iter()
                .map(|pair| {
                    let (path, index) =
                        pair.rsplit_once(':').expect("source must be <store.json>:<index>");
                    (load(path), index.parse().expect("notebook index"))
                })
                .collect();
            assert!(!sources.is_empty(), "need at least one <store.json>:<index> source");
            let net = network(&sources[0].0.network.clone());
            let ident = identity(net);
            let src = ident
                .watch_source()
                .expect("wallet-spend-build needs watch-only APP_KEY (xpub / descriptor)")
                .clone();
            let coins: Vec<WatchCoin> = sources
                .iter()
                .flat_map(|(store, index)| {
                    store.utxos.iter().filter(|u| !u.pending_spend).map(move |u| WatchCoin {
                        txid: u.txid.clone(),
                        vout: u.vout,
                        value: u.value,
                        index: *index,
                    })
                })
                .collect();
            let dest = Recipient::parse(net, &args[5]).expect("dest address");
            let built = build_watch_spend_psbt(&src, &coins, dest.spk, rate).expect("build");
            std::fs::write(&args[4], built.to_bytes()).expect("write psbt");
            println!(
                "cli: wallet-spend-build kind={kind} txid={} fee={} value={} inputs={} notebooks={} -> {}",
                built.txid,
                built.fee,
                built.sent_to_recipient,
                coins.len(),
                sources.len(),
                args[4]
            );
        }
        Some("bump-build") => {
            // bump-build <store.json> <base-url> <pending-txid> <rate> <out.psbt>
            // Watch identity: RBF replacement of a pending tx, rebuilt from
            // chain data; delta comes out of our own output (else largest).
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let src = ident.watch_source().expect("bump-build needs watch-only APP_KEY").clone();
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            // Single-notebook cli identity: every input is at APP_INDEX.
            let (coins, outputs, confirmed) =
                client.fetch_tx_io(&args[4], |_| Some(ident.index)).expect("fetch tx");
            assert!(!confirmed, "tx already confirmed");
            let rate: f64 = args[5].parse().expect("fee rate");
            let self_spk =
                app_core::notes_core::address::p2tr_script_pubkey(&ident.output_x());
            let reduce = outputs
                .iter()
                .enumerate()
                .filter(|(_, (spk, _))| *spk == self_spk)
                .max_by_key(|(_, (_, v))| *v)
                .map(|(i, _)| i)
                .or_else(|| {
                    outputs
                        .iter()
                        .enumerate()
                        .filter(|(_, (spk, _))| spk.first() != Some(&0x6a))
                        .max_by_key(|(_, (_, v))| *v)
                        .map(|(i, _)| i)
                })
                .expect("no reducible output");
            let built =
                build_watch_bump_psbt(&src, &coins, &outputs, reduce, rate).expect("build bump");
            std::fs::write(&args[6], built.to_bytes()).expect("write psbt");
            println!(
                "cli: bump-build replaces={} txid={} fee={} -> {}",
                args[4], built.txid, built.fee, args[6]
            );
        }
        Some("sweep-funded-build") => {
            // sweep-funded-build <store.json> <base-url> <funding-descriptor> <rate> <out.psbt> <dest>
            // Watch identity + external fee wallet: the destination receives
            // the FULL notes balance; the fee comes out of the funding
            // wallet's coins and its change returns there. Both input sets
            // carry key origins — sign externally, then spend-broadcast.
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let src = ident
                .watch_source()
                .expect("sweep-funded-build needs watch-only APP_KEY (xpub / descriptor)")
                .clone();
            let fund_src = FundingSource::parse(&args[4], net).expect("funding descriptor");
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let scan = client.scan_funding(&fund_src, 20).expect("funding scan");
            assert!(!scan.utxos.is_empty(), "funding wallet has no spendable coins");
            let rate: f64 = args[5].parse().expect("fee rate");
            let notes_coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend)
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: ident.index })
                .collect();
            let dest = Recipient::parse(net, &args[7]).expect("dest address");
            let identity_spk =
                app_core::notes_core::address::p2tr_script_pubkey(&ident.output_x());
            let plan = FundingPlan {
                source: &fund_src,
                coins: &scan.utxos,
                change_index: scan.next_change_index,
                fee_rate: rate,
                change_override: None,
            };
            let built =
                build_funded_sweep_psbt(identity_spk, Some(&src), &notes_coins, &plan, dest.spk)
                    .expect("build funded sweep");
            std::fs::write(&args[6], built.to_bytes()).expect("write psbt");
            println!(
                "cli: sweep-funded-build txid={} value={} fee={} change={} notes_in={} fund_in={} -> {}",
                built.txid,
                built.sent_to_recipient,
                built.fee,
                built.change,
                notes_coins.len(),
                scan.utxos.len(),
                args[6]
            );
        }
        Some("note-build") => {
            // note-build <store.json> <text> <rate> <out.psbt> [dest] [gift]
            // Watch identity: PUBLIC note PSBT over every spendable coin
            // (dest ⇒ directed-public with a gift, default dust). Sign
            // externally, then spend-broadcast; the note comes back via scan.
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let src = ident
                .watch_source()
                .expect("note-build needs watch-only APP_KEY (xpub / descriptor)")
                .clone();
            let text = &args[3];
            let rate: f64 = args[4].parse().expect("fee rate");
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend)
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: ident.index })
                .collect();
            let recipient = args.get(6).map(|a| Recipient::parse(net, a).expect("dest address"));
            let gift: u64 = args.get(7).and_then(|g| g.parse().ok()).unwrap_or(330);
            let aux = app_core::notes_core::keys::generate_aux_rand().expect("rng");
            let note_id = [aux[0], aux[1], aux[2], aux[3]];
            let built = build_watch_note_psbt(
                &src,
                &coins,
                text,
                recipient.as_ref().map(|r| r.spk.clone()),
                if recipient.is_some() { gift } else { 0 },
                note_id,
                store.chunk_size,
                rate,
            )
            .expect("build note psbt");
            std::fs::write(&args[5], built.to_bytes()).expect("write psbt");
            println!(
                "cli: note-build id={} txid={} fee={} gift={} inputs={} -> {}",
                hex::encode(note_id),
                built.txid,
                built.fee,
                built.sent_to_recipient,
                coins.len(),
                args[5]
            );
        }
        Some("note-funded-build") => {
            // note-funded-build <store.json> <base-url> <funding-descriptor> <text> <rate> <out.psbt> [dest] [gift]
            // Watch identity + funding wallet: PUBLIC note paid by the
            // funding coins (dust-to-self keeps it discoverable; a key-less
            // rescan shows it received-from-funder — frozen scan rule).
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            assert!(ident.watch_source().is_some(), "note-funded-build needs watch-only APP_KEY");
            let fund_src = FundingSource::parse(&args[4], net).expect("funding descriptor");
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let scan = client.scan_funding(&fund_src, 20).expect("funding scan");
            assert!(!scan.utxos.is_empty(), "funding wallet has no spendable coins");
            let text = &args[5];
            let rate: f64 = args[6].parse().expect("fee rate");
            let recipient = args.get(8).map(|a| Recipient::parse(net, a).expect("dest address"));
            let gift: u64 = args.get(9).and_then(|g| g.parse().ok()).unwrap_or(330);
            let aux = app_core::notes_core::keys::generate_aux_rand().expect("rng");
            let note_id = [aux[0], aux[1], aux[2], aux[3]];
            let plan = FundingPlan {
                source: &fund_src,
                coins: &scan.utxos,
                change_index: scan.next_change_index,
                fee_rate: rate,
                change_override: None,
            };
            let built = app_core::psbt_build::build_watch_funded_note_psbt(
                &ident.output_x(),
                &plan,
                text,
                recipient.as_ref().map(|r| r.spk.clone()),
                if recipient.is_some() { gift } else { 0 },
                note_id,
                store.chunk_size,
            )
            .expect("build funded note psbt");
            std::fs::write(&args[7], built.to_bytes()).expect("write psbt");
            println!(
                "cli: note-funded-build id={} txid={} fee={} gift={} fund_in={} -> {}",
                hex::encode(note_id),
                built.txid,
                built.fee,
                built.sent_to_recipient,
                scan.utxos.len(),
                args[7]
            );
        }
        Some("spend-broadcast") => {
            // spend-broadcast <base-url> <network> <signed.psbt> <expected-txid>
            // Validate the externally signed PSBT, finalize, broadcast.
            let net = network(&args[3]);
            let bytes = std::fs::read(&args[4]).expect("read signed psbt");
            let psbt = if bytes.starts_with(b"psbt\xff") {
                app_core::bitcoin::Psbt::deserialize(&bytes).expect("psbt binary")
            } else {
                parse_psbt(&String::from_utf8_lossy(&bytes)).expect("psbt text")
            };
            validate_signed(&psbt, &args[5]).expect("signed PSBT must match the built tx");
            let (raw, txid, vsize) = finalize_extract(psbt).expect("finalize");
            let client = ChainClient::new(HttpTransport::new(&args[2]), net);
            let got = client.broadcast(&raw).expect("broadcast");
            assert_eq!(got, txid, "node echoed a different txid");
            println!("cli: spend-broadcast txid={txid} vsize={vsize} ok");
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
                ident.expect_full(),
                net,
                &ComposeRequest {
                    text: &args[6],
                    private,
                    recipient: to,
                    change_to: None,
                    coins: None,
                    fee_rate,
                    gift_amount: None, now: std::time::SystemTime::now()
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
                &ident.expect_full().output_x,
                dest.spk,
                rate,
                &ident.expect_full().tweaked_seckey,
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
        Some("spending-address") => {
            // spending-address <store.json> <net>
            // Prints the identity's spending wallet's next unused receive
            // address (funding-unification M2) and persists it as handed
            // out (fresh-address discipline). The section is ACCOUNT-level
            // (M3.1) — shared by every notebook of the account — so it's
            // read/written through the notebooks index file next to
            // store.json, not the store itself. Needs a BIP-39/master-xprv
            // APP_KEY (APP_ACCOUNT selects the account); watch/WIF/hex/
            // account-xprv identities have no spending wallet.
            let net = network(&args[3]);
            let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | master xprv");
            let account: u32 =
                std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
            let material = parse_key_material(&key, net).expect("APP_KEY parse");
            let source = app_core::spending::funding_source(&material, net, account)
                .expect("spending wallet needs a BIP-39/master-xprv APP_KEY");
            let ix_path = spending_index_path(&args[2], net, &material);
            let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
            let mut section = ix.spending_for(account);
            let index = section.next_receive;
            let addr = source.derive(0, index).expect("derive receive address");
            section.mark_used(SpendingAddr {
                chain: 0,
                index,
                address: addr.address.clone(),
                script_pubkey_hex: hex::encode(&addr.spk),
            });
            ix.set_spending(account, section);
            ix.save(&ix_path).expect("save notebooks index");
            println!("cli: spending-address index={index} address={}", addr.address);
            println!("{}", addr.address);
        }
        Some("spending-discover") => {
            // spending-discover <store.json> <base-url> [gap]
            // Words-only recovery leg (funding-unification M4): gap-scan
            // BOTH chains of the identity's BIP-84 spending branch
            // (`chain::discover_spending`, the same walk
            // `spending_refresh_async` runs from the UI) and merge every
            // discovered address into the account-level notebooks index
            // — no local state needed beyond the mnemonic/xprv itself, so
            // a fresh (or missing) index file is created here. Needs a
            // BIP-39/master-xprv APP_KEY.
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | master xprv");
            let account: u32 =
                std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
            let material = parse_key_material(&key, net).expect("APP_KEY parse");
            let source = app_core::spending::funding_source(&material, net, account)
                .expect("spending wallet needs a BIP-39/master-xprv APP_KEY");
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let gap: u32 = args.get(4).and_then(|g| g.parse().ok()).unwrap_or(20);
            let (used, next_receive, next_change) =
                app_core::chain::discover_spending(&client, &source, gap);
            let ix_path = spending_index_path(&args[2], net, &material);
            let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
            let mut section = ix.spending_for(account);
            let found = used.len();
            section.apply_discovery(used, next_receive, next_change);
            ix.set_spending(account, section);
            ix.save(&ix_path).expect("save notebooks index");
            println!(
                "cli: spending-discover found={found} next_receive={next_receive} next_change={next_change}"
            );
        }
        Some("note-spend-funded") => {
            // note-spend-funded <store.json> <base-url> <public|private> <rate> <text> [to]
            // Fully in-app internal funding kind: scan the identity's OWN
            // spending wallet (ACCOUNT-level bookkeeping, funding-
            // unification M3.1 — shared by every notebook of the account,
            // so its next-change index and used-address list live in the
            // notebooks index file next to store.json, not the store),
            // build the SAME funded-note PSBT shape external funding
            // produces (`build_funding_psbt` — dust-to-recipient, no
            // configurable gift, same as `fund-build`), sign every P2WPKH
            // input in-process (no PSBT export/import round trip),
            // broadcast.
            let store = load(&args[2]);
            let net = network(&store.network.clone());
            let ident = identity(net);
            let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | master xprv");
            let account: u32 =
                std::env::var("APP_ACCOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(0);
            let material = parse_key_material(&key, net).expect("APP_KEY parse");
            let private = match args[4].as_str() {
                "private" => true,
                "public" => false,
                o => panic!("visibility must be public|private, got {o}"),
            };
            let fee_rate: f64 = args[5].parse().expect("fee rate");
            let text = args[6].clone();
            let to = args.get(7).cloned();

            let source = app_core::spending::funding_source(&material, net, account)
                .expect("spending wallet needs a BIP-39/master-xprv APP_KEY");
            let client = ChainClient::new(HttpTransport::new(&args[3]), net);
            let gap: u32 =
                std::env::var("CN_FUND_GAP").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
            let scan = client.scan_funding(&source, gap).expect("spending wallet scan");
            if scan.utxos.is_empty() {
                panic!("spending wallet has no spendable coins");
            }

            let recipient = to.as_deref().map(|a| Recipient::parse(net, a).expect("recipient"));
            let r = app_core::notes_core::keys::generate_aux_rand().expect("rng");
            let note_id = [r[0], r[1], r[2], r[3]];
            let ix_path = spending_index_path(&args[2], net, &material);
            let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
            let mut section = ix.spending_for(account);
            let change_index = section.next_change;
            let plan = FundingPlan {
                source: &source,
                coins: &scan.utxos,
                change_index,
                fee_rate,
                change_override: None,
            };
            let np = NoteParams {
                identity: ident.expect_full(),
                text: &text,
                private,
                recipient: recipient.as_ref(),
                note_id,
                max_op_return_bytes: store.chunk_size,
                network: net,
            };
            let built = build_funding_psbt(&plan, &np).expect("build funded note psbt");
            let mut psbt = built.psbt.clone();
            let signed = app_core::psbt_build::sign_own_wpkh_inputs(
                &mut psbt, &material, net, account, &scan.utxos,
            )
            .expect("sign spending-wallet inputs");
            assert!(signed > 0, "no spending-wallet inputs signed");
            let (raw, txid, vsize) = finalize_extract(psbt).expect("finalize");
            assert_eq!(txid, built.txid, "finalize changed the txid");
            let got = client.broadcast(&raw).expect("broadcast");
            assert_eq!(got, txid, "endpoint echoed a different txid");

            if built.change > 0 {
                let change_addr = source.derive(1, change_index).expect("derive change address");
                section.mark_used(SpendingAddr {
                    chain: 1,
                    index: change_index,
                    address: change_addr.address,
                    script_pubkey_hex: hex::encode(&change_addr.spk),
                });
                ix.set_spending(account, section);
                ix.save(&ix_path).expect("save notebooks index");
            }
            println!(
                "cli: compose id={} txid={} fee={} vsize={} to={} private={} broadcast=ok",
                hex::encode(note_id),
                txid,
                built.fee,
                vsize,
                to.as_deref().unwrap_or("self"),
                private,
            );
        }
        // ---- external funding (PSBT) — simulates a hardware/software signer ----
        Some("fund-keygen") => {
            // fund-keygen <network> <seed-hex> [tr|wpkh]
            //   → "<watch-descriptor>\t<xprv>\t<addr0/0>"
            // Default tr (P2TR); wpkh emits a P2WPKH (segwit v0) funding source.
            let net = network(&args[2]);
            let seed = hex::decode(&args[3]).expect("seed hex");
            let kind = args.get(4).map(String::as_str).unwrap_or("tr");
            let master = Xpriv::new_master(app_core::derive::btc_network(net), &seed).expect("master");
            let secp = Secp256k1::new();
            let xpub = Xpub::from_priv(&secp, &master);
            let desc = match kind {
                "tr" => format!("tr({xpub}/<0;1>/*)"),
                "wpkh" => format!("wpkh({xpub}/<0;1>/*)"),
                o => panic!("descriptor kind must be tr|wpkh, got {o}"),
            };
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
                identity: ident.expect_full(),
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
                identity: ident.expect_full(),
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
                 spending-address <store> <net> | \
                 spending-discover <store> <base> [gap] | \
                 note-spend-funded <store> <base> <public|private> <rate> <text> [to] | \
                 fund-keygen <net> <seed-hex> [tr|wpkh] | \
                 fund-build <base> <net> <desc> <public|private> <rate> <text> [to] | \
                 fund-sign <psbt> <xprv> | fund-finalize <base> <net> <psbt>   \
                 (identity from APP_KEY)"
            );
            std::process::exit(2);
        }
    }
}
