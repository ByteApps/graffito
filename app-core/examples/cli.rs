//! Host CLI over app-core for the regtest e2e — plays the APP role the
//! Slint shell will play later: identity from key material, scan via a
//! live esplora-shaped endpoint, compose+broadcast, list notes, and emit
//! sync-bundle JSON for ANY address (feeds prime's notes_cli — the two
//! cores share the SyncBundle serde). NOT part of the shipped app.
//!
//! Key material comes from APP_KEY (any accepted format: mnemonic /
//! xprv / WIF / 32-byte hex), so secrets never sit in argv.

use app_core::chain::{ChainClient, HttpTransport};
use app_core::compose::{compose_and_record, ComposeRequest};
use app_core::identity::{parse_key_material, realize, AppIdentity};
use app_core::notes_core::Network;
use app_core::store::{NoteStatus, Store};

fn identity(network: Network) -> AppIdentity {
    let key = std::env::var("APP_KEY").expect("APP_KEY: mnemonic | xprv | WIF | hex32");
    let material = parse_key_material(&key, network).expect("APP_KEY parse");
    realize(&material, network).expect("APP_KEY realize")
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
        _ => {
            eprintln!(
                "usage: cli address <net> | init <store> <net> | scan <store> <base> | \
                 notes <store> | compose <store> <base> <public|private> <rate> <text> [to] | \
                 bundle <addr> <net> <base> <out>   (identity from APP_KEY)"
            );
            std::process::exit(2);
        }
    }
}
