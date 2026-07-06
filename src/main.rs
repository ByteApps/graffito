//! M6 shell: onboarding (import / create+quiz), home + notes, compose
//! with live cost, contacts picker, settings. Every callback emits a
//! `cb:` log-contract line (grep targets for the M7 UI e2e).
//!
//! Env overrides for tests: APP_DATA_DIR, APP_KEY (bypasses keychain),
//! APP_NETWORK.

mod camera;
mod keychain;
mod qr;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use app_core::chain::{default_base, ChainClient, HttpTransport};
use app_core::compose::{compose_and_record, ComposeRequest};
use app_core::identity::{generate_mnemonic, parse_key_material, realize, AppIdentity};
use app_core::notes_core::address::Recipient;
use app_core::notes_core::bundle::{estimate_note_cost, FeeRates};
use app_core::notes_core::Network;
use app_core::store::{NoteStatus, Store};
use slint::{ComponentHandle, SharedString, VecModel};
use zeroize::Zeroizing;

slint::include_modules!();

const KEYCHAIN_ACCOUNT: &str = "identity-key";

struct State {
    data_dir: PathBuf,
    network: Network,
    account: u32,
    ident: Option<AppIdentity>,
    store: Option<Store>,
    fees: Option<FeeRates>,
    usd: Option<f64>,
    to_address: Option<String>, // None = self-note
    material: Option<Zeroizing<String>>, // session cache: avoids re-prompting Touch ID
    pending_import: Option<Zeroizing<String>>, // hierarchical import awaiting account pick
    pending_mnemonic: Option<String>,
    quiz_indices: Vec<usize>,
}

impl State {
    /// Per-identity, per-network store file — switching keys or accounts
    /// can never collide notebooks.
    fn store_path(&self) -> Option<PathBuf> {
        let fp = hex::encode(self.ident.as_ref()?.identity.output_x);
        Some(
            self.data_dir
                .join(format!("store-{}-{}.json", self.network.as_str(), &fp[..8])),
        )
    }

    fn base_url(&self) -> Option<String> {
        std::env::var("APP_ESPLORA")
            .ok()
            .or_else(|| self.store.as_ref().and_then(|s| s.esplora.clone()))
            .or_else(|| default_base(self.network).map(String::from))
    }

    fn save_store(&self) {
        if let (Some(s), Some(p)) = (&self.store, self.store_path()) {
            let _ = s.save(&p);
        }
    }

    fn save_config(&self) {
        let _ = std::fs::write(
            self.data_dir.join("config.json"),
            serde_json::json!({
                "network": self.network.as_str(),
                "account": self.account,
            })
            .to_string(),
        );
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn spendable_inputs(store: &Store) -> Vec<app_core::store::TxInput> {
    store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| app_core::store::TxInput { txid: u.txid.clone(), vout: u.vout, value: u.value })
        .collect()
}

/// mempool.space tx permalink, or empty on regtest (no public explorer).
fn explorer_tx_url(network: Network, txid: &str) -> String {
    match network {
        Network::Regtest => String::new(),
        Network::Mainnet => format!("https://mempool.space/tx/{txid}"),
        net => format!("https://mempool.space/{}/tx/{txid}", net.as_str()),
    }
}

/// Build the unified activity list (note txs + sweep/consolidate),
/// actionable (pending) first, then newest.
fn update_activity(w: &AppWindow, st: &State) {
    let Some(store) = &st.store else { return };
    let net = st.network;
    let mut items: Vec<(u64, bool, ActivityItem)> = Vec::new(); // (created, confirmed, item)

    for n in &store.notes {
        let Some(txid) = n.txids.last() else { continue };
        let kind = format!(
            "Note · {}{}",
            if n.private { "private" } else { "public" },
            if n.received {
                " · received"
            } else if n.directed {
                " · sent"
            } else {
                ""
            }
        );
        let status = match n.status {
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        items.push((
            n.created_at.or(n.blocktime).unwrap_or(0),
            n.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: n.note_id.clone().into(),
                is_note: true,
                kind: kind.into(),
                title: n.text.clone().unwrap_or_else(|| "(encrypted)".into()).into(),
                txid: txid.clone().into(),
                fee: n.fee.map(|f| f.to_string()).unwrap_or_else(|| "—".into()).into(),
                status: status.into(),
                explorer: explorer_tx_url(net, txid).into(),
                pending: n.status == NoteStatus::Pending && n.raw_hex.is_some(),
            },
        ));
    }

    for t in &store.txs {
        let Some(txid) = t.txids.last() else { continue };
        let status = match t.status {
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        let title = if t.dest == "self" {
            format!("Consolidate → your address · {} sats", t.value)
        } else {
            format!("→ {} · {} sats", t.dest, t.value)
        };
        items.push((
            t.created_at.unwrap_or(0),
            t.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: txid.clone().into(),
                is_note: false,
                kind: if t.kind == "consolidate" { "Consolidate" } else { "Sweep" }.into(),
                title: title.into(),
                txid: txid.clone().into(),
                fee: t.fee.to_string().into(),
                status: status.into(),
                explorer: explorer_tx_url(net, txid).into(),
                pending: t.status == NoteStatus::Pending && t.raw_hex.is_some(),
            },
        ));
    }

    // Actionable (unconfirmed) first, then newest created.
    items.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
    let list: Vec<ActivityItem> = items.into_iter().map(|(_, _, it)| it).collect();
    let pending = list.iter().filter(|i| i.pending).count();
    w.set_activity_summary(
        if list.is_empty() {
            "No transactions yet.".to_string()
        } else {
            format!("{} transaction{} · {pending} pending", list.len(), if list.len() == 1 { "" } else { "s" })
        }
        .into(),
    );
    w.set_activity(VecModel::from_slice(&list));
}

fn normalize_addr(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")) {
        s = rest.to_string();
    }
    if let Some(q) = s.find('?') {
        s.truncate(q);
    }
    s
}

fn activate(st: &mut State, material_str: &str, persist: bool) -> Result<(), String> {
    let material =
        parse_key_material(material_str, st.network).map_err(|e| e.to_string())?;
    let ident = realize(&material, st.network, st.account).map_err(|e| e.to_string())?;
    if persist {
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim())?;
    }
    st.material = Some(Zeroizing::new(material_str.trim().to_string()));
    let fp = hex::encode(ident.identity.output_x);
    let path = st
        .data_dir
        .join(format!("store-{}-{}.json", st.network.as_str(), &fp[..8]));
    let store = Store::load(&path).unwrap_or_else(|_| Store::new(&ident.identity, st.network));
    println!(
        "cb: identity kind={} account={} network={} address={}",
        ident.kind,
        ident.account,
        st.network.as_str(),
        ident.address
    );
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    st.save_config();
    Ok(())
}

fn is_hierarchical(material_str: &str, network: Network) -> bool {
    matches!(
        parse_key_material(material_str, network),
        Ok(app_core::identity::KeyMaterial::Mnemonic(_))
    ) || matches!(
        parse_key_material(material_str, network),
        Ok(app_core::identity::KeyMaterial::Xprv(x)) if x.depth == 0
    )
}

/// One picker page: 5 accounts with their derived addresses.
fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
            })
        })
        .collect()
}

fn show_account_picker(w: &AppWindow, material: &str, network: Network, page: u32, active: Option<u32>) {
    w.set_account_page(page as i32);
    w.set_accounts(VecModel::from_slice(&account_rows(material, network, page, active)));
    w.set_screen(9);
}

fn update_home(w: &AppWindow, st: &State) {
    let Some(ident) = &st.ident else { return };
    let Some(store) = &st.store else { return };
    w.set_address(ident.address.as_str().into());
    if let Some(img) = qr::qr_image(&ident.address.to_uppercase()) {
        w.set_address_qr(img);
    }
    w.set_balance_line(
        format!("{} sats · height {}", store.balance(), store.tip_height).into(),
    );
    let mut items: Vec<NoteItem> = store
        .notes
        .iter()
        .rev()
        .map(|n| {
            let badge = match n.status {
                NoteStatus::Pending => "pending",
                NoteStatus::Confirmed => "confirmed",
                NoteStatus::Orphaned => "orphaned",
            };
            let kind = match (n.received, n.directed, n.private) {
                (true, _, true) => "received private",
                (true, _, false) => "received",
                (false, true, true) => "sent private",
                (false, true, false) => "sent",
                (false, false, true) => "private",
                (false, false, false) => "public",
            };
            NoteItem {
                id: n.note_id.clone().into(),
                title: n
                    .text
                    .as_deref()
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .unwrap_or("(not decryptable)")
                    .into(),
                badge: badge.into(),
                meta: format!(
                    "{kind}{}",
                    n.height.map(|h| format!(" · block {h}")).unwrap_or_default()
                )
                .into(),
            }
        })
        .collect();
    items.sort_by_key(|i| i.badge == "confirmed");
    w.set_notes(VecModel::from_slice(&items));
    let contacts: Vec<ContactItem> = store
        .contacts
        .iter()
        .map(|c| ContactItem { address: c.address.clone().into(), name: c.name.clone().into() })
        .collect();
    w.set_contacts(VecModel::from_slice(&contacts));
    w.set_settings_network(st.network.as_str().into());
    w.set_settings_hierarchical(
        st.material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false),
    );
    if let Some(i) = &st.ident {
        w.set_settings_identity(
            format!(
                "{}{} · {}",
                i.kind,
                if matches!(i.kind, "mnemonic" | "xprv") {
                    format!(" · account {}", i.account)
                } else {
                    String::new()
                },
                st.network.as_str()
            )
            .into(),
        );
    }
    w.set_chunk_text(store.chunk_size.to_string().into());
    w.set_esplora_text(store.esplora.clone().unwrap_or_default().into());
    // Coins (spendable UTXOs) list + summary.
    let coins: Vec<CoinItem> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| CoinItem {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            status: if u.height.is_some() { "confirmed" } else { "unconfirmed" }.into(),
        })
        .collect();
    let spendable: u64 = store.utxos.iter().filter(|u| !u.pending_spend).map(|u| u.value).sum();
    let n = coins.len();
    w.set_coins(VecModel::from_slice(&coins));
    w.set_coins_summary(
        if n == 0 {
            "No coins yet — fund your address to add some.".to_string()
        } else {
            format!("{n} coin{} · {spendable} sats total", if n == 1 { "" } else { "s" })
        }
        .into(),
    );
}

fn refresh(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    let Some(base) = st.base_url() else {
        w.set_status("no esplora endpoint for this network — set one in Settings".into());
        return;
    };
    let client = ChainClient::new(HttpTransport::new(base), st.network);
    let address = st.ident.as_ref().unwrap().address.clone();
    match client.build_bundle(&address, None) {
        Ok(bundle) => {
            st.fees = Some(bundle.fee_rates.clone());
            st.usd = bundle.btc_usd;
            let identity = st.ident.as_ref().unwrap().identity.clone_fields();
            let network = st.network;
            match st.store.as_mut().unwrap().apply_bundle(&bundle, &identity, network) {
                Ok(stats) => {
                    println!(
                        "cb: refresh notes={} new={} orphaned={} balance={} tip={}",
                        stats.notes_seen,
                        stats.notes_new,
                        stats.orphaned,
                        st.store.as_ref().unwrap().balance(),
                        st.store.as_ref().unwrap().tip_height
                    );
                    st.save_store();
                    w.set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.set_status(format!("scan failed: {e}").into());
        }
    }
    update_home(w, st);
}

fn update_cost(w: &AppWindow, st: &State) {
    let Some(store) = &st.store else { return };
    let text = w.get_compose_text();
    let private = w.get_compose_private();
    let rate: f64 = w.get_rate_text().parse().unwrap_or(1.0);
    if text.is_empty() {
        w.set_cost_line("".into());
        return;
    }
    let spk_len = st
        .to_address
        .as_deref()
        .and_then(|a| Recipient::parse(st.network, a).ok())
        .map(|r| r.spk.len());
    let n_inputs = store.available_utxos().len().max(1);
    match estimate_note_cost(text.len(), private, store.chunk_size, n_inputs, spk_len) {
        Ok((chunks, vsize)) => {
            let fee = (vsize as f64 * rate).ceil() as u64;
            let usd = st
                .usd
                .map(|p| format!(" (~${:.2})", fee as f64 * p / 1e8))
                .unwrap_or_default();
            let dust = if spk_len.is_some() { " + 330 sats to recipient" } else { "" };
            w.set_cost_line(
                format!("{chunks} chunk(s) · ~{vsize} vB · ~{fee} sats{usd}{dust}").into(),
            );
        }
        Err(e) => w.set_cost_line(format!("{e}").into()),
    }
}

trait CloneFields {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity;
}
impl CloneFields for app_core::notes_core::bundle::Identity {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity {
        app_core::notes_core::bundle::Identity {
            internal_x: self.internal_x,
            output_x: self.output_x,
            tweaked_seckey: self.tweaked_seckey,
            enc_key: self.enc_key,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--spike") {
        let result = match args.get(2).map(String::as_str) {
            Some("keychain") => keychain::spike(),
            Some("keychain-auth") => keychain::spike_auth(),
            Some("camera") => {
                camera::spike(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15))
            }
            other => Err(format!("unknown spike {other:?}")),
        };
        if let Err(e) = result {
            eprintln!("cb: spike err={e}");
            std::process::exit(1);
        }
        return;
    }

    let data_dir = std::env::var("APP_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("Library/Application Support/ChainNotes")
    });
    let _ = std::fs::create_dir_all(&data_dir);
    let config: serde_json::Value = std::fs::read_to_string(data_dir.join("config.json"))
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(serde_json::Value::Null);
    let network = std::env::var("APP_NETWORK")
        .ok()
        .or_else(|| config.get("network").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| Network::from_str_opt(&s))
        .unwrap_or(Network::Testnet4);
    let account: u32 = std::env::var("APP_ACCOUNT")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("account").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);

    let st = Rc::new(RefCell::new(State {
        data_dir,
        network,
        account,
        ident: None,
        store: None,
        fees: None,
        usd: None,
        to_address: None,
        material: None,
        pending_import: None,
        pending_mnemonic: None,
        quiz_indices: Vec::new(),
    }));
    let window = AppWindow::new().expect("window");

    // Boot identity: APP_KEY env (dev/tests) or the keychain.
    {
        let mut s = st.borrow_mut();
        let material = match std::env::var("APP_KEY") {
            Ok(k) => Some(k),
            Err(_) => match keychain::load_secret_protected(
                KEYCHAIN_ACCOUNT,
                "unlock your Chain Notes identity",
            ) {
                Ok(m) => m,
                Err(e) if e == "cancelled" => {
                    println!("cb: unlock cancelled");
                    window.set_status(
                        "unlock cancelled — restart the app to try again, or import a key".into(),
                    );
                    None
                }
                Err(e) => {
                    window.set_status(format!("keychain: {e}").into());
                    None
                }
            },
        };
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    window.set_screen(4);
                    update_home(&window, &s);
                    refresh(&window, &mut s);
                }
                Err(e) => window.set_status(format!("stored key failed: {e}").into()),
            }
        }
    }

    macro_rules! cb {
        ($name:ident, |$w:ident, $s:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let st = st.clone();
            let weak = window.as_weak();
            window.$name(move |$($arg : $ty),*| {
                let $w = weak.unwrap();
                let mut $s = st.borrow_mut();
                $body
            });
        }};
    }

    cb!(on_door_import, |w, s| {
        println!("cb: door=import");
        let _ = &mut s;
        w.set_import_feedback("".into());
        w.set_screen(1);
    });

    cb!(on_door_create, |w, s, words: i32| {
        println!("cb: door=create words={words}");
        match generate_mnemonic(words as usize) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    // TEST ONLY (env-gated): lets the UI e2e complete the
                    // backup quiz. Never set outside automation.
                    println!("cb-test: words={phrase}");
                }
                w.set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
                w.set_screen(2);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_backup_continue, |w, s| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let count = phrase.split(' ').count();
        let mut idx = [0u8; 3];
        let _ = getrandom_fill(&mut idx);
        let mut picks: Vec<usize> = idx.iter().map(|b| (*b as usize) % count).collect();
        picks.sort();
        picks.dedup();
        while picks.len() < 3 {
            picks.push((picks.last().copied().unwrap_or(0) + 3) % count);
            picks.sort();
            picks.dedup();
        }
        if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
            println!("cb-test: quiz={} {} {}", picks[0] + 1, picks[1] + 1, picks[2] + 1);
        }
        w.set_quiz_prompt(
            format!(
                "Type words #{}, #{} and #{} (space separated):",
                picks[0] + 1,
                picks[1] + 1,
                picks[2] + 1
            )
            .into(),
        );
        s.quiz_indices = picks;
        w.set_quiz_answer("".into());
        w.set_screen(3);
    });

    cb!(on_quiz_submit, |w, s, answer: SharedString| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = s.quiz_indices.iter().map(|i| words[*i]).collect();
        let got: Vec<String> =
            answer.split_whitespace().map(|x| x.to_lowercase()).collect();
        let ok = got == expect;
        println!("cb: quiz ok={ok}");
        if !ok {
            w.set_status("mismatch — check your written words and try again".into());
            return;
        }
        match activate(&mut s, &phrase, true) {
            Ok(()) => {
                s.pending_mnemonic = None;
                w.set_status("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_import_changed, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if t.is_empty() {
            w.set_import_feedback("".into());
            w.set_import_suggestions("".into());
            return;
        }
        // Word autocomplete for the mnemonic path.
        let last = t.split_whitespace().last().unwrap_or("");
        let sugg = if last.len() >= 2 && last.chars().all(|c| c.is_ascii_alphabetic()) {
            let prefix = last.to_lowercase();
            let matches = bip39::Language::English.words_by_prefix(&prefix);
            if matches.len() > 1 || (matches.len() == 1 && matches[0] != last) {
                format!("… {}", matches.iter().take(6).cloned().collect::<Vec<_>>().join(" · "))
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        w.set_import_suggestions(sugg.into());
        let fb = match parse_key_material(&t, s.network) {
            Ok(m) if is_hierarchical(&t, s.network) => {
                format!("✓ {} — you'll choose an account next", m.kind())
            }
            Ok(m) => match realize(&m, s.network, 0) {
                Ok(p) => {
                    let a = &p.address;
                    format!("✓ {} → {}…{}", m.kind(), &a[..12.min(a.len())], &a[a.len().saturating_sub(6)..])
                }
                Err(e) => format!("{e}"),
            },
            Err(e) => format!("{e}"),
        };
        w.set_import_feedback(fb.into());
    });

    cb!(on_import_confirm, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if parse_key_material(&t, s.network).is_ok() && is_hierarchical(&t, s.network) {
            println!("cb: import hierarchical → account picker");
            s.pending_import = Some(Zeroizing::new(t.clone()));
            show_account_picker(&w, &t, s.network, 0, None);
            return;
        }
        s.account = 0;
        match activate(&mut s, text.trim(), true) {
            Ok(()) => {
                println!("cb: import ok");
                w.set_import_text("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => {
                println!("cb: import err={e}");
                w.set_import_feedback(format!("{e}").into());
            }
        }
    });

    {
        let weak = window.as_weak();
        window.on_import_scan(move || {
            println!("cb: import-scan start");
            let weak = weak.clone();
            std::thread::spawn(move || {
                let text = match camera::capture_and_decode(20, |_, _, _| {}) {
                    Ok(Some(payload)) => match app_core::seedqr::decode(&payload) {
                        Ok(m) => m.to_string(),
                        Err(_) => String::from_utf8_lossy(&payload).to_string(),
                    },
                    Ok(None) => String::new(),
                    Err(e) => {
                        println!("cb: import-scan err={e}");
                        String::new()
                    }
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    if !text.is_empty() {
                        println!("cb: import-scan ok len={}", text.len());
                        w.set_import_text(text.clone().into());
                        w.invoke_import_changed(text.into());
                    } else {
                        w.set_import_feedback("scan: no QR seen".into());
                    }
                });
            });
        });
    }

    cb!(on_import_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    println!("cb: import-file len={}", text.trim().len());
                    w.set_import_text(text.trim().into());
                    w.invoke_import_changed(text.trim().into());
                }
                Err(e) => w.set_import_feedback(format!("file: {e}").into()),
            }
        }
    });

    cb!(on_refresh, |w, s| {
        refresh(&w, &mut s);
    });

    cb!(on_open_note, |w, s, id: SharedString| {
        let Some(store) = &s.store else { return };
        if let Some(n) = store.notes.iter().find(|n| n.note_id.as_str() == id.as_str()) {
            println!("cb: open-note id={} status={:?}", n.note_id, n.status);
            let detail = format!(
                "{}\n\nid: {}\nkind: {}{}{}\ntxids: {}\nheight: {}\n{}{}",
                n.text.as_deref().unwrap_or("(not decryptable)"),
                n.note_id,
                if n.received { "received" } else { "own" },
                if n.directed { " · directed" } else { "" },
                if n.private { " · private" } else { " · public" },
                n.txids.join(", "),
                n.height.map(|h| h.to_string()).unwrap_or_else(|| "unconfirmed".into()),
                n.sender.as_deref().map(|a| format!("from: {a}\n")).unwrap_or_default(),
                n.recipient.as_deref().map(|a| format!("to: {a}\n")).unwrap_or_default(),
            );
            w.set_note_detail(detail.into());
            w.set_note_view_id(n.note_id.clone().into());
            w.set_note_pending(n.status == NoteStatus::Pending && n.raw_hex.is_some());
            w.set_note_txid(n.txids.last().cloned().unwrap_or_default().into());
            let bump = s.fees.as_ref().map(|f| f.fastest.max(2.0)).unwrap_or(2.0);
            w.set_bump_rate(format!("{bump}").into());
            let web = match s.network {
                Network::Regtest => String::new(),
                net => {
                    let addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                    format!(
                        "https://objsal.github.io/chain-notes-companion/note.html?address={addr}&network={}&note={}",
                        net.as_str(),
                        n.note_id
                    )
                }
            };
            w.set_note_web_url(web.into());
            w.set_screen(5);
        }
    });

    cb!(on_open_note_web, |w, s| {
        let _ = &mut s;
        let url = w.get_note_web_url().to_string();
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web url={url}");
        let _ = std::process::Command::new("open").arg(&url).spawn();
    });

    cb!(on_copy_text, |w, s, kind: SharedString, text: SharedString| {
        let _ = &mut s;
        let _ = &w;
        use std::io::Write;
        let ok = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.as_mut().expect("piped").write_all(text.as_bytes())?;
                c.wait()
            })
            .is_ok();
        println!("cb: copy kind={kind} len={} ok={ok}", text.len());
    });

    cb!(on_rebroadcast_note, |w, s| {
        let id = w.get_note_view_id().to_string();
        let raw = s
            .store
            .as_ref()
            .and_then(|st| st.notes.iter().find(|n| n.note_id == id))
            .and_then(|n| n.raw_hex.clone());
        let (Some(raw), Some(base)) = (raw, s.base_url()) else {
            w.set_status("nothing to rebroadcast".into());
            return;
        };
        let client = ChainClient::new(HttpTransport::new(base), s.network);
        match client.broadcast(&raw) {
            Ok(txid) => {
                println!("cb: rebroadcast id={id} txid={txid} ok");
                w.set_status(format!("rebroadcast {}…", &txid[..12.min(txid.len())]).into());
            }
            Err(e) => {
                println!("cb: rebroadcast id={id} err={e}");
                w.set_status(format!("rebroadcast failed: {e}").into());
            }
        }
    });

    cb!(on_bump_note, |w, s, rate: SharedString| {
        let id = w.get_note_view_id().to_string();
        let Ok(rate) = rate.trim().parse::<f64>() else {
            w.set_status("bad fee rate".into());
            return;
        };
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        let identity = s.ident.as_ref().unwrap().identity.clone_fields();
        let result = app_core::compose::bump_fee(
            s.store.as_mut().unwrap(),
            &identity,
            net,
            &id,
            rate,
        );
        match result {
            Ok(c) => {
                s.save_store();
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&c.tx.raw_hex) {
                    Ok(txid) => {
                        println!("cb: bump id={id} txid={txid} fee={} ok", c.tx.fee);
                        w.set_status(format!("bumped → {}…", &txid[..12.min(txid.len())]).into());
                        w.set_note_txid(txid.into());
                    }
                    Err(e) => {
                        println!("cb: bump id={id} broadcast err={e}");
                        w.set_status(format!("bump signed but broadcast failed: {e}").into());
                    }
                }
            }
            Err(e) => {
                println!("cb: bump id={id} err={e}");
                w.set_status(format!("{e}").into());
            }
        }
    });

    cb!(on_set_fee_tier, |w, s, tier: i32| {
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        w.set_fee_tier(tier);
        w.set_rate_text(format!("{rate}").into());
        println!("cb: fee-tier {tier} rate={rate}");
        update_cost(&w, &s);
    });

    cb!(on_open_coins, |w, s| {
        println!("cb: open-coins");
        update_home(&w, &s);
        w.set_status("".into());
        w.set_screen(10);
    });

    cb!(on_open_activity, |w, s| {
        println!("cb: open-activity");
        let rate = s.fees.as_ref().map(|f| f.fastest.max(2.0)).unwrap_or(2.0);
        w.set_activity_rate(format!("{rate}").into());
        update_activity(&w, &s);
        w.set_status("".into());
        w.set_screen(11);
    });

    cb!(on_act_retry, |w, s, ref_id: SharedString, is_note: bool| {
        let Some(base) = s.base_url() else { return };
        let raw = if is_note {
            s.store
                .as_ref()
                .and_then(|st| st.notes.iter().find(|n| n.note_id.as_str() == ref_id.as_str()))
                .and_then(|n| n.raw_hex.clone())
        } else {
            s.store
                .as_ref()
                .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id.as_str())))
                .and_then(|t| t.raw_hex.clone())
        };
        let Some(raw) = raw else {
            w.set_status("nothing to rebroadcast".into());
            return;
        };
        let client = ChainClient::new(HttpTransport::new(base), s.network);
        match client.broadcast(&raw) {
            Ok(txid) => {
                println!("cb: act-retry ref={ref_id} txid={txid} ok");
                w.set_status(format!("rebroadcast {}…", &txid[..12.min(txid.len())]).into());
            }
            Err(e) => {
                println!("cb: act-retry ref={ref_id} err={e}");
                w.set_status(format!("rebroadcast failed: {e}").into());
            }
        }
    });

    cb!(on_act_bump, |w, s, ref_id: SharedString, is_note: bool, rate_s: SharedString| {
        let Ok(rate) = rate_s.trim().parse::<f64>() else {
            w.set_status("bad fee rate".into());
            return;
        };
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        let identity = s.ident.as_ref().unwrap().identity.clone_fields();
        let result: Result<(String, String, u64), app_core::Error> = if is_note {
            app_core::compose::bump_fee(s.store.as_mut().unwrap(), &identity, net, ref_id.as_str(), rate)
                .map(|c| (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee))
        } else {
            app_core::compose::bump_raw_tx(s.store.as_mut().unwrap(), &identity, ref_id.as_str(), rate)
                .map(|tx| (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee))
        };
        match result {
            Ok((raw, txid, fee)) => {
                s.save_store();
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&raw) {
                    Ok(bt) => {
                        println!("cb: act-bump ref={ref_id} txid={txid} fee={fee} ok");
                        w.set_status(format!("bumped → {}…", &bt[..12.min(bt.len())]).into());
                        update_activity(&w, &s);
                    }
                    Err(e) => {
                        println!("cb: act-bump ref={ref_id} broadcast err={e}");
                        w.set_status(format!("bump signed but broadcast failed: {e}").into());
                        update_activity(&w, &s);
                    }
                }
            }
            Err(e) => {
                println!("cb: act-bump ref={ref_id} err={e}");
                w.set_status(format!("{e}").into());
            }
        }
    });

    cb!(on_act_explorer, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = std::process::Command::new("open").arg(url.as_str()).spawn();
    });

    cb!(on_consolidate, |w, s| {
        w.set_show_consolidate_confirm(false);
        let rate: f64 = w.get_consolidate_rate().trim().parse().unwrap_or(1.0);
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        let ident = s.ident.as_ref().unwrap();
        // Self-send: consolidate all spendable coins into one output at
        // our own address.
        let Ok(me) = Recipient::parse(net, &ident.address) else { return };
        let identity = ident.identity.clone_fields();
        let store = s.store.as_mut().unwrap();
        if store.available_utxos().len() < 2 {
            w.set_status("nothing to consolidate (need 2+ coins)".into());
            return;
        }
        let inputs = spendable_inputs(store);
        let dest_spk_hex = hex::encode(&me.spk);
        let tx = app_core::notes_core::tx::build_sweep_tx(
            &store.available_utxos(),
            &identity.output_x,
            me.spk,
            rate,
            &identity.tweaked_seckey,
            app_core::notes_core::keys::generate_aux_rand,
        );
        match tx {
            Ok(tx) => {
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&tx.raw_hex) {
                    Ok(txid) => {
                        for u in &mut store.utxos {
                            u.pending_spend = true;
                        }
                        store.record_tx("consolidate", txid.clone(), tx.tx.outputs[0].value, tx.fee, tx.raw_hex.clone(), "self".into(), inputs, dest_spk_hex, now());
                        s.save_store();
                        println!("cb: consolidate txid={txid} value={} fee={}", tx.tx.outputs[0].value, tx.fee);
                        w.set_status(format!("consolidating → {}…", &txid[..12.min(txid.len())]).into());
                        update_home(&w, &s);
                    }
                    Err(e) => w.set_status(format!("consolidate broadcast failed: {e}").into()),
                }
            }
            Err(e) => w.set_status(format!("consolidate: {e}").into()),
        }
    });

    cb!(on_sweep, |w, s| {
        w.set_show_sweep_confirm(false);
        let dest = w.get_sweep_dest().to_string();
        let rate: f64 = w.get_sweep_rate().trim().parse().unwrap_or(1.0);
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        let identity = s.ident.as_ref().unwrap().identity.clone_fields();
        let store = s.store.as_mut().unwrap();
        let inputs = spendable_inputs(store);
        let dest_spk_hex = hex::encode(&recipient.spk);
        let sweep = app_core::notes_core::tx::build_sweep_tx(
            &store.available_utxos(),
            &identity.output_x,
            recipient.spk,
            rate,
            &identity.tweaked_seckey,
            app_core::notes_core::keys::generate_aux_rand,
        );
        match sweep {
            Ok(tx) => {
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&tx.raw_hex) {
                    Ok(txid) => {
                        for u in &mut store.utxos {
                            u.pending_spend = true;
                        }
                        store.record_tx("sweep", txid.clone(), tx.tx.outputs[0].value, tx.fee, tx.raw_hex.clone(), dest.clone(), inputs, dest_spk_hex, now());
                        s.save_store();
                        println!(
                            "cb: sweep txid={txid} value={} fee={}",
                            tx.tx.outputs[0].value, tx.fee
                        );
                        w.set_status(format!("swept {} sats → {}…", tx.tx.outputs[0].value, &dest[..14.min(dest.len())]).into());
                        update_home(&w, &s);
                    }
                    Err(e) => w.set_status(format!("sweep broadcast failed: {e}").into()),
                }
            }
            Err(e) => w.set_status(format!("sweep: {e}").into()),
        }
    });

    cb!(on_compose_open, |w, s| {
        println!("cb: compose-open");
        let _ = &mut s;
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    cb!(on_pick_contact, |w, s, addr: SharedString| {
        if addr.as_str() == "self" {
            s.to_address = None;
            w.set_to_label("To: Self (my notebook)".into());
            println!("cb: pick-contact to=self");
        } else {
            let mut a = normalize_addr(addr.as_str());
            if Recipient::parse(s.network, &a).is_err() {
                let lower = a.to_lowercase();
                if Recipient::parse(s.network, &lower).is_ok() {
                    a = lower;
                } else {
                    println!("cb: pick-contact err=bad-address");
                    w.set_status(format!("not a valid {} address", s.network.as_str()).into());
                    return;
                }
            }
            println!("cb: pick-contact to={a}");
            if let Some(store) = &mut s.store {
                store.touch_contact(&a);
            }
            s.save_store();
            w.set_to_label(format!("To: {a} (+330 sat dust delivery)").into());
            s.to_address = Some(a);
        }
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        w.set_fee_tier(1);
        w.set_rate_text(format!("{rate}").into());
        w.set_status("".into());
        w.set_screen(6);
        update_cost(&w, &s);
    });

    {
        let weak = window.as_weak();
        window.on_contact_scan(move || {
            println!("cb: contact-scan start");
            let weak = weak.clone();
            std::thread::spawn(move || {
                let text = match camera::capture_and_decode(20, |_, _, _| {}) {
                    Ok(Some(p)) => String::from_utf8_lossy(&p).to_string(),
                    _ => String::new(),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    if text.is_empty() {
                        w.set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: contact-scan ok");
                        let a = normalize_addr(&text);
                        // Prefill so a failed validation leaves it editable,
                        // then pick directly — a valid scan goes straight
                        // to Compose (the Prime picker behavior).
                        w.set_contact_input(a.clone().into());
                        w.invoke_pick_contact(a.into());
                    }
                });
            });
        });
    }

    cb!(on_start_rename, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: rename-start addr={addr}");
        w.set_status("".into());
        w.set_rename_address(addr);
        w.set_rename_input(name);
    });

    cb!(on_save_rename, |w, s, name: SharedString| {
        let addr = w.get_rename_address().to_string();
        if let Some(store) = &mut s.store {
            store.name_contact(&addr, name.trim());
        }
        s.save_store();
        println!("cb: save-contact addr={addr} name-len={}", name.trim().len());
        w.set_status("".into());
        w.set_rename_address("".into());
        w.set_rename_input("".into());
        update_home(&w, &s);
    });

    cb!(on_cancel_rename, |w, s| {
        let _ = &mut s;
        w.set_rename_address("".into());
        w.set_rename_input("".into());
    });

    cb!(on_confirm_remove, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: confirm-remove addr={addr}");
        w.set_confirm_remove_name(name);
        w.set_confirm_remove_address(addr);
    });

    cb!(on_cancel_remove, |w, s| {
        let _ = &mut s;
        w.set_confirm_remove_address("".into());
    });

    cb!(on_remove_contact, |w, s, addr: SharedString| {
        if let Some(store) = &mut s.store {
            store.remove_contact(addr.as_str());
        }
        s.save_store();
        println!("cb: remove-contact addr={addr}");
        w.set_status("".into());
        w.set_confirm_remove_address("".into());
        if w.get_rename_address() == addr {
            w.set_rename_address("".into());
        }
        update_home(&w, &s);
    });

    cb!(on_compose_changed, |w, s| {
        let _ = &mut s;
        update_cost(&w, &s);
    });

    cb!(on_compose_send, |w, s| {
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        let Some(base) = s.base_url() else {
            w.set_status("no esplora endpoint — set one in Settings".into());
            return;
        };
        let ident_ptr = s.ident.as_ref().map(|i| i.identity.output_x);
        let Some(_) = ident_ptr else { return };
        let identity = s.ident.as_ref().unwrap().identity.clone_fields();
        let result = compose_and_record(
            s.store.as_mut().unwrap(),
            &identity,
            net,
            &ComposeRequest {
                text: &text,
                private,
                recipient: to.as_deref(),
                fee_rate: rate,
                now: now(),
            },
        );
        match result {
            Ok(c) => {
                s.save_store();
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&c.tx.raw_hex) {
                    Ok(txid) => {
                        println!(
                            "cb: compose id={} txid={txid} fee={} vsize={} to={} private={} broadcast=ok",
                            c.note_id, c.tx.fee, c.tx.vsize,
                            to.as_deref().unwrap_or("self"), private
                        );
                        w.set_status(format!("broadcast {}…", &txid[..12]).into());
                        w.set_compose_text("".into());
                        w.set_screen(4);
                        refresh(&w, &mut s);
                    }
                    Err(e) => {
                        println!("cb: compose broadcast err={e}");
                        w.set_status(format!("signed but broadcast failed ({e}) — note is pending, Refresh to retry visibility. If relay-policy, lower chunk bytes in Settings and recompose.").into());
                        update_home(&w, &s);
                        w.set_screen(4);
                    }
                }
            }
            Err(e) => {
                println!("cb: compose err={e}");
                w.set_status(format!("{e}").into());
            }
        }
    });

    cb!(on_settings_open, |w, s| {
        println!("cb: settings-open");
        let _ = &mut s;
        w.set_reveal_text("".into());
        w.set_status("".into());
        w.set_chunk_custom(false);
        w.set_screen(8);
    });

    cb!(on_open_account_picker, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = s.account / 5;
        show_account_picker(&w, &material, s.network, page, Some(s.account));
    });

    cb!(on_accounts_page, |w, s, delta: i32| {
        let page = (w.get_account_page() + delta).max(0) as u32;
        let material = s
            .pending_import
            .as_ref()
            .or(s.material.as_ref())
            .map(|z| String::from(z.as_str()));
        let Some(material) = material else { return };
        let active = if s.pending_import.is_some() { None } else { Some(s.account) };
        show_account_picker(&w, &material, s.network, page, active);
    });

    cb!(on_pick_account, |w, s, idx: i32| {
        let first_import = s.pending_import.is_some();
        let Some(material) = s
            .pending_import
            .take()
            .map(|z| String::from(z.as_str()))
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())))
        else {
            return;
        };
        s.account = idx.max(0) as u32;
        println!("cb: pick-account {}", s.account);
        match activate(&mut s, &material, first_import) {
            Ok(()) => {
                w.set_import_text("".into());
                w.set_status("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_account_cancel, |w, s| {
        if s.pending_import.take().is_some() {
            w.set_screen(1); // abandon import → back to the import form
        } else {
            update_home(&w, &s);
            w.set_screen(8); // came from settings
        }
    });

    cb!(on_reset_identity, |w, s| {
        println!("cb: reset-identity");
        let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);
        // Privacy: local stores cache decrypted note text — delete them.
        if let Ok(entries) = std::fs::read_dir(&s.data_dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("store-") && name.ends_with(".json") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        s.ident = None;
        s.store = None;
        s.material = None;
        s.account = 0;
        s.to_address = None;
        w.set_show_reset_confirm(false);
        w.set_reveal_text("".into());
        w.set_status("".into());
        w.set_import_text("".into());
        w.set_screen(0);
    });

    cb!(on_hide_backup, |w, s| {
        let _ = &mut s;
        w.set_reveal_text("".into());
    });

    cb!(on_set_network, |w, s, net: SharedString| {
        let Some(n) = Network::from_str_opt(net.as_str()) else { return };
        if n == s.network {
            return;
        }
        s.network = n;
        println!("cb: set-network {}", s.network.as_str());
        s.save_config();
        // Same key material, new network: re-derive + reload store.
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    update_home(&w, &s);
                    refresh(&w, &mut s);
                }
                Err(e) => w.set_status(format!("network switch: {e}").into()),
            }
        }
        w.set_settings_network(s.network.as_str().into());
    });

    cb!(on_set_chunk, |w, s, t: SharedString| {
        match t.trim().parse::<usize>() {
            Ok(n) if (20..=100_000).contains(&n) => {
                if let Some(store) = &mut s.store {
                    store.chunk_size = n;
                }
                s.save_store();
                println!("cb: set-chunk-size {n} ok");
                w.set_chunk_text(n.to_string().into());
                if n == 100_000 || n == 80 {
                    w.set_chunk_custom(false);
                }
                w.set_status("".into());
            }
            _ => {
                println!("cb: set-chunk-size err=range");
                w.set_status("chunk bytes must be 20..=100000".into());
            }
        }
    });

    cb!(on_set_esplora, |w, s, t: SharedString| {
        let v = t.trim().to_string();
        if let Some(store) = &mut s.store {
            store.esplora = if v.is_empty() { None } else { Some(v.clone()) };
        }
        s.save_store();
        println!("cb: set-esplora {}", if v.is_empty() { "default" } else { &v });
        w.set_status("".into());
    });

    cb!(on_reveal_backup, |w, s| {
        let _ = &mut s;
        match keychain::load_secret_protected(KEYCHAIN_ACCOUNT, "reveal your backup words") {
            Ok(Some(secret)) => {
                println!("cb: reveal-backup ok len={}", secret.len());
                w.set_reveal_text(secret.into());
            }
            Ok(None) => w.set_reveal_text("(no key in keychain — APP_KEY env session?)".into()),
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-backup cancelled");
                w.set_reveal_text("authentication cancelled".into());
            }
            Err(e) => w.set_reveal_text(format!("keychain: {e}").into()),
        }
    });

    cb!(on_go_home, |w, s| {
        w.set_reveal_text("".into());
        update_home(&w, &s);
        w.set_screen(4);
    });

    let auto_refresh = slint::Timer::default();
    {
        let st = st.clone();
        let weak = window.as_weak();
        auto_refresh.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(60),
            move || {
                if let Some(w) = weak.upgrade() {
                    if w.get_screen() == 4 {
                        let mut s = st.borrow_mut();
                        if s.ident.is_some() {
                            refresh(&w, &mut s);
                        }
                    }
                }
            },
        );
    }

    window.run().expect("event loop");
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::getrandom(buf).map_err(|_| ())
}
