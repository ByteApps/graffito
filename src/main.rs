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

slint::include_modules!();

const KEYCHAIN_ACCOUNT: &str = "identity-key";

struct State {
    data_dir: PathBuf,
    network: Network,
    ident: Option<AppIdentity>,
    store: Option<Store>,
    fees: Option<FeeRates>,
    usd: Option<f64>,
    to_address: Option<String>, // None = self-note
    material: Option<String>,   // session cache: avoids re-prompting Touch ID
    pending_mnemonic: Option<String>,
    quiz_indices: Vec<usize>,
}

impl State {
    fn store_path(&self) -> PathBuf {
        self.data_dir.join(format!("store-{}.json", self.network.as_str()))
    }

    fn base_url(&self) -> Option<String> {
        std::env::var("APP_ESPLORA")
            .ok()
            .or_else(|| self.store.as_ref().and_then(|s| s.esplora.clone()))
            .or_else(|| default_base(self.network).map(String::from))
    }

    fn save_store(&self) {
        if let Some(s) = &self.store {
            let _ = s.save(&self.store_path());
        }
    }

    fn save_config(&self) {
        let _ = std::fs::write(
            self.data_dir.join("config.json"),
            format!("{{\"network\":\"{}\"}}", self.network.as_str()),
        );
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    let ident = realize(&material, st.network).map_err(|e| e.to_string())?;
    if persist {
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim())?;
    }
    st.material = Some(material_str.trim().to_string());
    let path = st.data_dir.join(format!("store-{}.json", st.network.as_str()));
    let store = Store::load(&path).unwrap_or_else(|_| Store::new(&ident.identity, st.network));
    println!(
        "cb: identity kind={} network={} address={}",
        ident.kind,
        st.network.as_str(),
        ident.address
    );
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    Ok(())
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
    w.set_chunk_text(store.chunk_size.to_string().into());
    w.set_esplora_text(store.esplora.clone().unwrap_or_default().into());
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
    let network = std::env::var("APP_NETWORK")
        .ok()
        .or_else(|| {
            std::fs::read_to_string(data_dir.join("config.json"))
                .ok()
                .and_then(|c| serde_json_network(&c))
        })
        .and_then(|s| Network::from_str_opt(&s))
        .unwrap_or(Network::Testnet4);

    let st = Rc::new(RefCell::new(State {
        data_dir,
        network,
        ident: None,
        store: None,
        fees: None,
        usd: None,
        to_address: None,
        material: None,
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
                    .map(|(i, wd)| format!("{:2}. {wd}{}", i + 1, if i % 3 == 2 { "\n" } else { "   " }))
                    .collect();
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
            Ok(m) => format!("✓ recognized: {}", m.kind()),
            Err(e) => format!("{e}"),
        };
        w.set_import_feedback(fb.into());
    });

    cb!(on_import_confirm, |w, s, text: SharedString| {
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
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0);
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
        let material = std::env::var("APP_KEY").ok().or_else(|| s.material.clone());
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

    window.run().expect("event loop");
}

fn serde_json_network(config: &str) -> Option<String> {
    config
        .split('"')
        .skip_while(|s| *s != "network")
        .nth(2)
        .map(String::from)
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::getrandom(buf).map_err(|_| ())
}
