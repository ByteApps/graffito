//! Screen.home — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn go_home_or_list(&self, w: &AppWindow) {
    let st = self;
    let listed = st
        .ident
        .as_ref()
        .and_then(|i| st.notebooks.as_ref().map(|ix| ix.get(i.account, i.index).is_some()))
        .unwrap_or(false);
    if listed {
        st.update_home(w);
        w.global::<Ui>().set_screen(Screen::Home);
    } else {
        st.update_notebook_list(w);
        w.global::<Ui>().set_screen(Screen::Notebooks);
    }
}

pub(crate) fn update_home(&self, w: &AppWindow) {
    let st = self;
    let Some(ident) = &st.ident else { return };
    let Some(store) = &st.store else { return };
    let watch = ident.is_watch();
    st.update_identity_flags(w);
    w.global::<Home>().set_notebook_title(st.notebook_display_name(ident.index).into());
    w.global::<Ui>().set_address(ident.address.as_str().into());
    if let Some(img) = qr::qr_image(&ident.address.to_uppercase()) {
        w.global::<Home>().set_address_qr(img);
    }
    w.global::<Home>().set_balance_line(
        format!("{} sats · block {}", commas(store.balance()), commas(store.tip_height))
            .into(),
    );
    // Sender filter: the checklist model + the "hidden" pill, then the
    // notes list itself filtered through the persisted exclusion set.
    let senders: Vec<SenderItem> = store
        .senders()
        .into_iter()
        .map(|(key, count)| SenderItem {
            label: st.sender_label(&key).into(),
            sub: format!("{count} note{}", if count == 1 { "" } else { "s" }).into(),
            excluded: store.is_excluded(&key),
            key: key.into(),
        })
        .collect();
    let hidden = senders.iter().filter(|s| s.excluded).count();
    w.global::<Ui>().set_senders(VecModel::from_slice(&senders));
    w.global::<Home>().set_hidden_senders_label(
        match hidden {
            0 => String::new(),
            1 => "1 sender hidden".into(),
            n => format!("{n} senders hidden"),
        }
        .into(),
    );
    let address = ident.address.clone();
    let net = st.network;
    let mut items: Vec<NoteItem> = store
        .notes
        .iter()
        .rev()
        .filter(|n| !store.is_excluded(&store.sender_key(n)))
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
                    .unwrap_or(if n.locked.is_some() {
                        "(locked — tap to unlock)"
                    } else if watch && n.private {
                        "(private — key not on this device)"
                    } else {
                        "(not decryptable)"
                    })
                    .into(),
                badge: badge.into(),
                meta: format!(
                    "{kind}{}",
                    n.height.map(|h| format!(" · block {h}")).unwrap_or_default()
                )
                .into(),
                web_url: note_web_url(net, &address, &n.note_id).into(),
                private: n.private,
                locked: n.locked.is_some(),
            }
        })
        .collect();
    items.sort_by_key(|i| i.badge == "confirmed");
    w.global::<Ui>().set_notes(VecModel::from_slice(&items));
    st.refresh_contacts(w);
    st.update_settings_identity(w);
    st.load_backend_settings(w);
    st.update_wallet_coins(w);
    st.update_spending_ui(w);
}
}

impl State {
pub(crate) fn on_open_note(&mut self, w: &AppWindow, id: SharedString) {
        let Some(store) = &self.store else { return };
        if let Some(n) = store.notes.iter().find(|n| n.note_id.as_str() == id.as_str()) {
            println!("cb: open-note id={} status={:?}", n.note_id, n.status);
            let watch = self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            // PLAN-pnte-redesign.md: the note id IS the txid now (64 hex
            // chars, not the old synthetic hex8) — the inline "id:" quick-
            // view line shows just the first 8 chars, same footprint as
            // before; the full id is still available verbatim via the
            // "Copy text" button (copies this whole block) and the
            // dedicated "Copy txid" button (`note-txid`, set below).
            let detail = format_note_detail(n, watch, None);
            w.global::<Note>().set_note_detail(detail.into());
            w.global::<Ui>().set_note_view_id(n.note_id.clone().into());
            w.global::<Note>().set_note_pending(n.status == NoteStatus::Pending && n.raw_hex.is_some());
            w.global::<Note>().set_note_txid(n.txids.last().cloned().unwrap_or_default().into());
            refresh_note_unlock_ui(w, n);
            // Reply-all set ({sender} ∪ recipients minus me) — meaningful
            // for both a received note (sender + other recipients) and an
            // OWN directed note (a shortcut to write the same people again;
            // Sal 2026-07-19). Self-notes have an empty set → no buttons.
            let my_addr = self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let full_set = n.reply_set(&my_addr);
            // Reply = the single counterparty: the sender of a received note,
            // or the sole recipient of an own single-recipient directed note.
            // An own multi-recipient note has no single counterparty — it
            // gets Reply all only.
            let reply_addr = if n.received {
                n.sender.clone().unwrap_or_default()
            } else if full_set.len() == 1 {
                full_set[0].clone()
            } else {
                String::new()
            };
            w.global::<Note>().set_note_reply_address(reply_addr.into());
            let reply_rows: Vec<ContactItem> = full_set
                .iter()
                .map(|a| {
                    let name = self
                        .contacts
                        .iter()
                        .find(|c| &c.address == a && !c.name.is_empty())
                        .map(|c| c.name.clone())
                        .unwrap_or_default();
                    ContactItem { address: a.clone().into(), name: name.into(), synced: false, sync_status: 0, pq: false }
                })
                .collect();
            w.global::<Note>().set_note_reply_set(VecModel::from_slice(&reply_rows));
            let web = match self.network {
                Network::Regtest => String::new(),
                net => {
                    let addr = self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                    format!(
                        "https://byteapps.com/graffito/companion/note.html?address={addr}&network={}&note={}",
                        net.as_str(),
                        n.note_id
                    )
                }
            };
            w.global::<Note>().set_note_web_url(web.into());
            w.global::<Ui>().set_screen(Screen::Note);
        }
    }

pub(crate) fn on_open_note_web_url(&mut self, _w: &AppWindow, url: SharedString) {
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web-url");
        let _ = platform::open_url(url.as_str());
    }

pub(crate) fn on_compose_open(&mut self, w: &AppWindow) {
        println!("cb: compose-open");
        w.global::<Ui>().set_pick_mode("compose".into());
        self.pull_icloud_contacts_on_open(w);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Contacts);
    }

pub(crate) fn on_toggle_sender(&mut self, w: &AppWindow, key: SharedString, excluded: bool) {
        let Some(store) = self.store.as_mut() else { return };
        store.set_excluded(key.as_str(), excluded);
        let hidden = store.excluded_senders.len();
        println!("cb: toggle-sender excluded={excluded} hidden={hidden}");
        self.save_store();
        self.update_home(w);
    }
}
