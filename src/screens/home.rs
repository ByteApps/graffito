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
