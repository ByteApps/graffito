//! Screen.note — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// Repaint screen 5's locked-note unlock block for the note `on_open_note`
/// just resolved.
///
/// - Not locked (`n.locked` is `None`, whether it's a plaintext note or an
///   already-unlocked one): everything hidden.
/// - A SELF-note (`locked.is_self()`, PLAN-graffito-self-pw.md): checked
///   FIRST — unlike a directed note, the author always holds the enc key
///   `unlock_self` needs, so there is no `SenderCannotReopen` case here at
///   all. `FLAG_PW` shows the password field (+ Unlock button, unchanged
///   shape); `FLAG_MLKEM` alone (no password) still needs an Unlock button
///   to try the already-loaded imported key, which the DIRECTED-note
///   "nothing can help" caption-only block never offered — see
///   `note-unlock-show-button`.
/// - `FLAG_PW` set, and NOT a sender-side ML-KEM note (see below): a
///   passphrase can genuinely unlock it — show the field + Unlock button.
/// - Otherwise (locked, no password layer to type, OR an own note carrying
///   `FLAG_MLKEM`): nothing the user can type will help, so an explanatory
///   caption replaces the input entirely. An own note with `FLAG_MLKEM`
///   (with or without `FLAG_PW` alongside it) is `unlock_sent`'s
///   `SenderCannotReopen` case UNCONDITIONALLY — the sender never held the
///   recipient's decapsulation key, so no password will ever complete it,
///   which is why this case is checked FIRST (among directed notes) and
///   short-circuits past the password branch even when `FLAG_PW` is also
///   set.
pub(crate) fn refresh_note_unlock_ui(w: &AppWindow, n: &app_core::store::NoteRecord) {
    use app_core::notes_core::envelope::{FLAG_MLKEM, FLAG_PW};

    let locked = n.locked.is_some();
    w.global::<Ui>().set_note_locked(locked);
    w.global::<Note>().set_note_unlock_busy(false);
    w.global::<Ui>().set_note_unlock_show_button(false);
    if !locked {
        w.global::<Note>().set_note_unlock_needs_password(false);
        w.global::<Ui>().set_note_unlock_caption("".into());
        w.global::<Note>().set_note_unlock_passphrase("".into());
        return;
    }
    let is_self =
        n.locked.as_ref().map(app_core::notes_core::pq::LockedBody::is_self).unwrap_or(false);
    if is_self {
        let needs_password = n.pq_flags & FLAG_PW != 0;
        let needs_mlkem = n.pq_flags & FLAG_MLKEM != 0;
        w.global::<Note>().set_note_unlock_needs_password(needs_password);
        w.global::<Ui>().set_note_unlock_caption(
            if needs_mlkem && needs_password {
                "Also needs your quantum key to reopen — you'll be asked if it isn't \
                 loaded. Losing either the password or the key loses this note forever."
                    .to_string()
            } else if needs_mlkem {
                "Needs your quantum key to reopen (Settings → Quantum keys). Losing it \
                 loses this note forever, even with your seed."
                    .to_string()
            } else {
                String::new()
            }
            .into(),
        );
        w.global::<Ui>().set_note_unlock_show_button(true);
        w.global::<Note>().set_note_unlock_passphrase("".into());
        return;
    }
    let sender_kem_locked = !n.received && (n.pq_flags & FLAG_MLKEM != 0);
    if sender_kem_locked {
        w.global::<Note>().set_note_unlock_needs_password(false);
        w.global::<Ui>().set_note_unlock_caption("Can't re-read this note — it's sealed to the recipient's key.".into());
    } else if n.pq_flags & FLAG_PW != 0 {
        w.global::<Note>().set_note_unlock_needs_password(true);
        w.global::<Ui>().set_note_unlock_caption("".into());
    } else {
        w.global::<Note>().set_note_unlock_needs_password(false);
        w.global::<Ui>().set_note_unlock_caption(
            "Sealed to a quantum key this device doesn't hold.".into(),
        );
    }
    w.global::<Note>().set_note_unlock_passphrase("".into());
}

/// Build screen 5's detail text block for note `n` — shared by
/// `on_open_note` (the normal, store-backed render, `text_override: None`)
/// and `on_unlock_note`'s SELF-note view-only path (PLAN-graffito-self-pw.md),
/// which passes the just-decrypted plaintext as `text_override` WITHOUT
/// writing it into `n.text`/the store: a self-pq note's second factor stays
/// load-bearing on every future open, so nothing about this render may
/// persist. `text_override` always wins over `n.text` when present (it is
/// only ever passed when `n.text` is `None`, but preferring it here keeps
/// the precedence explicit rather than accidental).
pub(crate) fn format_note_detail(n: &app_core::store::NoteRecord, watch: bool, text_override: Option<&str>) -> String {
    let short_id = &n.note_id[..8.min(n.note_id.len())];
    format!(
        "{}\n\nid: {}…\nkind: {}{}{}\ntxids: {}\nheight: {}\n{}{}",
        text_override.or(n.text.as_deref()).unwrap_or(if n.locked.is_some() {
            "(locked — see below to unlock)"
        } else if watch && n.private {
            "(private — the key that reads this note isn't on this device)"
        } else {
            "(not decryptable)"
        }),
        short_id,
        if n.received { "received" } else { "own" },
        if n.directed { " · directed" } else { "" },
        if n.private { " · private" } else { " · public" },
        n.txids.join(", "),
        n.height.map(|h| h.to_string()).unwrap_or_else(|| "unconfirmed".into()),
        n.sender.as_deref().map(|a| format!("from: {a}\n")).unwrap_or_default(),
        // Multi-recipient note: list EVERY recipient (one per line,
        // output order); the singular field only names the first.
        if n.recipients.is_empty() {
            n.recipient.as_deref().map(|a| format!("to: {a}\n")).unwrap_or_default()
        } else {
            format!("to ({}): {}\n", n.recipients.len(), n.recipients.join("\n    "))
        },
    )
}

impl State {
/// Sender-filter label rules, in priority order: "Self · <notebook>" when
/// the sender is one of the ACTIVE account's addresses (this notebook's
/// own notes, or directed notes from a sibling notebook),
/// "Self · account N" when it belongs to another of our accounts (rev-3
/// follow-up 3 — accounts are separate wallets, but the sender is still
/// us), the contact name when known, else the short address form.
pub(crate) fn sender_label(&self, key: &str) -> String {
    let st = self;
    if let Some((index, ..)) = st.nb_addrs.iter().find(|(_, a, _)| a == key) {
        return format!("Self · {}", st.notebook_display_name(*index));
    }
    if let Some((acct, _)) = st.xacct_addrs.iter().find(|(_, a)| a == key) {
        return format!("Self · account {acct}");
    }
    if let Some(c) = st.contacts.iter().find(|c| c.address == key && !c.name.is_empty()) {
        return c.name.clone();
    }
    addr_short(key)
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_unlock_note(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // User-initiated tap — the LAUNCH-PATH rule's other sanctioned door
        // (besides opening the Quantum keys screen, and — since
        // PLAN-graffito-self-pw.md — the Security panel's own header tap)
        // for loading an imported ML-KEM secret from the Keychain this
        // session. Runs before the borrows below so it never conflicts
        // with them.
        s.ensure_pq_imported_loaded();
        let note_id = w.global::<Ui>().get_note_view_id().to_string();
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let identity = identity.clone_fields();
        let password = w.global::<Note>().get_note_unlock_passphrase().to_string();
        w.global::<Note>().set_note_unlock_busy(true);

        // A SELF-note's locked body goes through the VIEW-ONLY path
        // (PLAN-graffito-self-pw.md): `unlock_note`/`unlock_sent` refuse it
        // outright (`is_self()` discriminates in notes-core), so this check
        // must happen before picking which store fn to call at all.
        let is_self = s
            .store
            .as_ref()
            .and_then(|store| store.notes.iter().find(|n| n.note_id == note_id))
            .and_then(|n| n.locked.as_ref())
            .map(app_core::notes_core::pq::LockedBody::is_self)
            .unwrap_or(false);

        if is_self {
            // View-only: NEVER persisted, and `locked` never clears — every
            // future open asks again (the whole point of the second
            // factor). `unlock_note_view` takes `&self`, so nothing here
            // mutates the store — no `save_store()`, unlike the directed
            // path below.
            let mlkem_secret = s.pq_imported.as_ref().map(|kp| kp.secret());
            let result = match s.store.as_ref() {
                Some(store) => store.unlock_note_view(
                    &note_id,
                    &identity,
                    mlkem_secret.as_ref(),
                    Some(password.as_str()),
                ),
                None => Err(app_core::Error::Store("no store".into())),
            };
            w.global::<Note>().set_note_unlock_busy(false);
            match result {
                Ok(text) => {
                    println!("cb: unlock-note ok view-only");
                    let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
                    if let Some(n) =
                        s.store.as_ref().and_then(|store| store.notes.iter().find(|n| n.note_id == note_id))
                    {
                        let detail = format_note_detail(n, watch, Some(text.as_str()));
                        w.global::<Note>().set_note_detail(detail.into());
                    }
                    w.global::<Ui>().set_note_locked(false);
                    w.global::<Note>().set_note_unlock_needs_password(false);
                    w.global::<Ui>().set_note_unlock_show_button(false);
                    w.global::<Ui>().set_note_unlock_caption("".into());
                    w.global::<Note>().set_note_unlock_passphrase("".into());
                }
                Err(e) => {
                    println!("cb: unlock-note err={e}");
                    w.global::<Ui>().set_status(format!("couldn't unlock: {e}").into());
                }
            }
            return;
        }

        let secrets = mlkem_secrets_for(s.ident.as_ref().unwrap(), s.pq_imported.as_ref());
        let result = match s.store.as_mut() {
            Some(store) => store.unlock_note(&note_id, &identity, &secrets, Some(password.as_str())),
            None => Err(app_core::Error::Store("no store".into())),
        };
        w.global::<Note>().set_note_unlock_busy(false);
        match result {
            Ok(_text) => {
                println!("cb: unlock-note ok");
                s.save_store();
                s.update_home(w);
                // U4: was `w.global::<Home>().invoke_open_note(...)` — that
                // re-enters the SAME `&mut self` borrow now that on_open_note
                // is a method rather than a fresh `st.borrow_mut()`, so call
                // it directly instead of round-tripping through Slint.
                s.on_open_note(w, note_id.into());
            }
            Err(e) => {
                println!("cb: unlock-note err={e}");
                w.global::<Ui>().set_status(format!("couldn't unlock: {e}").into());
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_open_note_web(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        let url = w.global::<Note>().get_note_web_url().to_string();
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web url={url}");
        let _ = platform::open_url(&url);
    }

#[allow(unused_variables)]
pub(crate) fn on_reply_to_note(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let addr = w.global::<Note>().get_note_reply_address().to_string();
        if addr.is_empty() {
            return;
        }
        println!("cb: reply to={addr}");
        w.global::<Ui>().set_compose_return(Screen::Note);
        s.pick_contact_core(w, &addr);
    }

#[allow(unused_variables)]
pub(crate) fn on_reply_all_to_note(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let addrs: Vec<String> = w.global::<Note>().get_note_reply_set().iter().map(|c| c.address.to_string()).collect();
        let Some((first, rest)) = addrs.split_first() else { return };
        println!("cb: reply-all to={} n={}", addrs.join(","), addrs.len());
        w.global::<Ui>().set_compose_return(Screen::Note);
        // pick_contact_core resets the compose session (clearing any prior
        // to_addresses_extra) before we seed the rest as extra chips.
        s.pick_contact_core(w, first);
        s.to_addresses_extra = rest.to_vec();
        s.refresh_to_chips(w);
        s.refresh_compose(w);
    }
}
