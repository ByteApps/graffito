//! Screen.private-keys — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// "Home" for flows that end at the active notebook — unless the active
/// account has no notebook entry, in which case home would be a trap only
/// reachable by accident: land on the notebook list instead. Since the
/// onboarding unification (Sal 2026-07-21: create/import/restore all
/// ensure notebook 0 and open its home) the unlisted case is rare —
/// e.g. an account whose every notebook was archived — but the guard
/// stays for exactly those.
/// Wipe any revealed key-export material from the UI (nav away / reset /
/// hide) AND drop the cached private-reveal formats (`State.reveal_formats`
/// — the only place a freshly-authenticated secret is held; dropping it
/// zeroizes via `Zeroizing`). Values otherwise live only in these props, so
/// clearing them is the wipe.
pub(crate) fn clear_reveal(&mut self, w: &AppWindow) {
    let s = self;
    let empty: Vec<RevealRow> = Vec::new();
    w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&empty));
    w.global::<Ui>().set_reveal_public_hint("".into());
    w.global::<Ui>().set_reveal_fingerprint("".into());
    w.global::<PrivateKeys>().set_reveal_has_recovery(false);
    w.global::<PrivateKeys>().set_reveal_has_xprv(false);
    w.global::<PrivateKeys>().set_reveal_has_hex(false);
    w.global::<PrivateKeys>().set_reveal_has_wif(false);
    w.global::<Ui>().set_reveal_private_format("".into());
    w.global::<PrivateKeys>().set_reveal_private_value("".into());
    w.global::<PrivateKeys>().set_reveal_private_qr(slint::Image::default());
    w.global::<PrivateKeys>().set_reveal_words_col1("".into());
    w.global::<PrivateKeys>().set_reveal_words_col2("".into());
    w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
    w.global::<PrivateKeys>().set_reveal_seedqr_image(slint::Image::default());
    w.global::<PrivateKeys>().set_reveal_nb_rows(VecModel::from_slice(&Vec::<NbPickRow>::new()));
    w.global::<PrivateKeys>().set_reveal_nb_index(0);
    s.reveal_formats = None;
}

/// The active account's notebook picker rows for the Private-keys hex/WIF
/// views (archived notebooks excluded — matches the notebook list). `name`
/// falls back to the short address when unnamed (`notebook_display_name`),
/// `addr` is always the short address so an unnamed row isn't just a
/// duplicate string.
pub(crate) fn private_nb_rows(&self) -> Vec<NbPickRow> {
    let st = self;
    let Some(ix) = &st.notebooks else { return Vec::new() };
    ix.books(st.account)
        .iter()
        .filter(|m| !m.archived)
        .map(|m| {
            let addr = st
                .nb_addrs
                .iter()
                .find(|(a, ..)| *a == m.index)
                .map(|(_, a, _)| addr_short(a))
                .unwrap_or_default();
            // Named notebooks show their name; unnamed ones read the
            // default "Notebook <index+1>" (not the address again — the
            // addr already sits in its own column).
            let name = if m.name.trim().is_empty() {
                app_core::notebooks::default_name(m.index)
            } else {
                m.name.clone()
            };
            NbPickRow {
                index: m.index as i32,
                name: name.into(),
                addr: addr.into(),
            }
        })
        .collect()
}
}
