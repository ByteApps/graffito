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

impl State {
pub(crate) fn on_private_select(&mut self, w: &AppWindow, fmt: SharedString) {
        let fmt = fmt.as_str();
        if fmt == "hex" || fmt == "wif" {
            let Some(v) = self.derive_leaf_value(w, fmt) else { return };
            w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
            w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
            w.global::<PrivateKeys>().set_reveal_private_value(v.into());
            w.global::<Ui>().set_reveal_private_format(fmt.into());
            println!("cb: private-select fmt={fmt}");
            return;
        }
        let Some(f) = self.reveal_formats.as_ref() else { return };
        w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
        match fmt {
            "recovery" => {
                let Some(words) = f.mnemonic.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                let list: Vec<&str> = words.split_whitespace().collect();
                let half = list.len() / 2;
                let col = |range: std::ops::Range<usize>| -> String {
                    range
                        .map(|i| format!("{:2}. {}", i + 1, list[i]))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                w.global::<PrivateKeys>().set_reveal_words_col1(col(0..half).into());
                w.global::<PrivateKeys>().set_reveal_words_col2(col(half..list.len()).into());
                if let Ok(m) = bip39::Mnemonic::parse(&words) {
                    let digits = app_core::seedqr::encode_standard(&m);
                    w.global::<PrivateKeys>().set_reveal_seedqr_image(qr::qr_image(&digits).unwrap_or_default());
                }
                w.global::<PrivateKeys>().set_reveal_private_value(words.into());
                w.global::<PrivateKeys>().set_reveal_private_qr(slint::Image::default());
            }
            "xprv" => {
                let Some(v) = f.account_xprv.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
                w.global::<PrivateKeys>().set_reveal_private_value(v.into());
            }
            // hex/wif are handled above (picker-aware, returns early).
            _ => return,
        }
        w.global::<Ui>().set_reveal_private_format(fmt.into());
        println!("cb: private-select fmt={fmt}");
    }

pub(crate) fn on_private_pick_notebook(&mut self, w: &AppWindow, index: i32) {
        w.global::<PrivateKeys>().set_reveal_nb_index(index);
        println!("cb: private-pick-notebook index={index}");
        let fmt = w.global::<Ui>().get_reveal_private_format().to_string();
        if fmt != "hex" && fmt != "wif" {
            return;
        }
        let Some(v) = self.derive_leaf_value(w, &fmt) else { return };
        w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
        w.global::<PrivateKeys>().set_reveal_private_value(v.into());
    }

pub(crate) fn on_copy_secret(&mut self, w: &AppWindow, value: SharedString) {
        let ok = platform::set_clipboard_secret(value.as_str());
        println!("cb: copy-secret len={}", value.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }
}
