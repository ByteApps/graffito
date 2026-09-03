//! Screen.import-key — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
#[allow(unused_variables)]
pub(crate) fn on_import_changed(&mut self, w: &AppWindow, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let t = text.trim().to_string();
        if t.is_empty() {
            w.global::<ImportKey>().set_import_feedback("".into());
            w.global::<ImportKey>().set_import_suggestions("".into());
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
        w.global::<ImportKey>().set_import_suggestions(sugg.into());
        let (fb, ok) = match parse_key_material(&t, s.network) {
            Ok(m) if is_hierarchical(&t, s.network) => {
                (format!("{} OK — you'll choose an account next", m.kind()), true)
            }
            Ok(m) => match realize(&m, s.network, 0, 0) {
                Ok(p) => {
                    let a = &p.address;
                    let label = if m.is_watch() {
                        "account xpub OK — watch-only: public notes and balance, no signing"
                    } else {
                        "OK"
                    };
                    let kind_prefix = if m.is_watch() { String::new() } else { format!("{} ", m.kind()) };
                    (format!("{kind_prefix}{label} · {}…{}", &a[..12.min(a.len())], &a[a.len().saturating_sub(6)..]), true)
                }
                Err(e) => (format!("{e}"), false),
            },
            Err(e) => (format!("{e}"), false),
        };
        w.global::<ImportKey>().set_import_feedback_ok(ok);
        w.global::<ImportKey>().set_import_feedback(fb.into());
    }

#[allow(unused_variables)]
pub(crate) fn on_import_confirm(&mut self, w: &AppWindow, text: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        // Sal 2026-07-22: a SEED (hierarchical: mnemonic/xprv) no longer
        // branches into the account picker — it activates account 0 directly,
        // auto-creates its first notebook, and lands on the notebook LIST.
        // Single-key imports (WIF/hex) are unchanged: activate() adds their one
        // intrinsic notebook and they land on its home.
        let hierarchical = parse_key_material(text.trim(), s.network).is_ok()
            && is_hierarchical(text.trim(), s.network);
        s.account = 0;
        s.nb_index = 0;
        match s.activate(text.trim(), true) {
            Ok(()) => {
                println!("cb: import ok");
                w.global::<ImportKey>().set_import_text("".into());
                if hierarchical {
                    s.ensure_first_onboarded_notebook();
                    s.update_notebook_list(w);
                    w.global::<Ui>().set_screen(Screen::Notebooks);
                    s.refresh_async(w);
                    s.spending_refresh_async(w);
                } else {
                    w.global::<Ui>().set_screen(Screen::Home);
                    s.update_home(w);
                    s.refresh_async(w);
                }
            }
            Err(e) => {
                println!("cb: import err={e}");
                w.global::<ImportKey>().set_import_feedback_ok(false);
                w.global::<ImportKey>().set_import_feedback(e.to_string().into());
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_paste_import(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        match platform::clipboard_text() {
            Some(text) => {
                let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                    w.global::<ImportKey>().set_import_text(text.clone().into());
                    w.global::<ImportKey>().invoke_import_changed(text.into());
                });
            }
            None => {
                w.global::<ImportKey>().set_import_feedback_ok(false);
                w.global::<ImportKey>().set_import_feedback("clipboard empty".into());
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_import_file(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    println!("cb: import-file len={}", text.trim().len());
                    w.global::<ImportKey>().set_import_text(text.trim().into());
                    w.global::<ImportKey>().invoke_import_changed(text.trim().into());
                }
                Err(e) => {
                    w.global::<ImportKey>().set_import_feedback_ok(false);
                    w.global::<ImportKey>().set_import_feedback(format!("file: {e}").into());
                }
            }
        }
    }
}
