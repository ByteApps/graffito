//! Screen.onboarding — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// Unlock the saved keychain identity — the half that PROMPTS. Split from
/// [`activate_restored`] so the caller isn't holding a `State` borrow across a
/// Face ID prompt that can sit there for as long as the user takes.
///
/// **Never call this on the launch path.** Both callers are safe by
/// construction: the onboarding "Restore saved key" tap (user-initiated) and
/// the deferred auto-unlock timer (after the first frame).
pub(crate) fn read_saved_material(window: &AppWindow) -> Option<String> {
    // `load_secret_gated`, NOT `load_secret_protected`: a synced item has no
    // ACL to prompt on, so the restore door read the seed silently — most
    // visibly on a fresh install, where tapping Restore on an unlocked phone
    // was the whole authentication story (Sal, 2026-07-26). The gated variant
    // adds an LAContext check for exactly that shape; the local-ACL shape is
    // unchanged, the OS already prompts. Only the TAP path uses it — the
    // deferred auto-unlock reads directly, off-thread.
    match keychain::load_secret_gated(KEYCHAIN_ACCOUNT, "unlock your Graffito identity") {
        Ok(Some(m)) => Some(m),
        Ok(None) => {
            // Probed present but gone by the time we read it (deleted from
            // another device, or an iCloud item that vanished).
            println!("cb: unlock none");
            window.global::<Onboarding>().set_saved_key_present(false);
            None
        }
        Err(e) if e == "cancelled" => {
            println!("cb: unlock cancelled");
            window.global::<Ui>().set_status("unlock cancelled — tap Restore to try again".into());
            None
        }
        Err(e) => {
            println!("cb: unlock err={e}");
            window.global::<Ui>().set_status(format!("keychain: {e}").into());
            None
        }
    }
}

impl State {
/// Activate a just-unlocked saved identity and land on the notebook list.
/// Restoring IS the opt-in for automatic unlock: from here on launches unlock
/// on their own (still deferred past the first frame).
pub(crate) fn activate_restored(&mut self, window: &AppWindow, material: String, onboarding: bool) {
    let s = self;
    match s.activate(&material, false) {
        Ok(()) => {
            if !s.auto_unlock {
                s.auto_unlock = true;
                s.save_config();
            }
            // Stamp the backup state from the ITEM, not from a boot guess.
            // Boot sets `icloud_backup = icloud_available()` while no key is
            // loaded (it's the default for a key about to be created), so a
            // restored LOCAL-ONLY key on an iCloud-signed-in device would
            // otherwise leave Settings claiming a backup that doesn't exist.
            // The removed "Restore from iCloud" door hid this by forcing
            // true — right for its case only. `is_synced` forbids auth UI, so
            // this cannot prompt.
            let synced = keychain::is_synced(KEYCHAIN_ACCOUNT);
            s.icloud_backup = synced;
            window.global::<Ui>().set_icloud_backup(synced);
            // Restoring from the onboarding door is an ONBOARDING EXIT, and
            // every other one (create-seed, import, iCloud restore) ensures
            // the account's notebook 0 — I added this path and skipped it, so
            // a restore after a fresh install landed on an empty list. The
            // keychain item survives app deletion but `notebooks-*.json` does
            // NOT, so a restored key genuinely has no index to load.
            //
            // Guarded two ways. Only on the onboarding tap, never on the
            // deferred auto-unlock, which is a BOOT path — "boot never
            // resurrects archived entries". And only when the account has NO
            // notebooks AT ALL, active or archived: zero ACTIVE notebooks is
            // legitimate (archive-all is allowed), and re-creating one there
            // would undo a deliberate archive.
            if onboarding {
                let none_at_all = s
                    .notebooks
                    .as_ref()
                    .map(|ix| ix.active(s.account).count() == 0 && ix.archived_count(s.account) == 0)
                    .unwrap_or(true);
                if none_at_all {
                    println!("cb: restore first-notebook");
                    s.ensure_first_onboarded_notebook();
                }
            }
            println!("cb: unlock ok auto-unlock=1");
            s.update_home(window);
            s.update_notebook_list(window);
            window.global::<Ui>().set_status("".into());
            window.global::<Ui>().set_screen(Screen::Notebooks);
            s.refresh_async(window);
            s.spending_refresh_async(window);
        }
        Err(e) => {
            println!("cb: unlock activate-err={e}");
            window.global::<Ui>().set_status(format!("stored key failed: {e}").into());
        }
    }
}

/// Ensure the account's notebook 0 exists (first receive address) and, if it
/// has no name yet, auto-name it for the onboarding list view.
/// Sal 2026-07-21: onboarding (create/import/restore) lands on the notebook
/// LIST with this first row already named, rather than opening the
/// notebook's home. The name is the shared default, "Notebook 1"
/// (`notebooks::default_name`) — same as every other creation path since
/// 2026-07-26. (The pre-notebooks migration path names its first notebook
/// "Main" — see notebooks::FIRST_NOTEBOOK_NAME — that path is untouched.)
/// Everything both create paths (device RNG and dice) do once they have a
/// phrase: render the numbered grid, stash it as pending, default the iCloud
/// backup, and open the write-it-down screen. Factored out when dice landed so
/// the two paths can never drift on the iCloud default or the grid format.
pub(crate) fn stage_new_mnemonic(&mut self, w: &AppWindow, phrase: String) {
    let s = self;
    let grid: String = phrase
        .split(' ')
        .enumerate()
        .map(|(i, wd)| format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " }))
        .collect();
    if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
        // TEST ONLY (env-gated): lets the UI e2e complete the backup quiz.
        // Never set outside automation.
        println!("cb-test: words={phrase}");
    }
    w.global::<Ui>().set_backup_words(grid.into());
    s.pending_mnemonic = Some(phrase);
    // New key on an online device → default the iCloud backup ON when iCloud
    // is available (the user can still turn it off).
    let avail = keychain::icloud_available();
    s.icloud_backup = avail;
    w.global::<Ui>().set_icloud_backup(avail);
    w.global::<Ui>().set_icloud_enabled(avail);
    w.global::<Ui>().set_screen(Screen::BackupWords);
}

pub(crate) fn ensure_first_onboarded_notebook(&mut self) {
    let s = self;
    s.ensure_notebook(0);
    let account = s.account;
    if let Some(ix) = s.notebooks.as_mut() {
        let unnamed = ix.get(account, 0).map(|m| m.name.is_empty()).unwrap_or(true);
        if unnamed {
            ix.rename(account, 0, &app_core::notebooks::default_name(0));
        }
    }
    s.save_notebooks();
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_door_import(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: door=import");
        w.global::<ImportKey>().set_import_feedback("".into());
        // Default the iCloud backup ON for the imported key when iCloud is
        // available (parity with create; the toggle stays user-overridable).
        let avail = keychain::icloud_available();
        s.icloud_backup = avail;
        w.global::<Ui>().set_icloud_backup(avail);
        w.global::<Ui>().set_icloud_enabled(avail);
        w.global::<Ui>().set_screen(Screen::ImportKey);
    }

#[allow(unused_variables)]
pub(crate) fn on_door_create(&mut self, w: &AppWindow, words: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        println!("cb: door=create words={words}");
        s.new_word_count = words as usize;
        s.dice_rolls = Zeroizing::new(String::new());
        w.global::<Ui>().set_new_word_count(words);
        w.global::<BackupWords>().set_seed_from_dice(false);
        w.global::<Ui>().set_screen(Screen::EntropySource);
    }
}
