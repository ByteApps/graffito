//! Screen.backup-words — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
pub(crate) fn on_regenerate_words(&mut self, w: &AppWindow) {
        let count = self
            .pending_mnemonic
            .as_ref()
            .map(|m| m.split(' ').count())
            .unwrap_or(12);
        let salt = w.global::<BackupWords>().get_entropy_salt().to_string();
        match generate_mnemonic_with_salt(count, &salt) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid = word_grid(&phrase);
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    println!("cb-test: words={phrase}");
                }
                println!("cb: regenerate-words count={count}");
                w.global::<Ui>().set_backup_words(grid.into());
                self.pending_mnemonic = Some(phrase);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    }

pub(crate) fn on_backup_continue(&mut self, w: &AppWindow) {
        let Some(phrase) = self.pending_mnemonic.clone() else { return };
        let count = phrase.split(' ').count();
        let mut idx = [0u8; 3];
        // `idx` is NOT key material — it only selects which 3 of the
        // already-generated words the backup quiz asks the user to
        // retype. A failure here still leaves a valid (if predictable,
        // zeroed) selection, so we log and carry on rather than fail the
        // backup flow or reach for a fallback RNG.
        if getrandom_fill(&mut idx).is_err() {
            println!("cb: backup-quiz entropy err");
        }
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
        w.global::<Quiz>().set_quiz_prompt(
            format!(
                "Type words #{}, #{} and #{} (space separated):",
                picks[0] + 1,
                picks[1] + 1,
                picks[2] + 1
            )
            .into(),
        );
        self.quiz_indices = picks;
        w.global::<Quiz>().set_quiz_answer("".into());
        w.global::<Ui>().set_screen(Screen::Quiz);
    }
}

/// The numbered backup-word grid shown on the write-it-down screen. Three
/// columns on desktop; TWO on phones (`platform::type_scale() > 1.0`): a
/// 3-column row of 13px Menlo is ~44 chars, which the `Mono` char-wrap
/// splits mid-word on a 411dp phone even before the type scale. The one
/// formatter for both create paths (device RNG + dice) and the preview mock.
pub(crate) fn word_grid(phrase: &str) -> String {
    let cols = if crate::platform::type_scale() > 1.0 { 2 } else { 3 };
    // Longest BIP-39 word is 8 chars; the wider pad is the desktop look.
    let pad = if cols == 2 { 8 } else { 9 };
    phrase
        .split(' ')
        .enumerate()
        .map(|(i, wd)| {
            format!("{:>2}. {:<pad$}{}", i + 1, wd, if i % cols == cols - 1 { "\n" } else { " " }, pad = pad)
        })
        .collect()
}
