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
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    println!("cb-test: words={phrase}");
                }
                println!("cb: regenerate-words count={count}");
                set_backup_words(w, &phrase);
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
        let picks = quiz_picks(idx, count);
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

/// Three DISTINCT, ascending word positions for the backup quiz from three
/// random bytes. Collisions are resolved by walking forward from the last
/// pick until a free position turns up — the previous loop pushed
/// `(last + 3) % count` unconditionally and dedup'd, which never terminates
/// once that slot is already taken (e.g. picks `[0, 9]` on a 12-word seed
/// keep producing 0): the app's UI thread hung in the quiz step, caught
/// 2026-09-06 when `cargo test --lib` spun for 30 minutes in
/// `create_seed_backup_quiz_lands_on_notebook_list_named_notebook_1`.
/// Total function for every `count >= 3`.
pub(crate) fn quiz_picks(idx: [u8; 3], count: usize) -> Vec<usize> {
    let count = count.max(3);
    let mut picks: Vec<usize> = idx.iter().map(|b| (*b as usize) % count).collect();
    picks.sort_unstable();
    picks.dedup();
    while picks.len() < 3 {
        let mut next = (picks.last().copied().unwrap_or(0) + 3) % count;
        while picks.contains(&next) {
            next = (next + 1) % count;
        }
        picks.push(next);
        picks.sort_unstable();
        picks.dedup();
    }
    picks
}

/// The numbered backup-word grid shown on the write-it-down screen. Three
/// columns on desktop; TWO on phones (`platform::type_scale() > 1.0`): a
/// 3-column row of 13px Menlo is ~44 chars, which the `Mono` char-wrap
/// splits mid-word on a 411dp phone even before the type scale. The one
/// formatter for both create paths (device RNG + dice) and the preview mock.
/// Push a phrase to the backup screen: the numbered grid string (what Copy
/// puts on the clipboard, and what the UI suites read) AND the word list the
/// screen lays out as cells.
pub(crate) fn set_backup_words(w: &AppWindow, phrase: &str) {
    w.global::<Ui>().set_backup_words(word_grid(phrase).into());
    let words: Vec<slint::SharedString> = phrase.split(' ').filter(|s| !s.is_empty()).map(Into::into).collect();
    w.global::<Ui>().set_backup_word_list(slint::ModelRc::new(slint::VecModel::from(words)));
}

pub(crate) fn word_grid(phrase: &str) -> String {
    let cols = crate::platform::word_columns() as usize;
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

#[cfg(test)]
mod quiz_pick_tests {
    use super::quiz_picks;

    /// The exact shape that hung the old loop: two picks where `last + 3`
    /// wraps onto an existing one.
    #[test]
    fn quiz_picks_terminates_on_the_wrapping_collision() {
        assert_eq!(quiz_picks([9, 9, 9], 12), vec![0, 1, 9]);
        assert_eq!(quiz_picks([0, 9, 9], 12), vec![0, 1, 9]);
    }

    /// Exhaustive over every residue triple for the three seed lengths:
    /// always three distinct ascending positions inside the phrase.
    #[test]
    fn quiz_picks_are_three_distinct_in_range_positions_for_every_input() {
        for count in [12usize, 18, 24] {
            for a in 0..count {
                for b in 0..count {
                    for c in 0..count {
                        let p = quiz_picks([a as u8, b as u8, c as u8], count);
                        assert_eq!(p.len(), 3, "{count} {a} {b} {c}: {p:?}");
                        assert!(p[0] < p[1] && p[1] < p[2], "{count} {a} {b} {c}: {p:?}");
                        assert!(p[2] < count, "{count} {a} {b} {c}: {p:?}");
                    }
                }
            }
        }
    }

    /// Distinct random bytes are used as-is (the common case is untouched).
    #[test]
    fn quiz_picks_keeps_three_distinct_draws() {
        assert_eq!(quiz_picks([5, 2, 11], 12), vec![2, 5, 11]);
        assert_eq!(quiz_picks([200, 13, 77], 24), vec![5, 8, 13]);
    }
}
