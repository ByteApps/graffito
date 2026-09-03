//! Screen.backup-words — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
#[allow(unused_variables)]
pub(crate) fn on_regenerate_words(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let count = s
            .pending_mnemonic
            .as_ref()
            .map(|m| m.split(' ').count())
            .unwrap_or(12);
        let salt = w.global::<BackupWords>().get_entropy_salt().to_string();
        match generate_mnemonic_with_salt(count, &salt) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    println!("cb-test: words={phrase}");
                }
                println!("cb: regenerate-words count={count}");
                w.global::<Ui>().set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_backup_continue(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
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
        s.quiz_indices = picks;
        w.global::<Quiz>().set_quiz_answer("".into());
        w.global::<Ui>().set_screen(Screen::Quiz);
    }
}
