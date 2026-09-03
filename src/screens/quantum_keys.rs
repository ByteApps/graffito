//! Screen.quantum-keys — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// `pq-key-level` (Slint UI string) <-> `passphrase::MlKemLevel` — the
/// UI only ever needs the short "512"/"768"/"1024" form; config.json and
/// every app-core call keep using the real enum.
pub(crate) fn pq_level_str(level: app_core::passphrase::MlKemLevel) -> &'static str {
    match level {
        app_core::passphrase::MlKemLevel::MlKem512 => "512",
        app_core::passphrase::MlKemLevel::MlKem768 => "768",
        app_core::passphrase::MlKemLevel::MlKem1024 => "1024",
    }
}

pub(crate) fn pq_level_from_str(s: &str) -> Option<app_core::passphrase::MlKemLevel> {
    match s {
        "512" => Some(app_core::passphrase::MlKemLevel::MlKem512),
        "768" => Some(app_core::passphrase::MlKemLevel::MlKem768),
        "1024" => Some(app_core::passphrase::MlKemLevel::MlKem1024),
        _ => None,
    }
}

/// One line naming where an imported ML-KEM key came from, for the
/// post-import confirmation caption. Purely descriptive — never shown
/// again after the screen re-derives (a reload from the Keychain has no
/// OpenPGP framing to re-parse, so this is only set right after a
/// successful `pq-import-submit` this session).
pub(crate) fn pq_import_source_label(source: &app_core::pgp_import::ImportSource) -> String {
    match source {
        app_core::pgp_import::ImportSource::OpenPgp { fingerprint, primary_uid } => match primary_uid {
            Some(uid) => format!("OpenPGP key · {uid} · {fingerprint}"),
            None => format!("OpenPGP key · {fingerprint}"),
        },
        app_core::pgp_import::ImportSource::GraffitoNative => "Graffito export".to_string(),
    }
}

/// Post-quantum: the ML-KEM decapsulation secrets to try against any
/// received KEM-only-flagged note a scan recovers (`Store::apply_bundle`'s
/// `mlkem_secrets` param — see its doc comment for the full contract).
/// Covers the scanned notebook's OWN derived keys, all three levels
/// (`pqkeys::derive_secrets`), PLUS `imported` — Phase C2's cached
/// externally-imported secret (another identity's key kept around to read
/// notes addressed to it), when the caller already has it loaded
/// (`ensure_pq_imported_loaded`; never loaded here — this fn never touches
/// the Keychain). `notes_core::pq::unlock_received` tries a candidate
/// against whatever algorithm the ciphertext itself declares, so an
/// imported secret at a different level than the notebook's own derived
/// keys is still tried and simply fails cleanly (ML-KEM implicit
/// rejection) when it doesn't match — no per-secret alg tag needed here.
/// Watch-only and any identity with no leaf secret (`AppIdentity::
/// leaf_secret()` returns `None`) get just the imported secret (or none at
/// all) — a strict no-op for the derived half, exactly like
/// `apply_bundle_watch`.
pub(crate) fn mlkem_secrets_for(
    ident: &AppIdentity,
    imported: Option<&app_core::notes_core::pq::MlKemKeypair>,
) -> Vec<app_core::notes_core::pq::MlKemSecret> {
    let mut secrets =
        ident.leaf_secret().map(app_core::pqkeys::derive_secrets).unwrap_or_default();
    if let Some(kp) = imported {
        secrets.push(kp.secret());
    }
    secrets
}

impl State {
/// Repaint screen 29 (Settings → "Manage quantum keys…") from `st`: the
/// level picker's current selection, the active notebook's derived key at
/// that level (fingerprint only — never re-derives unless the level
/// actually changed, since ML-KEM keygen isn't free), and the imported-key
/// display line (from the session cache, NOT a fresh Keychain read — see
/// `ensure_pq_imported_loaded`). A watch-only identity (no leaf secret)
/// gets a blank fingerprint; the card itself is hidden in that case
/// (`!root.watch-only` in app.slint), so this is just defense in depth.
pub(crate) fn update_pq_keys_screen(&self, w: &AppWindow) {
    let st = self;
    w.global::<QuantumKeys>().set_pq_key_level(pq_level_str(st.pq_level).into());
    let fingerprint = st.ident.as_ref().and_then(|i| i.leaf_secret()).map(|ls| {
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(st.pq_level));
        app_core::pqkeys::fingerprint(&kp)
    });
    w.global::<QuantumKeys>().set_pq_key_fingerprint(fingerprint.unwrap_or_default().into());
    let import_line = st.pq_imported.as_ref().map(|kp| {
        format!(
            "{} · {}",
            app_core::pqkeys::from_pq_alg(kp.alg()).name(),
            app_core::pqkeys::fingerprint(kp)
        )
    });
    w.global::<Ui>().set_pq_import_fp(import_line.unwrap_or_default().into());
    // "My quantum key"'s public armor never needs a warning — show its QR
    // whenever a key is present so it's ready to share/scan immediately,
    // no separate reveal step (unlike the private half below screen 29's
    // export-warning modal).
    let public_qr = st
        .pq_imported
        .as_ref()
        .and_then(|kp| qr::qr_image(&app_core::notes_core::pq::export_public(kp.alg(), kp.ek())));
    w.global::<QuantumKeys>().set_pq_imported_public_qr(public_qr.unwrap_or_default());
}

/// Generate a fresh "My quantum key" — deliberately NOT seed-derived
/// (`app_core::pqkeys::generate_native_private`, PLAN-graffito-quantum-key.md)
/// — from the level/extra-entropy fields on screen 29, store it into the
/// SAME `pq-imported` Keychain slot the import flow writes, and update
/// in-memory state. Called directly when no key exists yet, or from
/// `on_pq_replace_confirm` once the replace guard is confirmed — never
/// called while a key exists without that confirm having fired first.
pub(crate) fn do_pq_generate(&mut self, w: &AppWindow) {
    let s = self;
    let level = pq_level_from_str(w.global::<QuantumKeys>().get_pq_gen_level().as_str())
        .unwrap_or(app_core::passphrase::MlKemLevel::DEFAULT);
    let extra = w.global::<QuantumKeys>().get_pq_gen_extra().to_string();
    w.global::<QuantumKeys>().set_pq_import_error("".into());
    let (kp, armor) = match app_core::pqkeys::generate_native_private(level, extra.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            println!("cb: pq-key-generate err={e}");
            w.global::<QuantumKeys>().set_pq_import_error(e.to_string().into());
            return;
        }
    };
    match keychain::store_secret_protected(PQ_IMPORTED_ACCOUNT, &armor, false) {
        Ok(()) => {
            let fp = app_core::pqkeys::fingerprint(&kp);
            println!("cb: pq-key-generate ok level={} fp={fp}", pq_level_str(level));
            w.global::<QuantumKeys>().set_pq_gen_extra("".into());
            w.global::<Ui>().set_pq_import_source("Generated on this device".into());
            s.pq_imported = Some(kp);
            s.update_pq_keys_screen(w);
        }
        Err(e) => {
            println!("cb: pq-key-generate err={e}");
            w.global::<QuantumKeys>().set_pq_import_error(format!("couldn't save this key: {e}").into());
        }
    }
}

/// Import an external "My quantum key" secret (OpenPGP or Graffito-native
/// armor) from screen 29's paste/file text field into the SAME
/// `pq-imported` Keychain slot [`do_pq_generate`] writes. Same calling
/// convention: direct when no key exists yet, or from
/// `on_pq_replace_confirm` after the replace guard fires.
pub(crate) fn do_pq_import(&mut self, w: &AppWindow) {
    let s = self;
    let text = w.global::<QuantumKeys>().get_pq_import_text().to_string();
    w.global::<QuantumKeys>().set_pq_import_error("".into());
    let imported = match app_core::pgp_import::parse_mlkem_key(&text) {
        Ok(v) => v,
        Err(e) => {
            println!("cb: pq-key-import err={e}");
            w.global::<QuantumKeys>().set_pq_import_error(e.to_string().into());
            return;
        }
    };
    let (kp, armor) = match app_core::pqkeys::import_to_native_private(&imported) {
        Ok(v) => v,
        Err(e) => {
            println!("cb: pq-key-import err={e}");
            w.global::<QuantumKeys>().set_pq_import_error(e.into());
            return;
        }
    };
    match keychain::store_secret_protected(PQ_IMPORTED_ACCOUNT, &armor, false) {
        Ok(()) => {
            let fp = app_core::pqkeys::fingerprint(&kp);
            println!("cb: pq-key-import ok fp={fp}");
            w.global::<QuantumKeys>().set_pq_import_text("".into());
            w.global::<Ui>().set_pq_import_source(pq_import_source_label(&imported.source).into());
            s.pq_imported = Some(kp);
            s.update_pq_keys_screen(w);
        }
        Err(e) => {
            println!("cb: pq-key-import err={e}");
            w.global::<QuantumKeys>().set_pq_import_error(format!("couldn't save this key: {e}").into());
        }
    }
}

/// Derive the CURRENTLY-selected picker notebook's hex/WIF leaf key from
/// the session-cached material (no re-auth) — shared by `private-select`
/// (switching format pills) and `private-pick-notebook` (switching
/// notebooks), so whichever changes last always shows the right value.
pub(crate) fn derive_leaf_value(&self, w: &AppWindow, which: &str) -> Option<String> {
    let s = self;
    let material = s.material.as_ref().map(|z| String::from(z.as_str()))?;
    let index = w.global::<PrivateKeys>().get_reveal_nb_index() as u32;
    let f = app_core::keyexport::export_formats(&material, s.network, s.account, index).ok()?;
    match which {
        "hex" => f.leaf_hex.as_ref().map(|z| z.as_str().to_string()),
        "wif" => f.leaf_wif.as_ref().map(|z| z.as_str().to_string()),
        _ => None,
    }
}

/// Post-quantum: lazily load the externally-imported ML-KEM secret
/// (Settings → Quantum keys → "Import a key") from its Keychain account
/// into `State.pq_imported` — a no-op once already cached this session
/// (mirrors `s.material`'s "avoids re-prompting Touch ID" caching). Call
/// ONLY from a user-initiated point — opening the Quantum keys screen, or
/// tapping Unlock on a locked note — NEVER from a scan or the boot path
/// (the LAUNCH-PATH rule: the keychain is off limits until the user asks
/// for it). A missing item is not an error — nothing has been imported
/// yet, or it was removed.
pub(crate) fn ensure_pq_imported_loaded(&mut self) {
    let s = self;
    if s.pq_imported.is_some() {
        return;
    }
    match keychain::load_secret_protected(PQ_IMPORTED_ACCOUNT, "unlock your quantum key") {
        Ok(Some(armor)) => match app_core::notes_core::pq::import_private(&armor) {
            Ok((alg, seed)) => {
                s.pq_imported = Some(app_core::notes_core::pq::MlKemKeypair::from_seed(alg, &seed));
            }
            Err(e) => println!("cb: pq-key-import-load err={e}"),
        },
        Ok(None) => {}
        Err(e) => println!("cb: pq-key-import-load err={e}"),
    }
}
}

impl State {
pub(crate) fn on_pq_set_level(&mut self, w: &AppWindow, level: SharedString) {
        let Some(level) = pq_level_from_str(level.as_str()) else { return };
        self.pq_level = level;
        self.save_config();
        println!("cb: pq-key level={}", pq_level_str(level));
        self.update_pq_keys_screen(w);
    }

pub(crate) fn on_pq_copy_public(&mut self, w: &AppWindow) {
        let Some(ls) = self.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(self.pq_level));
        let armor = app_core::pqkeys::export_public_armor(&kp);
        let ok = platform::set_clipboard_text(&armor);
        println!("cb: pq-key-export public len={}", armor.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }

pub(crate) fn on_pq_save_public(&mut self, w: &AppWindow) {
        let Some(ls) = self.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(self.pq_level));
        let armor = app_core::pqkeys::export_public_armor(&kp);
        if let Some(path) = platform::save_file("quantum-public-key.asc") {
            match std::fs::write(&path, armor.as_bytes()) {
                Ok(()) => {
                    println!("cb: pq-key-export public len={}", armor.len());
                    w.global::<Ui>().set_status("saved public key".into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    }

pub(crate) fn on_pq_import_paste(&mut self, w: &AppWindow) {
        match platform::clipboard_text() {
            Some(text) => w.global::<QuantumKeys>().set_pq_import_text(text.into()),
            None => w.global::<QuantumKeys>().set_pq_import_error("clipboard empty".into()),
        }
    }

pub(crate) fn on_pq_import_file(&mut self, w: &AppWindow) {
        if let Some(path) = platform::pick_file(&[("Key", &["asc", "txt", "pgp", "gpg"])]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => w.global::<QuantumKeys>().set_pq_import_text(text.trim().into()),
                Err(e) => w.global::<QuantumKeys>().set_pq_import_error(format!("file: {e}").into()),
            }
        }
    }

pub(crate) fn on_pq_generate(&mut self, w: &AppWindow) {
        if self.pq_imported.is_some() {
            self.pq_pending_replace = Some(PqReplaceKind::Generate);
            w.global::<Ui>().set_pq_show_replace_confirm(true);
            return;
        }
        self.do_pq_generate(w);
    }

pub(crate) fn on_pq_import_submit(&mut self, w: &AppWindow) {
        if self.pq_imported.is_some() {
            self.pq_pending_replace = Some(PqReplaceKind::Import);
            w.global::<Ui>().set_pq_show_replace_confirm(true);
            return;
        }
        self.do_pq_import(w);
    }

pub(crate) fn on_pq_import_remove(&mut self, w: &AppWindow) {
        let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);
        self.pq_imported = None;
        w.global::<Ui>().set_pq_import_source("".into());
        w.global::<QuantumKeys>().set_pq_import_error("".into());
        println!("cb: pq-key-remove");
        self.update_pq_keys_screen(w);
    }

pub(crate) fn on_pq_imported_copy_public(&mut self, w: &AppWindow) {
        let Some(kp) = self.pq_imported.as_ref() else { return };
        let armor = app_core::notes_core::pq::export_public(kp.alg(), kp.ek());
        let ok = platform::set_clipboard_text(&armor);
        println!("cb: pq-key-export public len={}", armor.len());
        show_toast(w, if ok { "Copied" } else { "Copy failed" });
    }
}
