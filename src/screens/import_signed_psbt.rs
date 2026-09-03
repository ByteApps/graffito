//! Screen.import-signed-psbt — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Import a signed PSBT (from file bytes, a base64/hex string, or a UR string),
/// validate it against the tx we built, render the Sparrow-style confirmation,
/// and advance to the review screen.
pub(crate) fn load_signed_psbt(&mut self, w: &AppWindow, data: &[u8]) {
    let st = self;
    let psbt: Result<bitcoin::Psbt, String> = if data.starts_with(b"psbt\xff") {
        bitcoin::Psbt::deserialize(data).map_err(|e| e.to_string())
    } else {
        let text = String::from_utf8_lossy(data);
        let t = text.trim();
        if t.to_lowercase().starts_with("ur:") {
            let mut dec = app_core::ur::PsbtUrDecoder::new();
            match dec.receive(t) {
                Ok(true) => dec
                    .psbt_bytes()
                    .map_err(|e| e.to_string())
                    .and_then(|b| bitcoin::Psbt::deserialize(&b).map_err(|e| e.to_string())),
                Ok(false) => Err("multi-frame UR — import the .psbt file instead".into()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            parse_psbt(t).map_err(|e| e.to_string())
        }
    };
    match psbt {
        Ok(p) => st.set_confirm_from_psbt(w, p),
        Err(e) => w.global::<Ui>().set_status(format!("import: {e}").into()),
    }
}
}

impl State {
pub(crate) fn on_psbt_import_file(&mut self, w: &AppWindow) {
        if let Some(path) = platform::pick_file(&[("PSBT", &["psbt", "txt"])]) {
            match std::fs::read(&path) {
                Ok(bytes) => self.load_signed_psbt(w, &bytes),
                Err(e) => w.global::<Ui>().set_status(format!("read failed: {e}").into()),
            }
        }
    }
}
