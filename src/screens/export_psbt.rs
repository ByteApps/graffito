//! Screen.export-psbt — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Put a freshly built unsigned PSBT on the sign screen (13): animated-UR
/// QR, cost line, save/copy state. Shared by external funding and the
/// watch-mode spend flows.
pub(crate) fn show_psbt_sign_screen(&mut self, w: &AppWindow, built: BuiltPsbt, cost_line: String) {
    let st = self;
    let frames = app_core::ur::encode_psbt(&built.to_bytes(), 300);
    w.global::<ExportPsbt>().set_psbt_cost_line(cost_line.into());
    w.global::<ExportPsbt>().set_psbt_qr(qr::qr_image(&frames[0]).unwrap_or_default());
    w.global::<ExportPsbt>().set_psbt_frame_label(
        if frames.len() > 1 { format!("frame 1 / {}", frames.len()).into() } else { "".into() },
    );
    st.ur_frames = frames;
    st.built_psbt = Some(built);
    st.signed_psbt = None;
    w.global::<Ui>().set_psbt_signed(false);
    w.global::<Ui>().set_status("".into());
    w.global::<Ui>().set_screen(Screen::ExportPsbt);
}
}

impl State {
#[allow(unused_variables)]
pub(crate) fn on_psbt_save(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let Some(built) = s.built_psbt.as_ref() else { return };
        let bytes = built.to_bytes();
        if let Some(path) = platform::save_file("note.psbt") {
            match std::fs::write(&path, &bytes) {
                Ok(()) => w.global::<Ui>().set_status("saved .psbt".into()),
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_psbt_goto_import(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::ImportSignedPsbt);
    }
}
