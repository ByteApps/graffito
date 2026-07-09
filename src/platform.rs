//! Small per-platform shims. On macOS these use native dialogs (rfd); on
//! mobile they return None for now (file import/export via the platform
//! document picker is a later step — the QR path covers the mobile flows).

use std::path::PathBuf;

/// Open a file picker with optional (label, extensions) filters.
#[cfg(target_os = "macos")]
pub fn pick_file(filters: &[(&str, &[&str])]) -> Option<PathBuf> {
    let mut d = rfd::FileDialog::new();
    for (name, exts) in filters {
        d = d.add_filter(*name, exts);
    }
    d.pick_file()
}

#[cfg(not(target_os = "macos"))]
pub fn pick_file(_filters: &[(&str, &[&str])]) -> Option<PathBuf> {
    None
}

/// Save-file picker pre-filled with `name`.
#[cfg(target_os = "macos")]
pub fn save_file(name: &str) -> Option<PathBuf> {
    rfd::FileDialog::new().set_file_name(name).save_file()
}

#[cfg(not(target_os = "macos"))]
pub fn save_file(_name: &str) -> Option<PathBuf> {
    None
}

/// Safe-area insets (top, bottom) in LOGICAL px. `scale` is the window's
/// scale factor — used on Android to convert `content_rect`'s physical
/// pixels; ignored on iOS, where UIKit already reports points (= logical
/// px). Must be called on the main thread once the window exists. Desktop
/// platforms have no system insets and return (0, 0).
#[cfg(target_os = "ios")]
pub fn safe_area_insets(_scale: f32) -> (f32, f32) {
    use objc2::MainThreadMarker;
    use objc2_ui_kit::UIApplication;
    let Some(mtm) = MainThreadMarker::new() else {
        return (0.0, 0.0);
    };
    let app = UIApplication::sharedApplication(mtm);
    let windows = app.windows();
    if let Some(w) = windows.firstObject() {
        let i = w.safeAreaInsets();
        return (i.top as f32, i.bottom as f32);
    }
    (0.0, 0.0)
}

/// Android: the NativeActivity content rectangle carries the status-bar (top)
/// and nav-bar (bottom) insets in physical pixels — the surface itself is
/// full-window, so without this the status bar overlaps the app. Converted to
/// logical px with `scale`. Returns (0, 0) until the first content-rect is
/// known (the caller re-polls), guarding the uninitialised empty rect.
#[cfg(target_os = "android")]
pub fn safe_area_insets(scale: f32) -> (f32, f32) {
    let Some(app) = crate::android_app() else {
        return (0.0, 0.0);
    };
    let rect = app.content_rect();
    // An all-zero / inverted rect means the content rect isn't known yet.
    if rect.bottom <= rect.top {
        return (0.0, 0.0);
    }
    let scale = if scale > 0.0 { scale } else { 1.0 };
    let top = (rect.top.max(0) as f32) / scale;
    let bottom = app
        .native_window()
        .map(|w| ((w.height() - rect.bottom).max(0) as f32) / scale)
        .unwrap_or(0.0);
    (top, bottom)
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub fn safe_area_insets(_scale: f32) -> (f32, f32) {
    (0.0, 0.0)
}

/// Whether this platform has system safe-area insets to wait for (mobile) vs
/// none (desktop). Used to decide when the UI can be revealed on cold start.
pub const fn has_insets() -> bool {
    cfg!(any(target_os = "ios", target_os = "android"))
}

/// Read the system clipboard. Needed because Slint's iOS text fields don't
/// surface the native paste menu — an in-app Paste button reads UIPasteboard.
#[cfg(target_os = "ios")]
pub fn clipboard_text() -> Option<String> {
    use objc2_ui_kit::UIPasteboard;
    let pb = unsafe { UIPasteboard::generalPasteboard() };
    let s = unsafe { pb.string() }?;
    Some(s.to_string())
}

#[cfg(target_os = "macos")]
pub fn clipboard_text() -> Option<String> {
    // The app already shells out to pbcopy for copy; pbpaste for read.
    std::process::Command::new("pbpaste")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .filter(|s| !s.is_empty())
}

#[cfg(not(target_vendor = "apple"))]
pub fn clipboard_text() -> Option<String> {
    None
}
