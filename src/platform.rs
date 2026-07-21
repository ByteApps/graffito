//! Small per-platform shims. On macOS the file dialogs use rfd; on mobile
//! they return None (file import/export via the platform document picker is
//! a later step — the QR + clipboard paths carry the mobile flows, and the
//! file-only buttons are hidden behind the `desktop-platform` slint
//! property). Clipboard writes and URL opens ARE implemented per platform:
//! pbcopy/`open` on macOS, UIPasteboard/UIApplication on iOS,
//! ClipboardManager/ACTION_VIEW-intent JNI on Android.

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

#[cfg(target_os = "android")]
pub fn clipboard_text() -> Option<String> {
    match android_jni::clipboard_text() {
        Ok(t) => t.filter(|s| !s.is_empty()),
        Err(e) => {
            eprintln!("clipboard: {e}");
            None
        }
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "android")))]
pub fn clipboard_text() -> Option<String> {
    None
}

/// Write the system clipboard. macOS keeps the pbcopy shell-out the app has
/// always used; iOS sets UIPasteboard; Android goes through the framework
/// ClipboardManager over JNI. Returns whether the write took.
#[cfg(target_os = "macos")]
pub fn set_clipboard_text(text: &str) -> bool {
    use std::io::Write;
    std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().expect("piped").write_all(text.as_bytes())?;
            c.wait()
        })
        .is_ok()
}

#[cfg(target_os = "ios")]
pub fn set_clipboard_text(text: &str) -> bool {
    use objc2_foundation::NSString;
    use objc2_ui_kit::UIPasteboard;
    let pb = unsafe { UIPasteboard::generalPasteboard() };
    unsafe { pb.setString(Some(&NSString::from_str(text))) };
    true
}

#[cfg(target_os = "android")]
pub fn set_clipboard_text(text: &str) -> bool {
    android_jni::set_clipboard(text).map_err(|e| eprintln!("clipboard: {e}")).is_ok()
}

/// Open a URL in the system browser. macOS `open`, iOS UIApplication,
/// Android an ACTION_VIEW intent. Returns whether the hand-off happened.
#[cfg(target_os = "macos")]
pub fn open_url(url: &str) -> bool {
    std::process::Command::new("open").arg(url).spawn().is_ok()
}

#[cfg(target_os = "ios")]
pub fn open_url(url: &str) -> bool {
    use objc2::MainThreadMarker;
    use objc2_foundation::{NSDictionary, NSString, NSURL};
    use objc2_ui_kit::UIApplication;
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let Some(nsurl) = (unsafe { NSURL::URLWithString(&NSString::from_str(url)) }) else {
        return false;
    };
    let app = UIApplication::sharedApplication(mtm);
    unsafe { app.openURL_options_completionHandler(&nsurl, &NSDictionary::new(), None) };
    true
}

#[cfg(target_os = "android")]
pub fn open_url(url: &str) -> bool {
    android_jni::open_url(url).map_err(|e| eprintln!("open-url: {e}")).is_ok()
}

/// The app bundle's build number — `CFBundleVersion` on Apple platforms —
/// shown in About next to the marketing version. `None` on a plain host/dev
/// binary (no app bundle), where About just shows the version. Read at
/// RUNTIME on purpose: iOS pins its build number at compile time, but the
/// macOS build number is assigned at upload (`manageAppVersionAndBuildNumber`
/// rewrites the bundle's CFBundleVersion), so no single compile-time value is
/// correct for both — the bundle is the source of truth.
#[cfg(target_vendor = "apple")]
pub fn build_number() -> Option<String> {
    use objc2_foundation::{NSBundle, NSString};
    let bundle = NSBundle::mainBundle();
    let key = NSString::from_str("CFBundleVersion");
    let val = unsafe { bundle.objectForInfoDictionaryKey(&key) }?;
    let s = val.downcast::<NSString>().ok()?.to_string();
    (!s.is_empty()).then_some(s)
}

// Android build number would come from PackageInfo.versionCode over JNI —
// not wired up yet; About shows the marketing version alone there.
// TODO(android): PackageManager.getPackageInfo(...).versionCode.
#[cfg(not(target_vendor = "apple"))]
pub fn build_number() -> Option<String> {
    None
}

/// Android framework calls used by the shims above — same JNI plumbing as
/// the Keystore backend (JavaVM + Activity context via ndk_context).
#[cfg(target_os = "android")]
mod android_jni {
    use jni::objects::{JObject, JValue};
    use jni::JNIEnv;

    const FLAG_ACTIVITY_NEW_TASK: i32 = 0x1000_0000;

    fn with_env_ctx<T>(
        f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>,
    ) -> Result<T, String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("JavaVM: {e}"))?;
        let mut env = vm.attach_current_thread().map_err(|e| format!("attach: {e}"))?;
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        match f(&mut env, &context) {
            Ok(v) => Ok(v),
            Err(e) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(format!("{e}"))
            }
        }
    }

    /// context.getSystemService("clipboard").setPrimaryClip(
    ///     ClipData.newPlainText("chain-notes", text))
    pub fn set_clipboard(text: &str) -> Result<(), String> {
        with_env_ctx(|env, context| {
            let name = env.new_string("clipboard")?;
            let cm = env
                .call_method(
                    context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            let label = env.new_string("chain-notes")?;
            let value = env.new_string(text)?;
            let clip = env
                .call_static_method(
                    "android/content/ClipData",
                    "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                    &[JValue::Object(&label), JValue::Object(&value)],
                )?
                .l()?;
            env.call_method(
                &cm,
                "setPrimaryClip",
                "(Landroid/content/ClipData;)V",
                &[JValue::Object(&clip)],
            )?;
            Ok(())
        })
    }

    /// clipboard.getPrimaryClip().getItemAt(0).coerceToText(context)
    pub fn clipboard_text() -> Result<Option<String>, String> {
        with_env_ctx(|env, context| {
            let name = env.new_string("clipboard")?;
            let cm = env
                .call_method(
                    context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            let clip = env
                .call_method(&cm, "getPrimaryClip", "()Landroid/content/ClipData;", &[])?
                .l()?;
            if clip.is_null() {
                return Ok(None);
            }
            let n = env.call_method(&clip, "getItemCount", "()I", &[])?.i()?;
            if n == 0 {
                return Ok(None);
            }
            let item = env
                .call_method(
                    &clip,
                    "getItemAt",
                    "(I)Landroid/content/ClipData$Item;",
                    &[JValue::Int(0)],
                )?
                .l()?;
            let cs = env
                .call_method(
                    &item,
                    "coerceToText",
                    "(Landroid/content/Context;)Ljava/lang/CharSequence;",
                    &[JValue::Object(context)],
                )?
                .l()?;
            if cs.is_null() {
                return Ok(None);
            }
            let s = env
                .call_method(&cs, "toString", "()Ljava/lang/String;", &[])?
                .l()?;
            let js = jni::objects::JString::from(s);
            let out = env.get_string(&js).map(|v| v.to_string_lossy().into_owned())?;
            Ok(Some(out))
        })
    }

    /// context.startActivity(new Intent(ACTION_VIEW, Uri.parse(url))
    ///     .addFlags(FLAG_ACTIVITY_NEW_TASK))
    pub fn open_url(url: &str) -> Result<(), String> {
        with_env_ctx(|env, context| {
            let url = env.new_string(url)?;
            let uri = env
                .call_static_method(
                    "android/net/Uri",
                    "parse",
                    "(Ljava/lang/String;)Landroid/net/Uri;",
                    &[JValue::Object(&url)],
                )?
                .l()?;
            let action = env.new_string("android.intent.action.VIEW")?;
            let intent = env.new_object(
                "android/content/Intent",
                "(Ljava/lang/String;Landroid/net/Uri;)V",
                &[JValue::Object(&action), JValue::Object(&uri)],
            )?;
            env.call_method(
                &intent,
                "addFlags",
                "(I)Landroid/content/Intent;",
                &[JValue::Int(FLAG_ACTIVITY_NEW_TASK)],
            )?;
            env.call_method(
                context,
                "startActivity",
                "(Landroid/content/Intent;)V",
                &[JValue::Object(&intent)],
            )?;
            Ok(())
        })
    }
}
