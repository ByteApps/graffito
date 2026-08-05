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

// ---- Data-at-rest protection (audit M1) ----
//
// The store files cache DECRYPTED note text (`NoteRecord.text`) — the very
// content the product exists to keep private. The notes key gets Keychain +
// Touch ID; until this shipped, the plaintext it protects got the process-wide
// defaults: readable from first unlock, and swept into device backups.

/// Raise the app data directory to `NSFileProtectionComplete` — its contents
/// become unreadable while the device is locked, instead of the iOS default
/// (`CompleteUntilFirstUserAuthentication`, i.e. readable from first unlock
/// until reboot).
///
/// Setting it on the DIRECTORY is what makes this maintenance-free: files
/// created inside inherit the class, including the `<store>.json.tmp` that
/// `Store::save` writes and renames over the real file on every single save.
/// No call site has to remember anything. Existing files from before this
/// shipped are migrated in the same pass.
///
/// Safe because the app declares no `UIBackgroundModes` — it only runs in the
/// foreground, i.e. while unlocked. A save racing a lock fails cleanly rather
/// than corrupting: `Store::save` writes the temp file first and only renames
/// on success, so a denied write leaves the previous file intact and the
/// cache re-derives from the chain on the next scan.
#[cfg(target_os = "ios")]
pub fn protect_data_dir(dir: &std::path::Path) {
    use objc2_foundation::{
        NSDictionary, NSFileAttributeKey, NSFileManager, NSFileProtectionComplete,
        NSFileProtectionKey, NSString,
    };
    let apply = |p: &std::path::Path| unsafe {
        let attrs = NSDictionary::<NSFileAttributeKey, objc2::runtime::AnyObject>::from_slices(
            &[NSFileProtectionKey],
            &[(*NSFileProtectionComplete).as_ref()],
        );
        let path = NSString::from_str(&p.to_string_lossy());
        if let Err(e) = NSFileManager::defaultManager().setAttributes_ofItemAtPath_error(&attrs, &path)
        {
            eprintln!("cb: file-protect failed err={e}");
        }
    };
    apply(dir);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            apply(&e.path());
        }
    }
}

#[cfg(not(target_os = "ios"))]
pub fn protect_data_dir(_dir: &std::path::Path) {
    // macOS has no file Data Protection classes (FileVault is volume-level),
    // and Android app-private storage is covered by device encryption.
}

/// Mark `path` excluded from backups — iCloud and, on macOS, Time Machine.
///
/// Applied to the `store-*.json` files ONLY. They cache decrypted note text
/// AND are fully chain-recoverable, so keeping them out of an **unencrypted**
/// Finder/iTunes backup (which would otherwise write every private note to
/// the host Mac in cleartext) costs nothing that a rescan can't rebuild.
///
/// Deliberately NOT applied to `contacts.json`, `notebooks-*.json` or
/// `config.json`: those hold user-authored data — contact names, notebook
/// names, node choices — that nothing can reconstruct, and none of it is note
/// plaintext.
///
/// Must be re-applied after every save: the flag lives on the file, and
/// `Store::save`'s temp-then-rename swaps in a fresh one each time. That is
/// what `save_store_file` in lib.rs is for.
#[cfg(target_vendor = "apple")]
pub fn exclude_from_backup(path: &std::path::Path) {
    use objc2_foundation::{NSNumber, NSString, NSURL, NSURLIsExcludedFromBackupKey};
    unsafe {
        let s = NSString::from_str(&path.to_string_lossy());
        let url = NSURL::fileURLWithPath(&s);
        let yes = NSNumber::new_bool(true);
        if let Err(e) = url.setResourceValue_forKey_error(Some(yes.as_ref()), NSURLIsExcludedFromBackupKey)
        {
            eprintln!("cb: backup-exclude failed err={e}");
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
pub fn exclude_from_backup(_path: &std::path::Path) {}

/// Read back `NSURLIsExcludedFromBackupKey`. `None` = the attribute isn't set
/// (or couldn't be read), which the OS treats as "include in backups".
/// Exists for `--spike file-protection`; nothing in the app reads it.
#[cfg(target_vendor = "apple")]
pub fn is_excluded_from_backup(path: &std::path::Path) -> Option<bool> {
    use objc2_foundation::{NSNumber, NSString, NSURL, NSURLIsExcludedFromBackupKey};
    unsafe {
        let s = NSString::from_str(&path.to_string_lossy());
        let url = NSURL::fileURLWithPath(&s);
        let mut value = None;
        url.getResourceValue_forKey_error(&mut value, NSURLIsExcludedFromBackupKey).ok()?;
        let n = value?.downcast::<NSNumber>().ok()?;
        Some(n.boolValue())
    }
}

/// Spike: the clipboard paths (audit M3) against the real pasteboard.
///
/// Proves three things the app depends on: the NSPasteboard rewrite still
/// round-trips (it replaced the `pbcopy`/`pbpaste` shell-outs, which a
/// sandboxed Mac App Store build cannot rely on), a secret copy is still
/// paste-able by the user, and — the actual point — a secret copy carries the
/// concealed flavour while an ordinary copy does not.
///
/// macOS-only: the iOS `localOnly` + expiry path has no host equivalent and
/// needs a device run.
#[cfg(target_os = "macos")]
pub fn spike_clipboard() -> Result<(), String> {
    use objc2::runtime::AnyObject;
    use objc2_foundation::NSString;

    // Is the concealed flavour present on the current pasteboard contents?
    let concealed_now = || unsafe {
        let pb: *mut AnyObject = objc2::msg_send![objc2::class!(NSPasteboard), generalPasteboard];
        let ty = NSString::from_str(PASTEBOARD_CONCEALED_TYPE);
        let s: Option<objc2::rc::Retained<NSString>> = objc2::msg_send![pb, stringForType: &*ty];
        s.is_some()
    };

    let plain = "not-a-secret-address";
    if !set_clipboard_text(plain) {
        return Err("set_clipboard_text failed".into());
    }
    if clipboard_text().as_deref() != Some(plain) {
        return Err("plain copy did not round-trip".into());
    }
    if concealed_now() {
        return Err("an ordinary copy was marked concealed".into());
    }

    let secret = "spike secret material";
    if !set_clipboard_secret(secret) {
        return Err("set_clipboard_secret failed".into());
    }
    // Still readable as text, or the user could not paste it anywhere.
    if clipboard_text().as_deref() != Some(secret) {
        return Err("secret copy is not paste-able as plain text".into());
    }
    if !concealed_now() {
        return Err("secret copy was NOT marked concealed".into());
    }

    // Leave the pasteboard clean rather than holding the spike's "secret".
    let _ = set_clipboard_text("");
    println!("cb: spike-clipboard roundtrip=ok concealed=secret-only");
    Ok(())
}

/// Spike: prove the data-at-rest wiring (audit M1) on the real filesystem.
///
/// The load-bearing claim is that the exclusion flag lives on the FILE, so
/// `Store::save`'s temp-then-rename silently drops it — which is why every
/// store write has to go back through `save_store_file`. That is exactly what
/// this asserts, rather than trusting the reasoning.
///
/// macOS-verifiable only. `protect_data_dir` is a no-op here (no file Data
/// Protection classes off iOS), so the protection class itself needs a run on
/// a real iOS device.
#[cfg(target_vendor = "apple")]
pub fn spike_file_protection() -> Result<(), String> {
    let dir = std::env::temp_dir().join("chain-notes-spike-fileprot");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    protect_data_dir(&dir);

    let path = dir.join("store-testnet4-deadbeef.json");
    std::fs::write(&path, b"{}").map_err(|e| e.to_string())?;
    if is_excluded_from_backup(&path) == Some(true) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("a fresh file was already excluded — test proves nothing".into());
    }
    exclude_from_backup(&path);
    if is_excluded_from_backup(&path) != Some(true) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("exclude_from_backup did not take".into());
    }

    // The regression this design exists to prevent: a temp-then-rename save,
    // exactly as `Store::save` does it, must LOSE the flag.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, b"{\"v\":2}").map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    let survived = is_excluded_from_backup(&path) == Some(true);

    // ...and re-applying restores it, which is what `save_store_file` does.
    exclude_from_backup(&path);
    let restored = is_excluded_from_backup(&path) == Some(true);
    let _ = std::fs::remove_dir_all(&dir);

    if !restored {
        return Err("re-applying after a rename did not take".into());
    }
    println!(
        "cb: spike-file-protection exclude=ok survives-rename={} reapply=ok",
        u8::from(survived)
    );
    Ok(())
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

/// macOS pasteboard access goes through NSPasteboard, NOT the `pbcopy` /
/// `pbpaste` shell-outs the app used to spawn. Two reasons: a sandboxed Mac
/// App Store build cannot rely on exec'ing helpers outside its container, and
/// only the direct API can attach the concealed flavour
/// [`set_clipboard_secret`] needs.
#[cfg(target_os = "macos")]
const PASTEBOARD_STRING_TYPE: &str = "public.utf8-plain-text";

/// The flavour password managers write so clipboard managers skip the value
/// instead of persisting it to disk. A de-facto convention, not an Apple API,
/// but it is the only lever macOS offers here.
#[cfg(target_os = "macos")]
const PASTEBOARD_CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";

#[cfg(target_os = "macos")]
fn write_pasteboard(text: &str, concealed: bool) -> bool {
    use objc2::runtime::AnyObject;
    use objc2_foundation::NSString;
    unsafe {
        let pb: *mut AnyObject = objc2::msg_send![objc2::class!(NSPasteboard), generalPasteboard];
        if pb.is_null() {
            return false;
        }
        let _: isize = objc2::msg_send![pb, clearContents];
        let value = NSString::from_str(text);
        // Concealed FIRST: a clipboard manager that sees this flavour skips
        // the item wholesale, so the plain flavour below stays paste-able by
        // the user without being archived.
        if concealed {
            let ty = NSString::from_str(PASTEBOARD_CONCEALED_TYPE);
            let _: bool = objc2::msg_send![pb, setString: &*value, forType: &*ty];
        }
        let ty = NSString::from_str(PASTEBOARD_STRING_TYPE);
        objc2::msg_send![pb, setString: &*value, forType: &*ty]
    }
}

#[cfg(target_os = "macos")]
pub fn clipboard_text() -> Option<String> {
    use objc2::runtime::AnyObject;
    use objc2_foundation::NSString;
    unsafe {
        let pb: *mut AnyObject = objc2::msg_send![objc2::class!(NSPasteboard), generalPasteboard];
        if pb.is_null() {
            return None;
        }
        let ty = NSString::from_str(PASTEBOARD_STRING_TYPE);
        let s: Option<objc2::rc::Retained<NSString>> =
            objc2::msg_send![pb, stringForType: &*ty];
        s.map(|s| s.to_string()).filter(|s| !s.is_empty())
    }
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
    write_pasteboard(text, false)
}

/// How long a copied secret stays on the iOS pasteboard. Long enough to
/// switch apps and paste, short enough that it isn't still sitting there
/// hours later.
#[cfg(target_os = "ios")]
const SECRET_CLIPBOARD_TTL_SECS: f64 = 60.0;

// ---- Secret clipboard (audit M3) ----
//
// The general pasteboard is a broadcast channel. On iOS every installed app
// can read it (iOS 14+ shows a banner but does not block the read) and it
// syncs to nearby devices over Universal Clipboard; on macOS clipboard
// managers persist it to disk. That is the wrong place for a recovery phrase,
// xprv, WIF or raw key — material that spends the wallet outright — so the
// private-keys screen routes through here instead of `set_clipboard_text`,
// and takes whatever opt-out each OS actually offers.

/// iOS: `localOnly` keeps it off Universal Clipboard, and an expiry date has
/// the system drop it after [`SECRET_CLIPBOARD_TTL_SECS`]. Neither hides it
/// from a determined app reading the pasteboard in that window — no iOS API
/// does — but together they stop the value leaving the device and stop it
/// lingering.
#[cfg(target_os = "ios")]
pub fn set_clipboard_secret(text: &str) -> bool {
    use objc2_foundation::{NSArray, NSDate, NSDictionary, NSNumber, NSString};
    use objc2_ui_kit::{
        UIPasteboard, UIPasteboardOptionExpirationDate, UIPasteboardOptionLocalOnly,
    };
    unsafe {
        let pb = UIPasteboard::generalPasteboard();
        let value = NSString::from_str(text);
        let ty = NSString::from_str("public.utf8-plain-text");
        let item = NSDictionary::from_slices(&[&*ty], &[value.as_ref()]);
        let items = NSArray::from_slice(&[&*item]);
        let local = NSNumber::new_bool(true);
        let expires = NSDate::dateWithTimeIntervalSinceNow(SECRET_CLIPBOARD_TTL_SECS);
        let options = NSDictionary::from_slices(
            &[UIPasteboardOptionLocalOnly, UIPasteboardOptionExpirationDate],
            &[local.as_ref(), expires.as_ref()],
        );
        pb.setItems_options(&items, &options);
    }
    true
}

/// macOS: mark the value concealed so clipboard managers skip it. Universal
/// Clipboard cannot be opted out of per-item here, so this is a partial
/// mitigation — the "never a screenshot" caption on the backup screen carries
/// the rest of the message.
#[cfg(target_os = "macos")]
pub fn set_clipboard_secret(text: &str) -> bool {
    write_pasteboard(text, true)
}

/// Android: mark the clip sensitive (`ClipDescription.EXTRA_IS_SENSITIVE`,
/// honored from API 33) so the system suppresses the paste-preview toast and
/// clipboard managers skip it. Like macOS this is a partial mitigation — the
/// value is still on the system clipboard — and there is no Android
/// counterpart to iOS's expiry. Falls back to a plain copy if the JNI call
/// fails: a copy that does not happen is worse than one that is merely
/// unmarked, since the user is trying to back up a recovery phrase.
#[cfg(target_os = "android")]
pub fn set_clipboard_secret(text: &str) -> bool {
    match android_jni::set_clipboard_sensitive(text) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("clipboard: sensitive copy failed ({e}), falling back to plain");
            set_clipboard_text(text)
        }
    }
}

/// Host builds (dev/test): nothing to mark.
#[cfg(all(not(target_vendor = "apple"), not(target_os = "android")))]
pub fn set_clipboard_secret(text: &str) -> bool {
    set_clipboard_text(text)
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

    /// Like [`set_clipboard`], but marks the clip SENSITIVE so the system
    /// suppresses the content preview in the clipboard toast/overlay and
    /// clipboard managers know to skip it — Android's counterpart to iOS's
    /// `localOnly` + expiring pasteboard and macOS's `ConcealedType`.
    ///
    /// The flag is `ClipDescription.EXTRA_IS_SENSITIVE`, honored from API 33.
    /// The string constant is written out rather than read off the class,
    /// because reading a static field that does not exist on an older device
    /// throws, whereas `setExtras` (API 24) carrying an extra the platform has
    /// not heard of is simply ignored. So this degrades quietly on older
    /// devices instead of failing the copy — and a failed copy would be the
    /// worse outcome, since the user is trying to back up a recovery phrase.
    ///
    /// This is a preview/manager hint, NOT secrecy: the value is still on the
    /// system clipboard and any app may read it. iOS's expiry has no Android
    /// equivalent to mirror.
    pub fn set_clipboard_sensitive(text: &str) -> Result<(), String> {
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
            // clip.getDescription().setExtras(bundle{IS_SENSITIVE: true})
            let desc = env
                .call_method(&clip, "getDescription", "()Landroid/content/ClipDescription;", &[])?
                .l()?;
            let bundle = env.new_object("android/os/PersistableBundle", "()V", &[])?;
            let key = env.new_string("android.content.extra.IS_SENSITIVE")?;
            env.call_method(
                &bundle,
                "putBoolean",
                "(Ljava/lang/String;Z)V",
                &[JValue::Object(&key), JValue::Bool(1)],
            )?;
            env.call_method(
                &desc,
                "setExtras",
                "(Landroid/os/PersistableBundle;)V",
                &[JValue::Object(&bundle)],
            )?;
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
