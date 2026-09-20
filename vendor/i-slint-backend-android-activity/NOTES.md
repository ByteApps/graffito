# Vendored `i-slint-backend-android-activity` (1.17.1)

Vendored from `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/i-slint-backend-android-activity-1.17.1/`
(copied verbatim, minus `.cargo_vcs_info.json`/`Cargo.toml.orig`/`.cargo-ok`/
`Cargo.lock` — none of those matter for a `path` patch), pinned via
`[patch.crates-io]` in the workspace `Cargo.toml`. `Cargo.toml`'s `name`/
`version = "1.17.1"` are untouched so the crate still satisfies every
`=1.17.1` sibling pin in the slint dependency graph.

Every hunk changed from upstream carries a `// graffito patch (2026-09-19): …`
comment (or, in the Java file, the same marker in a `//` comment) so a future
re-vendor onto a newer 1.17.x can find them with `grep -rn "graffito patch"`.

## Why this exists (measured on an Android emulator, 2026-09-19)

Three defects in the stock backend, all in
`androidwindowadapter.rs`/`java/SlintAndroidJavaHelper.java`:

### (a) Shift/meta state lost on key events

`androidwindowadapter.rs` (upstream `map_key_event` → `map_key_code`, was
line 702/715) resolved a key's text through a **static** `Keycode -> &str`
table that ignores `meta_state()` entirely and the device's own key
character map, so `Shift+;` always produced `;`, never `:` — a hardware/
Bluetooth keyboard (or `adb shell input text`) could not type `:` `@` `?`
etc. `android-activity` 0.6.1 already has the right API:
`AndroidApp::device_key_character_map(device_id)` (`android-activity-0.6.1/
src/lib.rs:1250`) → `KeyCharacterMap::get(key_code, meta_state) ->
Result<KeyMapChar>` (`android-activity-0.6.1/src/input/sdk.rs:153`), with
`KeyEvent::device_id()`/`meta_state()` on `android-activity-0.6.1/src/
native_activity/input.rs:45,141`.

Fix: `AndroidWindowAdapter` gained a `RefCell<HashMap<i32,
KeyCharacterMap>>` cache (`key_char_map`, `resolve_key_text`) that resolves
text through the device's real `KeyCharacterMap` first, falling back to
the static `map_key_code` table only when the KCM has no printable mapping
(`KeyMapChar::None`/`CombiningAccent`, a failed lookup, or a resolved
character that is itself a control character — the safety net that keeps
Back/arrows/Enter/Delete/etc. routing through `Key::…` as before, since a
device's KCM can map Enter to `'\r'`/`'\n'` rather than `KeyMapChar::None`).
`map_key_event` now takes the resolved text as a parameter instead of
looking it up itself.

The pure fallback decision — `Some(c) if !c.is_control() => Some(c), _ =>
None` — lives in `keymap.rs::key_text_from_unicode`, expressed over a bare
`Option<char>` because `KeyMapChar`/`Keycode`/`SharedString` are
android-only types unreachable on a host build (see "Host-testability"
below). `androidwindowadapter.rs::resolve_key_text` does only the
android/JNI plumbing around it.

### (b) Soft keyboard stays up after the focused field is destroyed

Slint core hides the IME only via `WindowInner::set_text_input_focused
(false)` → `InputMethodRequest::Disable` (`i-slint-core-1.17.1/
window.rs:2020-2026`), normally triggered by the focused item's own
`FocusOut` handling. When the focused `TextInput`'s item tree is dropped
(a screen switch) before that runs, no `FocusOut` ever reaches it, so
`text_input_focused()` sticks at `true` and the keyboard never hides.

Fix: `process_inputs` now checks, once per input-processing pass (cheap,
before handling any new input): `text_input_focused() == true &&
focus_item.borrow().upgrade().is_none()` → call `set_text_input_focused
(false)`, which is what actually emits `Disable` → `hide_keyboard()`.

Also hardened `java/SlintAndroidJavaHelper.java`'s `hide_keyboard()`
(upstream line 513): it used to hide by `mInputView`'s window token ONLY,
which can silently no-op once `mInputView` is itself detached/unfocused.
Now also tries `mActivity.getCurrentFocus()`'s token and the decor view's
token (`mActivity.getWindow().getDecorView().getWindowToken()`), each
individually null-guarded.

### (c) No tap-outside-a-text-field dismisses the keyboard

Sal's rule: a tap anywhere that is NOT a text field should blur the
focused field (so the IME hides); a tap ON a field must keep working
exactly as before, and the tap must still reach whatever is under it
(buttons etc.) — so this lives in the adapter's pointer handling, not an
app-side overlay `TouchArea`.

Fix: `process_inputs`'s `MotionAction::Down`/`Up` handling now tracks each
pointer's down position (`tap_down_positions: RefCell<HashMap<i32,
LogicalPoint>>`). On `Up`, **after** dispatching the touch event to Slint
as before (never intercepts/consumes it — if the tap landed on another
focusable item, Slint has already refocused it by this point, and the
outside-check then simply compares against that NEW focus item, which is
the desired "tap on a field keeps working" behavior): if the movement
since down was within an 8-logical-px slop (a genuine tap, not a drag) and
`text_input_focused()` is true, compute the focused item's window-space
rectangle — the same `geometry().translate(map_to_window(..).to_vector())`
the pre-existing `long_press_timeout` function already used — and if the
tap point falls outside it, clear focus via the public `WindowInner::
set_focus_item(&focus_item, false, FocusReason::PointerClick)`.
`WindowInner::take_focus_item` (mentioned as an option in the task brief)
turned out to be a **private** `fn`, not even `pub(crate)`, so it's
unreachable from this crate — `set_focus_item(.., false, ..)` is the
public API that clears focus (it requires the item passed in to equal the
current focus item when `set_focus == false`, which is exactly what we
have). Clearing focus (vs. moving it) means a later tap on the same field
produces a fresh `FocusIn`, which is what re-shows the IME.

The pure geometry decision — is a point outside a rect, matching
`euclid::Rect::contains`'s half-open convention — lives in
`geom.rs::tap_outside`.

## Host-testability (`keymap.rs` / `geom.rs`)

The crate used to gate its **entire** content behind one
`#![cfg(target_os = "android")]` on the crate root (`lib.rs`, upstream line
8). Verified empirically (a throwaway two-crate rustc test, not just read
off the reference) that this strips the WHOLE crate on a non-Android host
— including any `pub mod` declared textually after it, even with no cfg of
its own. So the original lib.rs body moved verbatim to `android_impl.rs`
(loaded via `#[cfg(target_os = "android")] mod android_impl;`,
`androidwindowadapter.rs`/`javahelper.rs` stay physically at the crate root
via `#[path = "…"]` on the nested `mod` declarations inside it), and
`keymap.rs`/`geom.rs` are declared as ordinary, ungated `pub mod`s in
`lib.rs`. They contain no android/Slint imports at all, by design, so
`cargo test -p i-slint-backend-android-activity --lib` runs — and passes —
on every host.

## App-side companion fix

`graffito/src/platform.rs`'s `android_jni::window_insets()` logs
`cb: window-insets Err("Null pointer in getRootWindowInsets")` on the
emulator (the window IS attached; `getRootWindowInsets()` simply returns
null there) and falls back to a fixed survey — this is a separate,
non-vendored fix in the app crate itself (`window_insets()` now falls back
to `WindowManager.getCurrentWindowMetrics().getWindowInsets()` on API ≥ 30
when `getRootWindowInsets()` is null, mirroring the fallback Slint's own
Java helper already takes in `get_safe_area()`/`get_view_rect()` for the
same SDK level), not part of this vendored crate.
