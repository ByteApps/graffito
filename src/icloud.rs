//! iCloud key-value sync for the device-level contacts list
//! (`NSUbiquitousKeyValueStore`) — Apple platforms only. Mirrors the
//! keychain module's shape (`src/keychain/apple.rs`): a thin FFI wrapper
//! around one Apple API, with a plain no-op fallback everywhere else.
//!
//! Only ONE key is ever touched here — `contacts-v1`, one JSON array of
//! `{address,name}` (see `app_core::contacts`) — never key material. On an
//! unsigned/no-entitlement build, or a device with no iCloud account, the
//! underlying API silently no-ops (returns nil / does nothing) rather than
//! erroring, exactly like the keychain's own iCloud-sync fallback — so the
//! app must run normally either way; every function here is infallible by
//! design (`Option`/unit returns, never a panic on nil).

/// The one KV entry this app ever writes: the whole device-level contacts
/// list, JSON-encoded (`app_core::contacts::serialize_contacts_blob`).
const CONTACTS_KEY: &str = "contacts-v1";

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use super::CONTACTS_KEY;
    use objc2_foundation::{
        NSFileManager, NSNotificationCenter, NSString, NSUbiquitousKeyValueStore,
        NSUbiquitousKeyValueStoreDidChangeExternallyNotification,
    };

    /// `synchronize()` (best-effort — pulls in whatever iCloud has landed
    /// since last check) then read the one key. `None` covers every "no
    /// value yet" case: never written, no iCloud account, or an
    /// unentitled/unsigned build — all indistinguishable from "empty" to
    /// the caller, which is exactly how an absent/garbage blob is already
    /// treated (`app_core::contacts::parse_contacts_blob` is tolerant).
    pub fn load_blob() -> Option<String> {
        let store = NSUbiquitousKeyValueStore::defaultStore();
        store.synchronize();
        let key = NSString::from_str(CONTACTS_KEY);
        store.stringForKey(&key).map(|s| s.to_string())
    }

    /// Write the blob and kick a `synchronize()` so it starts propagating
    /// immediately rather than waiting for the OS's own batching. A no-op
    /// (silently) when the OS has nowhere to put it (no iCloud account /
    /// missing entitlement) — `setString:forKey:` on
    /// `NSUbiquitousKeyValueStore` never throws or crashes in that case.
    ///
    /// Returns `synchronize()`'s own `BOOL` — Apple's docs: `false` means
    /// the store couldn't write (no iCloud account, missing entitlement, or
    /// too many recent writes), `true` means the write was accepted and
    /// queued for upload. This is the ONLY reliable signal the OS gives us
    /// that a contacts push actually reached iCloud — see the sync-status
    /// UI in `lib.rs`'s `State::save_contacts`.
    pub fn save_blob(s: &str) -> bool {
        let store = NSUbiquitousKeyValueStore::defaultStore();
        let key = NSString::from_str(CONTACTS_KEY);
        let value = NSString::from_str(s);
        store.setString_forKey(Some(&value), &key);
        store.synchronize()
    }

    /// Is this device signed into iCloud at all? Proxy:
    /// `NSFileManager.ubiquityIdentityToken` is non-nil — same check
    /// `keychain::apple::icloud_available` uses for the key-backup toggle,
    /// duplicated here (rather than shared) so this module stays a
    /// self-contained thin wrapper around exactly one Apple subsystem, same
    /// shape as `keychain/apple.rs`'s own doc comment describes. Used to
    /// tell a genuine "no iCloud account" failure apart from "this device IS
    /// signed in but the write is still in flight" — see `available()`'s
    /// callers.
    pub fn available() -> bool {
        NSFileManager::defaultManager().ubiquityIdentityToken().is_some()
    }

    /// Register for `NSUbiquitousKeyValueStoreDidChangeExternallyNotification`
    /// (fires when a change synced in from ANOTHER device lands here) and
    /// invoke `cb` every time. `cb` is expected to re-merge the just-synced
    /// blob into the live contacts list and refresh the picker — see
    /// `run()`'s registration, which wraps this in an
    /// `upgrade_in_event_loop` trampoline since this callback can fire on
    /// whatever thread delivered the notification, not necessarily the UI
    /// thread.
    ///
    /// The returned observer token is intentionally LEAKED
    /// (`std::mem::forget`): per Apple's docs for the block-based
    /// `addObserverForName:object:queue:usingBlock:` API, letting that
    /// token deallocate silently unregisters the observer — and this
    /// registration is meant to live for the whole app session, so there's
    /// nothing to clean up on the way out.
    pub fn start_observer(cb: impl Fn() + 'static) {
        use block2::RcBlock;
        use core::ptr::NonNull;
        use objc2_foundation::NSNotification;

        let center = NSNotificationCenter::defaultCenter();
        let block = RcBlock::new(move |_note: NonNull<NSNotification>| {
            cb();
        });
        let observer = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSUbiquitousKeyValueStoreDidChangeExternallyNotification),
                None,
                None,
                &block,
            )
        };
        std::mem::forget(observer);
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::{available, load_blob, save_blob, start_observer};

// All other targets (Android included): no NSUbiquitousKeyValueStore.
// TODO(android): Google backup / Drive — out of scope for this feature;
// Android contacts stay local-only for now (still survive uninstall via
// Android's own key/value backup for small app data IF the user has that
// turned on, but there's no live-sync equivalent wired up here).
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
mod noop {
    pub fn load_blob() -> Option<String> {
        None
    }

    pub fn save_blob(_s: &str) -> bool {
        false
    }

    /// No `NSUbiquitousKeyValueStore` equivalent wired up on this target —
    /// see the module doc's Android TODO. Always unavailable.
    pub fn available() -> bool {
        false
    }

    pub fn start_observer(_cb: impl Fn() + 'static) {}
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub use noop::{available, load_blob, save_blob, start_observer};
