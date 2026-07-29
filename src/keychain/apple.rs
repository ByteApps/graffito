//! macOS Keychain backend for the SecretStore spec (PLAN "Key storage").
//!
//! The identity item is stored with a **UserPresence access control**
//! (Touch ID / account password) on AccessibleWhenUnlockedThisDeviceOnly
//! — every read prompts: once at app launch (the "loaded at unlock"
//! read, cached in memory for the session) and freshly on every
//! Reveal-backup (spec guarantee 3). Writes and deletes don't prompt.
//! The raw SecItem* calls are used because security-framework's item
//! API exposes no access-control setter.

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework_sys::access_control::{
    kSecAccessControlUserPresence, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData,
    kSecUseAuthenticationUI, kSecValueData,
};

// Deprecated in the SDK headers (and unbound in security-framework-sys)
// but still functional: the reason string shown in the auth prompt.
extern "C" {
    static kSecUseOperationPrompt: core_foundation_sys::string::CFStringRef;
    static kSecUseDataProtectionKeychain: core_foundation_sys::string::CFStringRef;
    // iCloud Keychain sync: the attribute key + the "match either" query value.
    static kSecAttrSynchronizable: core_foundation_sys::string::CFStringRef;
    static kSecAttrSynchronizableAny: core_foundation_sys::string::CFStringRef;
    // "Do not present authentication UI; fail instead." Unbound in
    // security-framework-sys (the key itself IS bound, only this value is not).
    static kSecUseAuthenticationUIFail: core_foundation_sys::string::CFStringRef;
    // The `kSecAttrAccessible` dictionary KEY itself — unbound in
    // security-framework-sys, unlike the VALUES it's paired with
    // (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` etc., which are
    // bound in `access_control`). Used only by the RPC-credentials section
    // below; the identity item above sets protection via
    // `kSecAttrAccessControl` (an ACL), not this plain accessibility key.
    static kSecAttrAccessible: core_foundation_sys::string::CFStringRef;
}
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

const SERVICE: &str = "com.objsal.chainnotes";
const ERR_NOT_FOUND: i32 = -25300; // errSecItemNotFound
const ERR_CANCELED: i32 = -128; // errSecUserCanceled
/// errSecInteractionNotAllowed — returned when a query matches an item that
/// WOULD need authentication and we forbade the UI. For an existence check
/// this is a positive answer: the item is there, it just needs a prompt.
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// errSecMissingEntitlement — an unsigned dev build asking for the
/// data-protection keychain. Never a failure when walking KEYCHAIN_DOMAINS,
/// just "that domain isn't available to this binary"; keep looking.
const ERR_MISSING_ENTITLEMENT: i32 = -34018;

/// Set whenever the key is written to, or read from, the ungated `#la`
/// fallback item instead of an OS-protected one (audit M2).
///
/// The fallback exists because unsigned dev builds have no data-protection
/// keychain (errSecMissingEntitlement, -34018) and would otherwise be unable
/// to hold an identity at all. The problem was that it was SILENT: a signed
/// build that lost its entitlement — provisioning drift, an entitlement
/// regression, a future Mac App Store config change — would quietly swap the
/// OS-enforced UserPresence ACL for an in-app LAContext check that anything
/// running in the app's context bypasses, with a `println!` nobody sees in
/// release as the only trace.
///
/// It stays a fallback rather than a hard failure: refusing to store would
/// brick the app for a user whose device is in that state, and this is the
/// user's only copy of their key. Instead the downgrade is now VISIBLE —
/// Settings carries a standing warning while this is set. Process-global
/// because it describes the device/build, not one identity.
static PROTECTION_DEGRADED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn mark_degraded() {
    PROTECTION_DEGRADED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Is the identity key sitting in the ungated fallback item rather than
/// behind an OS-enforced ACL? Drives the Settings warning.
pub fn protection_degraded() -> bool {
    PROTECTION_DEGRADED.load(std::sync::atomic::Ordering::Relaxed)
}

fn key(k: core_foundation_sys::string::CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(k) }
}

fn base_query(account: &str) -> Vec<(CFString, CFType)> {
    vec![
        (key(unsafe { kSecClass }), key(unsafe { kSecClassGenericPassword }).as_CFType()),
        (key(unsafe { kSecAttrService }), CFString::new(SERVICE).as_CFType()),
        (key(unsafe { kSecAttrAccount }), CFString::new(account).as_CFType()),
    ]
}

/// macOS has **TWO** keychains, and an item's SHAPE silently decides which one
/// it lands in: `kSecAttrAccessControl` (the protected shape) forces the
/// data-protection keychain, while `set_generic_password` and any query that
/// does not pass `kSecUseDataProtectionKeychain` address the legacy file-based
/// one. A query only ever searches ONE of them.
///
/// That asymmetry is a real bug, found 2026-07-28 by running `--spike
/// keychain-atomic` on a SIGNED macOS build for the first time: the add landed
/// a protected item in the data-protection keychain, and every later probe —
/// `item_exists`, `is_synced`, `read_account`, and the `SecItemDelete` in
/// `purge_account` — looked in the file-based one and got `errSecItemNotFound`
/// (-25300). Consequences were: the boot probe reporting no saved key (so
/// onboarding never offered "Restore saved key"), staging recovery missing its
/// copy, and — worst — reset-identity NOT deleting a protected key at all.
///
/// **iOS has only the data-protection keychain**, so a single pass is correct
/// there and the whole class of bug is invisible — which is exactly how it
/// shipped. Note this also explains -25300 rather than the -25308 the
/// `kSecUseAuthenticationUIFail` reasoning predicted: the item was never
/// matched at all, so its access control was never evaluated.
///
/// So every READ, EXISTENCE and DELETE walks both domains. Adds are
/// deliberately NOT changed: their current placement works, and searching both
/// domains is strictly additive — it can only find MORE items, never fewer, so
/// no item that is reachable today becomes unreachable.
#[cfg(target_os = "macos")]
const KEYCHAIN_DOMAINS: [bool; 2] = [true, false];
#[cfg(not(target_os = "macos"))]
const KEYCHAIN_DOMAINS: [bool; 1] = [false];

/// Target the data-protection keychain for this query. No-op when false, which
/// leaves the query addressing macOS's legacy file-based keychain (and is the
/// only meaningful setting on iOS, where the flag is redundant).
fn push_domain(pairs: &mut Vec<(CFString, CFType)>, data_protection: bool) {
    if data_protection {
        pairs.push((
            key(unsafe { kSecUseDataProtectionKeychain }),
            CFBoolean::true_value().as_CFType(),
        ));
    }
}

/// OS-level check that the device owner is present (Touch ID or account
/// password). Used to gate reads when the item itself can't carry a
/// SecAccessControl (unsigned dev builds).
fn user_presence_check(reason: &str) -> Result<(), String> {
    use block2::RcBlock;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};
    let (tx, rx) = std::sync::mpsc::channel();
    unsafe {
        let ctx = LAContext::new();
        let reason = NSString::from_str(reason);
        let block = RcBlock::new(move |ok: objc2::runtime::Bool, _err: *mut objc2_foundation::NSError| {
            let _ = tx.send(ok.as_bool());
        });
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason,
            &block,
        );
    }
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(true) => Ok(()),
        Ok(false) => Err("cancelled".into()),
        Err(_) => Err("authentication timed out".into()),
    }
}

/// Store with UserPresence ACL. Replaces any existing item (protected or
/// legacy plain) for this account. Unsigned dev builds cannot create
/// ACL items (errSecMissingEntitlement -34018) — those fall back to a
/// plain item whose READS are gated by LAContext instead.
/// Fallback items use a DISTINCT account name so the protected-item
/// query can never be satisfied by an ungated plain item — a status-0
/// read of `account` therefore always means the OS enforced the prompt.
fn la_account(account: &str) -> String {
    format!("{account}#la")
}

/// Staging account for the crash-safe two-phase write — see
/// [`store_secret_protected`]. Distinct from both the primary account and
/// its `#la` variant, so all three can coexist mid-write.
fn staging_account(account: &str) -> String {
    format!("{account}#new")
}

/// Write ONE item under `account`. Deletes NOTHING: a colliding primary key
/// fails with errSecDuplicateItem rather than silently replacing, which is
/// exactly what makes the two-phase write below safe.
///
/// `Ok(true)` = the item carries OS-enforced protection (UserPresence ACL,
/// or synchronizable on the iCloud path). `Ok(false)` = this build has no
/// data-protection keychain (errSecMissingEntitlement) and fell back to a
/// plain item under `la_account(account)` whose reads are gated in-app by
/// LAContext.
fn add_item(account: &str, secret: &str, synced: bool) -> Result<bool, String> {
    if synced {
        // iCloud Keychain: a synchronizable item. It can't also carry a
        // biometric ACL (that is inherently device-local), so the reveal is
        // gated in-app via LAContext instead — see load_secret_protected.
        let mut pairs = base_query(account);
        pairs.push((
            key(unsafe { kSecValueData }),
            CFData::from_buffer(secret.as_bytes()).as_CFType(),
        ));
        pairs.push((
            key(unsafe { kSecAttrSynchronizable }),
            CFBoolean::true_value().as_CFType(),
        ));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
        return match status {
            0 => Ok(true),
            -34018 => {
                // errSecMissingEntitlement: unsigned dev builds have no
                // data-protection keychain, so a synchronizable item can't
                // be created either. Same fallback as the non-synced path
                // below: a plain item under the #la account, reads gated
                // by LAContext.
                println!("cb: keychain sync=unavailable fallback=lacontext");
                mark_degraded();
                set_generic_password(SERVICE, &la_account(account), secret.as_bytes())
                    .map(|()| false)
                    .map_err(|e| e.to_string())
            }
            other => Err(format!("SecItemAdd(sync) failed ({other})")),
        };
    }
    let acl = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence,
    )
    .map_err(|e| e.to_string())?;
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecValueData }),
        CFData::from_buffer(secret.as_bytes()).as_CFType(),
    ));
    pairs.push((key(unsafe { kSecAttrAccessControl }), acl.as_CFType()));
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    match status {
        0 => Ok(true),
        -34018 => {
            // errSecMissingEntitlement: no data-protection keychain for
            // unsigned builds. Plain item under the #la account; reads
            // gated by LAContext.
            println!("cb: keychain acl=unavailable fallback=lacontext");
            mark_degraded();
            set_generic_password(SERVICE, &la_account(account), secret.as_bytes())
                .map(|()| false)
                .map_err(|e| e.to_string())
        }
        other => Err(format!("SecItemAdd failed ({other})")),
    }
}

/// Does ANY item — protected, synced, or `#la` fallback — exist under
/// `account`? Queries ATTRIBUTES only, never `kSecReturnData`, so an ACL
/// item is not decrypted and no biometric prompt fires. That is what lets
/// the write below confirm its new copy landed without interrupting the
/// user mid-import.
fn item_exists(account: &str) -> bool {
    for acct in [account.to_string(), la_account(account)] {
        for dp in KEYCHAIN_DOMAINS {
            let status = probe_item(&acct, dp);
            // 0 = present and readable without auth (plain/synced shapes).
            // -25308 = present but gated — still present, which is the question.
            // Anything else (notably -25300, "not in THIS keychain") just means
            // keep looking; see KEYCHAIN_DOMAINS.
            if status == 0 || status == ERR_INTERACTION_NOT_ALLOWED {
                return true;
            }
        }
    }
    false
}

/// One existence probe, against one account shape in one keychain domain.
/// Returns the raw `OSStatus` so the caller can tell "present but gated" from
/// "not in this keychain".
fn probe_item(account: &str, data_protection: bool) -> i32 {
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecAttrSynchronizable }),
        key(unsafe { kSecAttrSynchronizableAny }).as_CFType(),
    ));
    pairs.push((
        key(unsafe { kSecReturnAttributes }),
        CFBoolean::true_value().as_CFType(),
    ));
    // THE LOAD-BEARING LINE. Asking for attributes only does NOT avoid
    // authentication: SecItemCopyMatching evaluates the item's access
    // control to decide whether it MATCHES, so a UserPresence item drags
    // in SecItemAuthDoQuery -> LAContext and blocks on an XPC round-trip
    // no matter what you asked it to return. That is what killed build 44
    // on launch (0x8BADF00D, 20 s wall clock, 0.095 s CPU). Forbidding the
    // UI makes the query answer immediately with
    // errSecInteractionNotAllowed, which is itself the "yes, it exists"
    // signal we want. Do not remove this believing attributes are safe —
    // an unsigned dev build cannot reproduce it, because its fallback item
    // carries no ACL at all.
    pairs.push((
        key(unsafe { kSecUseAuthenticationUI }),
        key(unsafe { kSecUseAuthenticationUIFail }).as_CFType(),
    ));
    push_domain(&mut pairs, data_protection);
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
    if !result.is_null() {
        // Release the attribute dictionary we only needed to exist.
        unsafe { CFType::wrap_under_create_rule(result) };
    }
    status
}

/// Is there a saved identity to restore — WITHOUT unlocking it?
///
/// This is what the launch path is allowed to ask. `load_secret_protected`
/// must never run during launch: reading a UserPresence item makes the OS put
/// up Face ID and BLOCKS the calling thread until the user answers, which is
/// exactly the shape that gets the app killed by the iOS launch watchdog
/// (black screen → `0x8badf00d`, invisible under Xcode/devicectl because they
/// relax the watchdog — same rule the post-first-frame network sync follows).
/// This probe reads attributes only, never `kSecReturnData`, so nothing is
/// decrypted and no prompt appears.
///
/// Also true when only a staging copy survives an interrupted write — that
/// key is restorable too, and `load_secret_protected` adopts it.
pub fn identity_exists(account: &str) -> bool {
    item_exists(account) || item_exists(&staging_account(account))
}

/// Store `secret` under `account`, replacing whatever is there.
///
/// **Crash-safe two-phase write.** The obvious shape — delete, then add —
/// has a window in which the device holds NO copy of the key material: an
/// `SecItemAdd` failure, or the process being killed (iOS watchdog, OOM,
/// user swipe) between the two, leaves the wallet unrecoverable. Every
/// caller is rewriting the user's ONLY copy of their seed — identity
/// import, and the iCloud-backup toggle, which re-stores on every flip —
/// so that window is not acceptable.
///
/// The sequence instead is: add under the staging account → confirm it
/// landed (attributes only, no prompt) → delete the live item → add the
/// live item → delete staging. **At every instant at least one item holds
/// the secret**, and [`load_secret_protected`] adopts a surviving staging
/// copy if the process died mid-sequence. A failure before phase 2 leaves
/// the old key untouched (the write is a no-op); a failure after it leaves
/// the new key in staging, which the next load promotes.
///
/// The staging item is created in the SAME mode as the target — including
/// synchronizable, so an iCloud-backed write briefly puts an
/// `identity-key#new` item in iCloud Keychain. That is deliberate:
/// recovery reads the intended mode back off the staging item
/// (`is_synced`), so a local-only spare would silently downgrade a
/// recovered identity to no-iCloud-backup. The cost is a little sync churn,
/// and another device adopting the staging copy is harmless — it is the
/// same secret under a different name.
pub fn store_secret_protected(account: &str, secret: &str, synced: bool) -> Result<(), String> {
    let staging = staging_account(account);
    // Debris from an earlier interrupted write whose primary was since
    // restored — the live item wins, so clear the way.
    purge_account(&staging)?;

    // Phase 1 — the new copy, off to the side. The live item is untouched,
    // so any failure here changes nothing at all.
    let protected = add_item(&staging, secret, synced)?;
    // Corroboration, NOT the authority. `SecItemAdd` returning 0 is what
    // proves the item persisted; this is a second opinion. It must not be
    // able to fail a write on its own, because `item_exists` now runs with
    // the auth UI forbidden and I cannot exercise the ACL shape on an
    // unsigned dev build — if Apple answered that query differently than
    // expected on a signed build, an abort here would break every import
    // while the key was in fact stored perfectly well. So: shout, don't fail.
    if !item_exists(&staging) {
        println!(
            "cb: keychain staging-unverified protected={} (add reported success)",
            u8::from(protected)
        );
    }

    // Phase 2 — only NOW is it safe to drop the old copy; staging holds one.
    // A failure here must abort: leaving the old item in place would make
    // phase 3 collide (errSecDuplicateItem) and the account would keep
    // reading back the OLD secret while the new one sat in staging.
    purge_account(account)?;

    // Phase 3 — the real item. If this fails the staging copy survives and
    // the next load recovers it: the key is misplaced, never lost.
    match add_item(account, secret, synced) {
        Ok(_) => {
            if synced {
                println!("cb: keychain stored synced=1");
            }
            // Phase 4 — settled; drop the spare.
            let _ = purge_account(&staging);
            Ok(())
        }
        Err(e) => Err(format!("{e} (key preserved — reopen the app to recover)")),
    }
}

/// Read the protected item — the OS shows a Touch ID / password prompt
/// with `prompt` as the reason. Ok(None) = no item; Err carries
/// "cancelled" when the user dismissed the prompt.
/// Is iCloud available on this device (so iCloud Keychain sync can work)?
///
/// Proxy: the user is signed into iCloud — `NSFileManager.ubiquityIdentityToken`
/// is non-nil. There is no public API for the iCloud Keychain toggle itself, but
/// no iCloud account means no keychain sync at all, so this gates the "Back up to
/// iCloud" affordance and its default-on. Cheap synchronous property read.
pub fn icloud_available() -> bool {
    use objc2::runtime::AnyObject;
    unsafe {
        let cls = objc2::class!(NSFileManager);
        let fm: *mut AnyObject = objc2::msg_send![cls, defaultManager];
        if fm.is_null() {
            return false;
        }
        let token: *mut AnyObject = objc2::msg_send![fm, ubiquityIdentityToken];
        !token.is_null()
    }
}

/// Does an iCloud-synced item exist for this account?
pub fn is_synced(account: &str) -> bool {
    KEYCHAIN_DOMAINS.iter().any(|&dp| is_synced_in(account, dp))
}

fn is_synced_in(account: &str, dp: bool) -> bool {
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecAttrSynchronizable }),
        CFBoolean::true_value().as_CFType(),
    ));
    pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
    // This one also runs before the first frame. A synchronizable item carries
    // no ACL so it should never authenticate — but that is exactly what was
    // assumed about `item_exists`, so forbid the UI here too rather than
    // reason about it again. Costs nothing: a no-ACL item is unaffected.
    pairs.push((
        key(unsafe { kSecUseAuthenticationUI }),
        key(unsafe { kSecUseAuthenticationUIFail }).as_CFType(),
    ));
    push_domain(&mut pairs, dp);
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
    if status == 0 && !result.is_null() {
        // Release the returned data we don't use.
        unsafe { CFData::wrap_under_create_rule(result as _) };
    }
    status == 0
}

/// Read the synced item (no biometric ACL — caller gates auth if needed).
fn read_synced(account: &str) -> Result<Option<String>, String> {
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        pairs.push((
            key(unsafe { kSecAttrSynchronizable }),
            CFBoolean::true_value().as_CFType(),
        ));
        pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        match status {
            0 => {
                let data = unsafe { CFData::wrap_under_create_rule(result as _) };
                return String::from_utf8(data.bytes().to_vec())
                    .map(Some)
                    .map_err(|e| e.to_string());
            }
            // Not in THIS keychain, or this keychain isn't ours to search —
            // try the other domain before concluding.
            ERR_NOT_FOUND | ERR_MISSING_ENTITLEMENT => continue,
            other => return Err(format!("SecItemCopyMatching(sync) failed ({other})")),
        }
    }
    Ok(None)
}

/// Read whatever is stored under exactly `account`. No staging recovery —
/// that lives in [`load_secret_protected`], which wraps this.
fn read_account(account: &str, prompt: &str) -> Result<Option<String>, String> {
    // iCloud-synced item has no biometric ACL — read it silently (it's
    // protected by the device passcode / accessible-when-unlocked). Boot MUST
    // NOT block on a Face ID prompt here: doing so on the main thread at launch
    // blanks the UI and trips the iOS watchdog. The Reveal-backup action gates
    // Face ID separately via `reveal_secret`.
    if is_synced(account) {
        return read_synced(account);
    }
    // Walk both macOS keychain domains before giving up: the protected shape
    // lives in the data-protection keychain, the `#la` fallback in the
    // file-based one (see KEYCHAIN_DOMAINS). Only once every domain has missed
    // does the `#la` fallback below apply.
    let mut status = ERR_NOT_FOUND;
    let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
        pairs.push((
            key(unsafe { kSecUseOperationPrompt }),
            CFString::new(prompt).as_CFType(),
        ));
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        result = std::ptr::null();
        status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        // -25300 ("not in this keychain") and -34018 ("this keychain isn't
        // ours") both mean keep looking; every other status — including a
        // cancelled prompt — is a real answer about the item we were after.
        if status != ERR_NOT_FOUND && status != ERR_MISSING_ENTITLEMENT {
            break;
        }
    }
    match status {
        0 => {
            let data = unsafe { CFData::wrap_under_create_rule(result as _) };
            String::from_utf8(data.bytes().to_vec())
                .map(Some)
                .map_err(|e| e.to_string())
        }
        ERR_NOT_FOUND | -34018 => {
            // Dev-build fallback item (#la account): enforce user
            // presence via LAContext BEFORE returning it.
            match get_generic_password(SERVICE, &la_account(account)) {
                Ok(bytes) => {
                    // Reached the ungated shape — the key is in it regardless
                    // of which session put it there (audit M2).
                    mark_degraded();
                    user_presence_check(prompt)?;
                    String::from_utf8(bytes).map(Some).map_err(|e| e.to_string())
                }
                Err(e) if e.code() == ERR_NOT_FOUND => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        ERR_CANCELED => Err("cancelled".into()),
        other => Err(format!("SecItemCopyMatching failed ({other})")),
    }
}

pub fn load_secret_protected(account: &str, prompt: &str) -> Result<Option<String>, String> {
    if let Some(secret) = read_account(account, prompt)? {
        return Ok(Some(secret));
    }
    // No live item. A surviving staging copy means `store_secret_protected`
    // was interrupted between its phases — finish the job now, rather than
    // reporting "no identity" and sending the user back to onboarding while
    // their key sits right there in the keychain.
    //
    // `item_exists` first (attributes only, never prompts) so the common
    // genuinely-empty case — a fresh install heading for onboarding — stays
    // prompt-free; only a real recovery reaches the gated read below.
    let staging = staging_account(account);
    if !item_exists(&staging) {
        return Ok(None);
    }
    println!("cb: keychain recover-start");
    let Some(secret) = read_account(&staging, prompt)? else {
        return Ok(None);
    };
    let synced = is_synced(&staging);
    match add_item(account, &secret, synced) {
        Ok(_) => {
            let _ = purge_account(&staging);
            println!("cb: keychain recover=ok synced={}", u8::from(synced));
        }
        // Couldn't promote it. Leave staging alone so the next launch tries
        // again; the caller still gets the key either way.
        Err(e) => println!("cb: keychain recover=deferred err={e}"),
    }
    Ok(Some(secret))
}

/// Read for a USER-INITIATED restore (onboarding's "Restore saved key").
///
/// A device-local item carries a UserPresence ACL, so the OS prompts by
/// itself. A SYNCED item carries NO ACL — it cannot, a biometric ACL is
/// inherently device-local (see `add_item`) — so nothing prompts at all, and
/// on a FRESH INSTALL anyone holding the unlocked phone could install the app,
/// tap Restore and walk away with the seed. iCloud Keychain protects the item
/// at rest, not per read. Gate that shape here with LAContext, exactly as
/// `reveal_secret` does.
///
/// NEVER call this from a boot path: it blocks on a prompt, which is what the
/// launch watchdog killed builds 42 and 44 for. The tap is user-initiated, so
/// blocking is fine.
pub fn load_secret_gated(account: &str, prompt: &str) -> Result<Option<String>, String> {
    if is_synced(account) {
        user_presence_check(prompt)?;
    }
    load_secret_protected(account, prompt)
}

/// Read the key for the Reveal-backup action — ALWAYS gated on user presence.
/// For the local ACL item the OS prompts; for the synced item (no ACL) we gate
/// with LAContext here. Unlike boot, this is invoked from a user action while
/// the UI is up, so a blocking Face ID prompt is fine.
pub fn reveal_secret(account: &str, prompt: &str) -> Result<Option<String>, String> {
    if is_synced(account) {
        user_presence_check(prompt)?;
        return read_synced(account);
    }
    load_secret_protected(account, prompt)
}

/// Delete every shape of item stored under exactly `account` — the
/// protected/synced item and its `#la` fallback. A missing item is success.
/// Does NOT touch the staging account: [`store_secret_protected`]'s phase 2
/// depends on staging surviving this call.
fn purge_account(account: &str) -> Result<(), String> {
    // synchronizable=Any removes both the local (ACL) item and any synced one —
    // and BOTH macOS keychains, or a protected key survives reset-identity
    // entirely (see KEYCHAIN_DOMAINS; this was live on macOS until 2026-07-28).
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        pairs.push((
            key(unsafe { kSecAttrSynchronizable }),
            key(unsafe { kSecAttrSynchronizableAny }).as_CFType(),
        ));
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status != 0 && status != ERR_NOT_FOUND && status != ERR_MISSING_ENTITLEMENT {
            return Err(format!("SecItemDelete failed ({status})"));
        }
    }
    for acct in [account.to_string(), la_account(account)] {
        match delete_generic_password(SERVICE, &acct) {
            Ok(()) | Err(_) => {} // not-found is fine; best-effort cleanup
        }
    }
    Ok(())
}

/// Remove the identity key entirely — the live item AND any staging copy a
/// half-finished write left behind. Reset-identity depends on that staging
/// sweep: without it, "Switch identity" would leave the previous seed
/// sitting in the keychain for the next load to helpfully recover.
pub fn delete_secret(account: &str) -> Result<(), String> {
    let live = purge_account(account);
    let staged = purge_account(&staging_account(account));
    // No key left, so "your key isn't protected" would be a lie. The next
    // store re-sets it immediately if the device still can't do ACL items.
    PROTECTION_DEGRADED.store(false, std::sync::atomic::Ordering::Relaxed);
    live.and(staged)
}

/// Headless spike: plain-item round-trip (no prompts — automation-safe).
pub fn spike() -> Result<(), String> {
    let account = "spike-test";
    let secret = "correct horse battery staple";
    set_generic_password(SERVICE, account, secret.as_bytes()).map_err(|e| e.to_string())?;
    let loaded = get_generic_password(SERVICE, account).map_err(|e| e.to_string())?;
    if loaded != secret.as_bytes() {
        return Err("loaded secret differs".into());
    }
    delete_generic_password(SERVICE, account).map_err(|e| e.to_string())?;
    println!("cb: spike-keychain roundtrip=ok len={}", secret.len());
    Ok(())
}

/// Headless spike: the crash-safe write's ordering invariant — the account
/// never has zero items on the device. Attributes-only checks throughout,
/// so it never prompts (automation-safe). The data read is out of reach
/// here; `spike_atomic_auth` covers the full recovery round-trip.
pub fn spike_atomic() -> Result<(), String> {
    let account = "spike-atomic-test";
    let staging = staging_account(account);
    let cleanup = || {
        let _ = purge_account(account);
        let _ = purge_account(&staging);
    };
    cleanup();

    // A normal store settles on exactly the primary — no staging debris.
    store_secret_protected(account, "first secret", false)?;
    if !item_exists(account) {
        cleanup();
        return Err("store left no primary item".into());
    }
    if item_exists(&staging) {
        cleanup();
        return Err("store left staging debris".into());
    }

    // Overwriting an existing key settles the same way. This is the case
    // the old delete-then-add shape got wrong.
    store_secret_protected(account, "second secret", false)?;
    if !item_exists(account) || item_exists(&staging) {
        cleanup();
        return Err("overwrite did not settle on the primary alone".into());
    }

    // Simulate a kill between phase 2 (old item deleted) and phase 3 (new
    // item written): staging holds the only copy. What must hold is that
    // the key is still ON the device — recoverable, not gone.
    add_item(&staging, "interrupted secret", false)?;
    purge_account(account)?;
    if !item_exists(&staging) {
        cleanup();
        return Err("interrupted write lost the key".into());
    }

    // And reset-identity must sweep staging too, or a switched-away seed
    // would linger for the next load to recover.
    delete_secret(account)?;
    if item_exists(account) || item_exists(&staging) {
        cleanup();
        return Err("delete_secret left key material behind".into());
    }

    // Full recovery round-trip, still prompt-free. Staging is seeded as a
    // PLAIN item under the staging account itself (not its `#la` variant),
    // which `read_account` satisfies with a straight status-0 read — no ACL,
    // so no LAContext gate. That isolates the promotion logic from the
    // biometric path, which `spike_atomic_auth` covers separately.
    set_generic_password(SERVICE, &staging, b"orphaned secret").map_err(|e| e.to_string())?;
    let recovered = load_secret_protected(account, "chain-notes-app atomic spike")?;
    let promoted = item_exists(account) && !item_exists(&staging);
    cleanup();
    match recovered.as_deref() {
        Some("orphaned secret") if promoted => {}
        Some("orphaned secret") => return Err("recovered but staging was not promoted".into()),
        other => return Err(format!("interrupted write did not recover: {other:?}")),
    }

    println!("cb: spike-keychain-atomic invariant=held recover=ok");
    Ok(())
}

/// Interactive spike: a write interrupted after its live item was deleted
/// is recovered on the next load, and the staging copy is promoted to the
/// real account. The read WILL prompt (Touch ID / password). Run by a human.
pub fn spike_atomic_auth() -> Result<(), String> {
    let account = "spike-atomic-auth-test";
    let staging = staging_account(account);
    let _ = purge_account(account);
    let _ = purge_account(&staging);

    // Stage the crash: only the staging copy exists.
    add_item(&staging, "recovered secret", false)?;
    println!("cb: spike-keychain-atomic-auth staged (expect a prompt now)");

    let loaded = load_secret_protected(account, "chain-notes-app recovery spike")?;
    let promoted = item_exists(account) && !item_exists(&staging);
    let _ = purge_account(account);
    let _ = purge_account(&staging);
    match loaded.as_deref() {
        Some("recovered secret") if promoted => {
            println!("cb: spike-keychain-atomic-auth recovered=ok promoted=ok");
            Ok(())
        }
        Some("recovered secret") => Err("recovered, but staging was not promoted".into()),
        other => Err(format!("unexpected recovery read: {other:?}")),
    }
}

/// Interactive spike: protected round-trip — the load WILL prompt for
/// Touch ID / password. Run by a human.
pub fn spike_auth() -> Result<(), String> {
    let account = "spike-auth-test";
    store_secret_protected(account, "protected test secret", false)?;
    println!("cb: spike-keychain-auth stored (expect a Touch ID prompt now)");
    let loaded = load_secret_protected(account, "chain-notes-app keychain spike")?;
    delete_secret(account)?;
    match loaded.as_deref() {
        Some("protected test secret") => {
            println!("cb: spike-keychain-auth roundtrip=ok user-presence=verified");
            Ok(())
        }
        other => Err(format!("unexpected read-back: {other:?}")),
    }
}

// =======================================================================
// Bitcoin Core RPC credentials
// (`../../PLAN-chain-notes-app-core-rpc.md` §2.4/U6 — orchestrator-owned
// security posture, not the implementer's call to change).
// =======================================================================
//
// These are NETWORK credentials for the user's own `bitcoind` — not key
// material — and get a DELIBERATELY DIFFERENT, weaker posture than the
// identity item above:
//
//   - NO `SecAccessControl` / `kSecAccessControlUserPresence` ACL, and no
//     `user_presence_check` (LAContext) gate anywhere in this section. A
//     lost RPC password just means re-typing it in Settings; it is not the
//     user's only copy of anything irreplaceable, so it does not earn the
//     identity item's biometric gate.
//   - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable by a
//     background network worker once the device has unlocked at least once
//     since boot, and NEVER synced (no `kSecAttrSynchronizable`) — an RPC
//     password must not leave this device via iCloud Keychain the way an
//     opted-in seed backup does.
//   - A distinct account namespace (`rpc-creds-<network>`) that is
//     structurally distinct from `identity-key` / `identity-key#la` /
//     `identity-key#new` — collision is not just avoided, it's a different
//     string shape entirely, so nothing here can shadow or be shadowed by
//     the identity path.
//
// LAUNCH-PATH RULE, unchanged: nothing on the boot path may call these.
// Load lazily — Settings open, or the first Core-backend network request —
// exactly like the identity item's `identity_exists` probe must stay off
// the boot path. These calls carry no ACL so they cannot themselves block
// on a biometric prompt, but the launch-watchdog lesson (builds 42/44) was
// general: zero NEW Keychain calls before the first frame, full stop.

/// Distinct account namespace for RPC credentials — see the module doc
/// above. Network-scoped because the Bitcoin-node URL itself is
/// (`State.node_urls`, keyed by network).
fn rpc_account(network: &str) -> String {
    format!("rpc-creds-{network}")
}

fn rpc_staging_account(network: &str) -> String {
    format!("rpc-creds-{network}#new")
}

/// One keychain item holds both fields as `"<user>\n<pass>"` — bitcoind's
/// `rpcuser`/`rpcpassword` are single config-file tokens and never contain
/// a newline, so this can't collide with either half.
fn encode_rpc_creds(user: &str, pass: &str) -> String {
    format!("{user}\n{pass}")
}

fn decode_rpc_creds(blob: &str) -> Option<(String, String)> {
    blob.split_once('\n').map(|(u, p)| (u.to_string(), p.to_string()))
}

/// Write one plain (no-ACL) item under `account`. Deletes nothing — a
/// collision fails with errSecDuplicateItem, exactly like the identity
/// item's `add_item`, which is what makes the two-phase write below safe.
fn add_rpc_item(account: &str, value: &str) -> Result<(), String> {
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecValueData }),
        CFData::from_buffer(value.as_bytes()).as_CFType(),
    ));
    pairs.push((
        key(unsafe { kSecAttrAccessible }),
        key(unsafe { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }).as_CFType(),
    ));
    // Deliberately absent: kSecAttrAccessControl (no ACL — see module doc)
    // and kSecAttrSynchronizable (never iCloud-synced).
    push_domain(&mut pairs, true);
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    match status {
        0 => Ok(()),
        other => Err(format!("SecItemAdd(rpc-creds) failed ({other})")),
    }
}

/// Attributes-only existence check — no `kSecReturnData`, so this never
/// touches the value. There is no ACL here to trigger authentication in the
/// first place (unlike the identity item's `probe_item`), but this keeps
/// the same "confirm it landed" shape the two-phase write depends on.
fn rpc_item_exists(account: &str) -> bool {
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        pairs.push((key(unsafe { kSecReturnAttributes }), CFBoolean::true_value().as_CFType()));
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        if !result.is_null() {
            unsafe { CFType::wrap_under_create_rule(result) };
        }
        if status == 0 {
            return true;
        }
    }
    false
}

fn rpc_read_item(account: &str) -> Result<Option<String>, String> {
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        match status {
            0 => {
                let data = unsafe { CFData::wrap_under_create_rule(result as _) };
                return String::from_utf8(data.bytes().to_vec())
                    .map(Some)
                    .map_err(|e| e.to_string());
            }
            ERR_NOT_FOUND | ERR_MISSING_ENTITLEMENT => continue,
            other => return Err(format!("SecItemCopyMatching(rpc-creds) failed ({other})")),
        }
    }
    Ok(None)
}

fn rpc_delete_account(account: &str) -> Result<(), String> {
    for dp in KEYCHAIN_DOMAINS {
        let mut pairs = base_query(account);
        push_domain(&mut pairs, dp);
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status != 0 && status != ERR_NOT_FOUND && status != ERR_MISSING_ENTITLEMENT {
            return Err(format!("SecItemDelete(rpc-creds) failed ({status})"));
        }
    }
    Ok(())
}

/// Store the RPC username/password for `network`, replacing whatever is
/// there. Same crash-safe two-phase shape as [`store_secret_protected`]
/// (2026-07-25 audit, H1) even though the stakes here are lower (a lost RPC
/// password is retypeable, not catastrophic): stage under `<account>#new`,
/// confirm it landed, purge the live item, write the live item, drop
/// staging. At every instant at least one copy of the credential exists on
/// the device.
pub fn store_rpc_creds(network: &str, user: &str, pass: &str) -> Result<(), String> {
    let account = rpc_account(network);
    let staging = rpc_staging_account(network);
    let value = encode_rpc_creds(user, pass);

    // Debris from an earlier interrupted write whose primary was since
    // restored — the live item wins, so clear the way (mirrors
    // `store_secret_protected`'s opening `purge_account(&staging)`).
    rpc_delete_account(&staging)?;

    // Phase 1 — the new copy, off to the side. The live item is untouched.
    add_rpc_item(&staging, &value)?;
    if !rpc_item_exists(&staging) {
        return Err("rpc-creds staging write did not verify".into());
    }

    // Phase 2 — only now is it safe to drop the old copy; staging holds one.
    rpc_delete_account(&account)?;

    // Phase 3 — the real item. If this fails, staging still holds the
    // credential and the next `load_rpc_creds` recovers it.
    match add_rpc_item(&account, &value) {
        Ok(()) => {
            let _ = rpc_delete_account(&staging);
            Ok(())
        }
        Err(e) => Err(format!("{e} (credentials preserved in staging — retry from Settings)")),
    }
}

/// Read the stored RPC username/password for `network`, if any. Adopts a
/// surviving staging copy from an interrupted write (same recovery shape as
/// [`load_secret_protected`]). Safe to call from any non-boot path — see
/// the module doc for why boot itself must still never reach this.
pub fn load_rpc_creds(network: &str) -> Result<Option<(String, String)>, String> {
    let account = rpc_account(network);
    if let Some(v) = rpc_read_item(&account)? {
        return Ok(decode_rpc_creds(&v));
    }
    let staging = rpc_staging_account(network);
    let Some(v) = rpc_read_item(&staging)? else {
        return Ok(None);
    };
    // Promote the staging copy now that we know it's the only one.
    if add_rpc_item(&account, &v).is_ok() {
        let _ = rpc_delete_account(&staging);
    }
    Ok(decode_rpc_creds(&v))
}

/// Remove stored RPC credentials for `network` — the live item and any
/// staging debris. A missing item is success.
pub fn delete_rpc_creds(network: &str) -> Result<(), String> {
    let live = rpc_delete_account(&rpc_account(network));
    let staged = rpc_delete_account(&rpc_staging_account(network));
    live.and(staged)
}
