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
use security_framework_sys::access_control::kSecAccessControlUserPresence;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecValueData,
};

// Deprecated in the SDK headers (and unbound in security-framework-sys)
// but still functional: the reason string shown in the auth prompt.
extern "C" {
    static kSecUseOperationPrompt: core_foundation_sys::string::CFStringRef;
    static kSecUseDataProtectionKeychain: core_foundation_sys::string::CFStringRef;
    // iCloud Keychain sync: the attribute key + the "match either" query value.
    static kSecAttrSynchronizable: core_foundation_sys::string::CFStringRef;
    static kSecAttrSynchronizableAny: core_foundation_sys::string::CFStringRef;
}
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

const SERVICE: &str = "com.objsal.chain-notes-app";
const ERR_NOT_FOUND: i32 = -25300; // errSecItemNotFound
const ERR_CANCELED: i32 = -128; // errSecUserCanceled

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

pub fn store_secret_protected(account: &str, secret: &str, synced: bool) -> Result<(), String> {
    delete_secret(account)?; // also migrates away any pre-ACL / previously-synced item
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
            0 => {
                println!("cb: keychain stored synced=1");
                Ok(())
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
        0 => Ok(()),
        -34018 => {
            // errSecMissingEntitlement: no data-protection keychain for
            // unsigned builds. Plain item under the #la account; reads
            // gated by LAContext.
            println!("cb: keychain acl=unavailable fallback=lacontext");
            set_generic_password(SERVICE, &la_account(account), secret.as_bytes())
                .map_err(|e| e.to_string())
        }
        other => Err(format!("SecItemAdd failed ({other})")),
    }
}

/// Read the protected item — the OS shows a Touch ID / password prompt
/// with `prompt` as the reason. Ok(None) = no item; Err carries
/// "cancelled" when the user dismissed the prompt.
/// Does an iCloud-synced item exist for this account?
pub fn is_synced(account: &str) -> bool {
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecAttrSynchronizable }),
        CFBoolean::true_value().as_CFType(),
    ));
    pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
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
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecAttrSynchronizable }),
        CFBoolean::true_value().as_CFType(),
    ));
    pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
    match status {
        0 => {
            let data = unsafe { CFData::wrap_under_create_rule(result as _) };
            String::from_utf8(data.bytes().to_vec()).map(Some).map_err(|e| e.to_string())
        }
        ERR_NOT_FOUND => Ok(None),
        other => Err(format!("SecItemCopyMatching(sync) failed ({other})")),
    }
}

pub fn load_secret_protected(account: &str, prompt: &str) -> Result<Option<String>, String> {
    // iCloud-synced item has no biometric ACL — read it silently (it's
    // protected by the device passcode / accessible-when-unlocked). Boot MUST
    // NOT block on a Face ID prompt here: doing so on the main thread at launch
    // blanks the UI and trips the iOS watchdog. The Reveal-backup action gates
    // Face ID separately via `reveal_secret`.
    if is_synced(account) {
        return read_synced(account);
    }
    let mut pairs = base_query(account);
    pairs.push((key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
    pairs.push((
        key(unsafe { kSecUseOperationPrompt }),
        CFString::new(prompt).as_CFType(),
    ));
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
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

pub fn delete_secret(account: &str) -> Result<(), String> {
    // synchronizable=Any removes both the local (ACL) item and any synced one.
    let mut pairs = base_query(account);
    pairs.push((
        key(unsafe { kSecAttrSynchronizable }),
        key(unsafe { kSecAttrSynchronizableAny }).as_CFType(),
    ));
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
    if status != 0 && status != ERR_NOT_FOUND {
        return Err(format!("SecItemDelete failed ({status})"));
    }
    for acct in [account.to_string(), la_account(account)] {
        match delete_generic_password(SERVICE, &acct) {
            Ok(()) | Err(_) => {} // not-found is fine; best-effort cleanup
        }
    }
    Ok(())
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
