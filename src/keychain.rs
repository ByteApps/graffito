//! macOS Keychain backend for the SecretStore spec (PLAN "Key storage").
//!
//! Stores the ORIGINAL key material verbatim (it doubles as the
//! re-revealable backup) as a generic password in the login keychain.
//! TODO(M6, with the reveal screen): move the item behind a
//! kSecAccessControlUserPresence ACL so reveal re-authenticates
//! (Touch ID / password) — the spec's guarantee 3.

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE: &str = "com.objsal.chain-notes-app";

pub fn store_secret(account: &str, secret: &str) -> Result<(), String> {
    set_generic_password(SERVICE, account, secret.as_bytes()).map_err(|e| e.to_string())
}

pub fn load_secret(account: &str) -> Result<Option<String>, String> {
    match get_generic_password(SERVICE, account) {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| e.to_string()),
        Err(e) if e.code() == -25300 => Ok(None), // errSecItemNotFound
        Err(e) => Err(e.to_string()),
    }
}

pub fn delete_secret(account: &str) -> Result<(), String> {
    match delete_generic_password(SERVICE, account) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == -25300 => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Headless spike: prove a secret round-trips (store → load → delete →
/// gone). Never logs the secret itself — lengths only (log contract).
pub fn spike() -> Result<(), String> {
    let account = "spike-test";
    let secret = "correct horse battery staple";
    store_secret(account, secret)?;
    let loaded = load_secret(account)?.ok_or("stored secret not found")?;
    if loaded != secret {
        return Err("loaded secret differs".into());
    }
    delete_secret(account)?;
    if load_secret(account)?.is_some() {
        return Err("secret survived delete".into());
    }
    println!("cb: spike-keychain roundtrip=ok len={}", secret.len());
    Ok(())
}
