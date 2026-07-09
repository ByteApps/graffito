//! Android SecretStore backend: the identity material is wrapped with a
//! per-account AES-GCM key that lives in the hardware-backed
//! AndroidKeyStore (never leaves the TEE/StrongBox); the ciphertext blob
//! (`iv || ct`) is written to the app's private internal storage. Reads
//! decrypt through the keystore key, so a stolen file is useless without
//! the device.
//!
//! All calls are JNI into the Android framework via the `jni` crate; the
//! JavaVM comes from `ndk_context`, populated by Slint's android-activity
//! backend at startup.
//!
//! Deferred to the Kotlin/Gradle layer (tracked in the phase-4 PLAN):
//! `setUserAuthenticationRequired` + BiometricPrompt so `reveal_secret`
//! shows a fingerprint/face gate. Today boot and reveal both decrypt
//! silently — the file is still keystore-protected at rest.

use std::path::PathBuf;

use jni::objects::{JByteArray, JObject, JString, JValue};
use jni::JNIEnv;

// KeyProperties.PURPOSE_ENCRYPT (1) | PURPOSE_DECRYPT (2)
const PURPOSE_ENCRYPT_DECRYPT: i32 = 3;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
const GCM_TAG_BITS: i32 = 128;

fn alias(account: &str) -> String {
    format!("chain-notes-app.{account}")
}

/// Where the wrapped blob lives — app-private internal storage, seeded by
/// `android_main` into `APP_DATA_DIR`. A sanitized account keeps it to a
/// single path segment.
fn blob_path(account: &str) -> PathBuf {
    let safe: String =
        account.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let base = std::env::var("APP_DATA_DIR").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(format!("kc-{safe}.bin"))
}

/// `.l()?` yields a `JObject`; reinterpret it as a byte array for
/// `convert_byte_array` (jbyteArray and jobject share the sys handle).
fn as_byte_array<'e>(obj: JObject<'e>) -> JByteArray<'e> {
    unsafe { JByteArray::from_raw(obj.into_raw()) }
}

fn jstr<'e>(env: &mut JNIEnv<'e>, s: &str) -> jni::errors::Result<JString<'e>> {
    env.new_string(s)
}

fn string_array1<'e>(env: &mut JNIEnv<'e>, s: &str) -> jni::errors::Result<JObject<'e>> {
    let val = jstr(env, s)?;
    Ok(env.new_object_array(1, "java/lang/String", &val)?.into())
}

/// KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null, null);
fn load_keystore<'e>(env: &mut JNIEnv<'e>) -> jni::errors::Result<JObject<'e>> {
    let provider = jstr(env, "AndroidKeyStore")?;
    let ks = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&provider)],
        )?
        .l()?;
    env.call_method(
        &ks,
        "load",
        "(Ljava/io/InputStream;[C)V",
        &[JValue::Object(&JObject::null()), JValue::Object(&JObject::null())],
    )?;
    Ok(ks)
}

/// Fetch the existing SecretKey for `alias`, or generate a fresh AES-GCM
/// key under it inside the keystore.
fn get_or_create_key<'e>(
    env: &mut JNIEnv<'e>,
    ks: &JObject,
    alias_str: &str,
) -> jni::errors::Result<JObject<'e>> {
    let alias_j = jstr(env, alias_str)?;
    let exists = env
        .call_method(ks, "containsAlias", "(Ljava/lang/String;)Z", &[JValue::Object(&alias_j)])?
        .z()?;
    if exists {
        let alias_j = jstr(env, alias_str)?;
        return env
            .call_method(
                ks,
                "getKey",
                "(Ljava/lang/String;[C)Ljava/security/Key;",
                &[JValue::Object(&alias_j), JValue::Object(&JObject::null())],
            )?
            .l();
    }

    // new KeyGenParameterSpec.Builder(alias, ENCRYPT|DECRYPT)
    //   .setBlockModes("GCM").setEncryptionPaddings("NoPadding").build()
    let alias_j = jstr(env, alias_str)?;
    let builder = env.new_object(
        "android/security/keystore/KeyGenParameterSpec$Builder",
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&alias_j), JValue::Int(PURPOSE_ENCRYPT_DECRYPT)],
    )?;
    let ret = "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;";
    let gcm = string_array1(env, "GCM")?;
    let builder = env.call_method(&builder, "setBlockModes", ret, &[JValue::Object(&gcm)])?.l()?;
    let nopad = string_array1(env, "NoPadding")?;
    let builder =
        env.call_method(&builder, "setEncryptionPaddings", ret, &[JValue::Object(&nopad)])?.l()?;
    let spec = env
        .call_method(
            &builder,
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )?
        .l()?;

    let aes = jstr(env, "AES")?;
    let provider = jstr(env, "AndroidKeyStore")?;
    let kg = env
        .call_static_method(
            "javax/crypto/KeyGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[JValue::Object(&aes), JValue::Object(&provider)],
        )?
        .l()?;
    env.call_method(
        &kg,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    )?;
    env.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?.l()
}

fn encrypt(env: &mut JNIEnv, key: &JObject, plaintext: &[u8]) -> jni::errors::Result<Vec<u8>> {
    let transform = jstr(env, "AES/GCM/NoPadding")?;
    let cipher = env
        .call_static_method(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&transform)],
        )?
        .l()?;
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(ENCRYPT_MODE), JValue::Object(key)],
    )?;
    let pt = env.byte_array_from_slice(plaintext)?;
    let ct = env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&pt)])?.l()?;
    let iv = env.call_method(&cipher, "getIV", "()[B", &[])?.l()?;
    let iv = env.convert_byte_array(as_byte_array(iv))?;
    let ct = env.convert_byte_array(as_byte_array(ct))?;
    // Blob = 1-byte IV length | IV | ciphertext+tag.
    let mut blob = Vec::with_capacity(1 + iv.len() + ct.len());
    blob.push(iv.len() as u8);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt(env: &mut JNIEnv, key: &JObject, blob: &[u8]) -> jni::errors::Result<Vec<u8>> {
    let iv_len = *blob.first().unwrap_or(&0) as usize;
    let iv = &blob[1..1 + iv_len];
    let ct = &blob[1 + iv_len..];
    let iv_arr = env.byte_array_from_slice(iv)?;
    let gcmp = env.new_object(
        "javax/crypto/spec/GCMParameterSpec",
        "(I[B)V",
        &[JValue::Int(GCM_TAG_BITS), JValue::Object(&iv_arr)],
    )?;
    let transform = jstr(env, "AES/GCM/NoPadding")?;
    let cipher = env
        .call_static_method(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&transform)],
        )?
        .l()?;
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Int(DECRYPT_MODE), JValue::Object(key), JValue::Object(&gcmp)],
    )?;
    let ct_arr = env.byte_array_from_slice(ct)?;
    let pt = env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&ct_arr)])?.l()?;
    env.convert_byte_array(as_byte_array(pt))
}

/// Attach the current thread to the JavaVM, run `f`, and surface any
/// pending Java exception as the error string.
fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>) -> Result<T, String> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|e| format!("JavaVM: {e}"))?;
    let mut env = vm.attach_current_thread().map_err(|e| format!("attach: {e}"))?;
    match f(&mut env) {
        Ok(v) => Ok(v),
        Err(e) => Err(format!("{e} :: {}", describe_exception(&mut env))),
    }
}

fn describe_exception(env: &mut JNIEnv) -> String {
    if env.exception_check().unwrap_or(false) {
        let t = env.exception_occurred().ok();
        let _ = env.exception_clear();
        if let Some(t) = t {
            if let Ok(msg) = env.call_method(&t, "toString", "()Ljava/lang/String;", &[]) {
                if let Ok(obj) = msg.l() {
                    if let Ok(s) = env.get_string(&JString::from(obj)) {
                        return s.to_string_lossy().into_owned();
                    }
                }
            }
        }
        "java exception".into()
    } else {
        "no pending exception".into()
    }
}

// ---- public SecretStore surface (mirrors keychain/apple.rs) ----

pub fn store_secret_protected(account: &str, secret: &str, _synced: bool) -> Result<(), String> {
    let alias_str = alias(account);
    let blob = with_env(|env| {
        let ks = load_keystore(env)?;
        let key = get_or_create_key(env, &ks, &alias_str)?;
        encrypt(env, &key, secret.as_bytes())
    })?;
    let path = blob_path(account);
    std::fs::write(&path, &blob).map_err(|e| format!("write blob: {e}"))?;
    log_len("store", secret.len());
    Ok(())
}

/// Android Keystore keys are device-bound — never iCloud/Drive synced.
pub fn is_synced(_account: &str) -> bool {
    false
}

pub fn load_secret_protected(account: &str, _prompt: &str) -> Result<Option<String>, String> {
    let path = blob_path(account);
    let blob = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let alias_str = alias(account);
    let pt = with_env(|env| {
        let ks = load_keystore(env)?;
        let key = get_or_create_key(env, &ks, &alias_str)?;
        decrypt(env, &key, &blob)
    })?;
    let s = String::from_utf8(pt).map_err(|_| "decrypted bytes not utf-8".to_string())?;
    log_len("load", s.len());
    Ok(Some(s))
}

/// Reveal path. Biometric gating (BiometricPrompt) is deferred to the
/// Kotlin layer; for now this decrypts through the keystore like boot.
pub fn reveal_secret(account: &str, prompt: &str) -> Result<Option<String>, String> {
    load_secret_protected(account, prompt)
}

pub fn delete_secret(account: &str) -> Result<(), String> {
    let _ = std::fs::remove_file(blob_path(account));
    let alias_str = alias(account);
    let _ = with_env(|env| {
        let ks = load_keystore(env)?;
        let alias_j = jstr(env, &alias_str)?;
        env.call_method(&ks, "deleteEntry", "(Ljava/lang/String;)V", &[JValue::Object(&alias_j)])?;
        Ok(())
    });
    Ok(())
}

fn log_len(op: &str, n: usize) {
    // Matches the no-secrets-in-logs contract: length only.
    eprintln!("cb: keychain {op} bytes={n}");
}

// --spike entry points don't run on Android (no CLI), but the shared
// dispatch in run() references them, so they must exist.
pub fn spike() -> Result<(), String> {
    Err("keychain spike is desktop-only".into())
}
pub fn spike_auth() -> Result<(), String> {
    Err("keychain spike is desktop-only".into())
}
