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
//! `reveal_secret` and `load_secret_gated` now show the system
//! BiometricPrompt first (`user_presence_check`), matching Apple. BOOT STILL
//! DECRYPTS SILENTLY, deliberately — a launch path that waits on a human is
//! what killed iOS builds 42 and 44.
//!
//! This is the APP-LEVEL gate, option (a) of
//! `PLAN-chain-notes-app-android-biometric.md`. The Keystore key is NOT
//! auth-bound (`setUserAuthenticationRequired`), because that permanently
//! invalidates it when the user removes their screen lock — destroying the
//! wrapped seed for anyone who never wrote the phrase down. So the honest
//! claim is "must satisfy the system prompt", not "the OS enforces it": code
//! already running in this process can skip it. Apple's unentitled builds give
//! exactly the same guarantee through their LAContext fallback.
//!
//! The doc above says the key is hardware-backed; note the code requests
//! neither `setIsStrongBoxBacked` nor verifies `KeyInfo.getSecurityLevel()`,
//! so TEE backing is what devices do in practice, not something asserted here.

use std::path::PathBuf;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::JNIEnv;

// KeyProperties.PURPOSE_ENCRYPT (1) | PURPOSE_DECRYPT (2)
const PURPOSE_ENCRYPT_DECRYPT: i32 = 3;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
const GCM_TAG_BITS: i32 = 128;

fn alias(account: &str) -> String {
    format!("graffito.{account}")
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

/// No iCloud on Android — the "Back up to iCloud" affordance is Apple-only.
pub fn icloud_available() -> bool {
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

// --- User-presence gate (app-level, PLAN-chain-notes-app-android-biometric.md
// option (a)) ------------------------------------------------------------
//
// The dex is EMBEDDED rather than shipped as an asset: `InMemoryDexClassLoader`
// takes a direct ByteBuffer, so there is no AssetManager plumbing and no
// packaging step to forget. Regenerate with `scripts/gen-biometric-dex.sh`
// after editing android/biometric/*.java — it is a committed build artifact,
// like the generated icons.
const BIOMETRIC_DEX: &[u8] = include_bytes!("../../assets/android/biometric.dex");

/// How long to leave the prompt up before treating silence as refusal. Long
/// enough for a real person to notice and react, short enough that a wedged
/// prompt cannot hang the reveal forever.
const BIOMETRIC_TIMEOUT_MS: i64 = 60_000;

/// `Build.VERSION.SDK_INT`. `BiometricPrompt` is API 28 while this app's
/// min_sdk is 26, so the two-version gap has to be checked at runtime.
fn sdk_int(env: &mut JNIEnv) -> jni::errors::Result<i32> {
    env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I")?.i()
}

/// Show the system biometric prompt and block until it resolves.
///
/// This is option (a) from the plan: an APP-LEVEL gate over the existing
/// Keystore key. It does NOT make the key itself auth-bound
/// (`setUserAuthenticationRequired`), because that permanently invalidates the
/// key if the user removes their screen lock — losing the wrapped seed for
/// anyone who never wrote the phrase down. So the honest claim is: this raises
/// the bar from "no authentication at all" to "must satisfy the system prompt",
/// and an attacker already executing code in this process can bypass it. That
/// is the same guarantee iOS gives on an unentitled build via its LAContext
/// fallback.
///
/// **Call this from a WORKER thread, never from the slint/android_main
/// thread.** That thread is not the Java main thread, but it IS the thread
/// that drains the NativeActivity input queue, and Android's input watchdog
/// raises "isn't responding" when a touch sits unconsumed for 5 s — which is
/// exactly what happened the first time a finger touched the screen while
/// this was parked in `await` (Sal's Pixel, 2026-09-05; ANR trace:
/// android_main → CountDownLatch.await ← BiometricBridge.await). Every caller
/// (`reveal_secret`, `load_secret_gated`) now runs on `std::thread::spawn`
/// and posts its result back to the UI thread.
/// Load one class out of the embedded dex (`assets/android/biometric.dex`,
/// every `.java` under android/biometric/) with the activity's own class
/// loader as parent so framework classes resolve.
fn load_dex_class<'l>(env: &mut JNIEnv<'l>, activity: &JObject, name: &str) -> jni::errors::Result<JObject<'l>> {
    let act_class = env.call_method(activity, "getClass", "()Ljava/lang/Class;", &[])?.l()?;
    let parent = env
        .call_method(&act_class, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;
    let buf = unsafe {
        env.new_direct_byte_buffer(BIOMETRIC_DEX.as_ptr() as *mut u8, BIOMETRIC_DEX.len())?
    };
    let loader = env.new_object(
        "dalvik/system/InMemoryDexClassLoader",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
        &[JValue::Object(&buf), JValue::Object(&parent)],
    )?;
    let name = jstr(env, name)?;
    env.call_method(
        &loader,
        "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        &[JValue::Object(&name)],
    )?
    .l()
}

/// FLAG_SECURE on/off for the activity window (see WindowSecure.java): the
/// window is excluded from screenshots, screen recording and the recents
/// thumbnail while a secret is on screen. Posted to the UI thread; returns
/// as soon as it is queued.
pub fn set_window_secure(secure: bool) -> Result<(), String> {
    with_env(|env| {
        let app = crate::android_app().ok_or_else(|| {
            jni::errors::Error::JniCall(jni::errors::JniError::Other(-1))
        })?;
        let activity = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
        let class = load_dex_class(env, &activity, "xyz.foundation.graffito.WindowSecure")?;
        let runnable = env.new_object(
            &JClass::from(class),
            "(Landroid/app/Activity;Z)V",
            &[JValue::Object(&activity), JValue::Bool(u8::from(secure))],
        )?;
        env.call_method(
            &activity,
            "runOnUiThread",
            "(Ljava/lang/Runnable;)V",
            &[JValue::Object(&runnable)],
        )?;
        Ok(())
    })
}

fn user_presence_check(reason: &str) -> Result<(), String> {
    let title = "Reveal secret";
    let negative = "Cancel";
    let outcome = with_env(|env| {
        if sdk_int(env)? < 28 {
            // Nothing to fall back to that is worth the risk: a
            // KeyguardManager confirm-credential Intent needs an activity
            // result, which NativeActivity does not forward to native code.
            // Report it and let the caller decide, rather than silently
            // pretending the user was verified.
            return Ok(-1i32);
        }
        // MUST be the Activity, not ndk_context's context — that one is the
        // APPLICATION, which has no runOnUiThread and no window for the prompt
        // to attach to. Verified the hard way on the emulator:
        // `NoSuchMethodError: no non-static method
        // "Landroid/app/Application;.runOnUiThread"`. `activity_as_ptr` is the
        // ANativeActivity's own Java object, stashed by android_main.
        let app = crate::android_app().ok_or_else(|| {
            jni::errors::Error::JniCall(jni::errors::JniError::Other(-1))
        })?;
        let activity = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };

        let class = load_dex_class(env, &activity, "xyz.foundation.graffito.BiometricBridge")?;

        let t = jstr(env, title)?;
        let s = jstr(env, reason)?;
        let n = jstr(env, negative)?;
        let bridge = env.new_object(
            &JClass::from(class),
            "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&activity),
                JValue::Object(&t),
                JValue::Object(&s),
                JValue::Object(&n),
            ],
        )?;

        // The prompt must be built and shown on the UI thread.
        env.call_method(
            &activity,
            "runOnUiThread",
            "(Ljava/lang/Runnable;)V",
            &[JValue::Object(&bridge)],
        )?;

        env.call_method(&bridge, "await", "(J)I", &[JValue::Long(BIOMETRIC_TIMEOUT_MS)])?.i()
    })?;

    match outcome {
        1 => {
            eprintln!("cb: keychain user-presence ok");
            Ok(())
        }
        -1 => {
            eprintln!("cb: keychain user-presence unavailable=api<28");
            Err("biometric prompt needs Android 9 or newer".into())
        }
        other => {
            eprintln!("cb: keychain user-presence denied result={other}");
            Err("not authenticated".into())
        }
    }
}

/// Reveal path — gated on the system biometric prompt, like Apple's.
///
/// The gate runs BEFORE the decrypt and a refusal propagates, so a cancelled
/// or failed prompt returns Err and the caller never sees the secret. That
/// ordering is the whole feature: checking afterwards would decrypt the seed
/// into memory first and only then ask.
pub fn reveal_secret(account: &str, prompt: &str) -> Result<Option<String>, String> {
    user_presence_check(prompt)?;
    load_secret_protected(account, prompt)
}

/// Apple's counterpart gates a SYNCED (ACL-less) item behind LAContext before
/// a user-initiated restore; Android has no synced shape (`is_synced` is always
/// false), but the restore tap hands over the same seed, so it takes the same
/// prompt.
///
/// TAP PATHS ONLY, exactly as on Apple: never call this from boot. It blocks
/// waiting for a human, and a launch path that blocks on a prompt is what
/// killed iOS builds 42 and 44.
pub fn load_secret_gated(account: &str, prompt: &str) -> Result<Option<String>, String> {
    user_presence_check(prompt)?;
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

/// Is there a saved identity to restore, without unlocking it? The wrapped
/// blob's presence is the whole answer here — no Keystore round-trip, so no
/// biometric prompt. Mirrors the Apple probe the launch path uses.
pub fn identity_exists(account: &str) -> bool {
    blob_path(account).exists()
}

/// Android has no equivalent downgrade (audit M2): the blob is wrapped by a
/// hardware-backed AndroidKeyStore key with no software fallback path — if
/// the Keystore is unavailable the store fails outright rather than quietly
/// writing something weaker. Always false.
pub fn protection_degraded() -> bool {
    false
}

// --spike entry points don't run on Android (no CLI), but the shared
// dispatch in run() references them, so they must exist.
pub fn spike() -> Result<(), String> {
    Err("keychain spike is desktop-only".into())
}
pub fn spike_auth() -> Result<(), String> {
    Err("keychain spike is desktop-only".into())
}

// ---- Bitcoin Core RPC credentials (PLAN-chain-notes-app-core-rpc.md
// §2.4/U6) — mirrors keychain/apple.rs's RPC-credentials section. ----
//
// These are network credentials, not key material, so they get NO
// biometric gate here either — but on Android there is nothing to
// deliberately weaken: `store_secret_protected` above already has no
// UserPresence/BiometricPrompt gate (deferred to the Kotlin layer, per the
// module doc) and is already device-bound (AndroidKeyStore keys never
// leave the TEE/StrongBox, and `is_synced` is always false — no Google
// backup path this needs to opt out of). Reusing it under a DISTINCT
// account namespace (`rpc-creds-<network>`, never `identity-key`) gives
// the same posture the Apple side hand-builds, for free.

fn rpc_account(network: &str) -> String {
    format!("rpc-creds-{network}")
}

fn encode_rpc_creds(user: &str, pass: &str) -> String {
    format!("{user}\n{pass}")
}

fn decode_rpc_creds(blob: &str) -> Option<(String, String)> {
    blob.split_once('\n').map(|(u, p)| (u.to_string(), p.to_string()))
}

pub fn store_rpc_creds(network: &str, user: &str, pass: &str) -> Result<(), String> {
    store_secret_protected(&rpc_account(network), &encode_rpc_creds(user, pass), false)
}

pub fn load_rpc_creds(network: &str) -> Result<Option<(String, String)>, String> {
    Ok(load_secret_protected(&rpc_account(network), "")?.and_then(|v| decode_rpc_creds(&v)))
}

pub fn delete_rpc_creds(network: &str) -> Result<(), String> {
    delete_secret(&rpc_account(network))
}
