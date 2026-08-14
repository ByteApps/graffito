// ---------------------------------------------------------------------------
// applicationId — DEFINED ONCE, HERE.
//
// com.objsal.graffito is PERMANENT the moment it is first uploaded to Google
// Play (Play ties the app listing to this id for life; it cannot be changed
// or reused later). This is deliberately a DIFFERENT id from the iOS/macOS
// bundle id family (xyz.foundation.chainnotes.app, set at the Rust-package
// level in ../../../Cargo.toml's [package.metadata.android] — that id is
// cargo-apk's sideload/dev path, NOT what ships to Play) — CONFIRM this is
// the intended id with Sal before running `./gradlew bundleRelease` against
// a real upload, and definitely before any `bundletool`/Play Console step
// that actually publishes.
val playApplicationId = "com.objsal.graffito"
// ---------------------------------------------------------------------------

plugins {
    id("com.android.application")
}

android {
    namespace = "com.objsal.graffito"
    // Google Play requires new-app uploads to target API 36 starting
    // 2026-08-31 (policy fact confirmed by the orchestrator after this
    // module was drafted) — compileSdk must be >= targetSdk.
    compileSdk = 36

    defaultConfig {
        applicationId = playApplicationId
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    // No java/kotlin sources: the BiometricPrompt bridge ships as a dex
    // embedded in the Rust binary via include_bytes! (see
    // ../../../src/keychain/android.rs — search BIOMETRIC_DEX) and loaded at
    // runtime with InMemoryDexClassLoader, so this Gradle project needs no
    // sourceSets.java entries and no assets/ dir of its own.
    sourceSets {
        getByName("main") {
            manifest.srcFile("src/main/AndroidManifest.xml")
            // Reuse the icon resources cargo-apk already consumes
            // ([package.metadata.android] resources = "assets/icon/android/res"
            // in ../../../Cargo.toml) rather than forking a copy that can
            // drift. AGP is fine merging a res dir outside the module tree.
            res.srcDirs("../../../assets/icon/android/res")
            // Staged by scripts/build-play-bundle.sh from the cargo-apk
            // output (lib/arm64-v8a/libchain_notes_app.so extracted out of
            // the APK cargo-apk builds) — see .gitignore, this directory's
            // contents are a build product, not checked in.
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        // The .so is already stripped by [profile.release] strip = true in
        // ../../../Cargo.toml; nothing extra to exclude here, but keep
        // legacy packaging off since this is an AAB (bundleRelease), not an
        // uncompressed-native-libs APK path.
        jniLibs {
            useLegacyPackaging = false
        }
    }

    // Only demand the signing env vars when a release-ish task was actually
    // requested (bundleRelease, assembleRelease, etc.) — otherwise plain
    // introspection tasks (`wrapper`, `tasks`, `help`, even `assembleDebug`
    // if one ever existed) would fail just because the signing env isn't
    // sourced in the current shell.
    val releaseTaskRequested = gradle.startParameter.taskNames.any {
        it.substringAfterLast(":").contains("release", ignoreCase = true)
    }

    signingConfigs {
        create("release") {
            // Values come from the environment (sourced from
            // ../../../../private/chain-notes-app/android-signing.env by
            // scripts/build-play-bundle.sh) — never hardcoded, never
            // committed. Fail loudly rather than silently falling back to
            // an unsigned/debug-signed bundle.
            val ksPath = System.getenv("ANDROID_UPLOAD_KEYSTORE")
            val ksPass = System.getenv("ANDROID_UPLOAD_KEYSTORE_PASSWORD")
            val ksAlias = System.getenv("ANDROID_UPLOAD_KEY_ALIAS")
            if (releaseTaskRequested) {
                require(!ksPath.isNullOrBlank()) {
                    "ANDROID_UPLOAD_KEYSTORE is not set — source " +
                        "private/chain-notes-app/android-signing.env before " +
                        "running ./gradlew bundleRelease (see " +
                        "scripts/build-play-bundle.sh)."
                }
                require(!ksPass.isNullOrBlank()) {
                    "ANDROID_UPLOAD_KEYSTORE_PASSWORD is not set — see " +
                        "ANDROID_UPLOAD_KEYSTORE error above."
                }
                require(!ksAlias.isNullOrBlank()) {
                    "ANDROID_UPLOAD_KEY_ALIAS is not set — see " +
                        "ANDROID_UPLOAD_KEYSTORE error above."
                }
            }
            if (!ksPath.isNullOrBlank()) storeFile = file(ksPath)
            if (!ksAlias.isNullOrBlank()) keyAlias = ksAlias
            // The upload keystore was generated with the same store/key
            // password (see scripts/build-play-bundle.sh's keystore-gen
            // step) — one 32-char random secret, not two.
            if (!ksPass.isNullOrBlank()) {
                storePassword = ksPass
                keyPassword = ksPass
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    buildFeatures {
        buildConfig = false
    }
}
