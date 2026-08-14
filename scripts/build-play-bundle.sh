#!/usr/bin/env bash
# Build the Google Play upload artifact for Graffito: a signed .aab.
#
# cargo-apk (the toolchain the rest of this repo's Android path uses — see
# gen-biometric-dex.sh, Cargo.toml's [package.metadata.android]) can only
# produce APKs. Google Play requires an Android App Bundle for new-app
# uploads, and AGP's bundleRelease task is the only practical way to get
# one — hence android/play/, a Gradle project with NO source of its own.
# It just repackages what cargo-apk already builds:
#   1. cargo-apk compiles the Rust cdylib (libchain_notes_app.so) and wraps
#      it in a throwaway APK (whose manifest/resources we do NOT use — see
#      android/play/app/src/main/AndroidManifest.xml's own header for why).
#   2. This script extracts just the .so out of that APK into
#      android/play/app/src/main/jniLibs/arm64-v8a/ (gitignored — a build
#      product, not source).
#   3. ./gradlew bundleRelease packages that .so + the shared launcher-icon
#      resources + the hand-mirrored manifest into a signed .aab.
#
# Needs BOTH the existing cargo-apk signing env (CARGO_APK_RELEASE_KEYSTORE*
# — cargo-apk --release refuses to run without it, even though the keystore
# it names is irrelevant here: we only take the .so out of that APK) and the
# NEW Play upload-keystore env (ANDROID_UPLOAD_*, generated once by
# keytool — see android/play/app/build.gradle.kts's signingConfigs block for
# what each var means). Both live under prime/private/chain-notes-app/,
# never in this repo. Since this script may run from an ordinary checkout
# (prime/graffito/scripts/…) OR from a git worktree nested arbitrarily deep
# under prime/.claude/worktrees/…/scripts/…, it locates prime/private by
# walking UP from the repo root until it finds a `private/chain-notes-app`
# sibling, rather than assuming a fixed `../private` hop like the existing
# signing.env/appstore symlink convention can (those symlinks are also
# gitignored and per-checkout, so a fresh worktree never has them).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# --- locate prime/private/chain-notes-app by walking up from the repo root -
find_private_dir() {
    local d="$REPO"
    while [ "$d" != "/" ]; do
        if [ -d "$d/private/chain-notes-app" ]; then
            printf '%s\n' "$d/private/chain-notes-app"
            return 0
        fi
        d="$(dirname "$d")"
    done
    return 1
}
PRIVATE_DIR="$(find_private_dir)" || {
    echo "!! could not find a private/chain-notes-app/ directory above $REPO" >&2
    exit 1
}
echo "== private config: $PRIVATE_DIR"

# --- signing env: cargo-apk's (existing) + the Play upload keystore's (new) -
[ -f "$PRIVATE_DIR/signing.env" ] || {
    echo "!! missing $PRIVATE_DIR/signing.env" >&2
    exit 1
}
# shellcheck disable=SC1091
source "$PRIVATE_DIR/signing.env"
for v in CARGO_APK_RELEASE_KEYSTORE CARGO_APK_RELEASE_KEYSTORE_PASSWORD; do
    [ -n "${!v:-}" ] || { echo "!! $v is empty after sourcing signing.env" >&2; exit 1; }
done

[ -f "$PRIVATE_DIR/android-signing.env" ] || {
    echo "!! missing $PRIVATE_DIR/android-signing.env — generate the upload" >&2
    echo "   keystore first (keytool -genkeypair ... -alias upload, see" >&2
    echo "   android/play/app/build.gradle.kts's signingConfigs comment)." >&2
    exit 1
}
# shellcheck disable=SC1091
source "$PRIVATE_DIR/android-signing.env"
for v in ANDROID_UPLOAD_KEYSTORE ANDROID_UPLOAD_KEYSTORE_PASSWORD ANDROID_UPLOAD_KEY_ALIAS; do
    [ -n "${!v:-}" ] || { echo "!! $v is empty after sourcing android-signing.env" >&2; exit 1; }
done
[ -s "$ANDROID_UPLOAD_KEYSTORE" ] || {
    echo "!! ANDROID_UPLOAD_KEYSTORE points at a missing/empty file: $ANDROID_UPLOAD_KEYSTORE" >&2
    exit 1
}

# --- toolchain --------------------------------------------------------------
export PATH="$HOME/.cargo/bin:$PATH"   # standalone rustup, not nix
command -v cargo >/dev/null || { echo "!! cargo not found on PATH" >&2; exit 1; }
command -v cargo-apk >/dev/null || { echo "!! cargo-apk not installed (cargo install cargo-apk)" >&2; exit 1; }

ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ -z "${ANDROID_NDK_ROOT:-}" ]; then
    # Newest installed NDK, same discovery style as gen-biometric-dex.sh uses
    # for build-tools/platforms (sort -Vr, first match) rather than a
    # hardcoded version string.
    NDK_VER="$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -Vr | head -1)"
    [ -n "$NDK_VER" ] || { echo "!! no NDK found under $ANDROID_HOME/ndk" >&2; exit 1; }
    export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/$NDK_VER"
fi
[ -d "$ANDROID_NDK_ROOT" ] || { echo "!! ANDROID_NDK_ROOT does not exist: $ANDROID_NDK_ROOT" >&2; exit 1; }
echo "== ANDROID_NDK_ROOT: $ANDROID_NDK_ROOT"

export CARGO_TARGET_DIR="$REPO/target-mobile"

# --- 1. cargo-apk: compile the cdylib + wrap it in a throwaway APK ---------
echo "== cargo apk build --lib --target aarch64-linux-android --release"
cargo apk build --lib --target aarch64-linux-android --release

APK="$CARGO_TARGET_DIR/release/apk/chain-notes-app.apk"
[ -s "$APK" ] || { echo "!! expected APK not found: $APK" >&2; exit 1; }
echo "== cargo-apk output: $APK"

# --- 2. extract libchain_notes_app.so into the Gradle project's jniLibs ----
PLAY_DIR="$REPO/android/play"
JNI_DIR="$PLAY_DIR/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNI_DIR"
rm -f "$JNI_DIR/libchain_notes_app.so"

UNZIP_TMP="$(mktemp -d)"
trap 'rm -rf "$UNZIP_TMP"' EXIT
unzip -q -o "$APK" "lib/arm64-v8a/libchain_notes_app.so" -d "$UNZIP_TMP"
SO_SRC="$UNZIP_TMP/lib/arm64-v8a/libchain_notes_app.so"
[ -s "$SO_SRC" ] || { echo "!! lib/arm64-v8a/libchain_notes_app.so missing from the APK" >&2; exit 1; }
cp "$SO_SRC" "$JNI_DIR/libchain_notes_app.so"
echo "== staged: $JNI_DIR/libchain_notes_app.so ($(wc -c < "$JNI_DIR/libchain_notes_app.so") bytes)"

# --- 3. bundletool.jar (official Google GitHub releases only) --------------
TOOLS_DIR="$PLAY_DIR/tools"
mkdir -p "$TOOLS_DIR"
BUNDLETOOL_VERSION="1.18.3"
BUNDLETOOL_JAR="$TOOLS_DIR/bundletool-all-$BUNDLETOOL_VERSION.jar"
if [ ! -s "$BUNDLETOOL_JAR" ]; then
    echo "== downloading bundletool $BUNDLETOOL_VERSION"
    curl -fsSL -o "$BUNDLETOOL_JAR" \
        "https://github.com/google/bundletool/releases/download/$BUNDLETOOL_VERSION/bundletool-all-$BUNDLETOOL_VERSION.jar"
fi
echo "== bundletool: $BUNDLETOOL_JAR"

# --- 4. Gradle: package the .aab --------------------------------------------
cd "$PLAY_DIR"
echo "== ./gradlew bundleRelease"
./gradlew bundleRelease --console=plain

AAB="$PLAY_DIR/app/build/outputs/bundle/release/app-release.aab"
[ -s "$AAB" ] || { echo "!! expected AAB not found: $AAB" >&2; exit 1; }

echo
echo "== DONE"
echo "AAB:    $AAB"
echo "Size:   $(wc -c < "$AAB") bytes"
echo "SHA256: $(shasum -a 256 "$AAB" | awk '{print $1}')"
