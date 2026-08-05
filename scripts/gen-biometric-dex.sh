#!/usr/bin/env bash
# Compile android/biometric/*.java into assets/android/biometric.dex.
#
# WHY THIS EXISTS: BiometricPrompt.AuthenticationCallback is an abstract class,
# so JNI cannot define it and reflect.Proxy cannot implement it — the callback
# has to be a real compiled class. cargo-apk has no Java compilation step, but
# it does not need one: the dex is loaded at RUNTIME with
# InMemoryDexClassLoader (API 26 = this app's min_sdk), so it ships as a plain
# asset. That is what keeps Gradle out of this build.
#
# Run before `cargo apk build` when the Java changes. Mirrors
# gen-icon-assets.sh: a generated artifact, committed, not built on every run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"

# Newest build-tools that actually contains d8.
BT=""
for c in $(ls -1 "$ANDROID_HOME/build-tools" 2>/dev/null | sort -Vr); do
    [ -x "$ANDROID_HOME/build-tools/$c/d8" ] && { BT="$ANDROID_HOME/build-tools/$c"; break; }
done
[ -n "$BT" ] || { echo "no build-tools with d8 under $ANDROID_HOME/build-tools" >&2; exit 1; }

# Compile against the newest installed platform; the class only touches APIs
# that exist from 28, and the runtime loader is version-gated by the caller.
JAR=""
for c in $(ls -1 "$ANDROID_HOME/platforms" 2>/dev/null | sort -Vr); do
    [ -f "$ANDROID_HOME/platforms/$c/android.jar" ] && { JAR="$ANDROID_HOME/platforms/$c/android.jar"; break; }
done
[ -n "$JAR" ] || { echo "no android.jar under $ANDROID_HOME/platforms" >&2; exit 1; }

OUT="$HERE/assets/android"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

echo "javac  -> $TMP  (against $(basename "$(dirname "$JAR")"))"
# NOT piped through grep: a pipeline's exit status is the LAST command's, so
# `javac ... | grep ... || true` swallowed a compile error and let d8 run on an
# empty directory — the script then failed confusingly at `mv`. set -e only
# helps if the failing command is the one whose status is checked.
if ! javac -source 8 -target 8 -bootclasspath "$JAR" -classpath "$JAR" \
        -d "$TMP" "$HERE"/android/biometric/*.java 2>"$TMP/javac.err"; then
    grep -v "^warning:\|^Note:" "$TMP/javac.err" >&2 || true
    echo "javac failed — not producing a dex" >&2
    exit 1
fi

echo "d8     -> $OUT/biometric.dex"
"$BT/d8" --min-api 26 --output "$TMP" $(find "$TMP" -name "*.class") >/dev/null
mv "$TMP/classes.dex" "$OUT/biometric.dex"
echo "done: $(wc -c < "$OUT/biometric.dex") bytes"
