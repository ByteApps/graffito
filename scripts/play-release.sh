#!/usr/bin/env bash
# One-command Google Play release for Graffito.
#
#   scripts/play-release.sh              # build → upload → promote
#   scripts/play-release.sh --validate   # prove the pipeline, ship nothing
#
# Real mode:
#   1. scripts/build-play-bundle.sh   — signed .aab + native-debug-symbols.zip
#                                       + the play-release-stamp pairing proof
#   2. fastlane android beta          — aab + symbols + listing + changelog in
#                                       ONE Play edit, to the internal track
#   3. fastlane android promote       — internal → alpha (same release object,
#                                       symbols and notes ride along)
#
# The symbols MUST ship in the same edit as the .aab: the Play API refuses to
# attach them to a committed bundle (400 FAILED_PRECONDITION). versionCode 3
# (2026-08-19) shipped symbol-less that way and needed a manual console
# upload — this script exists so that never recurs.
#
# --validate mode builds a PROBE bundle with an unused version code (current
# committed code + 1, overridable via PLAY_PROBE_VERSION_CODE) and runs the
# upload lane with SUPPLY_VALIDATE_ONLY=1: Google validates the full edit —
# aab, symbols, track, listing — then the edit is DISCARDED. Nothing ships,
# no version code is consumed, testers see nothing. Run it after touching any
# part of this pipeline.
#
# Before a real release: bump versionCode + versionName in
# android/play/app/build.gradle.kts and add
# fastlane/metadata/android/en-US/changelogs/<versionCode>.txt.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

MODE=release
[ "${1:-}" = "--validate" ] && MODE=validate

# --- locate prime/private/graffito (same walk-up as build-play-bundle.sh) --
find_private_dir() {
    local d="$REPO"
    while [ "$d" != "/" ]; do
        if [ -d "$d/private/graffito" ]; then
            printf '%s\n' "$d/private/graffito"
            return 0
        fi
        d="$(dirname "$d")"
    done
    return 1
}
PRIVATE_DIR="$(find_private_dir)" || {
    echo "!! could not find a private/graffito/ directory above $REPO" >&2
    exit 1
}

export SUPPLY_JSON_KEY="${SUPPLY_JSON_KEY:-$PRIVATE_DIR/play/play-supply-key.json}"
[ -s "$SUPPLY_JSON_KEY" ] || {
    echo "!! Play service-account key missing: $SUPPLY_JSON_KEY" >&2
    exit 1
}
command -v fastlane >/dev/null || { echo "!! fastlane not on PATH" >&2; exit 1; }

GRADLE_KTS="$REPO/android/play/app/build.gradle.kts"
CURRENT_CODE="$(sed -n 's/.*?: \([0-9][0-9]*\)$/\1/p' "$GRADLE_KTS" | head -1)"
[ -n "$CURRENT_CODE" ] || {
    echo "!! could not parse the default versionCode out of $GRADLE_KTS" >&2
    exit 1
}

if [ "$MODE" = "validate" ]; then
    PROBE="${PLAY_PROBE_VERSION_CODE:-$((CURRENT_CODE + 1))}"
    echo "== VALIDATE mode: probe versionCode $PROBE (committed default: $CURRENT_CODE)"
    PLAY_VERSION_CODE="$PROBE" scripts/build-play-bundle.sh
    # The probe code has no changelogs/<code>.txt — that is fine, supply
    # falls back to default.txt for the validation pass.
    SUPPLY_TRACK=internal SUPPLY_VALIDATE_ONLY=1 fastlane android beta
    echo
    echo "== VALIDATED — edit discarded, nothing shipped, versionCode $PROBE not consumed."
    exit 0
fi

CHANGELOG="$REPO/fastlane/metadata/android/en-US/changelogs/$CURRENT_CODE.txt"
[ -s "$CHANGELOG" ] || {
    echo "!! missing $CHANGELOG — write the release notes for versionCode" >&2
    echo "   $CURRENT_CODE before shipping (default.txt is only a fallback)." >&2
    exit 1
}

echo "== RELEASE mode: versionCode $CURRENT_CODE"
scripts/build-play-bundle.sh

# The Play API sometimes kills a fresh edit mid-upload ("This edit has
# expired, please create a new Edit" — hit live on v4's first attempt,
# seconds after the edit was created). A failed run is clean (supply commits
# only at the end), so retry once. And if the version code is already on
# Play, a previous run's commit went through — since supply uploads the
# symbols BEFORE committing, that committed edit always carries them, so
# skipping straight to promote is sound.
BETA_LOG="$(mktemp)"
beta_ok=0
for attempt in 1 2; do
    if SUPPLY_TRACK=internal fastlane android beta 2>&1 | tee "$BETA_LOG"; then
        beta_ok=1
        break
    fi
    if grep -q "has already been used" "$BETA_LOG"; then
        echo "== versionCode $CURRENT_CODE already committed on Play — continuing to promote"
        beta_ok=1
        break
    fi
    if grep -q "edit has expired" "$BETA_LOG" && [ "$attempt" = 1 ]; then
        echo "== transient 'edit has expired' from the Play API — retrying the upload once"
        continue
    fi
    break
done
[ "$beta_ok" = 1 ] || { echo "!! upload failed — see the log above" >&2; exit 1; }

SUPPLY_VERSION_CODE="$CURRENT_CODE" fastlane android promote
echo
echo "== SHIPPED — versionCode $CURRENT_CODE on internal + alpha, symbols attached."
