#!/usr/bin/env bash
# Archive the Release iOS build and upload it to App Store Connect / TestFlight.
#
# Auth is the App Store Connect API key (.p8) — no Apple ID / 2FA needed here.
# Automatic signing with -allowProvisioningUpdates mints the Apple Distribution
# cert + App Store provisioning profile on demand (using that same key), so a
# fresh machine needs nothing pre-installed beyond the key + GPG to decrypt it.
#
# Prereqs (once): the app RECORD must exist in App Store Connect
#   (fastlane ios create_app), and the Bundle ID must be registered
#   (fastlane ios ensure_bundle_id — already done for com.objsal.chainnotes).
#
# Usage (from the repo root):
#   source signing.env                 # DEVELOPMENT_TEAM
#   source appstore/config.local.env   # TEAM_ID / ASC_KEY_* / ASC_ISSUER_ID
#   scripts/ios-archive-upload.sh [--archive-only]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# --- config: prefer already-exported env, else source the local files -------
[ -n "${DEVELOPMENT_TEAM:-}" ] || { [ -f signing.env ] && source signing.env; }
[ -n "${ASC_KEY_ID:-}" ] || { [ -f appstore/config.local.env ] && source appstore/config.local.env; }
: "${TEAM_ID:=${DEVELOPMENT_TEAM:-}}"
export PATH="$HOME/.cargo/bin:$PATH"   # standalone rustup builds the Rust bin

for v in TEAM_ID ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_PATH; do
  [ -n "${!v:-}" ] || { echo "!! $v is empty — source signing.env + appstore/config.local.env" >&2; exit 1; }
done
[ -s "$ASC_KEY_PATH" ] || { echo "!! ASC key missing at $ASC_KEY_PATH — run appstore/install.sh" >&2; exit 1; }

SCHEME=chain-notes-app
PROJECT="$REPO/chain-notes-app.xcodeproj"
BUILD_DIR="$REPO/build/ios-release"
ARCHIVE="$BUILD_DIR/chain-notes-app.xcarchive"
EXPORT_DIR="$BUILD_DIR/export"
EXPORT_OPTS="$BUILD_DIR/ExportOptions.plist"
LOG="$BUILD_DIR/archive.log"
UPLOG="$BUILD_DIR/upload.log"
mkdir -p "$BUILD_DIR"
rm -rf "$ARCHIVE" "$EXPORT_DIR"

# Signing uses the Xcode signed-in session by default (the paid account is added
# in Xcode > Settings > Accounts). The ASC API key can create DEVELOPMENT
# profiles but NOT distribution cloud-signing (it fails with "Cloud signing
# permission error"), so it is NOT passed to xcodebuild unless you opt in with
# USE_ASC_KEY_SIGNING=1 (only works if the key has the Admin role).
AUTH=()
if [ "${USE_ASC_KEY_SIGNING:-0}" = "1" ]; then
  AUTH=( -authenticationKeyPath "$ASC_KEY_PATH"
         -authenticationKeyID "$ASC_KEY_ID"
         -authenticationKeyIssuerID "$ASC_ISSUER_ID" )
fi

echo "==> xcodegen generate (DEVELOPMENT_TEAM=$TEAM_ID)"
DEVELOPMENT_TEAM="$TEAM_ID" xcodegen generate --spec "$REPO/project.yml"

sed "s/__TEAM_ID__/${TEAM_ID}/" "$REPO/scripts/ExportOptions.plist.template" > "$EXPORT_OPTS"

archive() {
  echo "==> xcodebuild archive (team $TEAM_ID)"
  xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE" \
    -allowProvisioningUpdates \
    ${AUTH[@]+"${AUTH[@]}"} \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    archive 2>&1 | tee "$LOG"
  grep -q "ARCHIVE SUCCEEDED" "$LOG"
}

if ! archive; then
  if grep -q "missing Metal Toolchain" "$LOG"; then
    echo "==> Metal Toolchain missing; downloading and retrying once"
    xcodebuild -downloadComponent MetalToolchain || true
    rm -rf "$ARCHIVE"; archive
  else
    echo "ARCHIVE FAILED — see $LOG" >&2; exit 1
  fi
fi

# Stash this build's dSYM under build/dsyms/ios-<build> BEFORE anything can
# overwrite the archive — TestFlight crash feedback does NOT retain log
# payloads server-side and the ASC key can't re-download dSYMs (403), so a
# local copy is the only way to symbolicate an old build's device .ips
# later (learned inspecting the build-9 crashes, 2026-07-19).
BUILD_NUM="$(/usr/libexec/PlistBuddy -c 'Print :ApplicationProperties:CFBundleVersion' "$ARCHIVE/Info.plist" 2>/dev/null || echo unknown)"
DSYM_KEEP="$REPO/build/dsyms/ios-$BUILD_NUM"
rm -rf "$DSYM_KEEP"; mkdir -p "$DSYM_KEEP"
cp -R "$ARCHIVE/dSYMs/." "$DSYM_KEEP/"
echo "==> dSYM stashed at $DSYM_KEEP"

if [ "${1:-}" = "--archive-only" ]; then
  echo "✅ Archived at $ARCHIVE (upload skipped: --archive-only)"; exit 0
fi

echo "==> xcodebuild -exportArchive (destination=upload)"
xcodebuild -exportArchive \
  -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$EXPORT_OPTS" \
  -exportPath "$EXPORT_DIR" \
  -allowProvisioningUpdates \
  ${AUTH[@]+"${AUTH[@]}"} 2>&1 | tee "$UPLOG" || true

if grep -q "EXPORT SUCCEEDED" "$UPLOG" && grep -qi "Upload succeeded\|uploaded successfully" "$UPLOG"; then
  echo
  echo "✅ Uploaded to App Store Connect. It shows as 'Processing' for a few"
  echo "   minutes, then lands in TestFlight."
else
  echo
  echo "❌ Upload did not report success. Likely causes in the log:" >&2
  grep -iE "error|Invalid|Missing|No suitable|does not|90[0-9]{3}" "$UPLOG" | head -20 >&2 || true
  echo "   Full log: $UPLOG" >&2
  exit 1
fi
