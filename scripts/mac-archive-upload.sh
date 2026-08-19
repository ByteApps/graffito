#!/usr/bin/env bash
# Archive the Release macOS build and upload it to App Store Connect / Mac
# TestFlight. Sibling of ios-archive-upload.sh — same App Store Connect API key
# auth, same "Xcode session signs, key can't cloud-sign" model.
#
# The macOS target (graffito-mac, scheme graffito-mac) is
# App-Sandboxed (graffito-mac.entitlements) and signed for the Mac App Store
# (Apple Distribution + a Mac App Store provisioning profile, minted on demand by
# -allowProvisioningUpdates using the Xcode signed-in session).
#
# Prereqs (once): the app RECORD exists in App Store Connect as a Universal
# Purchase (iOS + macOS under com.byteapps.graffito — already created), and the
# paid account is added in Xcode > Settings > Accounts (for distribution signing).
#
# Usage (from the repo root):
#   source signing.env                 # DEVELOPMENT_TEAM
#   source appstore/config.local.env   # TEAM_ID / ASC_KEY_* / ASC_ISSUER_ID
#   scripts/mac-archive-upload.sh [--archive-only]
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

SCHEME=graffito-mac
PROJECT="$REPO/graffito.xcodeproj"
BUILD_DIR="$REPO/build/mac-release"
ARCHIVE="$BUILD_DIR/graffito-mac.xcarchive"
EXPORT_DIR="$BUILD_DIR/export"
EXPORT_OPTS="$BUILD_DIR/ExportOptions.plist"
LOG="$BUILD_DIR/archive.log"
UPLOG="$BUILD_DIR/upload.log"
mkdir -p "$BUILD_DIR"
rm -rf "$ARCHIVE" "$EXPORT_DIR"

# Signing uses the Xcode signed-in session by default (the paid account is added
# in Xcode > Settings > Accounts). The ASC API key can NOT do distribution
# cloud-signing (same gotcha as iOS), so it is NOT passed to xcodebuild unless
# you opt in with USE_ASC_KEY_SIGNING=1 (only works if the key has Admin).
AUTH=()
if [ "${USE_ASC_KEY_SIGNING:-0}" = "1" ]; then
  AUTH=( -authenticationKeyPath "$ASC_KEY_PATH"
         -authenticationKeyID "$ASC_KEY_ID"
         -authenticationKeyIssuerID "$ASC_ISSUER_ID" )
fi

echo "==> xcodegen generate (DEVELOPMENT_TEAM=$TEAM_ID)"
DEVELOPMENT_TEAM="$TEAM_ID" xcodegen generate --spec "$REPO/project.yml"

# Reuse the shared export template (method app-store-connect / destination upload /
# uploadSymbols / manageAppVersionAndBuildNumber) — identical for iOS and macOS.
sed "s/__TEAM_ID__/${TEAM_ID}/" "$REPO/scripts/ExportOptions.plist.template" > "$EXPORT_OPTS"

echo "==> xcodebuild archive (team $TEAM_ID, generic/platform=macOS)"
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath "$ARCHIVE" \
  -allowProvisioningUpdates \
  ${AUTH[@]+"${AUTH[@]}"} \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  archive 2>&1 | tee "$LOG"
grep -q "ARCHIVE SUCCEEDED" "$LOG" || { echo "ARCHIVE FAILED — see $LOG" >&2; exit 1; }

# File the archive (dSYM included) into Xcode's Organizer folder before the
# next run overwrites $ARCHIVE — same rationale as ios-archive-upload.sh:
# the local archive is the only symbolication source for old builds.
BUILD_NUM="$(/usr/libexec/PlistBuddy -c 'Print :ApplicationProperties:CFBundleVersion' "$ARCHIVE/Info.plist" 2>/dev/null || echo unknown)"
ORG_DIR="$HOME/Library/Developer/Xcode/Archives/$(date +%Y-%m-%d)"
ORG_ARCHIVE="$ORG_DIR/graffito macOS build $BUILD_NUM.xcarchive"
mkdir -p "$ORG_DIR"
rm -rf "$ORG_ARCHIVE"
cp -R "$ARCHIVE" "$ORG_ARCHIVE"
echo "==> archive filed for Organizer at $ORG_ARCHIVE"

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
  echo "   minutes, then lands in Mac TestFlight."
else
  echo
  echo "❌ Upload did not report success. Likely causes in the log:" >&2
  grep -iE "error|Invalid|Missing|No suitable|does not|90[0-9]{3}" "$UPLOG" | head -20 >&2 || true
  echo "   Full log: $UPLOG" >&2
  exit 1
fi
