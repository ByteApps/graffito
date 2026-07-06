#!/usr/bin/env bash
# Wrap the release binary in a minimal .app bundle — required for macOS
# TCC to attribute the camera permission (NSCameraUsageDescription) to
# the app rather than the terminal. Output: target/Chain Notes.app
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
cargo build --release
APP="$REPO/target/Chain Notes.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp target/release/chain-notes-app "$APP/Contents/MacOS/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.objsal.chain-notes-app</string>
    <key>CFBundleName</key><string>Chain Notes</string>
    <key>CFBundleExecutable</key><string>chain-notes-app</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>NSCameraUsageDescription</key>
    <string>Chain Notes scans QR codes: key imports (SeedQR) and contact addresses.</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
codesign --force --deep --sign - "$APP" 2>/dev/null || true
echo "bundled: $APP  (open it with: open \"$APP\")"
