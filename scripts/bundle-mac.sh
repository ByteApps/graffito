#!/usr/bin/env bash
# Wrap the release binary in a minimal .app bundle — required for macOS
# TCC to attribute the camera permission (NSCameraUsageDescription) to
# the app rather than the terminal. Output: target/Graffito.app
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
cargo build --release
APP="$REPO/target/Graffito.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/chain-notes-app "$APP/Contents/MacOS/"
cp assets/icon/mac/AppIcon.icns "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.objsal.chainnotes</string>
    <key>CFBundleName</key><string>Graffito</string>
    <key>CFBundleExecutable</key><string>chain-notes-app</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>NSCameraUsageDescription</key>
    <string>Graffito scans QR codes: key imports (SeedQR) and contact addresses.</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
codesign --force --deep --sign - "$APP" 2>/dev/null || true
echo "bundled: $APP  (open it with: open \"$APP\")"
