#!/usr/bin/env bash
# Regenerate every platform icon asset from the master assets/icon/icon.svg
# (256x256, first inner element = the background <rect ... rx="58" fill="#…"/>).
#   - iOS:     Assets.xcassets/AppIcon.appiconset/AppIcon.png (1024, full-bleed,
#              opaque — iOS masks its own corners)
#   - macOS:   assets/icon/mac/AppIcon.icns (rounded master at 824px centered
#              on a 1024 transparent canvas, Big Sur margin convention)
#   - Android: assets/icon/android/res — adaptive fg/bg mipmaps (fg = glyph
#              in the 66% safe zone) + legacy rounded ic_launcher.png
# Rasterizer: headless Chrome (ImageMagick's own SVG renderer botches strokes).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
MASTER="$REPO/assets/icon/icon.svg"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

render() { # render <abs-svg> <size> <outpng>
  printf '<!doctype html><style>html,body{margin:0}img{display:block;width:%spx;height:%spx}</style><img src="%s">' \
    "$2" "$2" "$1" > "$WORK/wrap.html"
  "$CHROME" --headless=new --disable-gpu --screenshot="$3" \
    --window-size="$2,$2" --default-background-color=00000000 \
    --hide-scrollbars "file://$WORK/wrap.html" >/dev/null 2>&1
}

BG=$(grep -o 'rx="58" fill="#[0-9A-Fa-f]*"' "$MASTER" | grep -o '#[0-9A-Fa-f]*')
render "$MASTER" 1024 "$WORK/master-1024.png"

# iOS
sed 's/rx="58"/rx="0"/' "$MASTER" > "$WORK/ios.svg"
render "$WORK/ios.svg" 1024 "$WORK/ios-1024.png"
magick "$WORK/ios-1024.png" -alpha off \
  "$REPO/Assets.xcassets/AppIcon.appiconset/AppIcon.png"

# macOS
ICONSET="$WORK/AppIcon.iconset"; mkdir -p "$ICONSET"
render "$MASTER" 824 "$WORK/mac-824.png"
magick -size 1024x1024 xc:none "$WORK/mac-824.png" -gravity center -composite \
  "$ICONSET/icon_512x512@2x.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$ICONSET/icon_512x512@2x.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d "$ICONSET/icon_512x512@2x.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
mkdir -p "$REPO/assets/icon/mac"
iconutil -c icns "$ICONSET" -o "$REPO/assets/icon/mac/AppIcon.icns"

# Android (adaptive foreground = master minus bg rect, scaled into safe zone)
{ head -1 "$MASTER" | sed 's/viewBox="0 0 256 256"/viewBox="-64 -64 384 384"/'
  grep -v 'rx="58" fill=' "$MASTER" | tail -n +2; } > "$WORK/fg.svg"
render "$WORK/fg.svg" 1024 "$WORK/fg-1024.png"
RES="$REPO/assets/icon/android/res"
DPIS=(mdpi hdpi xhdpi xxhdpi xxxhdpi); LEG=(48 72 96 144 192); ADP=(108 162 216 324 432)
for i in 0 1 2 3 4; do
  d="${DPIS[$i]}"; mkdir -p "$RES/mipmap-$d"
  sips -z "${LEG[$i]}" "${LEG[$i]}" "$WORK/master-1024.png" --out "$RES/mipmap-$d/ic_launcher.png" >/dev/null
  sips -z "${ADP[$i]}" "${ADP[$i]}" "$WORK/fg-1024.png" --out "$RES/mipmap-$d/ic_launcher_foreground.png" >/dev/null
  magick -size "${ADP[$i]}x${ADP[$i]}" "xc:$BG" "$RES/mipmap-$d/ic_launcher_background.png"
done
mkdir -p "$RES/mipmap-anydpi-v26"
cat > "$RES/mipmap-anydpi-v26/ic_launcher.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/ic_launcher_background"/>
    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
XML
echo "regenerated icon assets from $MASTER"
