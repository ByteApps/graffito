#!/usr/bin/env bash
# Regenerate every platform icon asset from the master assets/icon/icon.svg
# ("Graffito" mark: 1024x1024 viewBox, squircle clip-path id="squircle"
#  rect rx="230", background = <g clip-path="url(#squircle)"> wrapping a
#  radial-gradient "wall" rect + plaster-speckle/hairline-crack groups,
#  then the scratched-"g" mark group + the orange scratched-period group
#  on top).
#   - iOS:     Assets.xcassets/AppIcon.appiconset/AppIcon.png (1024, full-bleed,
#              square corners — iOS masks its own corners)
#   - macOS:   assets/icon/mac/AppIcon.icns (rounded master at 824px centered
#              on a 1024 transparent canvas, Big Sur margin convention) +
#              the same iconset PNGs copied into
#              Assets.xcassets/AppIcon-mac.appiconset (Xcode build target)
#   - Android: assets/icon/android/res — adaptive fg/bg mipmaps (fg = the
#              scratched-g + period group only, scaled into the 66% safe
#              zone on transparent; bg = a flat fill sampled as the mean
#              pixel color of the wall/speckle/crack layer, matching the
#              flat-adaptive-background convention this pipeline has always
#              used) + legacy rounded ic_launcher.png
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

render "$MASTER" 1024 "$WORK/master-1024.png"

# iOS — square corners, iOS applies its own mask
sed 's/rx="230"/rx="0"/' "$MASTER" > "$WORK/ios.svg"
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
# Keep the Xcode asset catalog (used by the actual Mac build target) in sync.
MACSET="$REPO/Assets.xcassets/AppIcon-mac.appiconset"
for f in icon_16x16.png icon_16x16@2x.png icon_32x32.png icon_32x32@2x.png \
         icon_128x128.png icon_128x128@2x.png icon_256x256.png icon_256x256@2x.png \
         icon_512x512.png icon_512x512@2x.png; do
  cp "$ICONSET/$f" "$MACSET/$f"
done

# Android — split the master into its natural background (wall + speckle +
# cracks) and foreground (the scratched-g + period) layers for the adaptive
# icon, un-clipped (the OS applies its own mask shape). Slicing is by the
# master's own marker comments, via python3 (portable across BSD/GNU sed
# differences) — update these markers if the master's structure changes.
python3 - "$MASTER" "$WORK/bg.svg" "$WORK/fg.svg" <<'PY'
import sys
master, bg_out, fg_out = sys.argv[1:4]
src = open(master).read()

def between(a, b=None):
    start = src.index(a)
    end = src.index(b) if b else len(src)
    return src[start:end]

gradient = between("<radialGradient", "</radialGradient>") + "</radialGradient>"
speckle = between("<!-- plaster speckle -->", "<!-- hairline cracks -->")
cracks = between("<!-- hairline cracks -->", "<!-- the scratched g -->")
scratched_g = between("<!-- the scratched g -->", "<!-- orange scratched period -->")
# between() stops right before the closing tag of the OUTER clip-path <g>,
# so it already includes the period group's own </g> — do not re-append one.
period = between("<!-- orange scratched period -->", "</g>\n</svg>")

bg = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">\n'
    '<defs>' + gradient + '</defs>\n'
    '<rect width="1024" height="1024" fill="url(#wall)"/>\n'
    + speckle + cracks +
    '</svg>\n'
)
open(bg_out, "w").write(bg)

fg = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-256 -256 1536 1536" width="1024" height="1024">\n'
    + scratched_g + period +
    '</svg>\n'
)
open(fg_out, "w").write(fg)
PY
render "$WORK/bg.svg" 1024 "$WORK/bg-1024.png"
BG=$(magick "$WORK/bg-1024.png" -resize 1x1 txt:- | tail -1 | sed -n 's/.*\(#[0-9A-Fa-f]\{6\}\).*/\1/p')

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
echo "regenerated icon assets from $MASTER (android adaptive bg sampled as $BG)"
