#!/usr/bin/env bash
# Publish companion/ (the canonical source — its tests live next to it)
# into this repo's Pages tree, docs/companion/, served at
# https://byteapps.com/graffito/companion/.
#
# The source moved here from ByteApps/prime-graffito on 2026-09-02 when the
# Prime app was shelved; before that this script lived there and synced
# across repos. Never edit docs/companion directly — edit companion/ and
# run this. The old chain-notes-companion deploy-mirror repo is archived
# and serves only redirects.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/companion"
DEST="$HERE/docs/companion"

mkdir -p "$DEST"
cp "$SRC/index.html" "$SRC/viewer.html" "$SRC/note.html" \
   "$SRC/chain-scan.js" "$SRC/owner-probe.js" "$SRC/server.py" \
   "$SRC/jsqr.js" "$SRC/qrcode-gen.js" "$SRC/ur.js" "$DEST/"
cd "$HERE"
if [ -z "$(git status --porcelain docs/companion)" ]; then
    echo "docs/companion already up to date"
    exit 0
fi
if [ "${1:-}" = "--no-commit" ]; then
    echo "docs/companion updated (not committed)"
    exit 0
fi
git add docs/companion
git commit -S -m "Publish companion ($(git rev-parse --short HEAD))"
git push
echo "published — https://byteapps.com/graffito/companion/"
