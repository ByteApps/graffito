#!/usr/bin/env bash
# Headless render of EVERY screen to <out-dir>/screen-<id>.png via the
# app's `--render` mode (software renderer, no window, `preview_mock`
# state). Deterministic — two runs are byte-identical — so a before/after
# `cmp` of the PNGs is the structural check for any UI refactor that
# claims to be pixel-preserving (PLAN-graffito-app-arch.md).
#
#   scripts/render-all.sh <out-dir> [screens]   (default: all 28)
#
# Compare two runs:  for f in A/*.png; do cmp -s "$f" "B/${f##*/}" || echo "DIFF ${f##*/}"; done
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
out="${1:?usage: render-all.sh <out-dir> [screens]}"
screens="${2:-0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,24,25,26,27,28,29}"
mkdir -p "$out"
cargo build --bin graffito --quiet
APP_DATA_DIR="$(mktemp -d)" ./target/debug/graffito --render "$out" "$screens"
ls "$out"/*.png | wc -l | xargs echo "rendered:"
