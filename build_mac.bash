#!/usr/bin/env bash
# Xcode post-compile step for the macOS target: build the Rust bin with the
# standalone cargo (into target-macapp/, separate from the dev /target) and drop
# it where Xcode code-signs the .app. Sibling of build_ios.bash (M8b / Mac App
# Store). See PLAN-chain-notes-app.md.
#
# Universal by $ARCHS: Xcode archives a Mac app for `arm64 x86_64`, so each
# requested arch is built and lipo'd into one fat binary. A Debug/run build with
# ONLY_ACTIVE_ARCH=YES asks for just arm64 (fast path).
#
# Release also emits a **dSYM** for App Store Connect crash symbolication: the
# Rust bin IS the app's main executable, so it's built WITH debug info, a .dSYM
# is extracted into Xcode's dSYM folder (so the archive carries it and
# exportArchive's uploadSymbols pushes it), then the in-app copy is stripped.
# Debug-info + strip overrides are env-only, so Cargo.toml's release strip=true
# (and thus iOS/Android/dev builds) is unchanged.
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$SRCROOT/target-macapp"

NAME="$1"

if [ "${CONFIGURATION:-Debug}" = "Debug" ]; then
  PROFILE=debug; REL=""
else
  PROFILE=release; REL="--release"
fi

# Map Xcode's $ARCHS (space-separated) to rust triples. Fall back to the host's
# arm64 when ARCHS is unset (a plain `bash build_mac.bash` outside Xcode).
ARCHS="${ARCHS:-arm64}"
TRIPLES=()
for a in $ARCHS; do
  case "$a" in
    arm64)  TRIPLES+=(aarch64-apple-darwin) ;;
    x86_64) TRIPLES+=(x86_64-apple-darwin) ;;
    *) echo "!! unknown arch '$a'" >&2; exit 1 ;;
  esac
done

BINS=()
for T in "${TRIPLES[@]}"; do
  if [ "$PROFILE" = release ]; then
    # Full debug info in release so a dSYM can be produced. Env overrides only —
    # Cargo.toml (and thus other platforms) keep strip=true / no debug.
    CARGO_PROFILE_RELEASE_DEBUG=2 CARGO_PROFILE_RELEASE_STRIP=false \
      cargo build $REL --bin "$NAME" --target "$T" --manifest-path "$SRCROOT/Cargo.toml"
  else
    cargo build $REL --bin "$NAME" --target "$T" --manifest-path "$SRCROOT/Cargo.toml"
  fi
  BINS+=("$CARGO_TARGET_DIR/$T/$PROFILE/$NAME")
done

# One arch → copy; multiple → lipo into a fat binary.
FAT="$CARGO_TARGET_DIR/$NAME-lipo"
if [ "${#BINS[@]}" -eq 1 ]; then
  cp -f "${BINS[0]}" "$FAT"
else
  lipo -create "${BINS[@]}" -output "$FAT"
fi
cp -f "$FAT" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"

# Release: extract the dSYM (same UUID(s) as the fat binary) into Xcode's dSYM
# folder so it rides in the archive, then strip debug info from the in-app copy.
if [ "$PROFILE" = release ] && [ -n "${DWARF_DSYM_FOLDER_PATH:-}" ]; then
  mkdir -p "$DWARF_DSYM_FOLDER_PATH"
  DSYM="$DWARF_DSYM_FOLDER_PATH/${WRAPPER_NAME:-$NAME.app}.dSYM"
  dsymutil "$FAT" -o "$DSYM"
  strip -S "$TARGET_BUILD_DIR/$EXECUTABLE_PATH" || true
fi
