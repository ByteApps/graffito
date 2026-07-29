#!/usr/bin/env bash
# Xcode post-compile step: build the Rust bin with the standalone cargo (into
# target-mobile/, separate from the Nix SDK's /target) and drop it where Xcode
# code-signs the .app. See PLAN-chain-notes-app-phase4.md (M8b).
#
# Release builds also emit a **dSYM** for crash symbolication in App Store
# Connect: the Rust bin IS the app's main executable, so we build it WITH debug
# info, extract a .dSYM into Xcode's dSYM folder (so the archive carries it and
# exportArchive's uploadSymbols pushes it to ASC), then strip the in-app copy to
# keep the binary small. The debug-info + strip overrides are env-only, so
# Mac/Android --release builds (which read Cargo.toml's strip=true) are unchanged.
set -euxo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$SRCROOT/target-mobile"

NAME="$1"

if [ "${CONFIGURATION:-Debug}" = "Debug" ]; then
  PROFILE=debug; REL=""
else
  PROFILE=release; REL="--release"
fi

if [ "${LLVM_TARGET_TRIPLE_SUFFIX-}" = "-simulator" ]; then
  TARGET=aarch64-apple-ios-sim
else
  TARGET=aarch64-apple-ios
fi

if [ "$PROFILE" = release ]; then
  # Full debug info in release so a dSYM can be produced. Env overrides only —
  # Cargo.toml (and thus other platforms) keep strip=true / no debug.
  CARGO_PROFILE_RELEASE_DEBUG=2 CARGO_PROFILE_RELEASE_STRIP=false \
    cargo build $REL --bin "$NAME" --target "$TARGET" --manifest-path "$SRCROOT/Cargo.toml"
else
  cargo build $REL --bin "$NAME" --target "$TARGET" --manifest-path "$SRCROOT/Cargo.toml"
fi

BIN="$CARGO_TARGET_DIR/$TARGET/$PROFILE/$NAME"
cp -f "$BIN" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"

# Release: extract the dSYM (same UUID as the binary we just copied) into Xcode's
# dSYM folder so it rides in the archive, then strip debug info from the in-app
# binary. Skipped for the simulator/debug builds.
if [ "$PROFILE" = release ] && [ -n "${DWARF_DSYM_FOLDER_PATH:-}" ]; then
  mkdir -p "$DWARF_DSYM_FOLDER_PATH"
  DSYM="$DWARF_DSYM_FOLDER_PATH/${WRAPPER_NAME:-$NAME.app}.dSYM"
  dsymutil "$BIN" -o "$DSYM"
  strip -S "$TARGET_BUILD_DIR/$EXECUTABLE_PATH" || true
fi

# App Review rejects a binary that merely REFERENCES a non-public API — and it
# does so AFTER upload, costing a review cycle. Catch it here instead. Release
# only: this guards what ships, and a debug build links the same crates anyway.
if [ "$PROFILE" = release ]; then
  "$SRCROOT/scripts/check-private-apis.sh" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
fi
