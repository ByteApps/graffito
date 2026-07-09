#!/usr/bin/env bash
# Xcode post-compile step: build the Rust bin with the standalone cargo (into
# target-mobile/, separate from the Nix SDK's /target) and drop it where Xcode
# code-signs the .app. See PLAN-chain-notes-app-phase4.md (M8b).
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

cargo build $REL --bin "$NAME" --target "$TARGET" --manifest-path "$SRCROOT/Cargo.toml"
cp -f "$CARGO_TARGET_DIR/$TARGET/$PROFILE/$NAME" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
