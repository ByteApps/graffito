#!/usr/bin/env bash
# Fail the build if a Mach-O binary references an Apple non-public API.
#
# Why this exists: macOS 1.0 build 31 was rejected on 2026-07-28 with
#
#   The app uses or references the following non-public or deprecated APIs:
#   • _CGSSetWindowBackgroundBlurRadius
#
# The symbol came from winit's macOS backend (dead code — slint never calls
# `Window::set_blur`), reached the binary purely as an undefined symbol, and
# nothing in the normal build surfaced it. Cargo.toml carries a `[patch.crates-io]`
# fork of winit that removes it; THIS script is what stops a slint/winit bump, a
# new dependency, or a dropped patch from quietly putting it back.
#
# Apple's static analysis works on the binary, so this does too — the checks are
# on what the linker actually emitted, not on source.
#
#   1. Undefined symbols (`nm -u`): what the binary imports from the system.
#      A private API can only be called through one of these.
#   2. Objective-C selector literals (`__TEXT,__objc_methname`): the other half
#      of Apple's scan — a private method invoked by name leaves no undefined
#      symbol, only a selector string.
#
# Usage: scripts/check-private-apis.sh <binary> [<binary>...]
# Exit 0 = clean, 1 = a match (build should fail), 2 = usage/tooling problem.
set -uo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <mach-o binary> [...]" >&2
  exit 2
fi

# Undefined symbols that are outright disqualifying. Extended-regex, anchored.
#
#  _CGS[A-Z]…  CoreGraphics Services / SkyLight — the private window-server
#              namespace `_CGSSetWindowBackgroundBlurRadius` lives in. Note
#              `_CGSession*` (e.g. CGSessionCopyCurrentDictionary) IS public and
#              is excluded below, which is why this is not a bare `_CGS` match.
#  _SLS[A-Z]…  SkyLight, the modern name for the same window-server SPI.
#  _LSApplicationWorkspace…  private LaunchServices, a perennial rejection.
DENY_SYMBOL='^_(CGS[A-Z]|SLS[A-Z]|LSApplicationWorkspace)'

# Selector literals that are disqualifying. Apple flags private methods by name;
# a leading underscore is the convention for them, but it is NOT sufficient on
# its own (Rust string data never lands in __objc_methname, yet some public
# frameworks do vend underscored selectors), so this stays an explicit list.
DENY_SELECTOR='^_(didDismissViewController:|setStatusBarStyle:|isSystemProcess|networkInterfaceName|volumeUIMode)$'

fail=0

for bin in "$@"; do
  if [ ! -f "$bin" ]; then
    echo "check-private-apis: no such binary: $bin" >&2
    exit 2
  fi
  if ! archs=$(lipo -archs "$bin" 2>/dev/null); then
    echo "check-private-apis: not a Mach-O binary: $bin" >&2
    exit 2
  fi

  for arch in $archs; do
    hits=$(nm -arch "$arch" -u "$bin" 2>/dev/null | grep -E "$DENY_SYMBOL")
    if [ -n "$hits" ]; then
      echo "!! non-public API referenced in $(basename "$bin") ($arch):" >&2
      echo "$hits" | sed 's/^/     /' >&2
      fail=1
    fi

    sels=$(otool -arch "$arch" -v -s __TEXT __objc_methname "$bin" 2>/dev/null \
            | sed -n 's/^[0-9a-f][0-9a-f]*[[:space:]][[:space:]]*//p' | grep -E "$DENY_SELECTOR")
    if [ -n "$sels" ]; then
      echo "!! private Objective-C selector in $(basename "$bin") ($arch):" >&2
      echo "$sels" | sed 's/^/     /' >&2
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'MSG'

   App Review rejects a binary that merely REFERENCES a non-public API, whether
   or not the code runs. Find the dependency that pulls the symbol in
   (`grep -rl <symbol> ~/.cargo/registry/src/`), then remove or patch it —
   Cargo.toml's `[patch.crates-io] winit` is the worked example.
MSG
  exit 1
fi

echo "check-private-apis: clean ($#)"
exit 0
