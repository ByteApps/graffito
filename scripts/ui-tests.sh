#!/usr/bin/env bash
# In-process Slint UI HARNESS tests for graffito — headless, deterministic,
# NO simulator/window/screen control. The flake-free replacement for the
# coordinate simtap suites (see the slint-ui-testing memory).
#
#   scripts/ui-tests.sh
#
# Runs the ELEMENT-TREE tests, which need Slint introspection compiled in
# (SLINT_EMIT_DEBUG_INFO=1, build.rs — production binaries stay lean):
#   - tests/ui_harness_spike.rs   findability (screen 29 + compose Security
#                                 panel) via find_by_accessible_label
#   - tests/ui_harness_click.rs   single_click reaching a handler
#
# The in-process FLOW tests (src/lib.rs ui_flow_quantum_key::* — real
# quantum-key generate/import) do NOT need introspection and run under a plain
# `cargo test -p graffito --lib`, so they're deliberately NOT here: mixing the
# two build configs in one target dir thrashes the relink, and a separate
# target dir duplicates the whole (multi-GB) build. Keep them apart.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export SLINT_EMIT_DEBUG_INFO=1
cd "$(dirname "$0")/.."
cargo test --test ui_harness_spike --test ui_harness_click
echo "IN-PROCESS UI HARNESS TESTS PASSED  (flow tests: cargo test --lib ui_flow_quantum_key)"
