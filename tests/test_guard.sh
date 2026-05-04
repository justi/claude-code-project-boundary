#!/bin/bash
# Test runner for guard.sh — runs all test suites
# Usage: bash tests/test_guard.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/helpers.sh"
source "$SCRIPT_DIR/test_bash_core.sh"
source "$SCRIPT_DIR/test_bash_advanced.sh"
source "$SCRIPT_DIR/test_file_guard.sh"
source "$SCRIPT_DIR/test_true_negatives.sh"
source "$SCRIPT_DIR/test_bypass_reproducers_core.sh"
source "$SCRIPT_DIR/test_bypass_reproducers_recent.sh"
source "$SCRIPT_DIR/test_bypass_reproducers_flags.sh"
source "$SCRIPT_DIR/test_allowlist.sh"
source "$SCRIPT_DIR/test_session_hint.sh"

print_summary
