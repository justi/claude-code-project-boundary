#!/bin/bash
# Test runner for guard.sh — runs all test suites
# Usage: bash tests/test_guard.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/helpers.sh"
source "$SCRIPT_DIR/test_bash_guard.sh"
source "$SCRIPT_DIR/test_file_guard.sh"
source "$SCRIPT_DIR/test_true_negatives.sh"

print_summary
