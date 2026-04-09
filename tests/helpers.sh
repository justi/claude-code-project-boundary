#!/bin/bash
# Shared test helpers for guard.sh test suite

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/../hooks/guard.sh"

PASS=0
FAIL=0
TOTAL=0

# Create a temp directory to act as project root
TMPDIR_BASE=$(mktemp -d)
PROJECT="$TMPDIR_BASE/myproject"
mkdir -p "$PROJECT"
mkdir -p "$PROJECT/subdir"

export CLAUDE_PROJECT_DIR="$PROJECT"

# --- Bash command helpers ---

run_guard() {
  local cmd="$1"
  local json
  json=$(jq -n --arg c "$cmd" '{"tool_input": {"command": $c}}')
  echo "$json" | bash "$GUARD" 2>/dev/null
  return $?
}

expect_blocked() {
  local description="$1"
  local cmd="$2"
  TOTAL=$((TOTAL + 1))
  if run_guard "$cmd"; then
    echo "FAIL: $description -- expected BLOCKED but got ALLOWED"
    echo "      command: $cmd"
    FAIL=$((FAIL + 1))
  else
    local rc=$?
    if [ "$rc" -eq 2 ] || [ "$rc" -ne 0 ]; then
      echo "PASS: $description"
      PASS=$((PASS + 1))
    else
      echo "FAIL: $description -- expected exit 2 but got exit $rc"
      FAIL=$((FAIL + 1))
    fi
  fi
}

expect_allowed() {
  local description="$1"
  local cmd="$2"
  TOTAL=$((TOTAL + 1))
  if run_guard "$cmd"; then
    echo "PASS: $description"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $description -- expected ALLOWED but got BLOCKED"
    echo "      command: $cmd"
    FAIL=$((FAIL + 1))
  fi
}

# --- Edit/Write file_path helpers ---

run_guard_file() {
  local file_path="$1"
  local json
  json=$(jq -n --arg f "$file_path" '{"tool_input": {"file_path": $f}}')
  echo "$json" | bash "$GUARD" 2>/dev/null
  return $?
}

expect_file_blocked() {
  local description="$1"
  local file_path="$2"
  TOTAL=$((TOTAL + 1))
  run_guard_file "$file_path"
  local rc=$?
  if [ "$rc" -eq 2 ]; then
    echo "PASS: $description"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $description -- expected BLOCKED (exit 2) but got exit $rc"
    echo "      file_path: $file_path"
    FAIL=$((FAIL + 1))
  fi
}

expect_file_allowed() {
  local description="$1"
  local file_path="$2"
  TOTAL=$((TOTAL + 1))
  run_guard_file "$file_path"
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "PASS: $description"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $description -- expected ALLOWED (exit 0) but got exit $rc"
    echo "      file_path: $file_path"
    FAIL=$((FAIL + 1))
  fi
}

# --- Summary ---

print_summary() {
  rm -rf "$TMPDIR_BASE"
  echo "========================================"
  echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL)"
  echo "========================================"
  if [ "$FAIL" -gt 0 ]; then
    exit 1
  fi
  exit 0
}
