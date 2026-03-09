#!/bin/bash
# Comprehensive tests for guard.sh
# Usage: ./tests/test_guard.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="$SCRIPT_DIR/../hooks/guard.sh"

PASS=0
FAIL=0
TOTAL=0

# Create a temp directory to act as project root
TMPDIR_BASE=$(mktemp -d)
PROJECT="$TMPDIR_BASE/myproject"
mkdir -p "$PROJECT"

export CLAUDE_PROJECT_DIR="$PROJECT"

# --- Helpers ---

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

echo "========================================"
echo "  guard.sh test suite"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# 1. Always-blocked patterns
# ============================================================
echo "--- Always-blocked patterns ---"

expect_blocked "git push --force" \
  "git push --force origin main"

expect_blocked "git push -f (with space after)" \
  "git push -f origin main"

expect_blocked "git push -f (end of command)" \
  "git push origin main -f"

expect_blocked "git reset --hard" \
  "git reset --hard HEAD~1"

expect_blocked "git checkout ." \
  "git checkout ."

expect_blocked "git clean -f" \
  "git clean -fd"

expect_blocked "drop table (SQL)" \
  "echo 'DROP TABLE users;'"

expect_blocked "truncate table (SQL)" \
  "echo 'TRUNCATE TABLE users;'"

expect_blocked "rails db:drop" \
  "rails db:drop"

expect_blocked "rails db:reset" \
  "rails db:reset"

expect_blocked "rake db:drop" \
  "rake db:drop"

expect_blocked "rake db:reset" \
  "rake db:reset"

expect_blocked "mkfs" \
  "mkfs.ext4 /dev/sda1"

expect_blocked "dd if=" \
  "dd if=/dev/zero of=/dev/sda"

echo ""

# ============================================================
# 2. rm inside project (should PASS)
# ============================================================
echo "--- rm inside project ---"

expect_allowed "rm file inside project (relative)" \
  "rm somefile.txt"

expect_allowed "rm file inside project (absolute)" \
  "rm $PROJECT/somefile.txt"

expect_allowed "rm -rf inside project" \
  "rm -rf $PROJECT/tmp/cache"

echo ""

# ============================================================
# 3. rm outside project (should BLOCK)
# ============================================================
echo "--- rm outside project ---"

expect_blocked "rm /etc/hosts" \
  "rm /etc/hosts"

expect_blocked "rm -rf /tmp/something" \
  "rm -rf /tmp/something"

expect_blocked "rm project root itself" \
  "rm -rf $PROJECT"

echo ""

# ============================================================
# 4. rm with ~, $HOME, quoted paths (should BLOCK)
# ============================================================
echo "--- rm with tilde, HOME, and quoted paths ---"

expect_blocked "rm ~/somefile" \
  "rm ~/somefile"

expect_blocked 'rm $HOME/.ssh' \
  'rm $HOME/.ssh'

expect_blocked 'rm "${HOME}/.bashrc"' \
  'rm "${HOME}/.bashrc"'

expect_blocked 'rm with double-quoted absolute path' \
  'rm "/etc/passwd"'

echo ""

# ============================================================
# 5. mv with destination outside project (should BLOCK)
# ============================================================
echo "--- mv destination outside project ---"

expect_blocked "mv to /tmp" \
  "mv $PROJECT/file.txt /tmp/file.txt"

expect_blocked "mv to ~" \
  "mv $PROJECT/file.txt ~/file.txt"

echo ""

# ============================================================
# 6. mv with source outside project (should BLOCK)
# ============================================================
echo "--- mv source outside project ---"

expect_blocked "mv /etc/passwd into project" \
  "mv /etc/passwd $PROJECT/backup"

expect_blocked "mv ~/secret into project" \
  "mv ~/secret $PROJECT/stolen"

echo ""

# ============================================================
# 7. mv inside project (should PASS)
# ============================================================
echo "--- mv inside project ---"

expect_allowed "mv within project" \
  "mv $PROJECT/a.txt $PROJECT/b.txt"

expect_allowed "mv relative paths within project" \
  "mv old.txt new.txt"

echo ""

# ============================================================
# 8. Redirect > outside project (should BLOCK)
# ============================================================
echo "--- Redirect > outside project ---"

expect_blocked "echo > /etc/file" \
  "echo hello > /etc/file"

expect_blocked "echo > ~/file" \
  "echo hello > ~/file"

echo ""

# ============================================================
# 9. Redirect >> outside project (should BLOCK)
# ============================================================
echo "--- Redirect >> outside project ---"

expect_blocked "echo >> /etc/file" \
  "echo hello >> /etc/file"

expect_blocked "echo >> ~/file" \
  "echo hello >> ~/file"

echo ""

# ============================================================
# 10. Redirect inside project (should PASS)
# ============================================================
echo "--- Redirect inside project ---"

expect_allowed "echo > file inside project (absolute)" \
  "echo hello > $PROJECT/output.txt"

expect_allowed "echo >> file inside project (absolute)" \
  "echo hello >> $PROJECT/output.txt"

echo ""

# ============================================================
# 11. chmod/chown outside project (should BLOCK)
# ============================================================
echo "--- chmod/chown outside project ---"

expect_blocked "chmod on /etc/hosts" \
  "chmod 777 /etc/hosts"

expect_blocked "chown on /etc/hosts" \
  "chown root:root /etc/hosts"

expect_blocked "chmod on ~/file" \
  "chmod 644 ~/somefile"

echo ""

# ============================================================
# 12. chmod/chown inside project (should PASS)
# ============================================================
echo "--- chmod/chown inside project ---"

expect_allowed "chmod inside project" \
  "chmod 755 $PROJECT/script.sh"

expect_allowed "chown inside project" \
  "chown user:group $PROJECT/file.txt"

echo ""

# ============================================================
# 13. Safe commands (should always PASS)
# ============================================================
echo "--- Safe commands ---"

expect_allowed "ls" \
  "ls -la"

expect_allowed "git status" \
  "git status"

expect_allowed "git diff" \
  "git diff"

expect_allowed "git log" \
  "git log --oneline -10"

expect_allowed "cat a file" \
  "cat $PROJECT/README.md"

expect_allowed "echo without redirect" \
  "echo hello world"

expect_allowed "grep" \
  "grep -r 'pattern' $PROJECT/"

expect_allowed "git push (no force)" \
  "git push origin main"

echo ""

# ============================================================
# 14. Path prefix attack (should BLOCK)
# ============================================================
echo "--- Path prefix boundary ---"

expect_blocked "rm on path that is a prefix match but different dir" \
  "rm ${PROJECT}-elsewhere/file.txt"

expect_blocked "mv to prefix-match dir" \
  "mv $PROJECT/file.txt ${PROJECT}-other/file.txt"

echo ""

# ============================================================
# 15. Empty / no command (should PASS)
# ============================================================
echo "--- Empty / no command ---"

TOTAL=$((TOTAL + 1))
EMPTY_JSON='{"tool_input": {}}'
if echo "$EMPTY_JSON" | bash "$GUARD" 2>/dev/null; then
  echo "PASS: empty command passes"
  PASS=$((PASS + 1))
else
  echo "FAIL: empty command should pass"
  FAIL=$((FAIL + 1))
fi

echo ""

# ============================================================
# Cleanup and summary
# ============================================================
rm -rf "$TMPDIR_BASE"

echo "========================================"
echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL)"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
