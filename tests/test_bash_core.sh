#!/bin/bash
# Core Bash guard tests — destructive command detection (rm/mv/cp/ln/
# tee/chmod/chown/dd/curl/wget/xargs/find), redirect handling, path
# boundary checks, safe commands, sudo/chained/multi-target coverage.
# Extended coverage (shells, command substitution, pipe-to-shell,
# option extractors, cwd-from-hook) lives in test_bash_advanced.sh.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bash guard tests (core)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# 1. rm inside project (should PASS)
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
# 15. Path traversal with .. (should BLOCK)
# ============================================================
echo "--- Path traversal with .. ---"

expect_blocked "rm with .. escaping project" \
  "rm $PROJECT/../../../etc/passwd"

expect_blocked "mv with .. escaping project" \
  "mv $PROJECT/file.txt $PROJECT/../../outside.txt"

expect_blocked "redirect with .. escaping project" \
  "echo data > $PROJECT/../../../etc/passwd"

expect_allowed ".. staying inside project" \
  "rm $PROJECT/subdir/../file.txt"

echo ""

# ============================================================
# 16. Quoted absolute paths (should BLOCK)
# ============================================================
echo "--- Quoted absolute paths ---"

expect_blocked 'rm with single-quoted absolute path' \
  "rm '/etc/passwd'"

expect_blocked 'mv with quoted destination outside' \
  "mv file.txt \"/tmp/stolen\""

expect_blocked 'chmod with quoted path outside' \
  "chmod 600 \"/etc/ssh/sshd_config\""

expect_blocked 'chown with quoted path outside' \
  "chown root:root '/etc/hosts'"

echo ""

# ============================================================
# 17. Redirect with $HOME and quoted paths (should BLOCK)
# ============================================================
echo "--- Redirect edge cases ---"

expect_blocked 'redirect > with $HOME' \
  'echo data > $HOME/.bashrc'

expect_blocked 'redirect >> with $HOME' \
  'echo data >> $HOME/.bashrc'

expect_blocked 'redirect > with quoted path' \
  'echo data > "/etc/passwd"'

expect_blocked 'redirect >> with quoted path' \
  'echo data >> "/etc/passwd"'

expect_allowed "redirect > relative path (inside project)" \
  "echo data > output.txt"

expect_allowed "redirect >> relative path (inside project)" \
  "echo data >> log.txt"

echo ""

# ============================================================
# 18. Commands that look dangerous but are safe
# ============================================================
echo "--- False positive avoidance ---"

expect_allowed "grep containing rm" \
  "grep -r 'rm -rf' $PROJECT/"

expect_allowed "echo containing rm" \
  "echo 'do not rm -rf anything'"

expect_allowed "variable named format" \
  "echo format_string=test"

expect_allowed "git push to specific remote (no force)" \
  "git push upstream feature-branch"

expect_allowed "npm run format" \
  "npm run format"

echo ""
