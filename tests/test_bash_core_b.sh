#!/bin/bash
# bash core suite (part B).
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  bash core (part B)"
echo "========================================"
echo ""


# ============================================================
# 19. Multiple targets in one command
# ============================================================
echo "--- Multiple targets ---"

expect_blocked "rm with mixed inside and outside targets" \
  "rm $PROJECT/safe.txt /etc/passwd"

expect_allowed "rm multiple files inside project" \
  "rm $PROJECT/a.txt $PROJECT/b.txt $PROJECT/c.txt"

echo ""

# ============================================================
# 20. chmod/chown with $HOME and ~ (should BLOCK)
# ============================================================
echo "--- chmod/chown with tilde and HOME ---"

expect_blocked 'chown on ~/file' \
  "chown user:group ~/somefile"

expect_blocked 'chmod on $HOME/.ssh' \
  'chmod 700 $HOME/.ssh'

expect_blocked 'chown on ${HOME}/.config' \
  'chown user:group ${HOME}/.config'

echo ""

# ============================================================
# 21. Empty / no command (should PASS)
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
# 22. cp tests
# ============================================================
echo "--- cp tests ---"

expect_allowed "cp inside project" \
  "cp $PROJECT/a.txt $PROJECT/b.txt"

expect_blocked "cp source outside project" \
  "cp /etc/passwd $PROJECT/stolen.txt"

expect_blocked "cp destination outside project" \
  "cp $PROJECT/file.txt /tmp/file.txt"

expect_allowed "cp -r inside project" \
  "cp -r $PROJECT/subdir $PROJECT/subdir_copy"

expect_blocked "cp ~/file into project" \
  "cp ~/file $PROJECT/file.txt"

echo ""

# ============================================================
# 23. ln tests
# ============================================================
echo "--- ln tests ---"

expect_allowed "ln -s inside project" \
  "ln -s $PROJECT/a.txt $PROJECT/b.txt"

expect_blocked "ln -s target outside project" \
  "ln -s $PROJECT/a.txt /tmp/link"

expect_blocked "ln -s source outside project" \
  "ln -s /etc/passwd $PROJECT/link"

echo ""

# ============================================================
# 24. tee tests
# ============================================================
echo "--- tee tests ---"

expect_allowed "tee inside project" \
  "tee $PROJECT/output.txt"

expect_blocked "echo | tee /etc/file" \
  "echo hello | tee /etc/file"

expect_blocked "echo | tee ~/file" \
  "echo hello | tee ~/file"

expect_blocked "echo | tee -a /etc/file" \
  "echo hello | tee -a /etc/file"

echo ""

# ============================================================
# 25. Chained commands
# ============================================================
echo "--- Chained commands ---"

expect_blocked "ls && rm /etc/passwd" \
  "ls && rm /etc/passwd"

expect_blocked "ls; rm /etc/passwd" \
  "ls; rm /etc/passwd"

expect_blocked "ls || rm /etc/passwd" \
  "ls || rm /etc/passwd"

expect_blocked "echo hello | tee /etc/file" \
  "echo hello | tee /etc/file"

expect_allowed "ls && ls" \
  "ls && ls"

expect_allowed "echo hello; echo world" \
  "echo hello; echo world"

echo ""

# ============================================================
# 26. sudo prefix
# ============================================================
echo "--- sudo prefix ---"

expect_blocked "sudo rm /etc/passwd" \
  "sudo rm /etc/passwd"

expect_blocked "sudo chmod 777 /etc/hosts" \
  "sudo chmod 777 /etc/hosts"

echo ""

# ============================================================
# 27. xargs with dangerous commands
# ============================================================
echo "--- xargs with dangerous commands ---"

expect_blocked "echo file | xargs rm" \
  "echo file | xargs rm"

expect_blocked "find . | xargs chmod 777" \
  "find . | xargs chmod 777"

expect_allowed "echo hello | xargs echo (safe command)" \
  "echo hello | xargs echo"

echo ""

# ============================================================
# 28. find with -delete and -exec rm/mv
# ============================================================
echo "--- find -delete and -exec rm/mv ---"

expect_blocked "find /tmp -delete" \
  "find /tmp -delete"

expect_blocked "find /tmp -exec rm {} ;" \
  "find /tmp -exec rm {} ;"

expect_allowed "find inside project -delete" \
  "find $PROJECT -name '*.log' -delete"

expect_allowed "find inside project -exec rm" \
  "find $PROJECT -name '*.tmp' -exec rm {} ;"

echo ""

# ============================================================
# 29. curl/wget output file tests
# ============================================================
echo "--- curl/wget output file ---"

expect_blocked "curl -o /etc/file" \
  "curl -o /etc/file http://example.com"

expect_allowed "curl -o inside project" \
  "curl -o $PROJECT/file.txt http://example.com"

expect_blocked "wget -O /etc/file" \
  "wget -O /etc/file http://example.com"

expect_allowed "wget -O inside project" \
  "wget -O $PROJECT/file.txt http://example.com"

expect_blocked "curl --output ~/file" \
  "curl --output ~/file http://example.com"

echo ""

# ============================================================
# 30. Spaces in paths (quoted — properly supported)
# ============================================================
echo "--- Spaces in quoted paths ---"

# Set up a project directory with spaces in its path
SPACE_PROJECT="$TMPDIR_BASE/my project/sub dir"
mkdir -p "$SPACE_PROJECT"
SAVED_PROJECT_DIR="$CLAUDE_PROJECT_DIR"
export CLAUDE_PROJECT_DIR="$SPACE_PROJECT"

# Double-quoted paths with spaces — all major commands
expect_allowed "rm with spaces in project path (double quotes)" \
  "rm \"$SPACE_PROJECT/file.txt\""

expect_allowed "mv with spaces in project path (double quotes)" \
  "mv \"$SPACE_PROJECT/a.txt\" \"$SPACE_PROJECT/b.txt\""

expect_allowed "cp with spaces in project path (double quotes)" \
  "cp \"$SPACE_PROJECT/a.txt\" \"$SPACE_PROJECT/b.txt\""

expect_allowed "ln with spaces in project path (double quotes)" \
  "ln -s \"$SPACE_PROJECT/a.txt\" \"$SPACE_PROJECT/b.txt\""

expect_allowed "tee with spaces in project path (double quotes)" \
  "echo hi | tee \"$SPACE_PROJECT/out.txt\""

# Single-quoted paths with spaces
expect_allowed "rm with spaces in project path (single quotes)" \
  "rm '$SPACE_PROJECT/file.txt'"

# Mixed: flags and quoted space path
expect_allowed "rm -f with spaces in project path" \
  "rm -f \"$SPACE_PROJECT/file.txt\""

# Outside project should still block
expect_blocked "mv from space project to /tmp (double quotes)" \
  "mv \"$SPACE_PROJECT/a.txt\" \"/tmp/b.txt\""

expect_blocked "rm outside project with spaces (double quotes)" \
  "rm \"/tmp/my dir/file.txt\""

# chmod/chown with quoted space paths
expect_allowed "chmod with spaces in project path (double quotes)" \
  "chmod 644 \"$SPACE_PROJECT/file.txt\""

expect_blocked "chown with spaces outside project (double quotes)" \
  "chown root \"/tmp/my dir/file.txt\""

# install with quoted space paths
expect_allowed "install with spaces in project path (double quotes)" \
  "install -m 644 \"$SPACE_PROJECT/src.txt\" \"$SPACE_PROJECT/dst.txt\""

# rsync with quoted space paths
expect_allowed "rsync with spaces in project path (double quotes)" \
  "rsync -av \"$SPACE_PROJECT/src/\" \"$SPACE_PROJECT/dst/\""

# find with quoted space paths
expect_allowed "find with spaces in project path (double quotes)" \
  "find \"$SPACE_PROJECT\" -name '*.tmp' -delete"

# cd with quoted space path
expect_allowed "cd to space project path (double quotes)" \
  "cd \"$SPACE_PROJECT\""

# Restore original project dir
export CLAUDE_PROJECT_DIR="$SAVED_PROJECT_DIR"

echo ""

# ============================================================
# 31. Spaces in paths — remaining limitation
# ============================================================
echo "--- Spaces in paths (unquoted) ---"

# Unquoted paths with spaces cannot be parsed correctly — this is inherent
# to shell argument splitting and would require full shell-level parsing.
echo "SKIP: unquoted paths with spaces remain unsupported (would require shell-level parsing)"

echo ""

# ============================================================
# 32. \s in redirect regex (should be [[:space:]])
# ============================================================
echo "--- Redirect with tab/space variants ---"

expect_blocked 'redirect > /etc/passwd (space before path)' \
  'echo data > /etc/passwd'

expect_blocked 'redirect >> /etc/passwd (space before path)' \
  'echo data >> /etc/passwd'

echo ""

# ============================================================
# 33. extract_path_args unused — just verify it doesn't break anything
# ============================================================
# (no test needed, just code cleanup)

# ============================================================
# 34. find -L /tmp -delete (options before path)
# ============================================================
echo "--- find with options before path ---"

expect_blocked "find -L /tmp -delete" \
  "find -L /tmp -delete"

expect_blocked "find -H /tmp -exec rm {} ;" \
  "find -H /tmp -exec rm {} ;"

expect_allowed "find -L inside project -delete" \
  "find -L $PROJECT -name '*.log' -delete"

echo ""

