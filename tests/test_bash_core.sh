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

