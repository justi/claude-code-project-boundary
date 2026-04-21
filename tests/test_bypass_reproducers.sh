#!/bin/bash
# Security audit: reproducers for known guard.sh bypasses.
#
# Every test below asserts `expect_blocked` for a command that targets a path
# OUTSIDE the project boundary. Each test currently FAILS (guard returns 0
# instead of 2), documenting a concrete bypass.
#
# When a bypass is fixed in guard.sh, its reproducer should start passing
# without modification.
#
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (expected failing)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# 1. Subshell without surrounding spaces: `(rm ...)`
# ------------------------------------------------------------
# The regex `(^|[[:space:]])rm($|[[:space:]])` requires start-of-line or
# whitespace before `rm`. A leading `(` (subshell grouping) is neither, so
# the destructive-command check never fires. Bash still executes `rm` in
# the subshell. The same bypass applies to mv/cp/ln/chmod/chown/tee/curl/wget.
# ============================================================
echo "--- 1. subshell-without-space prefix ---"

expect_blocked "subshell rm: (rm /etc/passwd_test)" \
  "(rm /etc/passwd_test)"

expect_blocked "subshell mv: (mv PROJECT/a /etc/passwd_test)" \
  "(mv $PROJECT/a /etc/passwd_test)"

expect_blocked "subshell curl -o outside: (curl -o /etc/passwd_test http://x)" \
  "(curl -o /etc/passwd_test http://example.com)"

echo ""

# ============================================================
# 2. Backslash-escaped command name: `\rm`
# ------------------------------------------------------------
# `\rm` disables alias lookup but still invokes the `rm` binary. The guard's
# regex treats `\` as a non-whitespace prefix and skips the check.
# ============================================================
echo "--- 2. backslash prefix ---"

expect_blocked "\\rm outside project" \
  '\rm /etc/passwd_test'

expect_blocked "\\tee outside project" \
  '\tee /etc/passwd_test'

echo ""

# ============================================================
# 3. Absolute/alternate path to binary: `/bin/rm`, `/usr/bin/curl`
# ------------------------------------------------------------
# The regex only matches bare command names. Calling the same tool via an
# explicit path bypasses every destructive-command and option-extractor
# check (rm, mv, cp, ln, tee, curl -o, wget -O, tar -C, ...).
# ============================================================
echo "--- 3. absolute path to binary ---"

expect_blocked "/bin/rm outside project" \
  "/bin/rm /etc/passwd_test"

expect_blocked "/usr/bin/tee outside project" \
  "/usr/bin/tee /etc/passwd_test"

expect_blocked "/usr/bin/curl -o outside project" \
  "/usr/bin/curl -o /etc/owned http://example.com"

echo ""

# ============================================================
# 4. Non-shell interpreters: python/perl/ruby/node -c|-e
# ------------------------------------------------------------
# The guard blocks `bash -c` / `sh -c` / `eval` because the inner string
# cannot be inspected. The same argument applies to every other interpreter
# that takes code on the command line, but none are blocked — so arbitrary
# filesystem writes are trivial.
# ============================================================
echo "--- 4. non-shell interpreters ---"

expect_blocked "python3 -c writing outside" \
  'python3 -c "open(\"/tmp/owned\",\"w\").write(\"x\")"'

expect_blocked "perl -e writing outside" \
  'perl -e "open(F,\">/tmp/owned\");print F 1"'

expect_blocked "ruby -e writing outside" \
  'ruby -e "File.write(\"/tmp/owned\", 1)"'

expect_blocked "node -e writing outside" \
  'node -e "require(\"fs\").writeFileSync(\"/tmp/owned\",\"x\")"'

expect_blocked "awk BEGIN system() outside" \
  'awk "BEGIN{system(\"rm /etc/passwd_test\")}"'

echo ""

# ============================================================
# 5. Variable indirection: `X=/etc/x && rm $X`
# ------------------------------------------------------------
# `expand_path` only expands `~`, `$HOME`, `${HOME}`. A literal `$X` token
# is kept verbatim, then joined with `$EFFECTIVE_CWD` as if it were a
# relative path. The resolved path sits *inside* the project so the check
# passes. Bash then expands `$X` to `/etc/x` at execution time.
# ============================================================
echo "--- 5. env-var indirection ---"

expect_blocked "rm via \$VAR expansion" \
  'X=/etc/passwd_test && rm $X'

expect_blocked "redirect via \$VAR expansion" \
  'X=/tmp/owned && echo pwned > $X'

echo ""

# ============================================================
# 6. Destructive commands not on the block list
# ------------------------------------------------------------
# The outside-cwd block list is `rm|mv|cp|ln|chmod|chown|tee|find|curl|wget`.
# Several equally destructive tools are missing: `sed -i`, `truncate`, `ed`,
# `dd` is covered but sed-in-place is not. These can mutate arbitrary files.
# ============================================================
echo "--- 6. unlisted destructive tools ---"

expect_blocked "sed -i outside project" \
  "sed -i '' 's/x/y/' /etc/passwd_test"

expect_blocked "truncate outside project" \
  "truncate -s 0 /etc/passwd_test"

echo ""

# ============================================================
# 7. Redirect target that is a symlink pointing outside
# ------------------------------------------------------------
# Edit/Write dereferences symlinks in a readlink loop (guard.sh:227-235),
# but the Bash-redirect check only canonicalizes the *dirname* of the
# target — the basename (the symlink itself) is not followed. If a symlink
# inside the project points outside, `echo x > project/link` silently
# writes through it.
# ============================================================
echo "--- 7. redirect through inside-project symlink ---"

# Setup: a symlink inside the project pointing outside. If this setup fails
# (e.g., filesystem without symlink support), the reproducer no longer
# exercises the intended bypass — so the setup itself is asserted as a test
# and the reproducer only runs when the prerequisite holds.
ln -sf /tmp/owned "$PROJECT/evil_link" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$PROJECT/evil_link" ]]; then
  echo "PASS: setup: inside-project symlink created for redirect test"
  PASS=$((PASS + 1))
  expect_blocked "redirect > project/link -> /tmp/owned" \
    "echo pwned > $PROJECT/evil_link"
else
  echo "FAIL: setup: could not create inside-project symlink at $PROJECT/evil_link"
  FAIL=$((FAIL + 1))
  echo "SKIP: redirect > project/link -> /tmp/owned (prerequisite symlink missing)"
fi
rm -f "$PROJECT/evil_link"

echo ""

# ============================================================
# 8. Executing script files outside the project
# ------------------------------------------------------------
# Current guard blocks `bash -c "..."`, `sh -c "..."` and piping to sh/bash,
# but NOT running a script file whose path is outside the project:
#   bash /tmp/evil.sh
#   sh ~/evil.sh
#   zsh /tmp/evil.sh       (only bash|sh covered by nested-shell rule)
#   source /tmp/evil.sh    (builtin — loads and runs)
#   . /tmp/evil.sh         (. is synonym for source)
#
# Critical interaction with hooks/allowlist.conf: a write-only allowlist
# (e.g. memory/) becomes an RCE escape hatch if the same path can then
# be executed. Execute paths must use a STRICT project-root check that
# ignores the allowlist.
# ============================================================
echo "--- 8. executing external script files ---"

expect_blocked "bash /tmp/evil.sh" \
  "bash /tmp/evil.sh"

expect_blocked "sh /tmp/evil.sh" \
  "sh /tmp/evil.sh"

expect_blocked "/bin/bash /tmp/evil.sh" \
  "/bin/bash /tmp/evil.sh"

expect_blocked "bash ~/evil.sh" \
  "bash ~/evil.sh"

expect_blocked "zsh /tmp/evil.sh" \
  "zsh /tmp/evil.sh"

expect_blocked "ksh /tmp/evil.sh" \
  "ksh /tmp/evil.sh"

expect_blocked "dash /tmp/evil.sh" \
  "dash /tmp/evil.sh"

expect_blocked "source /tmp/evil.sh" \
  "source /tmp/evil.sh"

expect_blocked ". /tmp/evil.sh" \
  ". /tmp/evil.sh"

# Critical: execute path inside an ALLOWLISTED dir must still be blocked.
# allowlist grants WRITE, execute must NOT inherit that.
# Hermetic: override HOME so the test never touches real ~/.claude data.
_BYP_HOME_SAVE="$HOME"
export HOME="$TMPDIR_BASE/fake_home_bypass"
mkdir -p "$HOME"
MEMDIR="$HOME/.claude/projects/-test-slug/memory"
mkdir -p "$MEMDIR"
expect_blocked "bash memory/evil.sh (allowlist write-only, execute must block)" \
  "bash $MEMDIR/evil.sh"
expect_blocked "source memory/evil.sh (allowlist write-only, execute must block)" \
  "source $MEMDIR/evil.sh"
rm -rf "$HOME/.claude"
export HOME="$_BYP_HOME_SAVE"

echo ""
