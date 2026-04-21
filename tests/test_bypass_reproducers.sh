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

expect_blocked "subshell rm: (rm /etc/passwd)" \
  "(rm /etc/passwd_test)"

expect_blocked "subshell mv: (mv project /etc/x)" \
  "(mv $PROJECT/a /etc/x)"

expect_blocked "subshell curl -o outside: (curl -o /etc/x http://x)" \
  "(curl -o /etc/x http://example.com)"

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

ln -sf /tmp/owned "$PROJECT/evil_link" 2>/dev/null || true
expect_blocked "redirect > project/link -> /tmp/owned" \
  "echo pwned > $PROJECT/evil_link"
rm -f "$PROJECT/evil_link"

echo ""
