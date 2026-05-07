#!/bin/bash
# Bypass reproducers (core, part B) — sections 1-15 second half.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (core, part B)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""


# ============================================================
# 10. truncate: digit-leading filename skipped as if it were a size
# ------------------------------------------------------------
# The truncate guard walks argv and tries to skip size literals using a
# regex like `^[+=\<\>\%]?[0-9]`. That regex also matches a filename
# whose basename starts with a digit, so after `-s 0` has already been
# consumed as (flag, value), the next digit-leading token — the actual
# file operand — is also skipped. No path check fires and the write
# is accepted while bash mutates the outside file at exec time.
#
# Concretely, from a /tmp cwd:
#   truncate -s 0 123.log
# is allowed and zeroes /tmp/123.log even though /tmp is outside the
# project. Same failure shape applies to any size-suffix filename
# (1.txt, 2024-04-22.log, etc.) when invoked from an outside cwd.
# ============================================================
echo "--- 10. truncate digit-leading filename ---"

expect_blocked "truncate -s 0 123.log in /tmp cwd (digit-leading filename)" \
  "cd /tmp && truncate -s 0 123.log"

expect_blocked "truncate -s 0 2024-04-22.log in /tmp cwd" \
  "cd /tmp && truncate -s 0 2024-04-22.log"

expect_blocked "truncate -s 0 /etc/9owned (absolute digit-leading)" \
  "truncate -s 0 /etc/9owned"

# Positive cases that must remain ALLOWED after the fix:
# - in-project digit-leading filename
# - size value passed as space-separated -s operand (not the file)
expect_allowed "truncate -s 0 PROJECT/tests/1.log (in-project, digit-leading)" \
  "truncate -s 0 $PROJECT/tests/1.log"

expect_allowed "truncate -s 100 PROJECT/tests/file.log (size then file)" \
  "truncate -s 100 $PROJECT/tests/file.log"

expect_allowed "truncate -s0 PROJECT/tests/file.log (attached -s0)" \
  "truncate -s0 $PROJECT/tests/file.log"

echo ""

# ============================================================
# 11. CMD-normalization corrupts redirect targets
# ------------------------------------------------------------
# `check_single_command` strips common binary path prefixes
# (`/bin/`, `/usr/bin/`, `/sbin/`, `/usr/sbin/`, `/usr/local/bin/`)
# from the entire CMD string so that `/bin/rm` is recognized as `rm`.
# The regex matches any `(^|whitespace)/bin/...`, including the
# whitespace AFTER a redirect operator. As a result,
#   echo x > /bin/owned
# is rewritten to `echo x > owned`, the redirect target collapses to
# a relative inside-project path, and the boundary check passes —
# while bash physically writes to /bin/owned outside the project.
# Reported by Copilot review on PR #12.
# ============================================================
echo "--- 11. cmd-normalization corrupts redirect targets ---"

expect_blocked "redirect to /bin/owned (path-prefix stripped from target)" \
  "echo x > /bin/owned"

expect_blocked "redirect to /usr/bin/owned" \
  "echo pwned > /usr/bin/owned"

expect_blocked "append to /sbin/owned" \
  "echo x >> /sbin/owned"

expect_blocked "redirect to /usr/local/bin/owned" \
  "echo x > /usr/local/bin/owned"

# Positive cases that must remain ALLOWED after the fix:
# - the original /bin/<command> command-name normalization still works
expect_allowed "/bin/cat PROJECT/file (command-name path prefix still recognized)" \
  "/bin/cat $PROJECT/CHANGELOG.md"

expect_allowed "/usr/bin/echo hello inside project" \
  "/usr/bin/echo hello"

echo ""

# ============================================================
# 12. `--` end-of-options ignored by sed -i / truncate parsers
# ------------------------------------------------------------
# The flag walkers for sed -i (line ~1730) and truncate (line ~1762)
# treat ANY token starting with `-` as an option and skip it. POSIX
# `--` signals end-of-options: every token after `--` is a positional
# operand, even if its name starts with `-`. Without handling `--`, a
# file operand whose name begins with `-` is skipped as an unknown
# flag, never reaching is_write_permitted.
# Reported by Copilot review on PR #12.
# ============================================================
echo "--- 12. -- end-of-options ignored by sed/truncate parsers ---"

expect_blocked "sed -i with -- and dash-prefix file in /tmp cwd" \
  "cd /tmp && sed -i 's/a/b/' -- -owned"

expect_blocked "truncate with -- and dash-prefix file in /tmp cwd" \
  "cd /tmp && truncate -s 0 -- -owned"

# Note on -- with a relative dash-prefix file (no `cd`):
# `-owned` resolves to EFFECTIVE_CWD/-owned. With EFFECTIVE_CWD inside
# the project, that's an in-project write — not a bypass. The bypass
# only manifests when cwd is moved outside (the two `cd /tmp` cases
# above) or when the operand is an absolute outside path.

# Positive cases that must remain ALLOWED after the fix:
# - operand after -- inside the project boundary
# - normal flag walking still works (no regression in option parsing)
expect_allowed "sed -i 's/a/b/' -- PROJECT/tests/file (in-project after --)" \
  "sed -i 's/a/b/' -- $PROJECT/tests/file"

expect_allowed "truncate -s 0 -- PROJECT/tests/file (in-project after --)" \
  "truncate -s 0 -- $PROJECT/tests/file"

expect_allowed "sed -i 's/a/b/' PROJECT/tests/file (no --, normal call)" \
  "sed -i 's/a/b/' $PROJECT/tests/file"

echo ""

# ============================================================
# 13. php -r / --run / -R inline code execution
# ------------------------------------------------------------
# The non-shell-interpreter detector covers python/perl/ruby/node/php
# inline-code flags via the regex `-[a-zA-Z]*[ceE]|--eval|--execute`.
# The comment for that block explicitly lists `php` as covered, but
# PHP's actual inline-code flags are `-r`, `-R`, and `--run` — none
# of which match the regex. So `php -r 'system("rm /etc/x")'` reaches
# the parser unchecked.
#
# `-r` cannot be added to the shared regex without false-positives:
# `ruby -r library` and `node -r module` use `-r` to PRELOAD a module,
# not to execute inline code. Hence a dedicated PHP-only check.
# Reported by Copilot review on PR #12.
# ============================================================
echo "--- 13. php inline-code flags (-r / -R / --run) ---"

expect_blocked "php -r 'system(\"...\")' (inline code execution)" \
  "php -r 'system(\"echo pwned\")'"

expect_blocked "php --run inline code" \
  "php --run 'echo 1;'"

expect_blocked "php -R 'code' (per-line inline code)" \
  "php -R 'echo \$argn;'"

expect_blocked "php with attached -r form: php -rcode" \
  "php -r'system(\"x\")'"

# Positive cases — preload-style -r in other interpreters must NOT
# regress (ruby -r lib, node -r mod load a module, no code exec).
expect_allowed "ruby -r somelib PROJECT/script.rb (preload module)" \
  "ruby -r json $PROJECT/CHANGELOG.md"

expect_allowed "node -r module PROJECT/script.js (preload module)" \
  "node -r dotenv $PROJECT/CHANGELOG.md"

expect_allowed "php PROJECT/script.php (no inline-code flag)" \
  "php $PROJECT/CHANGELOG.md"

echo ""

# ============================================================
# 14. is_write_permitted does not dereference inside-project symlinks
# ------------------------------------------------------------
# is_write_permitted at hooks/guard.sh:381 returns true as soon as
# is_inside_project succeeds — without following the leaf symlink.
# Every write-style detector that reaches the function on a Bash-side
# command (tee, sed -i, truncate, curl -o, wget -O, dd of=, the
# redirect-target scanner does its own deref) trusts the lexical
# inside-project check. So:
#   ln -s /etc/passwd_test PROJECT/evil_link && tee PROJECT/evil_link
# writes outside the project because PROJECT/evil_link is lexically
# inside but resolves to /etc/passwd_test.
#
# The Edit/Write tool branch (line ~430) already does a full readlink
# loop before calling is_write_permitted, so it's unaffected. The
# allowlist branch of is_write_permitted also derefs (line ~394). The
# missing deref is the inside-project branch when reached from a Bash
# command.
# Reported by Copilot review on PR #12 (commit 7641a412).
# ============================================================
echo "--- 14. write through inside-project symlink (no deref in is_write_permitted) ---"

# Setup helper: create a symlink inside the project pointing outside.
# Asserted as a test so a filesystem without symlink support produces
# a clear FAIL rather than misleading silent ALLOWs.
ln -sf /etc/passwd_test "$PROJECT/evil_write_link" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$PROJECT/evil_write_link" ]]; then
  echo "PASS: setup: inside-project symlink created for write-leak test"
  PASS=$((PASS + 1))

  expect_blocked "tee via inside-project symlink to outside" \
    "tee $PROJECT/evil_write_link"

  expect_blocked "sed -i via inside-project symlink to outside" \
    "sed -i 's/a/b/' $PROJECT/evil_write_link"

  expect_blocked "truncate via inside-project symlink to outside" \
    "truncate -s 0 $PROJECT/evil_write_link"

  expect_blocked "curl -o via inside-project symlink to outside" \
    "curl -o $PROJECT/evil_write_link http://example.com"

  expect_blocked "wget -O via inside-project symlink to outside" \
    "wget -O $PROJECT/evil_write_link http://example.com"

  expect_blocked "dd of= via inside-project symlink to outside" \
    "dd of=$PROJECT/evil_write_link if=/dev/zero"
else
  echo "FAIL: setup: could not create inside-project symlink at $PROJECT/evil_write_link"
  FAIL=$((FAIL + 1))
fi
rm -f "$PROJECT/evil_write_link"

# Positive cases that must remain ALLOWED after the fix:
# - in-project regular file (no symlink)
# - inside-project symlink that points to another inside-project file
expect_allowed "tee on a regular in-project file" \
  "tee $PROJECT/tests/scratch.txt"

ln -sf "$PROJECT/CHANGELOG.md" "$PROJECT/inside_link" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$PROJECT/inside_link" ]]; then
  echo "PASS: setup: inside-project symlink to in-project target created"
  PASS=$((PASS + 1))
  expect_allowed "tee via symlink whose ultimate target is in-project" \
    "tee $PROJECT/inside_link"
else
  echo "FAIL: setup: could not create inside-project to inside-project symlink"
  FAIL=$((FAIL + 1))
fi
rm -f "$PROJECT/inside_link"

echo ""

# ============================================================
# 15. Newline as command separator ignored by split_and_check
# ------------------------------------------------------------
# Bash treats a literal newline as a command terminator, equivalent to
# `;`. split_and_check at hooks/guard.sh:1908 only splits on
# `&&`, `||`, `;`, `|` — newlines are passed through into a single
# subcommand. As a result, the FIRST line's command name is what
# every "first-token" detector sees (script-execute, env wrappers,
# etc.); a destructive command on the SECOND line slips past those
# detectors that look only at command position.
#
# Concrete bypass:
#   echo ok\n
#   bash /tmp/evil.sh
# is treated as a single subcommand whose command-name is `echo`. The
# script-execute detector never sees `bash /tmp/evil.sh` in command
# position and the outside script execution is allowed.
# Reported by Codex review on commit e01df86.
# ============================================================
echo "--- 15. newline command separator ignored ---"

expect_blocked "echo ok\\n bash /tmp/evil.sh (script-execute on line 2)" \
  "echo ok
bash /tmp/evil.sh"

expect_blocked "true\\n source /tmp/evil.sh" \
  "true
source /tmp/evil.sh"

expect_blocked "echo hi\\n /bin/bash /tmp/evil.sh" \
  "echo hi
/bin/bash /tmp/evil.sh"

# Positive cases that must remain ALLOWED after the fix:
# - newline-separated commands all in-project
# - heredoc body containing newlines (must NOT be split)
expect_allowed "echo a\\n echo b (both safe)" \
  "echo a
echo b"

expect_allowed "git commit -F - <<'EOF' body has newlines (must not split)" \
  "git commit -F - <<'EOF'
fix something

with body line
EOF"

echo ""

