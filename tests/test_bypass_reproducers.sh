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

# ============================================================
# 9. Positional / special parameters bypass $VAR fail-closed check
# ------------------------------------------------------------
# The $VAR fail-closed scan only fires when $ is followed by [A-Za-z_]
# (regular name) or `{` (braced form). It misses every other shell
# parameter that expands at exec time:
#   $1..$9, ${1}, ${23}  — positional parameters set by `set --` / function args
#   $@, $*, ${@}, ${*}   — all positional args
#   $#                    — arg count (not a path, but still exec-time expansion)
#   $?, $$, $!, $-, $0    — special parameters
# Concretely: `set -- /etc/passwd_test; rm $1` is accepted because the
# guard sees the literal `$1` as a relative path (joined under cwd and
# judged "inside project"), while bash expands it to the outside path
# at execution time. Same class of bug as $FOO — must fail closed
# unless explicitly allowlisted (currently only $HOME).
# ============================================================
echo "--- 9. positional / special parameter expansion ---"

expect_blocked "set -- /etc/... ; rm \$1 (positional)" \
  'set -- /etc/passwd_test; rm $1'

expect_blocked "rm \${1} (braced positional)" \
  'rm ${1}'

expect_blocked "rm \${10} (multi-digit positional)" \
  'rm ${10}'

expect_blocked "rm \$@ (all positional)" \
  'rm $@'

expect_blocked "rm \$* (all positional, IFS-joined)" \
  'rm $*'

expect_blocked "rm \${@} (braced all-positional)" \
  'rm ${@}'

expect_blocked "echo > \$0 (script name)" \
  'echo x > $0'

expect_blocked "rm \$- (shell flags)" \
  'rm $-'

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

# ============================================================
# 16. Heredoc delimiter parser stops at non-[A-Za-z0-9_] char
# ------------------------------------------------------------
# blank_quoted_heredoc_bodies parses the heredoc delimiter using the
# char class [A-Za-z0-9_], which excludes characters that bash itself
# allows in a word (the heredoc delimiter is just a word). For a real
# heredoc opener like `<<\EOF-1` (or `<<EOF.1`, `<<EOF+1`, `<<-EOF-1`)
# the parser captures only the leading [A-Za-z0-9_] run and treats
# the delim as `EOF` while the actual terminator on the body line is
# `EOF-1`. The terminator is never matched, so the helper falls into
# the "heredoc still open at EOF" branch and blanks everything from
# the body start through the end of the CMD — including any LIVE
# command that bash would actually execute after the real terminator.
#
# Concrete bypass:
#   cat > PROJECT/file <<\EOF-1
#   body
#   EOF-1
#   sed -i 's/a/b/' /etc/passwd_test
# The outside-project sed call after `EOF-1` is hidden from the
# guard's file-walker (because the file/redirect detectors consume
# CMD_BLANKED, which is now all-blank from the body onwards) and
# allowed to run.
# Reported by Codex review on commit e01df86.
# ============================================================
echo "--- 16. heredoc delimiter parser stops at hyphen / dot ---"

expect_blocked "<<\\EOF-1 body then sed -i to /etc" \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF-1
body
EOF-1
sed -i 's/a/b/' /etc/passwd_test"

expect_blocked "<<\\EOF-1 body then redirect to /etc" \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF-1
body
EOF-1
echo x > /etc/passwd_test"

expect_blocked "<<EOF.1 (dot in delim) body then truncate to /etc" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF.1'
body
EOF.1
truncate -s 0 /etc/passwd_test"

expect_blocked "<<-\\TAG-X (indented backslash + hyphen) body then sed" \
  "cat > $PROJECT/tests/scratch.txt <<-\\TAG-X
	body
	TAG-X
sed -i 's/a/b/' /etc/passwd_test"

# Positive cases that must remain ALLOWED after the fix:
# - benign use of hyphenated delimiter
expect_allowed "<<\\EOF-1 with in-project commands" \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF-1
body
EOF-1
echo done"

echo ""

# ============================================================
# 17. /bin path-prefix stripped from operands, not just command-name
# ------------------------------------------------------------
# CMD normalization strips /bin/, /sbin/, /usr/bin/, /usr/sbin/,
# /usr/local/bin/ so that `/bin/rm` is recognised as `rm` by command
# name detectors. The v1.5.0 fix narrowed the strip to "command
# position OR after a non-redirect, non-pipe, non-separator
# character", but the second clause still matches operands whose
# preceding character is a regular alphanumeric — i.e. ALL ordinary
# operands. So `rm /bin/sh`, `tee /bin/owned`, `curl -o /bin/owned`,
# `mv x /sbin/owned` all see their outside-system path operand
# rewritten to a relative bare name (sh / owned / etc.), which then
# resolves to `EFFECTIVE_CWD/sh` and passes the boundary check.
# Bash, of course, still hits the original system path.
# Reported by Codex review on commit e01df86.
# ============================================================
echo "--- 17. /bin prefix stripped from path operands ---"

expect_blocked "rm /bin/sh (operand has /bin prefix)" \
  "rm /bin/sh"

expect_blocked "rm /usr/bin/foo" \
  "rm /usr/bin/foo"

expect_blocked "tee /bin/owned (write target with /bin prefix)" \
  "tee /bin/owned"

expect_blocked "curl -o /bin/owned (download target outside)" \
  "curl -o /bin/owned http://example.com"

expect_blocked "mv PROJECT/x /sbin/owned (mv target stripped)" \
  "mv $PROJECT/CHANGELOG.md /sbin/owned"

expect_blocked "ln -sf foo /usr/local/bin/owned (ln target stripped)" \
  "ln -sf $PROJECT/CHANGELOG.md /usr/local/bin/owned"

# Positive cases that must remain ALLOWED after the fix:
# - /bin/<command> in command position must still be recognised
#   (this was the original purpose of the normalisation)
# - in-project command line that mentions /bin/ as part of an
#   ordinary literal string after `echo`
expect_allowed "/bin/cat PROJECT/file (command position)" \
  "/bin/cat $PROJECT/CHANGELOG.md"

expect_allowed "/usr/bin/echo hello (command position)" \
  "/usr/bin/echo hello"

expect_allowed "echo /bin/sh (literal arg, no write tool)" \
  "echo /bin/sh"

# Wrapper + /bin/<cmd> regression coverage. Without the tokenize-aware
# strip, `nice /bin/rm /etc/x` and friends would not match the rm/cp/...
# command-name regexes (the bare-name regex sees only `/bin/rm`) and
# slip past the destructive-command detectors.
expect_blocked "nice /bin/rm /etc/passwd_test (wrapper + /bin/cmd)" \
  "nice /bin/rm /etc/passwd_test"

expect_blocked "timeout 5 /bin/rm /etc/passwd_test (wrapper + numeric arg)" \
  "timeout 5 /bin/rm /etc/passwd_test"

expect_blocked "env /bin/rm /etc/passwd_test (env + /bin/cmd)" \
  "env /bin/rm /etc/passwd_test"

expect_blocked "env FOO=bar /bin/rm /etc/passwd_test (env+VAR=val)" \
  "env FOO=bar /bin/rm /etc/passwd_test"

expect_blocked "nohup /bin/curl -o /etc/passwd_test (wrapper + tool)" \
  "nohup /bin/curl -o /etc/passwd_test http://example.com"

echo ""

# ============================================================
# 18. /bin path-prefix stripped from operands in CMD_BLANKED view
# ------------------------------------------------------------
# Section 17 covered the primary CMD stream (check_single_command at
# guard.sh:756-757 — `^/bin/` anchor + tokenize-aware
# strip_command_name_prefix). It did NOT cover CMD_BLANKED: the
# heredoc-sanitised parallel stream at guard.sh:847-854 still ran a
# broad sed (`([^<>|&;[:space:]])[[:space:]]+/(bin|...)/` → `\1 `)
# that strips /bin/, /sbin/, /usr/bin/, /usr/sbin/, /usr/local/bin/
# from any operand position whose preceding character is a regular
# non-separator char (the exclusion class only rejects redirect
# operators, pipes, semicolons, and whitespace).
#
# CMD_BLANKED feeds CMD_TOKENS_SCAN, which is what the sed -i,
# truncate, and `>`-redirect walkers iterate. With /bin/ stripped
# from a sed/truncate target operand, the absolute path collapses
# to a bare relative name, gets joined under $EFFECTIVE_CWD, and
# resolves inside the project — while the actual tool (sed -i,
# truncate) writes to the absolute outside-project path at exec
# time. The redirect walker happens to be safe because the
# exclusion class includes `>`, but sed -i and truncate operand
# positions are preceded by ordinary characters (closing quote,
# letter, etc.) and match the broad sed.
#
# Reported by Copilot review on commit aa6409b (guard.sh:758/853).
# ============================================================
echo "--- 18. /bin prefix stripped from sed/truncate target operands (CMD_BLANKED) ---"

expect_blocked "sed -i target /usr/bin/owned (operand prefix stripped in BLANKED view)" \
  "sed -i 's/a/b/' /usr/bin/owned"

expect_blocked "sed -i target /bin/sh" \
  "sed -i 's/a/b/' /bin/sh"

expect_blocked "sed -i target /sbin/owned" \
  "sed -i 's/a/b/' /sbin/owned"

expect_blocked "sed -i target /usr/local/bin/owned" \
  "sed -i 's/a/b/' /usr/local/bin/owned"

expect_blocked "truncate -s 0 /usr/bin/owned (operand prefix stripped)" \
  "truncate -s 0 /usr/bin/owned"

expect_blocked "truncate -s 0 /bin/bash (overwrite system binary)" \
  "truncate -s 0 /bin/bash"

# Positive cases that must remain ALLOWED after the fix:
# - sed -i on an inside-project file whose path mentions /bin/ only
#   as a command-name prefix (wrapper + /bin/cmd inside the project)
# - echo of a literal /bin/ path with no write tool
expect_allowed "sed -i on PROJECT file (no /bin/ operand)" \
  "sed -i 's/a/b/' $PROJECT/CHANGELOG.md"

expect_allowed "echo /bin/sh (literal arg, no write tool)" \
  "echo /bin/sh"

echo ""

# ============================================================
# 19. php inline-code attached-flag form (`php -rcode`)
# ------------------------------------------------------------
# The dedicated PHP rule added for prior Copilot feedback
# (guard.sh:1087) matches `php -r`, `-R`, `--run` in space-separated
# and long-flag forms:
#   php[[:space:]]+(-[a-zA-Z]*[rR]|--run)([[:space:]]|=|$|'|")
# PHP accepts attached forms too (POSIX-style short-flag clustering):
#   php -rcode             argv = ["php", "-rcode"] → executes `code`
#   php -Rcode
# The current regex requires the match to END at a boundary
# (space/=/$/quote), so `-rsystem('x')` (no separator between -r and
# the code) fails to match and bypasses the inline-code block.
#
# Reported by Copilot review on commit aa6409b (guard.sh:1068) — the
# finding was partially addressed via the dedicated PHP rule, but the
# attached form remained uncovered.
# ============================================================
echo "--- 19. php inline-code attached flag form ---"

expect_blocked "php -rsystem('x') (attached -r, no separator)" \
  "php -rsystem('rm /etc/passwd_test')"

expect_blocked "php -Rsystem(...) attached -R" \
  "php -Rsystem('x')"

expect_blocked "php -recho attached short" \
  "php -recho 1;"

# Positive cases — legitimate php invocations must remain ALLOWED.
# Every variant either (a) has no -r/-R flag or (b) uses -r in a
# non-inline-code sense (PHP has no such sense — any -r prefix is
# inline code — so only (a) matters).
expect_allowed "php script.php (no flags)" \
  "php script.php"

expect_allowed "php -v (version)" \
  "php -v"

expect_allowed "php --version" \
  "php --version"

expect_allowed "php -l script.php (lint)" \
  "php -l script.php"

expect_allowed "php -f script.php (explicit script)" \
  "php -f script.php"

expect_allowed "php -d memory_limit=256M script.php" \
  "php -d memory_limit=256M script.php"

expect_allowed "php -S localhost:8080 (built-in server)" \
  "php -S localhost:8080"

expect_allowed "php -i (config info)" \
  "php -i"

expect_allowed "php -m (modules list)" \
  "php -m"

expect_allowed "php artisan migrate (Laravel)" \
  "php artisan migrate"

expect_allowed "php composer.phar install" \
  "php composer.phar install"

echo ""

# ============================================================
# 20. Multi-heredoc body ordering — quoted body range overlaps
#     unquoted body and hides expansions from fail-closed scans.
# ------------------------------------------------------------
# bash accepts multiple `<<` openers on one command line and reads
# the bodies in declaration order (each terminated by its own
# delimiter on its own line). When the openers mix quoted and
# unquoted delimiters (e.g. `<<EOF <<'Q'`), bash still expands the
# unquoted body (parameter / command / arithmetic expansion runs
# at parse time, even if that body's bytes end up unused on stdin
# because only the LAST heredoc feeds a process).
#
# blank_quoted_heredoc_bodies queued ALL heredocs from an opener
# line with body_start = next-line-start, so a later quoted
# heredoc's blank range covered bytes that belonged to an earlier
# unquoted heredoc body. Quoted body blanking then overwrote the
# unquoted body's expansion bytes in CMD_EXPAND_SCAN, hiding
# $(...) / backtick / $VAR from the fail-closed detectors —
# exactly the shape Copilot review on commit aa6409b flagged.
#
# The correct reading is sequential: only the queue head's body
# starts on the next line. Each subsequent heredoc's body starts
# on the line AFTER its predecessor's terminator.
# ============================================================
echo "--- 20. multi-heredoc body ordering (mixed quoted / unquoted) ---"

expect_blocked "<<EOF <<'Q' — \$(cmd) in unquoted EOF body" \
  "cat > $PROJECT/tests/scratch.txt <<EOF <<'Q'
\$(echo owned)
EOF
second body
Q"

expect_blocked "<<EOF <<'Q' — backtick in unquoted EOF body" \
  "cat > $PROJECT/tests/scratch.txt <<EOF <<'Q'
\`echo owned\`
EOF
second body
Q"

expect_blocked "<<EOF <<'Q' — \$VAR in unquoted EOF body" \
  "cat > $PROJECT/tests/scratch.txt <<EOF <<'Q'
\$SECRET
EOF
second body
Q"

expect_blocked "<<EOF <<\\Q — \$(cmd) in unquoted EOF body (backslash-quoted second)" \
  "cat > $PROJECT/tests/scratch.txt <<EOF <<\\Q
\$(echo owned)
EOF
second
Q"

# Positive cases that must remain ALLOWED after the fix:
# - all-quoted multi-heredoc with literal body text (no expansion)
# - all-unquoted multi-heredoc with plain text (no expansion markers)
# - single quoted heredoc unchanged
expect_allowed "<<'A' <<'B' both quoted, literal bodies" \
  "cat > $PROJECT/tests/scratch.txt <<'A' <<'B'
literal text only
A
more literal text
B"

expect_allowed "<<EOF <<END both unquoted, no expansion markers" \
  "cat > $PROJECT/tests/scratch.txt <<EOF <<END
first plain line
EOF
second plain line
END"

expect_allowed "<<'Q' <<EOF quoted first, unquoted second with plain text" \
  "cat > $PROJECT/tests/scratch.txt <<'Q' <<EOF
quoted body with \$literal
Q
unquoted body with plain text
EOF"

echo ""

# ============================================================
# 21. Quoted command-name bypass — `"rm" /etc/x`, `'rm' /etc/x`
# ------------------------------------------------------------
# bash strips surrounding quotes from a command word at exec time,
# so `"rm" /etc/passwd` actually invokes the `rm` binary. Every
# destructive-command detector in guard.sh matches bare command
# names via regexes like `(^|[[:space:]])rm($|[[:space:]])` on the
# normalized CMD string. The normalization chain strips subshell
# parens and alias-escape backslashes but does NOT strip
# surrounding quotes, so a quoted command-name token keeps its
# quotes in CMD and the regex misses the match entirely.
#
# Affects every bare-name detector: rm, mv, cp, ln, chmod, chown,
# tee, curl, wget, find, sed, truncate, rsync — wrapping the
# command-name in single or double quotes (or a combination with
# absolute paths and wrappers) slips the whole class past the
# guard.
#
# Reported by Copilot review on commit 22112ba (guard.sh:1078,1503).
# ============================================================
echo "--- 21. quoted command-name bypass ---"

expect_blocked '"rm" /etc/passwd_test (double-quoted rm)' \
  '"rm" /etc/passwd_test'

expect_blocked "'rm' /etc/passwd_test (single-quoted rm)" \
  "'rm' /etc/passwd_test"

expect_blocked '"tee" /etc/passwd_test (quoted tee target)' \
  '"tee" /etc/passwd_test'

expect_blocked '"/bin/rm" /etc/passwd_test (quoted absolute path)' \
  '"/bin/rm" /etc/passwd_test'

expect_blocked 'nice "rm" /etc/passwd_test (wrapper + quoted cmd)' \
  'nice "rm" /etc/passwd_test'

expect_blocked 'sudo "rm" /etc/passwd_test' \
  'sudo "rm" /etc/passwd_test'

expect_blocked '"sed" -i to /usr/bin/owned (quoted sed)' \
  '"sed" -i "s/a/b/" /usr/bin/owned'

expect_blocked '"truncate" -s 0 /usr/bin/owned (quoted truncate)' \
  '"truncate" -s 0 /usr/bin/owned'

expect_blocked 'env FOO=bar "rm" /etc/passwd_test (env VAR + quoted cmd)' \
  'env FOO=bar "rm" /etc/passwd_test'

# Positive cases that must remain ALLOWED after the fix:
# - quoted read-only command inside project
# - quoted destructive command targeting in-project path
# - command-name literal inside a string argument (not a command)
expect_allowed '"ls" PROJECT (quoted ls inside project)' \
  "\"ls\" $PROJECT"

expect_allowed '"rm" PROJECT/file (quoted rm, in-project target)' \
  "\"rm\" $PROJECT/tests/scratch.txt"

expect_allowed "echo 'rm /etc/x' (rm inside a string literal, no exec)" \
  "echo 'rm /etc/x'"

echo ""

# ============================================================
# 22. install detector unconditionally skips mode/user_group tokens
# ------------------------------------------------------------
# install's path-walker tries to "skip" the value of -m/-o/-g flags
# by matching every token against:
#     ^[0-9]+$                               (mode)
#     ^[a-zA-Z_][a-zA-Z0-9_]*(:user)?$       (owner[:group])
# but applies the skip UNCONDITIONALLY — to every token, not just
# the one immediately following -m/--mode/-o/--owner/-g/--group.
#
# Bash semantics: install grammar puts mode/owner/group ONLY as the
# value of their respective flag. A bare positional token like
# "0755", "root", or "root_wheel" is a SOURCE or DEST file name.
#
# Concrete attack: when EFFECTIVE_CWD sits outside the project
# (event_cwd or `cd /tmp && ...`), an install destination whose
# bare name happens to match the mode or user_group regex slips
# past the boundary check. The guard never resolves it; the actual
# write lands at <outside_cwd>/<name>.
#
# Reported by Copilot review on commit b6de687
# (write_targets.sh:47).
# ============================================================
echo "--- 22. install dest matching mode/user_group regex bypass ---"

expect_blocked_cwd "install src DEST=1234 (mode regex bypass, cwd=/tmp)" \
  "install $PROJECT/CHANGELOG.md 1234" \
  "/tmp"

expect_blocked_cwd "install src DEST=root (user_group regex bypass, cwd=/tmp)" \
  "install $PROJECT/CHANGELOG.md root" \
  "/tmp"

expect_blocked_cwd "install src DEST=root_wheel (alphanumeric name bypass, cwd=/tmp)" \
  "install $PROJECT/CHANGELOG.md root_wheel" \
  "/tmp"

expect_blocked_cwd "install src DEST=user:wheel (user:group bypass, cwd=/tmp)" \
  "install $PROJECT/CHANGELOG.md user:wheel" \
  "/tmp"

# Positive cases that must remain ALLOWED after the fix:
# - install -m 0755 src dest (mode value AFTER -m must still be skipped)
# - install -o root -g wheel src dest (owner/group values after their flags)
# - install with attached --mode=VALUE / --owner=VALUE / --group=VALUE
# - bare install with no args (no abort under set -euo pipefail)
expect_allowed "install -m 0755 src dest (mode value after -m, in project)" \
  "install -m 0755 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install -o root src dest (owner value after -o, in project)" \
  "install -o root $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install -g wheel src dest (group value after -g, in project)" \
  "install -g wheel $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install --mode=0755 src dest (attached mode)" \
  "install --mode=0755 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install --owner=root src dest (attached owner)" \
  "install --owner=root $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install --group=wheel src dest (attached group)" \
  "install --group=wheel $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install -m 0755 -o root -g wheel src dest (all flags combined)" \
  "install -m 0755 -o root -g wheel $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

echo ""
