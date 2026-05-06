#!/bin/bash
# Bypass reproducers (recent / sections 16-28) — heredoc parser,
# multi-heredoc body ordering, quoted command-name, /bin prefix in
# CMD_BLANKED, install / rsync walker fixes (POSIX `--`, attached
# write-target white-list, quoted-option normalization), php attached
# form, attached-flag behavior pinning, rsync first-segment-only
# remote-path skip.
# Continuation of test_bypass_reproducers_core.sh; same TDD discipline.
#
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (recent, sections 16-28)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
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

# ============================================================
# 23. rsync detector ignores POSIX `--` end-of-options
# ------------------------------------------------------------
# The rsync path-walker treats every token starting with `-` as a
# flag (`[[ "$TARGET" == -* ]] && continue`) and skips it without
# validation. POSIX `--` ends option parsing; every token after it
# is a positional operand even when its name begins with `-`. So a
# file operand named `-owned` slips past the boundary check, and
# rsync writes to / from a path the guard never resolved.
#
# Same shape as the sed -i / truncate POSIX `--` bypass that PR #12
# closed for those two walkers — rsync was missed because Codex's
# original audit didn't include it.
#
# Reported by Copilot review on commit b6de687
# (write_targets.sh:66).
# ============================================================
echo "--- 23. rsync ignores POSIX -- end-of-options ---"

expect_blocked_cwd "rsync src -- -owned (POSIX --, cwd=/tmp)" \
  "rsync $PROJECT/CHANGELOG.md -- -owned" \
  "/tmp"

expect_blocked_cwd "rsync -a src -- -dash_dest (with -a flag, POSIX --, cwd=/tmp)" \
  "rsync -a $PROJECT/CHANGELOG.md -- -dash_dest" \
  "/tmp"

expect_blocked_cwd "rsync -- -src -dest (both operands dash-prefixed)" \
  "rsync -- -src -dest" \
  "/tmp"

# Positive cases that must remain ALLOWED after the fix:
# - rsync without -- (current flag-skip behaviour preserved)
# - rsync -- src dest with non-dash operands (-- handled, both validated)
# - rsync --help / --version (long flags before -- still skipped)
expect_allowed "rsync -a src dest (no --, normal flag handling, in project)" \
  "rsync -a $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "rsync -- src dest (-- with normal operands, in project)" \
  "rsync -- $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "rsync --help (long flag before --)" \
  "rsync --help"

expect_allowed "rsync --version (long flag before --)" \
  "rsync --version"

echo ""

# ============================================================
# 24. install detector ignores POSIX `--` end-of-options
# ------------------------------------------------------------
# The install path-walker uses the same `[[ "$TARGET" == -* ]] &&
# continue` flag-skip pattern as rsync had before section 23. After
# `--`, every token is a positional operand even when its name
# begins with `-`. So a file operand like `-owned` slips past the
# boundary check.
#
# Other write/destructive walkers (tee / rm / mv / cp / ln) carry
# the same code shape but are NOT exploitable via this path: the
# cd-outside-chain destructive gate fires earlier and blocks them
# wholesale ("Destructive command outside project directory")
# before their per-arg walker runs. install is classified as a
# write tool, not destructive, so it passes that earlier gate and
# the walker bug becomes the boundary.
#
# Same bug class as the rsync POSIX `--` bypass closed in section
# 23 of this branch.
#
# Reported by Copilot review on commit c4a70e0
# (write_targets.sh:67).
# ============================================================
echo "--- 24. install ignores POSIX -- end-of-options ---"

expect_blocked_cwd "install src -- -owned (cwd=/tmp)" \
  "install $PROJECT/CHANGELOG.md -- -owned" \
  "/tmp"

expect_blocked_cwd "install -m 0755 src -- -dash_dest (cwd=/tmp)" \
  "install -m 0755 $PROJECT/CHANGELOG.md -- -dash_dest" \
  "/tmp"

expect_blocked_cwd "install -- -src -dest (both operands dash-prefixed)" \
  "install -- -src -dest" \
  "/tmp"

# Positive cases that must remain ALLOWED after the fix:
# - install without -- (current flag-skip behaviour preserved)
# - install -- src dest with non-dash operands in project
expect_allowed "install src dest (no --, in project)" \
  "install $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install -- src dest (-- with normal operands, in project)" \
  "install -- $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "install --help (long flag before --)" \
  "install --help"

echo ""

# ============================================================
# 25. Quoted attached options must NOT bypass flag-skip
# ------------------------------------------------------------
# Earlier commit ce011af stripped quotes before the generic `-*`
# flag-skip in install / rsync walkers. Side effect: a quoted
# attached option like "--target-directory=/tmp/out" or
# "--log-file=/tmp/log" was normalized into a flag and skipped
# unconditionally — even though its VALUE points outside the
# project. Pre-existing behaviour treated the quoted form as a
# pathname (joined to EFFECTIVE_CWD, resolved, blocked by
# is_inside_project).
#
# Fix (current shape after follow-ups): every flag test is run
# on a strip_quotes view of the token (`*_tok`), so `"--help"`
# behaves like `--help`, `"--"` behaves like `--`, and a quoted
# attached option like `"--target-directory=/tmp/out"` reaches
# the white-list match below and gets its value validated. The
# raw token is no longer special-cased — the white-list (here)
# and the explicit -m/-o/-g case (further down) decide which
# tokens carry write-target values vs. ordinary skip-as-flag.
#
# Reported by Codex review on commit ce011af
# (write_targets.sh:76-87 + 123-128); refined by f76ec34 and
# narrowed to the white-list shape by 00d7300.
# ============================================================
echo "--- 25. quoted attached options must reach path validation ---"

expect_blocked_cwd "install \"--target-directory=/tmp/out\" src (cwd=/tmp)" \
  "install \"--target-directory=/tmp/out\" $PROJECT/CHANGELOG.md" \
  "/tmp"

expect_blocked_cwd "rsync \"--log-file=/tmp/rsynclog\" src dest (cwd=/tmp)" \
  "rsync \"--log-file=/tmp/rsynclog\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_blocked_cwd "rsync \"--partial-dir=/tmp/p\" src dest (cwd=/tmp)" \
  "rsync \"--partial-dir=/tmp/p\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# Positive cases that must remain ALLOWED:
# - unquoted --target-directory=/in-project-path (already works)
# - unquoted --log-file with in-project value
expect_allowed "install --target-directory=PROJECT/dir src" \
  "install --target-directory=$PROJECT/tests $PROJECT/CHANGELOG.md"

expect_allowed "rsync --log-file=PROJECT/log src dest" \
  "rsync --log-file=$PROJECT/tests/log.txt $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

echo ""

# ============================================================
# 26. Attached path-bearing options (--name=PATH) bypass
# ------------------------------------------------------------
# install / rsync walkers used `[[ "$TARGET" == -* ]] && continue`,
# which dropped attached options like `--target-directory=/tmp/out`,
# `--log-file=/tmp/log`, `--partial-dir=/tmp/p` regardless of
# their value. The PATH portion was never validated.
#
# Note: closes BOTH the unquoted form (pre-existing bypass not
# previously reproduced) and the quoted form (regression that
# would have been re-introduced by commit bb9e2c3).
#
# Fix shape (current, after Codex 00d7300): instead of a generic
# "any `-*=value` with `/` in value" heuristic, the walkers carry
# an explicit white-list of options that actually point at a write
# target — for `install` it is `--target-directory=`; for `rsync`
# it is `--log-file=`, `--partial-dir=`, `--backup-dir=`,
# `--temp-dir=`, `--write-batch=`, `--only-write-batch=`. Only
# values of those options are run through the boundary check;
# every other attached option (`--exclude=`, `--rsync-path=`,
# `--mode=`, `--owner=`, `--group=`, …) is skipped as a flag.
# The earlier `=*/*` heuristic both missed relative values and
# over-matched benign options carrying `/`.
# ============================================================
echo "--- 26. attached path-bearing options must be validated ---"

expect_blocked_cwd "install --target-directory=/tmp/out src (unquoted attached)" \
  "install --target-directory=/tmp/out $PROJECT/CHANGELOG.md" \
  "/tmp"

expect_blocked_cwd "rsync --log-file=/tmp/log src dest (unquoted attached)" \
  "rsync --log-file=/tmp/log $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_blocked_cwd "rsync --partial-dir=/tmp/p src dest" \
  "rsync --partial-dir=/tmp/p $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# Positive cases (P2 regression fix from earlier P1 fix):
# Quoted plain flags must remain ALLOWED — they are flag names,
# not paths.
expect_allowed_cwd "install \"--help\" (quoted plain flag)" \
  "install \"--help\"" \
  "/tmp"

expect_allowed_cwd "install \"--mode\" 0755 src dst (quoted -m two-token)" \
  "install \"--mode\" 0755 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_allowed_cwd "rsync \"--help\" (quoted plain flag)" \
  "rsync \"--help\"" \
  "/tmp"

expect_allowed_cwd "rsync \"-a\" src dest (quoted short flag)" \
  "rsync \"-a\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# Non-path attached values must remain ALLOWED.
expect_allowed_cwd "install --mode=0755 src dst (attached non-path value)" \
  "install --mode=0755 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_allowed_cwd "install --owner=root src dst (attached non-path value)" \
  "install --owner=root $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# Relative attached values must also be blocked (resolve under cwd):
expect_blocked_cwd "install --target-directory=out src (relative value, cwd=/tmp)" \
  "install --target-directory=out $PROJECT/CHANGELOG.md" \
  "/tmp"

expect_blocked_cwd "rsync --log-file=log.txt src dst (relative value, cwd=/tmp)" \
  "rsync --log-file=log.txt $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# rsync read-only / non-write flags that happen to carry slashes
# must NOT trigger the boundary check — they are not write targets.
expect_allowed_cwd "rsync --exclude=/tmp src dst (filter pattern, not a write)" \
  "rsync --exclude=/tmp $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_allowed_cwd "rsync --rsync-path=/usr/bin/rsync src host:dst (remote bin)" \
  "rsync --rsync-path=/usr/bin/rsync $PROJECT/CHANGELOG.md host:dst" \
  "/tmp"

expect_allowed_cwd "rsync --include=/conf src dst (filter include)" \
  "rsync --include=/conf $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# rsync batch-file write options (Codex commit 00d7300):
expect_blocked_cwd "rsync --write-batch=/tmp/batch src dst" \
  "rsync --write-batch=/tmp/batch $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

expect_blocked_cwd "rsync --only-write-batch=/tmp/batch src dst" \
  "rsync --only-write-batch=/tmp/batch $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

# --read-batch is a READ, not a write target — must remain ALLOWED:
expect_allowed_cwd "rsync --read-batch=/tmp/batch src dst (read-only)" \
  "rsync --read-batch=/tmp/batch $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" \
  "/tmp"

echo ""

# ============================================================
# 27. Attached-flag forms: behavior pinning for install -m/-o/-g
# ------------------------------------------------------------
# Documents what the `install` walker actually does for the four
# attached forms of mode/owner/group flags, so future doc drift
# is caught by the test suite (and not just by Copilot review on
# the next PR). No bypass exists in any of these shapes — the
# tests pin the contract:
#
#   bare:                `-m`, `--mode`         → consume next token (skip_next)
#   short attached:      `-m0644`               → ordinary flag, no skip
#   long  attached:      `--mode=0644`          → ordinary flag, no skip
#   white-listed attached: `--target-directory=`→ value validated
#
# Mode/owner/group VALUES are never validated as paths — even
# when the value syntactically looks like one (`--mode=/0644`).
# This deliberately differs from the f76ec34 `=*/*` heuristic
# (replaced by 00d7300) and matches the install grammar: those
# flags carry a mode bitmask / owner-name / group-name, not a
# filesystem path.
#
# True positives (BLOCKED) — the destination operand AFTER an
# attached flag is still validated against the project boundary.
# False positives prevented (ALLOWED) — legitimate use of every
# attached form must pass when the destination is in-project.
# ============================================================
echo "--- 27. attached-flag behavior pinning (install) ---"

# True positives: outside-project destination after attached flag
# must be BLOCKED on the destination, not on the flag itself.
expect_blocked_cwd "install -m0644 OUTSIDE (short attached + outside dest)" \
  "install -m0644 $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

expect_blocked_cwd "install --mode=0644 OUTSIDE (long attached + outside dest)" \
  "install --mode=0644 $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

expect_blocked_cwd "install --owner=root OUTSIDE (long attached + outside dest)" \
  "install --owner=root $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

expect_blocked_cwd "install --group=wheel OUTSIDE (long attached + outside dest)" \
  "install --group=wheel $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

expect_blocked_cwd "install -m0644 -o root --group=wheel OUTSIDE (mixed attached)" \
  "install -m0644 -o root --group=wheel $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

# True positive: POSIX `--` after attached flags still routes the
# trailing positional through path validation.
expect_blocked_cwd "install -m0644 -- OUTSIDE (attached then --)" \
  "install -m0644 -- $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

# False positives prevented: in-project destination, every shape.
expect_allowed "install -m0644 IN_PROJECT (short attached, in-project dest)" \
  "install -m0644 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt"

expect_allowed "install --mode=0644 IN_PROJECT (long attached, in-project dest)" \
  "install --mode=0644 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt"

expect_allowed "install -oroot IN_PROJECT (short attached owner)" \
  "install -oroot $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt"

expect_allowed "install -gwheel IN_PROJECT (short attached group)" \
  "install -gwheel $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt"

# False positives prevented: mode/owner/group VALUES that look
# like paths must NOT trigger the boundary check — they aren't
# write destinations. Pins the explicit "no path-validation for
# -mPATH / --mode=PATH" contract that 00d7300 replaced the
# earlier `=*/*` heuristic with.
expect_allowed_cwd "install --mode=/0644 IN_PROJECT (path-shaped mode value, ignored)" \
  "install --mode=/0644 $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt" \
  "/tmp"

expect_allowed_cwd "install --owner=user/group IN_PROJECT (slash in owner, ignored)" \
  "install --owner=user/group $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt" \
  "/tmp"

# Quoted attached forms behave identically to unquoted (strip_quotes
# normalizes before the flag tests):
expect_blocked_cwd "install \"-m0644\" OUTSIDE (quoted short attached)" \
  "install \"-m0644\" $PROJECT/CHANGELOG.md /tmp/install_target_t27" \
  "/tmp"

expect_allowed_cwd "install \"--mode=0644\" IN_PROJECT (quoted long attached)" \
  "install \"--mode=0644\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t27.txt" \
  "/tmp"

# ============================================================
# 28. rsync remote-path skip should require `:` in first segment
# ------------------------------------------------------------
# The rsync walker skipped any TARGET matching `=~ :` on the
# assumption that a colon meant remote (host:path / user@host:path /
# host::module / rsync://...). That blanket skip also dropped LOCAL
# paths that legitimately contain a colon AFTER the first slash
# (filenames like `a:b`, `tmp/a:b`, `../tmp/a:b`). With cwd outside
# the project, such a target slipped past the boundary check and the
# write landed at an unvalidated location.
#
# Concrete bypass:
#   cwd=/tmp; rsync $PROJECT/src.txt ../tmp/a:b
# The destination resolves to /tmp/a:b (outside project). Pre-fix the
# `=~ :` test matched and `continue` skipped path validation entirely.
# Post-fix the walker checks only the FIRST path segment for `:` (or
# requires `rsync://` URL prefix), so local colons-after-slash fall
# through to the existing path resolution and is_inside_project check.
#
# Reported by Copilot review on buildwithclaude PR #137
# (plugins/project-boundary/hooks/lib/detectors/write_targets.sh:182).
# ============================================================

expect_blocked_cwd "rsync local target with colon AFTER slash (../tmp/a:b OUTSIDE)" \
  "rsync $PROJECT/CHANGELOG.md ../tmp/a:b" \
  "/tmp"

expect_blocked_cwd "rsync local target with colon AFTER slash (./sub/a:b OUTSIDE)" \
  "rsync $PROJECT/CHANGELOG.md ./sub/a:b" \
  "/tmp"

# Positives that must keep ALLOWED — the remote-path skip still applies
# when the colon really does sit in the first segment.
expect_allowed_cwd "rsync remote host:path (host: in first segment, skipped)" \
  "rsync $PROJECT/CHANGELOG.md host:/dest" \
  "/tmp"

expect_allowed_cwd "rsync remote user@host:path (user@host: in first segment)" \
  "rsync $PROJECT/CHANGELOG.md user@host:/dest" \
  "/tmp"

expect_allowed_cwd "rsync remote rsync:// URL (skipped via URL prefix)" \
  "rsync $PROJECT/CHANGELOG.md rsync://host/dest" \
  "/tmp"

expect_allowed_cwd "rsync local target with colon-after-slash IN_PROJECT" \
  "rsync $PROJECT/CHANGELOG.md $PROJECT/tests/scratch_t28:b" \
  "/tmp"

echo ""

# ============================================================
# 49. Non-bash shell `-c` walker: zsh / ksh / dash / fish
# ------------------------------------------------------------
# The nested-shell-execution walker (guard.sh:607) hardcoded the
# regex `(bash|sh)` for `-c` inline-code blocks. zsh, ksh, dash, and
# fish all accept `-c CMD` with the same un-inspectable semantics
# but slipped past. macOS ships zsh by default, so `zsh -c <verb>`
# is a real bypass. Same root cause for the pipe-to-shell walkers
# below at guard.sh:655 / 660 (only `(sh|bash)` matched).
# Fix: extend regexes to (bash|sh|zsh|ksh|dash|fish).
# ============================================================
echo "--- 49. non-bash shell -c walker ---"

expect_blocked "zsh -c destructive" \
  "zsh -c 'rm /etc/passwd_test'"
expect_blocked "ksh -c destructive" \
  "ksh -c 'rm /etc/passwd_test'"
expect_blocked "dash -c destructive" \
  "dash -c 'rm /etc/passwd_test'"
expect_blocked "fish -c destructive" \
  "fish -c 'rm /etc/passwd_test'"
expect_blocked "/bin/zsh -c destructive" \
  "/bin/zsh -c 'rm /etc/passwd_test'"
expect_blocked "env zsh -c destructive" \
  "/usr/bin/env zsh -c 'rm /etc/passwd_test'"
expect_blocked "bare zsh piped (no script)" \
  "echo 'rm /etc/passwd_test' | zsh"
expect_blocked "zsh -s piped (only flags)" \
  "echo 'rm /etc/passwd_test' | zsh -s"

# True-negative: zsh running a script PATH inside project must stay ALLOWED
# (file-path is the script-execution walker's territory, not -c).
expect_allowed "zsh script-path inside project" \
  "zsh $PROJECT/CHANGELOG.md"

echo ""

# ============================================================
# 50. In-place editor walker covered only sed/truncate (perl/ruby)
# ------------------------------------------------------------
# inplace.sh walked sed -i and truncate; perl `-pi` / `-i` and ruby
# `-i` rewrite the file in place with identical write semantics but
# were never inspected. So `perl -pi -e "..." /etc/passwd_test`
# silently overwrote files outside the project.
#
# Bypass shapes:
#   perl -pi -e "..." /etc/x
#   perl -i -ne "..." /etc/x
#   perl -i.bak -pe "..." /etc/x       (in-place with backup suffix)
#   ruby -i -pe "" /etc/x
#   ruby -i.bak -pe "" /etc/x
#
# Fix: add a perl/ruby in-place walker mirroring sed -i — engages
# only when -i / -pi / --in-place is present, then walks every
# positional file operand through is_write_permitted.
# ============================================================
echo "--- 50. in-place edit: perl -pi / ruby -i ---"

expect_blocked "perl -pi outside" \
  "perl -pi -e 's/x/y/' /etc/passwd_test"
expect_blocked "perl -i outside" \
  "perl -i -ne 'print' /etc/passwd_test"
expect_blocked "perl -i.bak outside" \
  "perl -i.bak -pe 's/x/y/' /etc/passwd_test"
expect_blocked "ruby -i outside" \
  "ruby -i -pe '' /etc/passwd_test"
expect_blocked "ruby -i.bak outside" \
  "ruby -i.bak -pe '' /etc/passwd_test"

# True-negatives: in-place forms targeting in-project files must stay ALLOWED.
# (Note: bare `perl -e CODE` / `ruby -e CODE` are already BLOCKED by the
# generic interpreter-with-inline-code walker at guard.sh:626 — that is a
# separate fail-closed rule, not the in-place walker we add here.)
expect_allowed "perl -pi inside project" \
  "perl -pi -e 's/x/y/' $PROJECT/CHANGELOG.md"
expect_allowed "ruby -i inside project" \
  "ruby -i -pe '' $PROJECT/CHANGELOG.md"

echo ""

# ============================================================
# 51. shred — destructive overwrite verb missing from walker list
# ------------------------------------------------------------
# `shred` overwrites a file's bytes with random data (and `shred -u`
# also unlinks it). Same destruction semantics as `rm` + `dd of=`,
# but it wasn't in destructive.sh's verb table. So `shred /etc/x`
# and `shred -u /etc/x` slipped through.
#
# Fix: add a shred walker to destructive.sh — STRICT boundary
# (is_inside_project, no allowlist; allowlist grants WRITE not
# DESTROY-CONTENTS).
# ============================================================
echo "--- 51. shred destructive overwrite ---"

expect_blocked "shred /etc/x" \
  "shred /etc/passwd_test"
expect_blocked "shred -u /etc/x" \
  "shred -u /etc/passwd_test"
expect_blocked "shred -n 5 /etc/x" \
  "shred -n 5 /etc/passwd_test"
expect_blocked "shred -uvz /etc/x" \
  "shred -uvz /etc/passwd_test"
expect_blocked "/usr/bin/shred /etc/x" \
  "/usr/bin/shred /etc/passwd_test"

# True-negatives: shred inside project must remain ALLOWED (refactoring
# inside the project is the plugin's intended permission model).
expect_allowed "shred inside project" \
  "shred $PROJECT/tests/scratch.txt"
expect_allowed "shred -u inside project" \
  "shred -u $PROJECT/tests/scratch.txt"

echo ""

# ============================================================
# 52. mkdir creates directories outside project unchecked
# ------------------------------------------------------------
# `mkdir <path>` (and `mkdir -p`) was not in the walker list. While
# mkdir is not destructive on existing files, it modifies filesystem
# structure outside the project — a dropper for later writes (any
# subsequent `cp` / `tee` / `rsync` into the new directory would
# need its own walker to BLOCK, but the user clearly intended to
# write outside the boundary). The plugin's purpose is "blocks
# outside, allows inside", so creating directories outside violates
# the contract.
#
# Walker uses WRITE semantics (is_write_permitted, allowlist applies
# — same as `cp` / `mv` destinations). Walks every positional
# operand after consuming -m MODE / -Z CTX flag+value pairs.
# ============================================================
echo "--- 52. mkdir outside project ---"

expect_blocked "mkdir /etc/x" \
  "mkdir /etc/passwd_test"
expect_blocked "mkdir -p /etc/x" \
  "mkdir -p /etc/passwd_test"
expect_blocked "mkdir -p /etc/a/b/c" \
  "mkdir -p /etc/a/b/c"
expect_blocked "mkdir -m 755 /etc/x" \
  "mkdir -m 755 /etc/passwd_test"
expect_blocked "/bin/mkdir /etc/x" \
  "/bin/mkdir /etc/passwd_test"
expect_blocked "sudo mkdir -p /etc/x" \
  "sudo mkdir -p /etc/passwd_test"

# True-negatives: mkdir inside project must remain ALLOWED.
expect_allowed "mkdir inside project" \
  "mkdir $PROJECT/tests/scratch_dir"
expect_allowed "mkdir -p inside project" \
  "mkdir -p $PROJECT/tests/a/b"

echo ""

# ============================================================
# 53. git -C <outside-path> destructive walker
# ------------------------------------------------------------
# `git -C <path>` changes git's working dir to <path> for that
# invocation. Existing git walkers (subcmd_flags `-c core.sshCommand`,
# alias-exec, etc.) inspected the git invocation but didn't check
# where git was operating. So `git -C / clean -fdx` ran clean on /
# (deleting every untracked file) and `git -C ~ reset --hard`
# nuked the user's home directory — both bypassed the boundary.
#
# Same shape for `--git-dir=<path>` (sets the .git directory) when
# the path is outside the project AND the subcommand is destructive.
#
# Destructive git subcommands relevant here: clean -fd / -fdx,
# reset --hard, checkout -- / restore --staged, rm -f, branch -D,
# stash drop / clear, worktree remove.
#
# Fix: add a git -C walker to remote_dispatch.sh — when -C /
# --git-dir / -c GIT_DIR= points outside project AND a destructive
# subcommand follows, BLOCK with STRICT semantics. Read-only git
# (-C path log, status, show, diff) stays ALLOWED.
# ============================================================
echo "--- 53. git -C outside-project destructive ---"

expect_blocked "git -C / clean -fdx" \
  "git -C / clean -fdx"
expect_blocked "git -C ~ reset --hard" \
  "git -C ~ reset --hard"
expect_blocked "git -C /etc clean -fd" \
  "git -C /etc clean -fd"
expect_blocked "git -C /tmp/repo reset --hard HEAD~1" \
  "git -C /tmp/repo reset --hard HEAD~1"
expect_blocked "git --git-dir=/tmp/.git reset --hard" \
  "git --git-dir=/tmp/.git reset --hard"

# True-negatives: read-only git outside project must remain ALLOWED
# (status / log / show don't write).
expect_allowed "git -C / status (read-only)" \
  "git -C / status"
expect_allowed "git -C ~ log -1 (read-only)" \
  "git -C ~ log -1"

# True-negatives: destructive git INSIDE project must remain ALLOWED.
expect_allowed "git clean -fd (in-project, current dir)" \
  "git clean -fd"
expect_allowed "git reset --hard (in-project, current dir)" \
  "git reset --hard"
expect_allowed "git -C \$PROJECT clean -fd (explicit in-project)" \
  "git -C $PROJECT clean -fd"

echo ""

# ============================================================
# 54. ~user tilde expansion bypassed boundary check
# ------------------------------------------------------------
# `expand_path` handled `~/` (current user's HOME) and bare `~` but
# not `~user/path` (other-user home, e.g. `~root/.bashrc` →
# `/var/root/.bashrc` on macOS). Without expansion, the path stayed
# as relative-looking `~user/...`, the caller prepended
# EFFECTIVE_CWD ("$PROJECT/~user/..."), and is_inside_project
# returned TRUE — so `rm ~root/.bashrc` ALLOWED.
#
# Bash expands `~user` to that user's actual home at exec time, so
# the real target was always outside the project.
#
# Fix: add a `~user` branch in expand_path that substitutes a
# sentinel non-project absolute path (e.g. `/__tilde_other_user/`).
# We can't safely resolve to the real home without exec'ing
# getent/dscl/eval — fail-closed by routing the path through a
# guaranteed-outside-project prefix.
# ============================================================
echo "--- 54. ~user tilde expansion ---"

expect_blocked "rm ~root/.bashrc" \
  "rm ~root/.bashrc"
expect_blocked "rm ~daemon/x" \
  "rm ~daemon/x"
expect_blocked "cat /etc/passwd > ~root/x" \
  "cat /etc/passwd > ~root/x"
expect_blocked "tee ~root/x" \
  "echo y | tee ~root/x"
expect_blocked "cp file ~root/" \
  "cp $PROJECT/CHANGELOG.md ~root/"
expect_blocked "sed -i ~root/.bashrc" \
  "sed -i '' 's/x/y/' ~root/.bashrc"

# True-negatives: ~/  (current user's home) is unchanged behavior
# — still resolves to $HOME and gets normal treatment.
# Note: $HOME itself is outside project, so `rm ~/.bashrc` SHOULD
# block (this was already the case pre-patch).
expect_blocked "rm ~/.bashrc (current user home)" \
  "rm ~/.bashrc"

echo ""

# ============================================================
# 55. git -C outside: missing `submodule deinit -f` (P1, Codex)
# ------------------------------------------------------------
# Sec 53 added the git -C / --git-dir outside-project walker but
# its destructive-subcommand regex covered clean / reset --hard /
# checkout . / restore . / push --force / stash drop|clear /
# branch -D / reflog expire / rm -f / worktree remove. Codex
# adversarial review found `submodule deinit -f` missing —
# `git -C / submodule deinit -f .` removes the submodule checkout
# from the working tree, equivalent in destructiveness to
# `rm -rf` on the submodule path.
# Fix: add `submodule[[:space:]]+deinit[[:space:]]+(-[a-zA-Z]*f|--force)`
# to the regex in guard.sh.
# ============================================================
echo "--- 55. git -C / submodule deinit -f ---"

expect_blocked "git -C / submodule deinit -f ." \
  "git -C / submodule deinit -f ."
expect_blocked "git -C /etc submodule deinit --force lib" \
  "git -C /etc submodule deinit --force lib"
expect_blocked "git -C ~ submodule deinit -f ." \
  "git -C ~ submodule deinit -f ."

# True-negatives.
expect_allowed "git -C / submodule status (read-only)" \
  "git -C / submodule status"
expect_allowed "git submodule deinit (in-project)" \
  "git submodule deinit -f lib"

echo ""

# ============================================================
# 56. git -C outside: missing `filter-branch` (P2, Codex)
# ------------------------------------------------------------
# `git filter-branch` rewrites every commit and ref in the repo —
# pointed outside-project via -C, this rewrites the foreign repo's
# entire history. Different destruction shape than working-tree
# verbs (no rm/clean), but for a safety-net plugin it should be
# blocked when -C points outside.
# ============================================================
echo "--- 56. git -C / filter-branch ---"

expect_blocked "git -C / filter-branch --all" \
  "git -C / filter-branch --all"
expect_blocked "git -C ~ filter-branch HEAD" \
  "git -C ~ filter-branch HEAD"
expect_blocked "git --git-dir=/tmp/.git filter-branch --all" \
  "git --git-dir=/tmp/.git filter-branch --all"

# True-negatives.
expect_allowed "git filter-branch (in-project)" \
  "git filter-branch --all"
expect_allowed "git -C / show (read-only)" \
  "git -C / show HEAD"

echo ""
