#!/bin/bash
# Bypass reproducers (recent / sections 16-21) — heredoc parser,
# multi-heredoc body ordering, quoted command-name, /bin prefix in
# CMD_BLANKED, install / rsync walker fixes (POSIX `--`, attached
# write-target white-list, quoted-option normalization), php attached
# form, attached-flag behavior pinning, rsync first-segment-only
# remote-path skip.
# Continuation of test_bypass_reproducers_core.sh; same TDD discipline.
#
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (recent, sections 16-21)"
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
