#!/bin/bash
# Bypass reproducers (sections 29+) — argument-as-command sinks.
#
# A category of tools that take a SHELL COMMAND as the value of a
# specific flag and execute it locally at runtime: tar --to-command=,
# rsync -e= / --rsh=, git -c core.sshCommand= / gpg.program= /
# core.editor= / credential.helper= / pager.*. The exec happens on
# the LOCAL filesystem this guard protects, so the value must be
# walked by the destructive / write-target detectors — but the
# walkers only see flag names, not flag values.
#
# Same shape as the find -exec sink (already covered) and the
# remote-dispatch verbs from issue #21 (ssh / docker exec / kubectl
# exec): a side channel that bypasses bare-name regex detection.
#
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (flags, sections 29+)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# 29. tar --to-command=<cmd> sink
# ------------------------------------------------------------
# GNU tar's --to-command flag executes the given shell command for
# every member of the archive at extract time. A value like
# `rm /etc/x` is therefore a live exec sink, not opaque data — and
# the value can sit on either side of the verb / archive operands.
#
# Pre-fix: the guard tokenizes the cmd, recognises `tar` and walks
# its path operands (-C, -f, --file, ...), but never inspects the
# `--to-command=` value or its space-separated form. Both attached
# (`--to-command='rm /etc/x'`) and detached (`--to-command 'rm
# /etc/x'`) shapes pass.
#
# Reported by adversarial round-2 review (Claude Code session,
# 2026-05-04).
# ============================================================
echo "--- 29. tar --to-command sink ---"

expect_blocked "tar -xf attached --to-command='rm /etc/x'" \
  "tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "tar --extract --file= attached --to-command (long form)" \
  "tar --extract --file=$PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "tar -xf detached --to-command 'rm /etc/x' (space form)" \
  "tar -xf $PROJECT/archive.tar --to-command 'rm /etc/passwd_test'"

expect_blocked "tar -xf attached --to-command with sed -i to /etc" \
  "tar -xf $PROJECT/archive.tar --to-command=\"sed -i 's/a/b/' /etc/passwd_test\""

expect_blocked "tar -xf with --to-command paired with destructive truncate" \
  "tar -xf $PROJECT/archive.tar --to-command='truncate -s 0 /etc/passwd_test'"

# Positive cases that must remain ALLOWED after the fix:
# - tar with no --to-command (current path-walker behaviour preserved)
# - tar --to-command pointing at a benign read-only command
# - tar create (-c) with --to-command targeting in-project (literal,
#   command never actually runs because -c, but the validator must
#   not over-block on the literal)
expect_allowed "tar -xf without --to-command (in-project archive)" \
  "tar -xf $PROJECT/archive.tar -C $PROJECT/extracted"

expect_allowed "tar -xf --to-command='cat' (read-only payload)" \
  "tar -xf $PROJECT/archive.tar --to-command='cat'"

expect_allowed "tar -xf --to-command='echo done' (literal echo)" \
  "tar -xf $PROJECT/archive.tar --to-command='echo done'"

expect_allowed "tar -xf --to-command='rm PROJECT/file' (in-project rm payload)" \
  "tar -xf $PROJECT/archive.tar --to-command='rm $PROJECT/tests/scratch.txt'"

echo ""

# ============================================================
# 30. rsync -e / --rsh=<cmd> sink
# ------------------------------------------------------------
# rsync's -e (short) / --rsh (long) flag substitutes a custom remote
# shell. rsync passes the substituted string to a `sh -c` invocation
# at runtime, so a value like `rm /etc/x` is a live exec sink the
# moment rsync would actually start a connection. Same shape as
# tar --to-command (section 29).
#
# Both attached and detached forms must be covered: `rsync -e VAL`,
# `rsync -eVAL`, `rsync --rsh=VAL`, `rsync --rsh VAL`.
#
# Reported by adversarial round-2 review (Claude Code session,
# 2026-05-04).
# ============================================================
echo "--- 30. rsync -e / --rsh sink ---"

expect_blocked "rsync -e 'rm /etc/x' (short detached)" \
  "rsync -e 'rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "rsync --rsh='rm /etc/x' (long attached)" \
  "rsync --rsh='rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "rsync --rsh 'rm /etc/x' (long detached)" \
  "rsync --rsh 'rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "rsync -e \"sed -i s/a/b/ /etc/x\" (short detached, sed payload)" \
  "rsync -e \"sed -i 's/a/b/' /etc/passwd_test\" $PROJECT/CHANGELOG.md host:/dst"

# Positive cases that must remain ALLOWED after the fix:
# - rsync without -e / --rsh
# - rsync with benign -e value (ssh / ssh -p 22 — no destructive path)
# - rsync --version, --help
expect_allowed "rsync -a src dst (no -e, in project)" \
  "rsync -a $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "rsync -e ssh src host:dst (benign ssh value)" \
  "rsync -e ssh $PROJECT/CHANGELOG.md host:/dst"

expect_allowed "rsync --rsh='ssh -p 2222' src host:dst (ssh with port)" \
  "rsync --rsh='ssh -p 2222' $PROJECT/CHANGELOG.md host:/dst"

expect_allowed "rsync --version" \
  "rsync --version"

echo ""
