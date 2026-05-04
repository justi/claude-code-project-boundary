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

# ============================================================
# 31. git -c core.sshCommand=<cmd> sink
# ------------------------------------------------------------
# git's `-c <key>=<value>` flag sets a config value for the duration
# of one invocation. Several config keys are exec sinks: git uses
# their value as the command line for an external program (ssh, gpg,
# editor, credential helper, pager, ...). `core.sshCommand` is the
# canonical example — its value replaces the ssh invocation when git
# opens a remote connection, and a destructive value runs locally.
#
# Different shape from sections 29 / 30: the flag value is `key=cmd`
# (a config assignment), not the command directly. Only specific
# keys are exec sinks; benign keys like `user.name` carry data, not
# code. The new "git-config" kind in SUBCMD_FLAG_SINKS uses a key
# regex to discriminate.
#
# This section pins the regression for `core.sshCommand` only;
# section 32 extends the regex to gpg.program / core.editor /
# credential.helper / pager.*.
#
# Reported by adversarial round-2 review (Claude Code session,
# 2026-05-04).
# ============================================================
echo "--- 31. git -c core.sshCommand sink ---"

expect_blocked "git -c core.sshCommand='rm /etc/x' (detached)" \
  "git -c core.sshCommand='rm /etc/passwd_test' clone foo"

expect_blocked "git -c core.sshCommand=\"rm /etc/x\" (double-quoted)" \
  "git -c core.sshCommand=\"rm /etc/passwd_test\" fetch"

expect_blocked "git -ccore.sshCommand='rm /etc/x' (attached short form)" \
  "git -ccore.sshCommand='rm /etc/passwd_test' clone foo"

# Positive cases that must remain ALLOWED after the fix:
# - git with no -c
# - git -c with a benign config key carrying ordinary data
# - git -c with a key NOT in the exec-sink regex (color.ui, alias.*)
expect_allowed "git status (no -c)" \
  "git status"

expect_allowed "git -c user.name='Foo Bar' status (benign data)" \
  "git -c user.name='Foo Bar' status"

expect_allowed "git -c user.email=foo@bar.com status" \
  "git -c user.email=foo@bar.com status"

expect_allowed "git -c color.ui=true status (benign config)" \
  "git -c color.ui=true status"

expect_allowed "git -c alias.lg='log --oneline' status (alias data)" \
  "git -c alias.lg='log --oneline' status"

echo ""

# ============================================================
# 32. git -c <other-exec-sink-keys> — extend the key regex
# ------------------------------------------------------------
# git has more exec-sink config keys than just core.sshCommand
# (covered in section 31). Each of these substitutes the value as
# the program git invokes for some subsystem:
#
#   core.editor               commit / tag -a / rebase -i
#   core.pager / pager.<cmd>  output paging
#   sequence.editor           rebase -i todo edit
#   gpg.program / gpg.ssh.program  signing
#   credential.helper         auth
#   diff.external             custom diff
#   mergetool.<tool>.cmd      merge tool invocation
#
# This section extends the git-config kind's key regex to cover the
# whole class. Benign data-only keys (user.*, color.*, alias.*,
# init.*, http.proxy, safe.directory) must remain ALLOWED.
#
# Reported by Codex review follow-up after section 31.
# ============================================================
echo "--- 32. git -c extended exec-sink key coverage ---"

expect_blocked "git -c core.editor='rm /etc/x' commit" \
  "git -c core.editor='rm /etc/passwd_test' commit"

expect_blocked "git -c core.pager='rm /etc/x' log" \
  "git -c core.pager='rm /etc/passwd_test' log"

expect_blocked "git -c pager.log='rm /etc/x' log (per-subcmd pager)" \
  "git -c pager.log='rm /etc/passwd_test' log"

expect_blocked "git -c sequence.editor='rm /etc/x' rebase" \
  "git -c sequence.editor='rm /etc/passwd_test' rebase -i HEAD~1"

expect_blocked "git -c gpg.program='rm /etc/x' commit -S" \
  "git -c gpg.program='rm /etc/passwd_test' commit -S"

expect_blocked "git -c gpg.ssh.program='rm /etc/x' commit -S" \
  "git -c gpg.ssh.program='rm /etc/passwd_test' commit -S"

expect_blocked "git -c credential.helper='rm /etc/x' fetch" \
  "git -c credential.helper='rm /etc/passwd_test' fetch"

expect_blocked "git -c diff.external='rm /etc/x' diff" \
  "git -c diff.external='rm /etc/passwd_test' diff"

expect_blocked "git -c mergetool.foo.cmd='rm /etc/x' mergetool" \
  "git -c mergetool.foo.cmd='rm /etc/passwd_test' mergetool"

# Positive cases — benign data keys must remain ALLOWED:
expect_allowed "git -c http.proxy=http://proxy:8080 fetch (URL data)" \
  "git -c http.proxy=http://proxy:8080 fetch"

expect_allowed "git -c safe.directory=/path status (path data)" \
  "git -c safe.directory=/some/path status"

expect_allowed "git -c init.defaultBranch=main init" \
  "git -c init.defaultBranch=main init"

expect_allowed "git -c push.default=current push" \
  "git -c push.default=current push"

expect_allowed "git -c color.diff=auto diff (color benign)" \
  "git -c color.diff=auto diff"

# Edge: pager.log='less -R' is a benign pager invocation (in-project
# binary `less`, no destructive payload). Validator must accept.
expect_allowed "git -c pager.log='less -R' log (benign pager)" \
  "git -c pager.log='less -R' log"

echo ""

# ============================================================
# 33. Chained sub-commands must each be expanded (not just the first)
# ------------------------------------------------------------
# expand_subcmd_flags was applied to the FULL command string before
# split_and_check splits on `;` / `&&` / `||` / `|` / newline, but
# the function only inspected the FIRST verb. A chained command
# whose later subcommand carries the exec-sink flag was therefore
# never expanded — every walker downstream saw only the original
# (un-routed) value, and the destructive payload slipped through.
#
# Example:
#   echo ok ; tar -xf foo --to-command='rm /etc/x'
# Pre-fix: expand_subcmd_flags inspects `echo`, finds no sink, the
# full string is split into [echo ok, tar ... --to-command=...]
# and check_single_command runs on each subcommand. The tar
# subcommand still has the unrouted --to-command= value — same
# state as before any patch.
#
# Fix: route the expansion per-subcommand, after splitting. The
# refactor lifts payload extraction into check_single_command and
# recursively dispatches each payload through the same function.
# Heredoc-related edge cases collapse with the same change because
# the new path never mutates the chained command string.
#
# Reported by Copilot review on PR #23 (options.sh:92).
# ============================================================
echo "--- 33. chained sub-commands per-subcmd expansion ---"

expect_blocked "echo ok ; tar -xf … --to-command='rm /etc/x' (chained ;)" \
  "echo ok ; tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "git status && tar --to-command='rm /etc/x' (chained &&)" \
  "git status && tar --to-command='rm /etc/passwd_test' -xf $PROJECT/archive.tar"

expect_blocked "false || rsync --rsh='rm /etc/x' (chained ||)" \
  "false || rsync --rsh='rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "true | git -c core.sshCommand='rm /etc/x' clone (pipe)" \
  "true | git -c core.sshCommand='rm /etc/passwd_test' clone foo"

expect_blocked "tar … --to-command='rm /etc/x' AS LATER subcmd in newline-chain" \
  "echo first
tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

# Positive: chained legitimate commands must remain ALLOWED.
expect_allowed "echo ok ; tar -xf in-project (no destructive payload)" \
  "echo ok ; tar -xf $PROJECT/archive.tar -C $PROJECT/extracted"

expect_allowed "git status && rsync -e ssh src host:dst (benign chain)" \
  "git status && rsync -e ssh $PROJECT/CHANGELOG.md host:/dst"

echo ""

# ============================================================
# 34. rsync clustered short flags — `-avze <cmd>`
# ------------------------------------------------------------
# rsync (and getopt-style CLIs in general) accepts clustered short
# flags: `-avze` is shorthand for `-a -v -z -e`. Because `-e`
# consumes the next token as its value, a clustered form ending in
# `e` makes the following token the exec-sink value. The previous
# parser only recognised `-e VAL` (own token) and `-eVAL` (attached
# form), so `rsync -avze 'rm /etc/x' src host:dst` slipped through.
#
# Fix: when the token is a short-flag cluster (starts with `-`,
# does not start with `--`, longer than the bare short flag, and
# its last character matches the sink's short-flag letter), treat
# it like a detached short flag — consume the next token as the
# value.
#
# Reported by Copilot review on PR #23 (subcmd_flags.sh:167).
# ============================================================
echo "--- 34. rsync clustered short flags ---"

expect_blocked "rsync -avze 'rm /etc/x' src host:dst (full cluster)" \
  "rsync -avze 'rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "rsync -ae 'rm /etc/x' src host:dst (minimal cluster)" \
  "rsync -ae 'rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

expect_blocked "rsync -ze 'rm /etc/x' src host:dst (compress + e)" \
  "rsync -ze 'rm /etc/passwd_test' $PROJECT/CHANGELOG.md host:/dst"

# Positive cases: clustered forms with a benign value, or clusters
# whose last char is NOT `e` (no exec sink consumed).
expect_allowed "rsync -avze ssh src host:dst (benign cluster)" \
  "rsync -avze ssh $PROJECT/CHANGELOG.md host:/dst"

expect_allowed "rsync -avz src dst (no -e at end)" \
  "rsync -avz $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

expect_allowed "rsync -avzh src dst (cluster ends in -h, not exec sink)" \
  "rsync -avzh $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt"

echo ""
