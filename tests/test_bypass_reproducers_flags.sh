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

# ============================================================
# 35. Additional git-config exec-sink keys
# ------------------------------------------------------------
# Section 32 covered the most common exec-sink config keys but
# missed several that also substitute the value as a program git
# invokes:
#
#   core.askPass               password / passphrase prompt helper
#   core.fsmonitor             file-system monitor command
#   uploadpack.packObjectsHook hook run when packing for transfer
#   filter.<name>.clean        content filter (working tree -> index)
#   filter.<name>.smudge       content filter (index -> working tree)
#   filter.<name>.process      long-running filter process
#   diff.<name>.command        custom diff driver
#   diff.<name>.textconv       text-conversion command for diff
#   merge.<name>.driver        custom merge driver
#
# Reported by Codex review on PR #23 (Q6).
# ============================================================
echo "--- 35. additional git-config exec-sink keys ---"

expect_blocked "git -c core.askPass='rm /etc/x' fetch" \
  "git -c core.askPass='rm /etc/passwd_test' fetch"

expect_blocked "git -c core.fsmonitor='rm /etc/x' status" \
  "git -c core.fsmonitor='rm /etc/passwd_test' status"

expect_blocked "git -c uploadpack.packObjectsHook='rm /etc/x' fetch" \
  "git -c uploadpack.packObjectsHook='rm /etc/passwd_test' fetch"

expect_blocked "git -c filter.lfs.clean='rm /etc/x' add" \
  "git -c filter.lfs.clean='rm /etc/passwd_test' add file.txt"

expect_blocked "git -c filter.lfs.smudge='rm /etc/x' checkout" \
  "git -c filter.lfs.smudge='rm /etc/passwd_test' checkout file.txt"

expect_blocked "git -c filter.lfs.process='rm /etc/x' add" \
  "git -c filter.lfs.process='rm /etc/passwd_test' add file.txt"

expect_blocked "git -c diff.foo.command='rm /etc/x' diff" \
  "git -c diff.foo.command='rm /etc/passwd_test' diff"

expect_blocked "git -c diff.foo.textconv='rm /etc/x' diff" \
  "git -c diff.foo.textconv='rm /etc/passwd_test' diff"

expect_blocked "git -c merge.foo.driver='rm /etc/x' merge" \
  "git -c merge.foo.driver='rm /etc/passwd_test' merge"

# Positive cases — these config keys are NOT exec sinks and must
# remain ALLOWED:
expect_allowed "git -c filter.lfs.required=true add (boolean filter config)" \
  "git -c filter.lfs.required=true add file.txt"

expect_allowed "git -c merge.foo.name='My driver' merge (friendly name string)" \
  "git -c merge.foo.name='My driver' merge"

expect_allowed "git -c diff.foo.cachetextconv=true diff (boolean)" \
  "git -c diff.foo.cachetextconv=true diff"

expect_allowed "git -c protocol.allow=user fetch" \
  "git -c protocol.allow=user fetch"

echo ""

# ============================================================
# 36. More git-config exec-sink keys (gpg.<format>.program, submodule.<n>.update)
# ------------------------------------------------------------
# Codex round-2 review on PR #23 (Q8) flagged three more keys:
#
#   gpg.openpgp.program        OpenPGP signing program
#   gpg.x509.program           X.509 / S/MIME signing program
#   submodule.<name>.update    only an exec sink when value starts
#                              with `!` (everything else is a
#                              reserved word: rebase / merge /
#                              checkout / none).
#
# `submodule.<n>.update` requires special handling: the new
# git-config-bang kind strips the leading `!` before dispatching
# the payload (and skips values that don't begin with `!`, since
# those are reserved words, not commands).
# ============================================================
echo "--- 36. more git-config exec-sink keys ---"

expect_blocked "git -c gpg.openpgp.program='rm /etc/x' commit -S" \
  "git -c gpg.openpgp.program='rm /etc/passwd_test' commit -S"

expect_blocked "git -c gpg.x509.program='rm /etc/x' commit -S" \
  "git -c gpg.x509.program='rm /etc/passwd_test' commit -S"

expect_blocked "git -c submodule.foo.update='!rm /etc/x' submodule update" \
  "git -c submodule.foo.update='!rm /etc/passwd_test' submodule update"

# Positive cases that must remain ALLOWED:
expect_allowed "git -c submodule.foo.update=rebase submodule update" \
  "git -c submodule.foo.update=rebase submodule update"

expect_allowed "git -c submodule.foo.update=merge submodule update" \
  "git -c submodule.foo.update=merge submodule update"

expect_allowed "git -c submodule.foo.update=checkout submodule update" \
  "git -c submodule.foo.update=checkout submodule update"

expect_allowed "git -c submodule.foo.update=none submodule update" \
  "git -c submodule.foo.update=none submodule update"

echo ""

# ============================================================
# 37. git-config keys are case-insensitive
# ------------------------------------------------------------
# git treats configuration keys as case-insensitive (`Core.SshCommand`
# == `core.sshCommand`), but the exec-sink regex match was case-
# sensitive (`[[ "$key" =~ $regex ]]` without nocasematch). A bypass
# like `git -c Core.SshCommand='rm /etc/x' clone foo` therefore
# slipped past the regex.
#
# Fix: enable nocasematch around the regex test (save/restore the
# previous shopt state so callers are unaffected).
#
# Reported by Copilot review on PR #23 (subcmd_flags.sh:203).
# ============================================================
echo "--- 37. git-config case-insensitive keys ---"

expect_blocked "git -c Core.SshCommand='rm /etc/x' (CamelCase key)" \
  "git -c Core.SshCommand='rm /etc/passwd_test' clone foo"

expect_blocked "git -c CORE.SSHCOMMAND='rm /etc/x' (uppercase key)" \
  "git -c CORE.SSHCOMMAND='rm /etc/passwd_test' clone foo"

expect_blocked "git -c GPG.Program='rm /etc/x' (mixed case)" \
  "git -c GPG.Program='rm /etc/passwd_test' commit -S"

# True-negative: still differentiate exec keys from data keys
# (case-insensitively).
expect_allowed "git -c USER.Name='Foo Bar' status (case-insensitive non-sink)" \
  "git -c USER.Name='Foo Bar' status"

echo ""

# ============================================================
# 38. git -c alias.<name>='!cmd' is an exec sink
# ------------------------------------------------------------
# git aliases support shell commands when the value starts with
# `!`. `git -c alias.pwn='!rm /etc/x' pwn` runs the destructive
# command as a shell command. Section 31 / 32 explicitly excluded
# `alias.*` from the exec-sink regex (treating it as data only),
# missing the bang-prefix exec form.
#
# Same shape as `submodule.<n>.update` (section 36) — only the
# bang-prefixed variant is an exec sink. Generalises the previous
# special-case to a list of bang-required keys: alias.<n>,
# submodule.<n>.update, credential.helper.
#
# Reported by Codex review round-3 on PR #23 (P1).
# ============================================================
echo "--- 38. git -c alias.<n>='!cmd' exec sink ---"

expect_blocked "git -c alias.pwn='!rm /etc/x' pwn" \
  "git -c alias.pwn='!rm /etc/passwd_test' pwn"

expect_blocked "git -c alias.foo='!sed -i s/a/b/ /etc/x' foo" \
  "git -c alias.foo=\"!sed -i 's/a/b/' /etc/passwd_test\" foo"

# True-negatives: non-bang aliases are git-internal subcommands,
# not shell commands.
expect_allowed "git -c alias.lg='log --oneline' lg (no bang)" \
  "git -c alias.lg='log --oneline' lg"

expect_allowed "git -c alias.co=checkout co (single subcommand)" \
  "git -c alias.co=checkout co"

echo ""

# ============================================================
# 39. `git config <key> <value>` form
# ------------------------------------------------------------
# `git config` is the long-form alternative to `git -c`. Setting an
# exec-sink config persistently runs the same shell command at the
# next git operation; a destructive value is therefore still a
# live exec sink even when set via `git config` rather than `-c`.
# Sections 31-38 only recognised the `-c` flag-attached form.
#
# Forms to recognise:
#   git config <key> <value>
#   git config --global <key> <value>
#   git config --system <key> <value>
#   git config --local <key> <value>
#   git config --file PATH <key> <value>
#
# Read-only forms (--get, --list, --get-all, --get-regexp) carry
# no value to dispatch and must remain ALLOWED.
#
# Reported by Codex review round-3 on PR #23 (P2).
# ============================================================
echo "--- 39. git config <key> <value> exec-sink form ---"

expect_blocked "git config core.sshCommand 'rm /etc/x'" \
  "git config core.sshCommand 'rm /etc/passwd_test'"

expect_blocked "git config --global core.sshCommand 'rm /etc/x'" \
  "git config --global core.sshCommand 'rm /etc/passwd_test'"

expect_blocked "git config --system gpg.program 'rm /etc/x'" \
  "git config --system gpg.program 'rm /etc/passwd_test'"

expect_blocked "git config --local credential.helper 'rm /etc/x'" \
  "git config --local credential.helper 'rm /etc/passwd_test'"

# True-negatives:
expect_allowed "git config user.name 'Foo Bar' (data-only key)" \
  "git config user.name 'Foo Bar'"

expect_allowed "git config --get core.sshCommand (read-only get)" \
  "git config --get core.sshCommand"

expect_allowed "git config --list (list subcommand)" \
  "git config --list"

expect_allowed "git config --global user.email foo@bar.com" \
  "git config --global user.email foo@bar.com"

echo ""

# ============================================================
# 40. sudo / env / timeout opt-flags before the real verb
# ------------------------------------------------------------
# `_sf_find_verb_idx` skipped the wrapper command (`sudo`, `env`,
# `nohup`, `timeout`, ...) but not its OPTION-WITH-VALUE flags.
# For common forms like `sudo -u root tar --to-command='<payload>'`
# the verb-finder treated `root` as the verb (not `tar`), so the
# sink table never matched and the destructive payload slipped
# past extract_subcmd_flag_payloads entirely.
#
# Fix: per-wrapper list of options-that-consume-the-next-token,
# walked alongside the wrapper-skip pass. `sudo -u USER`,
# `env -u VAR`, `timeout -k DUR`, `timeout -s SIG`, etc. now
# advance the verb-finder past both the flag and its value.
# Bonus: timeout duration suffix matching extended with `inf`/
# `infinity`.
#
# Reported by Copilot review on PR #23 (guard.sh:897 — verb
# mis-identification under sudo / env wrappers; subcmd_flags.sh:84
# — timeout duration suffixes).
# ============================================================
echo "--- 40. wrapper opt-flags before verb ---"

expect_blocked "sudo -u root tar --to-command='rm /etc/x'" \
  "sudo -u root tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "sudo --user=root tar (long attached, already ok) + payload" \
  "sudo --user=root tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "env -u FOO tar --to-command='rm /etc/x'" \
  "env -u FOO tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "timeout -k 5 10 tar --to-command='rm /etc/x'" \
  "timeout -k 5 10 tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "timeout -s 9 1.5s tar --to-command='rm /etc/x' (suffix duration)" \
  "timeout -s 9 1.5s tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "nice -n 10 tar --to-command='rm /etc/x'" \
  "nice -n 10 tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

# Positive: wrapper without exec-sink-bearing verb stays ALLOWED.
expect_allowed "sudo -u root ls (benign command, no sink)" \
  "sudo -u root ls"

expect_allowed "env -u FOO PROJECT-relative read (no sink)" \
  "env -u FOO cat $PROJECT/CHANGELOG.md"

echo ""

# ============================================================
# 41. Wrapper opt-flags before verb in command_name.sh helpers
# ------------------------------------------------------------
# Same root cause as section 40, different functions:
# `strip_command_name_prefix`, `strip_command_name_quotes`, and
# `command_name_is` in hooks/lib/command_name.sh skipped wrapper
# tokens (sudo / env / nice / timeout / ionice / chrt) and bare
# `-flag` tokens, but NOT a wrapper's option-with-value pairs.
#
# Three concrete bypasses fall out of this:
#
# 1. command_name_is install — the install detector is gated on
#    the actual command-name token (by design, to avoid false-
#    positives on `npm install` / `cargo install` / etc.). With
#    `sudo -u root install ...`, the helper saw `-u` as a flag
#    (skipped) and `root` as the verb; the install detector never
#    fired and the destination was never validated.
#
# 2. strip_command_name_prefix — `/bin/rm` -> `rm` rewriting (so
#    bare-name walkers match) gave up at the orphaned wrapper
#    value. `sudo -u root /bin/rm /etc/x` left `/bin/rm` un-rewritten
#    and the bare rm walker (`(^|\s)rm\s`) missed it.
#
# 3. strip_command_name_quotes — `"rm"` / `'rm'` -> `rm`,
#    same pattern.
#
# Two-part fix (mirror section 40):
#
# A. _cn_wrapper_opts_with_val table per wrapper, walked alongside
#    the existing wrapper-skip pass in all three helpers.
#
# B. The literal `sudo ` strip in check_single_command also strips
#    sudo's option-value pairs (-u USER, --user=USER, etc.), so by
#    the time the helpers run, `sudo -u root` has been removed
#    entirely. Without (B) the post-sudo-strip CMD has orphaned
#    `-u root` which the helper wrapper-walk cannot anchor (sudo
#    is no longer in the token list). env / nice / ionice / timeout
#    are NOT literal-stripped, so the per-wrapper opt-skip in (A)
#    handles them on its own.
#
# Reported by Codex review round-4 on PR #23 (out-of-scope follow-up:
# analogous wrapper-skip risk in command_name.sh / remote_dispatch.sh).
# ============================================================
echo "--- 41. wrapper opt-flags in command_name.sh helpers ---"

# command_name_is install — sudo / env / nice / timeout / ionice variants.
expect_blocked "sudo -u root install -m 755 ... /etc/owned" \
  "sudo -u root install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "env -u FOO install -m 755 ... /etc/owned" \
  "env -u FOO install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "nice -n 10 install -m 755 ... /etc/owned" \
  "nice -n 10 install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "timeout -k 5 10 install -m 755 ... /etc/owned" \
  "timeout -k 5 10 install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "ionice -c 3 install -m 755 ... /etc/owned" \
  "ionice -c 3 install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

# strip_command_name_prefix — /bin/rm normalization under wrappers.
expect_blocked "sudo -u root /bin/rm /etc/passwd_test" \
  "sudo -u root /bin/rm /etc/passwd_test"

expect_blocked "env -u FOO /bin/rm /etc/passwd_test" \
  "env -u FOO /bin/rm /etc/passwd_test"

expect_blocked "nice -n 10 /bin/rm /etc/passwd_test" \
  "nice -n 10 /bin/rm /etc/passwd_test"

expect_blocked "timeout -k 5 10 /bin/rm /etc/passwd_test" \
  "timeout -k 5 10 /bin/rm /etc/passwd_test"

# strip_command_name_quotes — quoted command name under wrappers.
expect_blocked 'sudo -u root "rm" /etc/passwd_test' \
  "sudo -u root \"rm\" /etc/passwd_test"

expect_blocked "nice -n 10 'rm' /etc/passwd_test" \
  "nice -n 10 'rm' /etc/passwd_test"

# Long-form attached opt: --user=root must also be skipped from sudo.
expect_blocked "sudo --user=root install -m 755 ... /etc/owned" \
  "sudo --user=root install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

# True-negatives: legit reads / non-destructive uses must remain ALLOWED.
expect_allowed "sudo -u root cat (read in-project)" \
  "sudo -u root cat $PROJECT/CHANGELOG.md"

expect_allowed "env -u FOO cat (read in-project)" \
  "env -u FOO cat $PROJECT/CHANGELOG.md"

expect_allowed "env -u FOO npm install (npm subcmd, not GNU install)" \
  "env -u FOO npm install"

expect_allowed "nice -n 10 ls (benign command)" \
  "nice -n 10 ls $PROJECT"

echo ""

# ============================================================
# 42. Wrapper opt-flags before verb in remote_dispatch.sh
# ------------------------------------------------------------
# Final piece of the same wrapper-opt-flag root cause: `_rd_find_verb_idx`
# in hooks/lib/remote_dispatch.sh skipped wrapper tokens (sudo / env /
# nice / timeout / ionice) and bare `-flag` tokens, but NOT a wrapper's
# option-with-value pairs. With `env -u FOO docker exec ctr rm -rf /`
# the verb-finder treated `FOO` as the verb (not `docker`) and the
# `docker exec` neutralisation never fired — leaving the foreign-fs
# `rm -rf /` visible to the bare rm walker, which over-blocked the
# (legitimate) container-side cleanup.
#
# Direction is OVER-block, not bypass: the broken neutralisation
# leaves remote command strings exposed to the local-fs walkers, so
# the failure mode is "false positive on legitimate `docker exec` /
# `kubectl exec` / `ssh` invocations". The fix tightens the verb-
# finder so the dispatch class is recognised and the cmd is correctly
# collapsed before the local walkers run.
#
# Sudo cases are already covered by section 41's sudo-strip-with-opts
# (sudo + opts are gone before rewrite_remote_dispatch sees CMD). This
# section pins env / nice / timeout / ionice variants and keeps a
# regression test for the kubectl cp download path that must stay
# BLOCKED.
#
# Reported by Codex review round-4 on PR #23 (out-of-scope follow-up).
# ============================================================
echo "--- 42. wrapper opt-flags in remote_dispatch.sh ---"

# Over-block fix: docker exec / kubectl exec must collapse cleanly so
# the foreign-fs verb body is NOT walked by local-path walkers.
expect_allowed "env -u FOO docker exec ctr rm -rf / (foreign fs)" \
  "env -u FOO docker exec ctr rm -rf /"

expect_allowed "nice -n 10 docker exec ctr rm -rf / (foreign fs)" \
  "nice -n 10 docker exec ctr rm -rf /"

expect_allowed "timeout -k 5 10 docker exec ctr rm -rf / (foreign fs)" \
  "timeout -k 5 10 docker exec ctr rm -rf /"

expect_allowed "ionice -c 3 docker exec ctr rm -rf / (foreign fs)" \
  "ionice -c 3 docker exec ctr rm -rf /"

expect_allowed "env -u FOO kubectl exec pod -- rm -rf / (foreign fs)" \
  "env -u FOO kubectl exec pod -- rm -rf /"

expect_allowed "nice -n 10 kubectl exec pod -- rm -rf / (foreign fs)" \
  "nice -n 10 kubectl exec pod -- rm -rf /"

# Regression-pin: even with the fix, kubectl cp / docker cp DOWNLOAD to
# a host destination must STILL block. The remote-copy rewrite
# (_rd_rewrite_remote_copy) emits a synthetic `cp <local-dst>` so the
# cp walker validates the host-side write target.
expect_blocked "env -u FOO kubectl cp pod:/x /etc/owned (download)" \
  "env -u FOO kubectl cp pod:/x /etc/passwd_test"

expect_blocked "nice -n 10 docker cp ctr:/x /etc/owned (download)" \
  "nice -n 10 docker cp ctr:/x /etc/passwd_test"

# True-negative: ssh remote command stays ALLOWED — the cmd runs on
# the remote host and the local fs is not the target.
expect_allowed "env -u FOO ssh host 'rm /etc/x' (remote dispatch)" \
  "env -u FOO ssh host 'rm /etc/passwd_test'"

expect_allowed "nice -n 10 ssh host 'rm /etc/x' (remote dispatch)" \
  "nice -n 10 ssh host 'rm /etc/passwd_test'"

echo ""

# ============================================================
# 43. Valueless sudo flags mis-classified as value-bearing
# ------------------------------------------------------------
# The sudo opt tables in sections 40 / 41 / 42 listed `-A` (askpass),
# `-K` (kill-cache), `-k` (invalidate-timestamp), and `--preserve-env`
# in the value-bearing branch — i.e. the wrapper-walk and the new
# strip_sudo_wrapper_with_opts both consumed the next token as the
# flag's value. But these sudo flags are VALUE-LESS (they do not take
# an argument); skipping the next token strips the actual verb.
#
# Concrete bypasses Codex round-1 on PR #24 surfaced:
#
#   sudo -A install -m 755 src /etc/owned       (askpass valueless)
#   sudo -k install -m 755 src /etc/owned       (invalidate-ts valueless)
#   sudo -K install -m 755 src /etc/owned       (kill-cache valueless)
#   sudo --preserve-env install ... /etc/owned  (long valueless)
#   sudo -A /bin/rm /etc/passwd                 (same on /bin/rm path)
#
# Fix: split the sudo opt tables into a value-bearing list (`-C -D -g
# -h -p -r -t -T -U -u`, and the long forms `--close-from --chdir
# --group --host --prompt --role --type --command-timeout
# --other-user --user --auth-type`) and let everything else fall
# through to the generic value-less `-*` branch (i += 1). Applied
# symmetrically across hooks/lib/command_name.sh,
# hooks/lib/subcmd_flags.sh, hooks/lib/remote_dispatch.sh and
# strip_sudo_wrapper_with_opts.
#
# Reported by Codex review round-1 on PR #24 (P1; same root cause as
# `-A` / `-K` / `-k` / `--preserve-env` being mis-listed in the
# section 40 fix from PR #23, propagated forward into sections 41 / 42).
# ============================================================
echo "--- 43. valueless sudo flags mis-classified as value-bearing ---"

# command_name_is install bypass with valueless sudo flags.
expect_blocked "sudo -A install -m 755 ... /etc/owned" \
  "sudo -A install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo -k install -m 755 ... /etc/owned" \
  "sudo -k install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo -K install -m 755 ... /etc/owned" \
  "sudo -K install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo --preserve-env install -m 755 ... /etc/owned" \
  "sudo --preserve-env install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

# strip_command_name_prefix bypass with the same flags.
expect_blocked "sudo -A /bin/rm /etc/passwd_test" \
  "sudo -A /bin/rm /etc/passwd_test"

expect_blocked "sudo --preserve-env /bin/rm /etc/passwd_test" \
  "sudo --preserve-env /bin/rm /etc/passwd_test"

# Subcmd-flag sink bypass (section 40 territory) with valueless sudo flag.
expect_blocked "sudo -A tar --to-command='rm /etc/x'" \
  "sudo -A tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

expect_blocked "sudo --preserve-env tar --to-command='rm /etc/x'" \
  "sudo --preserve-env tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

# Nested wrapper combination Codex flagged as untested.
expect_blocked "sudo nice -n 10 install -m 755 ... /etc/owned" \
  "sudo nice -n 10 install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

# True-negatives: legit sudo with valueless flags must remain ALLOWED.
expect_allowed "sudo -A cat (askpass + read in-project)" \
  "sudo -A cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo -k ls (invalidate-ts + benign)" \
  "sudo -k ls $PROJECT"

expect_allowed "sudo --preserve-env cat (long valueless + read)" \
  "sudo --preserve-env cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo -E cat (preserve-env short, valueless)" \
  "sudo -E cat $PROJECT/CHANGELOG.md"

# Regression-pin: value-bearing forms must still consume their value.
expect_blocked "sudo -p 'pwd:' install ... /etc/owned (-p prompt takes value)" \
  "sudo -p 'pwd:' install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo -C 100 install ... /etc/owned (-C close-from takes value)" \
  "sudo -C 100 install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

echo ""

# ============================================================
# 44. Missing sudo value-bearing flags — `-a` / `-R` / `--chroot`
# ------------------------------------------------------------
# Round-1 fixed `-A` / `-K` / `-k` / `--preserve-env` mis-listed as
# value-bearing. Round-2 found the OPPOSITE error in the same set:
# three sudo flags that DO take a value were missing from the
# value-bearing list. Per `man sudo` (1.9.x):
#
#   -a type  / --auth-type=type   BSD authentication type
#   -R dir   / --chroot=dir       chroot directory before running cmd
#   -T sec   / --command-timeout  (already in list)
#
# Without these in the value-bearing branch, `sudo -a bsdauth install
# ...` was walked as `bsdauth install ...` — the verb-finder treated
# `bsdauth` as the verb and the install detector never fired. Same
# bypass shape as round-1 but for a complementary subset of sudo's
# option grammar.
#
# Fix: add `-a`, `-R`, `--chroot` to all four sites (three module
# tables — _cn_ / _sf_ / _rd_ — plus strip_sudo_wrapper_with_opts).
#
# Reported by Codex review round-2 on PR #24 (P1).
# ============================================================
echo "--- 44. missing sudo value-bearing flags (-a / -R / --chroot) ---"

# command_name_is install bypass.
expect_blocked "sudo -a bsdauth install ... /etc/owned" \
  "sudo -a bsdauth install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo -R / install ... /etc/owned" \
  "sudo -R / install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo --chroot / install ... /etc/owned" \
  "sudo --chroot / install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

# strip_command_name_prefix bypass on /bin/rm.
expect_blocked "sudo -a bsdauth /bin/rm /etc/passwd_test" \
  "sudo -a bsdauth /bin/rm /etc/passwd_test"

expect_blocked "sudo -R / /bin/rm /etc/passwd_test" \
  "sudo -R / /bin/rm /etc/passwd_test"

# Subcmd-flag exec-sink bypass.
expect_blocked "sudo -a bsdauth tar --to-command='rm /etc/x'" \
  "sudo -a bsdauth tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

# True-negatives: legit sudo with these flags + read must remain ALLOWED.
expect_allowed "sudo -a bsdauth cat (read in-project)" \
  "sudo -a bsdauth cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo -R / cat (chroot + read)" \
  "sudo -R / cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo --chroot / ls (long-form chroot + benign)" \
  "sudo --chroot / ls $PROJECT"

echo ""

# ============================================================
# 45. Empty-CMD shell-opening sudo (`sudo -i` / `sudo -s`)
# ------------------------------------------------------------
# When `strip_sudo_wrapper_with_opts` (commit 76cc301) consumes all
# sudo flags and reaches the end of the token list with no positional
# verb, it returns an empty string. Three shapes hit this:
#
#   sudo            bare invocation (prints usage; harmless)
#   sudo -l|-V|-v   list creds / version / validate-only (harmless)
#   sudo -i|-s      open a privileged interactive shell — DANGEROUS
#   sudo --login    long-form -i (DANGEROUS)
#   sudo --shell    long-form -s (DANGEROUS)
#
# The previous code didn't re-check for an empty CMD after the sudo
# strip; downstream walkers ran on `""` and crashed (`tokens[@]:
# unbound variable` under `set -u`) before exiting ALLOWED. Net
# effect: a bare `bash` invocation correctly blocks (interactive
# shell whose subsequent commands cannot be inspected), but `sudo -i`
# (a strictly more privileged equivalent) slipped through.
#
# Fix: after the sudo strip, re-check for empty CMD. If empty AND
# `_CMD_PRE_STRIP` contained `-i` / `-s` / `--login` / `--shell` as
# a standalone token, block — same rationale as the existing bare
# shell-execute walker. Otherwise return 0 (harmless empty).
#
# Reported by Codex review round-2 on PR #24 (P2 finding).
# ============================================================
echo "--- 45. empty-CMD shell-opening sudo ---"

# Shell-opening sudo invocations must BLOCK (privileged interactive shell).
expect_blocked "sudo -i (login shell)" \
  "sudo -i"

expect_blocked "sudo -s (shell)" \
  "sudo -s"

expect_blocked "sudo --login (long-form -i)" \
  "sudo --login"

expect_blocked "sudo --shell (long-form -s)" \
  "sudo --shell"

expect_blocked "sudo -A -i (askpass + login shell)" \
  "sudo -A -i"

expect_blocked "sudo -u root -i (user + login shell)" \
  "sudo -u root -i"

# True-negatives: harmless empty-after-strip shapes must remain ALLOWED.
expect_allowed "bare sudo (prints usage, harmless)" \
  "sudo"

expect_allowed "sudo -l (list creds, harmless)" \
  "sudo -l"

expect_allowed "sudo -V (version, harmless)" \
  "sudo -V"

expect_allowed "sudo -v (validate timestamp, harmless)" \
  "sudo -v"

expect_allowed "sudo --list (long-form -l)" \
  "sudo --list"

expect_allowed "sudo --version (long-form -V)" \
  "sudo --version"

echo ""

# ============================================================
# 46. Missing sudo value-bearing flag — `-c` / `--login-class`
# ------------------------------------------------------------
# Round-2 added `-a` / `-R` / `--chroot`. Round-3 found one more
# value-bearing sudo flag still absent from the list. Per `man sudo`
# (1.9.x):
#
#   -c class / --login-class=class   BSD login class
#
# Without it in the value-bearing branch, `sudo -c staff install
# ... /etc/owned` was walked as `staff install ...` — the verb-
# finder treated `staff` as the verb. Same bypass shape as round-2
# section 44 (-a / -R / --chroot), one missing flag.
#
# Reported by Codex review round-3 on PR #24 (P1).
# ============================================================
echo "--- 46. missing sudo value-bearing flag (-c / --login-class) ---"

expect_blocked "sudo -c staff install ... /etc/owned" \
  "sudo -c staff install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo --login-class staff install ... /etc/owned" \
  "sudo --login-class staff install -m 755 $PROJECT/CHANGELOG.md /etc/passwd_test"

expect_blocked "sudo -c staff /bin/rm /etc/passwd_test" \
  "sudo -c staff /bin/rm /etc/passwd_test"

expect_blocked "sudo -c staff tar --to-command='rm /etc/x'" \
  "sudo -c staff tar -xf $PROJECT/archive.tar --to-command='rm /etc/passwd_test'"

# True-negatives: legit sudo with -c + read must remain ALLOWED.
expect_allowed "sudo -c staff cat (login-class + read)" \
  "sudo -c staff cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo --login-class staff ls (long-form + benign)" \
  "sudo --login-class staff ls $PROJECT"

echo ""
