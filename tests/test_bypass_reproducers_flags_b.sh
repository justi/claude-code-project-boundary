#!/bin/bash
# Bypass reproducers (flags, sections 33-39) — chained subcmd
# expansion, rsync clustered shorts, additional git-config sink keys,
# case-insensitive keys, alias-bang execution, git config <k> <v>.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (flags, sections 33-39)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

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
