#!/bin/bash
# Bypass reproducers (flags, sections 45-48) — shell-opening sudo
# variants: empty-CMD, missing -c/--login-class, clustered/quoted/
# wrapper-prefixed forms, long-form valueless flags before -i/-s.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (flags, sections 45-48)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

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

# ============================================================
# 47. Shell-opening sudo: clustered / quoted / wrapper-prefixed
# ------------------------------------------------------------
# Round-2 section 45 added an empty-CMD check that blocked the
# standalone forms `sudo -i` / `-s` / `--login` / `--shell`. Round-3
# found three shapes that still slipped past:
#
#   (a) Clustered short flags ending in `i` or `s`:
#       sudo -ni, sudo -in, sudo -A -ni, sudo -nis
#       (sudo accepts -nis as the cluster of -n / -i / -s)
#
#   (b) Quoted standalone forms that the regex didn't strip:
#       sudo "-i", sudo '-i'
#
#   (c) Outer wrapper around sudo:
#       env -u FOO sudo -i
#       nice -n 10 sudo -s
#       timeout -k 5 10 sudo -i
#       (the empty-CMD branch never fires because CMD doesn't start
#        with sudo, so strip_sudo_wrapper_with_opts is a no-op and
#        CMD stays non-empty.)
#
# Fix: replace the regex-based empty-CMD check with a proper
# `_cn_is_sudo_shell_opener` helper that:
#   1. Tokenises _CMD_PRE_STRIP and walks past outer wrappers + opts
#      (env / nice / nohup / time / stdbuf / ionice / chrt / taskset
#      / command / builtin / exec / timeout) using the same logic as
#      _cn_find_verb_idx.
#   2. When `sudo` is reached, walks sudo's flags consuming opt-with-
#      value pairs correctly. Standalone `-i`/`-s`/`--login`/`--shell`
#      AND clustered short flags whose body contains `i` or `s` set
#      found_shell_opener=1.
#   3. Returns 0 (shell-opener) iff a shell-opening flag was seen
#      AND no positional verb followed (sudo with a real command
#      runs the cmd via shell — that's still walked by detectors).
# Called before the sudo strip so it sees the original wrapper +
# sudo + flag layout.
#
# Reported by Codex review round-3 on PR #24 (P2).
# ============================================================
echo "--- 47. shell-opening sudo: clustered / quoted / wrapper-prefixed ---"

# (a) Clustered short flags.
expect_blocked "sudo -ni (cluster -n + -i)" \
  "sudo -ni"

expect_blocked "sudo -in (cluster reverse order)" \
  "sudo -in"

expect_blocked "sudo -A -ni (after -A askpass valueless)" \
  "sudo -A -ni"

expect_blocked "sudo -nis (cluster -n + -i + -s)" \
  "sudo -nis"

expect_blocked "sudo -ns (cluster -n + -s)" \
  "sudo -ns"

# (b) Quoted standalone forms.
expect_blocked 'sudo "-i" (double-quoted)' \
  'sudo "-i"'

expect_blocked "sudo '-i' (single-quoted)" \
  "sudo '-i'"

expect_blocked 'sudo "-s" (quoted -s)' \
  'sudo "-s"'

expect_blocked 'sudo "--login" (quoted long form)' \
  'sudo "--login"'

# (c) Outer wrapper around sudo.
expect_blocked "env -u FOO sudo -i (env wrapper + sudo shell)" \
  "env -u FOO sudo -i"

expect_blocked "env -u FOO sudo -ni (env wrapper + cluster)" \
  "env -u FOO sudo -ni"

expect_blocked "nice -n 10 sudo -s (nice wrapper + sudo shell)" \
  "nice -n 10 sudo -s"

expect_blocked "timeout -k 5 10 sudo -i (timeout wrapper + sudo shell)" \
  "timeout -k 5 10 sudo -i"

expect_blocked "ionice -c 3 sudo --login (ionice + long-form)" \
  "ionice -c 3 sudo --login"

# True-negatives: sudo with a positional verb (NOT shell-opener — cmd is
# still walked by the destructive / install / etc. detectors).
expect_allowed "sudo -i cat ./README.md (login + actual cmd, walked normally)" \
  "sudo -i cat $PROJECT/CHANGELOG.md"

expect_allowed "sudo -s ls (shell + actual cmd)" \
  "sudo -s ls $PROJECT"

# True-negative: clustered shape WITHOUT shell letters.
expect_allowed "sudo -nE cat (cluster -n + -E, no i/s)" \
  "sudo -nE cat $PROJECT/CHANGELOG.md"

# True-negative: env wrapper + sudo + benign verb.
expect_allowed "env -u FOO sudo cat (wrapper + sudo + read)" \
  "env -u FOO sudo cat $PROJECT/CHANGELOG.md"

echo ""

# ============================================================
# 48. Shell-opening sudo: long-form valueless flag before -i / -s
# ------------------------------------------------------------
# Phase 2 of `_cn_is_sudo_shell_opener` matches `-[A-Za-z]*` for
# clustered shorts but falls through to `*) return 1` on long-form
# valueless flags (`--preserve-env`, `--background`, `--set-home`,
# ...) — they don't match `--*=*` (no `=`) nor `-[A-Za-z]*` (start
# with `--`). Phase 2 then mis-treats them as a positional verb and
# bails before seeing the shell-opener that follows.
# Fix: `-*` catch-all before `*) return 1`.
# ============================================================
echo "--- 48. shell-opening sudo: long-form valueless flag before -i/-s ---"

expect_blocked "sudo --preserve-env -i" "sudo --preserve-env -i"
expect_blocked "sudo --background -s" "sudo --background -s"
expect_blocked "sudo --non-interactive -i" "sudo --non-interactive -i"
expect_blocked "env -u FOO sudo --preserve-env -i" "env -u FOO sudo --preserve-env -i"
expect_blocked "sudo --preserve-env -ni (cluster after long valueless)" "sudo --preserve-env -ni"

expect_allowed "sudo --preserve-env cat (long valueless + read)" \
  "sudo --preserve-env cat $PROJECT/CHANGELOG.md"

echo ""
