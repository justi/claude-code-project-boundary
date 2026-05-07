#!/bin/bash
# Bypass reproducers (flags, sections 40-44) — wrapper opt-flag
# bypass class introduced in PR #23 / closed across subcmd_flags /
# command_name / remote_dispatch in PR #24, plus sudo flag
# classification rounds.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (flags, sections 40-44)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

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
# A. _wrapper_opts_with_val table (hooks/lib/wrapper_opts.sh) per
#    wrapper, walked alongside the existing wrapper-skip pass in all
#    three helpers.
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
