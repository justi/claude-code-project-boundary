#!/bin/bash
# Bypass reproducers (recent / sections 22-28) — install/rsync walker
# fixes (POSIX `--`, attached write-target white-list, quoted-option
# normalization), php attached form, attached-flag behavior pinning,
# rsync first-segment-only remote-path skip.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Bypass reproducers (recent, sections 22-28)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

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

