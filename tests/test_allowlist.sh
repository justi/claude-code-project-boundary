#!/bin/bash
# Tests for allowlist.conf — paths that bypass the boundary check.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  Allowlist tests (hooks/allowlist.conf)"
echo "========================================"
echo ""

# Hermetic: point HOME at a throwaway dir so tests never touch the
# developer's real ~/.claude/projects/. The guard expands ~ against
# the live $HOME at invocation time, so overriding here is sufficient.
ALLOWLIST_TEST_HOME_SAVE="$HOME"
export HOME="$TMPDIR_BASE/fake_home"
mkdir -p "$HOME"

# Claude auto-memory lives under ~/.claude/projects/<slug>/memory/.
# Default allowlist must permit writes there so plugins that write
# memory files don't trigger the boundary guard.
MEMORY_DIR="$HOME/.claude/projects/-test-slug/memory"
mkdir -p "$MEMORY_DIR"

expect_file_allowed "Write to ~/.claude/projects/<slug>/memory/ (allowlisted)" \
  "$MEMORY_DIR/feedback_example.md"

expect_file_allowed "Write to memory MEMORY.md index (allowlisted)" \
  "$MEMORY_DIR/MEMORY.md"

# Negative cases — allowlist must NOT broaden to sibling / parent dirs
expect_file_blocked "Write to ~/.claude/projects/<slug>/ (parent of memory, not allowlisted)" \
  "$HOME/.claude/projects/-test-slug/other.md"

expect_file_blocked "Write to ~/.claude/settings.json (not allowlisted)" \
  "$HOME/.claude/settings.json"

expect_file_blocked "Write to /etc/passwd (not allowlisted)" \
  "/etc/passwd"

# Bash redirect into memory dir — should also be allowed
expect_allowed "echo > memory file (allowlisted redirect target)" \
  "echo hello > $MEMORY_DIR/note.md"

expect_blocked "echo > /etc/passwd (redirect still blocked)" \
  "echo hello > /etc/passwd"

# Codex review P1 — allowlist is WRITE-only, must NOT cover destructive ops.
expect_blocked "rm of allowlisted memory file is blocked (delete != write)" \
  "rm $MEMORY_DIR/old.md"

expect_blocked "chmod on allowlisted memory file is blocked" \
  "chmod 600 $MEMORY_DIR/note.md"

expect_blocked "chown on allowlisted memory file is blocked" \
  "chown user $MEMORY_DIR/note.md"

expect_blocked "cd into allowlisted dir + git clean -fd still blocked" \
  "cd $MEMORY_DIR && git clean -fd"

expect_blocked "find -delete on allowlisted dir is blocked" \
  "find $MEMORY_DIR -delete"

# Codex review P2 — `*` in glob must stop at path separator.
# Pattern `~/.claude/projects/*/memory/**` must NOT match nested subdir.
NESTED_MEMORY="$HOME/.claude/projects/-test-slug/nested/memory"
mkdir -p "$NESTED_MEMORY"
expect_file_blocked "glob * must not cross / (nested projects/*/nested/memory should not match)" \
  "$NESTED_MEMORY/x.md"
rm -rf "$HOME/.claude/projects/-test-slug/nested"

# Codex review round 2 — P1: symlink pivot through allowlisted dir.
# If memory/link -> /tmp/owned, writes via tee/truncate must not land on /tmp.
ln -sf /tmp/owned "$MEMORY_DIR/pwn" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$MEMORY_DIR/pwn" ]]; then
  echo "PASS: setup: symlink memory/pwn -> /tmp/owned"
  PASS=$((PASS + 1))
  expect_blocked "tee through allowlisted symlink -> outside" \
    "tee $MEMORY_DIR/pwn"
  expect_blocked "truncate through allowlisted symlink -> outside" \
    "truncate -s 0 $MEMORY_DIR/pwn"
  expect_blocked "redirect > through allowlisted symlink -> outside" \
    "echo x > $MEMORY_DIR/pwn"
else
  echo "FAIL: setup: could not create allowlisted symlink"
  FAIL=$((FAIL + 1))
fi
rm -f "$MEMORY_DIR/pwn"

# Codex review round 2 — P2: mv source from allowlisted dir is destructive.
expect_blocked "mv from allowlisted dir is destructive (source gets deleted)" \
  "mv $MEMORY_DIR/foo $PROJECT/foo"
expect_blocked "cp of allowlisted dir source (still strict — narrow scope)" \
  "cp /etc/passwd $MEMORY_DIR/leak"

# Codex review round 3 — cp/ln source from allowlisted dir stays strict
# (consistency with pre-allowlist behavior and with mv source rule).
expect_blocked "cp from allowlisted dir (source must be strict)" \
  "cp $MEMORY_DIR/MEMORY.md $PROJECT/copy"
expect_blocked "ln from allowlisted dir (source strict)" \
  "ln $MEMORY_DIR/MEMORY.md $PROJECT/link"

# Codex review round 3 — env-wrapped shell execution must also be blocked.
expect_blocked "env bash /tmp/evil.sh" \
  "env bash /tmp/evil.sh"
expect_blocked "/usr/bin/env bash /tmp/evil.sh" \
  "/usr/bin/env bash /tmp/evil.sh"
expect_blocked "env FOO=1 bash /tmp/evil.sh (env with var assignment)" \
  "env FOO=1 bash /tmp/evil.sh"
expect_blocked "env -i bash /tmp/evil.sh (env with flag)" \
  "env -i bash /tmp/evil.sh"
expect_blocked "env -u HOME bash /tmp/evil.sh (env flag with operand)" \
  "env -u HOME bash /tmp/evil.sh"
expect_blocked "bash -O extglob /tmp/evil.sh (shell flag with operand)" \
  "bash -O extglob /tmp/evil.sh"
expect_blocked "bash -o pipefail /tmp/evil.sh (shell flag with operand)" \
  "bash -o pipefail /tmp/evil.sh"
expect_blocked "bash +x /tmp/evil.sh (bash + option form)" \
  "bash +x /tmp/evil.sh"
expect_blocked "bash +O extglob /tmp/evil.sh (bash + option + operand)" \
  "bash +O extglob /tmp/evil.sh"
expect_blocked "env -S 'bash /tmp/evil.sh' (env split-string fail-closed)" \
  "env -S 'bash /tmp/evil.sh'"
expect_blocked "env --split-string='bash /tmp/evil.sh'" \
  "env --split-string='bash /tmp/evil.sh'"
expect_blocked "env -C /tmp bash evil.sh (env chdir fail-closed)" \
  "env -C /tmp bash evil.sh"
expect_blocked "env --chdir=/tmp bash evil.sh (env chdir fail-closed)" \
  "env --chdir=/tmp bash evil.sh"
expect_blocked "command bash /tmp/evil.sh (command wrapper)" \
  "command bash /tmp/evil.sh"
expect_blocked "sudo -E bash /tmp/evil.sh (sudo wrapper, post-strip)" \
  "sudo -E bash /tmp/evil.sh"
expect_blocked "nice bash /tmp/evil.sh (nice wrapper)" \
  "nice bash /tmp/evil.sh"
expect_blocked "nice -n 10 bash /tmp/evil.sh (nice with operand)" \
  "nice -n 10 bash /tmp/evil.sh"
expect_blocked "nohup bash /tmp/evil.sh (nohup wrapper)" \
  "nohup bash /tmp/evil.sh"
expect_blocked "timeout 10 bash /tmp/evil.sh (timeout wrapper with operand)" \
  "timeout 10 bash /tmp/evil.sh"

# Codex round 6 — P1: intermediate symlink in allowlist path.
# memory/linkdir -> /etc: writes under linkdir land outside boundary.
mkdir -p "$MEMORY_DIR" 2>/dev/null
ln -sf /etc "$MEMORY_DIR/linkdir" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$MEMORY_DIR/linkdir" ]]; then
  echo "PASS: setup: memory/linkdir -> /etc"
  PASS=$((PASS + 1))
  expect_file_blocked "write to allowlisted/intermediate-symlink/file" \
    "$MEMORY_DIR/linkdir/passwd"
  expect_blocked "redirect > allowlisted/intermediate-symlink/file" \
    "echo x > $MEMORY_DIR/linkdir/passwd"
else
  echo "FAIL: setup: could not create intermediate symlink"
  FAIL=$((FAIL + 1))
fi
rm -f "$MEMORY_DIR/linkdir"

# Codex round 6 — P1: shell stdin redirection from outside / allowlist.
expect_blocked "bash < /tmp/evil.sh (stdin redirect to outside file)" \
  "bash < /tmp/evil.sh"
expect_blocked "bash <<< 'rm -rf /' (here-string)" \
  "bash <<< 'rm -rf /'"
expect_blocked "bash << EOF (heredoc)" \
  "bash << EOF"
expect_blocked "bash</tmp/evil.sh (attached stdin redirect)" \
  "bash</tmp/evil.sh"
expect_blocked "bash<<EOF (attached heredoc)" \
  "bash<<EOF"
expect_blocked "bash<<<'rm -rf /' (attached here-string)" \
  "bash<<<'rm -rf /'"

# Codex round 8 — process substitution as shell stdin
expect_blocked "bash < <(cat /tmp/evil.sh) (process substitution stdin)" \
  "bash < <(cat /tmp/evil.sh)"

# Codex round 8 — cd into allowlisted dir should permit WRITE commands
# (tee, curl -o, redirect >) but still BLOCK destructive ops (rm, mv)
expect_allowed "cd memory && tee note.md (relative write in allowlisted cwd)" \
  "cd $MEMORY_DIR && tee note.md"
expect_allowed "cd memory && echo x > note.md (relative redirect in allowlisted cwd)" \
  "cd $MEMORY_DIR && echo x > note.md"
expect_blocked "cd memory && rm note.md (destructive still strict)" \
  "cd $MEMORY_DIR && rm note.md"
expect_blocked "cd memory && mv note.md new.md (destructive still strict)" \
  "cd $MEMORY_DIR && mv note.md new.md"

# Codex round 9 — wget/curl in allowlisted cwd: -P / --output-dir to outside
expect_blocked "cd memory && wget -P /etc URL (wget directory-prefix escape)" \
  "cd $MEMORY_DIR && wget -P /etc http://x"
expect_blocked "cd memory && curl --output-dir /etc -O URL (curl output-dir escape)" \
  "cd $MEMORY_DIR && curl --output-dir /etc -O http://x"

# Codex round 9 — leading stdin redirect before shell
expect_blocked "< /tmp/evil.sh bash (leading redirect feeding shell)" \
  "< /tmp/evil.sh bash"

# Wrapper detection is greedy (security > precision). Known false positive:
# `time echo bash /tmp/x` is over-blocked because the walker finds `bash`
# anywhere in the arg stream. Accepted tradeoff — weird command, and
# aggressive skipping is required to catch bypasses like
# `timeout -s TERM 10 bash /tmp/evil.sh` where flag operands are non-numeric.
expect_blocked "timeout 10 bash /tmp/evil.sh (duration then shell)" \
  "timeout 10 bash /tmp/evil.sh"
expect_blocked "timeout -s TERM 10 bash /tmp/evil.sh (flag+operand+duration+shell)" \
  "timeout -s TERM 10 bash /tmp/evil.sh"
expect_blocked "stdbuf -o L bash /tmp/evil.sh (flag+operand+shell)" \
  "stdbuf -o L bash /tmp/evil.sh"

# Codex round 10 — shell builtins wrapping shell exec
expect_blocked "exec bash /tmp/evil.sh (exec builtin)" \
  "exec bash /tmp/evil.sh"
expect_blocked "builtin source /tmp/evil.sh" \
  "builtin source /tmp/evil.sh"

# Codex round 10 — leading redirect after wrapper/VAR=val
expect_blocked "FOO=1 < /tmp/evil.sh bash (leading redirect after VAR=val)" \
  "FOO=1 < /tmp/evil.sh bash"
expect_blocked "nice < /tmp/evil.sh bash (leading redirect after wrapper)" \
  "nice < /tmp/evil.sh bash"

# Codex round 11 — fd-prefixed stdin redirect
expect_blocked "bash 0</tmp/evil.sh (fd 0 stdin redirect)" \
  "bash 0</tmp/evil.sh"
expect_blocked "bash <&3 (fd duplicate)" \
  "bash <&3"

# Codex round 12 — shell at non-standard path (Homebrew, Nix, etc.)
expect_blocked "/opt/homebrew/bin/bash /tmp/evil.sh (Homebrew path)" \
  "/opt/homebrew/bin/bash /tmp/evil.sh"
expect_blocked "/nix/store/abcdef/bin/bash /tmp/evil.sh (Nix path)" \
  "/nix/store/abcdef/bin/bash /tmp/evil.sh"
expect_blocked "/opt/homebrew/bin/zsh /tmp/evil.sh (Homebrew zsh)" \
  "/opt/homebrew/bin/zsh /tmp/evil.sh"

# Codex round 7 — P1: '..' after an allowlisted symlinked subdir.
# Use /etc (guaranteed to exist as directory cross-platform).
ln -sf /etc "$MEMORY_DIR/linkdir2" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$MEMORY_DIR/linkdir2" && -d "$MEMORY_DIR/linkdir2" ]]; then
  echo "PASS: setup: memory/linkdir2 -> /etc"
  PASS=$((PASS + 1))
  # memory/linkdir2/../owned physically resolves to / (parent of /etc),
  # so `echo x > memory/linkdir2/../owned` would write /owned — escaping
  # both the project and the allowlist.
  expect_blocked "redirect > memory/linkdir/../owned (escapes allowlist via symlink+..)" \
    "echo x > $MEMORY_DIR/linkdir2/../owned"
  expect_file_blocked "write memory/linkdir/../owned file_path (escapes via ..)" \
    "$MEMORY_DIR/linkdir2/../owned"
else
  echo "FAIL: setup: could not create symlink for .. bypass test"
  FAIL=$((FAIL + 1))
fi
rm -f "$MEMORY_DIR/linkdir2"

# Symlink inside project pointing to outside — bash dereferences at exec time.
ln -sf /tmp/evil_via_link.sh "$PROJECT/evil_link.sh" 2>/dev/null
TOTAL=$((TOTAL + 1))
if [[ -L "$PROJECT/evil_link.sh" ]]; then
  echo "PASS: setup: project/evil_link.sh -> /tmp/evil_via_link.sh"
  PASS=$((PASS + 1))
  expect_blocked "bash project/link.sh (symlink leaf to outside)" \
    "bash $PROJECT/evil_link.sh"
  expect_blocked "source project/link.sh (symlink leaf to outside)" \
    "source $PROJECT/evil_link.sh"
else
  echo "FAIL: setup: could not create project symlink"
  FAIL=$((FAIL + 1))
fi
rm -f "$PROJECT/evil_link.sh"

# Restore HOME and scrub the throwaway dir (safe: only inside $TMPDIR_BASE).
rm -rf "$HOME/.claude"
export HOME="$ALLOWLIST_TEST_HOME_SAVE"
