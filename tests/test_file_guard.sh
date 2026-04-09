#!/bin/bash
# Tests for Edit/Write file_path boundary guard
# Sourced by test_guard.sh — requires helpers.sh loaded first

echo "========================================"
echo "  Edit/Write file_path guard tests"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# Edit tool — file_path boundary check
# ============================================================
echo "--- Edit tool ---"

# Inside project — should be allowed
expect_file_allowed "Edit file inside project" \
  "$PROJECT/file.txt"

expect_file_allowed "Edit file in project subdir" \
  "$PROJECT/subdir/file.txt"

# Outside project — should be blocked
expect_file_blocked "Edit file in /tmp" \
  "/tmp/file.txt"

expect_file_blocked "Edit file in /etc" \
  "/etc/passwd"

expect_file_blocked "Edit file in home dir" \
  "$HOME/.bashrc"

# Path traversal
expect_file_blocked "Edit with .. escaping project" \
  "$PROJECT/../../../etc/passwd"

# Tilde and $HOME (defense-in-depth: Claude Code sends absolute paths,
# but we guard against these in case the contract changes)
expect_file_blocked "Edit ~/file" \
  "~/file.txt"

expect_file_blocked 'Edit $HOME/file' \
  '$HOME/file.txt'

# Project root itself — allowed (editing a file at project root is fine)
expect_file_allowed "Edit file at project root" \
  "$PROJECT/README.md"

echo ""

# ============================================================
# Write tool — file_path boundary check
# ============================================================
echo "--- Write tool ---"

expect_file_allowed "Write file inside project" \
  "$PROJECT/new_file.txt"

expect_file_blocked "Write file in /tmp" \
  "/tmp/new_file.txt"

expect_file_blocked "Write file in /etc" \
  "/etc/crontab"

expect_file_blocked "Write with .. escaping project" \
  "$PROJECT/../../outside.txt"

echo ""

# ============================================================
# Edge cases
# ============================================================
echo "--- Edit/Write edge cases ---"

# Root path
expect_file_blocked "Edit root path /" \
  "/"

# Path prefix collision: project-evil vs project
expect_file_blocked "Write to project-evil (prefix collision)" \
  "${PROJECT}-evil/file.txt"

# Sensitive dotfiles
expect_file_blocked "Edit ~/.ssh/authorized_keys" \
  "$HOME/.ssh/authorized_keys"

expect_file_blocked "Edit ~/.gitconfig" \
  "$HOME/.gitconfig"

expect_file_blocked "Write ~/.ssh/id_rsa" \
  "$HOME/.ssh/id_rsa"

# System paths
expect_file_blocked "Write /etc/crontab" \
  "/etc/crontab"

expect_file_blocked "Edit /etc/hosts" \
  "/etc/hosts"

# Device paths
expect_file_blocked "Write /dev/null" \
  "/dev/null"

# Relative path (defense-in-depth: Claude Code sends absolute paths)
expect_file_allowed "Edit relative path inside project" \
  "file.txt"

expect_file_allowed "Edit ./subdir/file.txt" \
  "./subdir/file.txt"

# Relative path traversal escaping project
expect_file_blocked "Edit relative ../../etc/passwd" \
  "../../etc/passwd"

# ${HOME} expansion
expect_file_blocked 'Edit ${HOME}/.bashrc' \
  '${HOME}/.bashrc'

# Dotfiles inside project — allowed
expect_file_allowed "Edit .env inside project" \
  "$PROJECT/.env"

expect_file_allowed "Edit .gitignore inside project" \
  "$PROJECT/.gitignore"

# Deep path traversal
expect_file_blocked "Edit deep traversal" \
  "$PROJECT/a/b/c/../../../../etc/passwd"

# macOS /private/tmp vs /tmp
expect_file_blocked "Write /var/tmp/file" \
  "/var/tmp/file"

# Empty-ish paths
expect_file_allowed "Edit with . (current dir = project)" \
  "."

echo ""

# ============================================================
# Symlink bypass — Edit/Write must dereference symlinks
# ============================================================
echo "--- Symlink bypass ---"

# Create a file outside the project and symlink to it from inside
OUTSIDE_FILE="$TMPDIR_BASE/outside_secret.txt"
echo "secret" > "$OUTSIDE_FILE"
ln -s "$OUTSIDE_FILE" "$PROJECT/symlink_to_outside.txt"

expect_file_blocked "Edit symlink pointing outside project" \
  "$PROJECT/symlink_to_outside.txt"

expect_file_blocked "Write symlink pointing outside project" \
  "$PROJECT/symlink_to_outside.txt"

# Symlink to file inside project — should be allowed
ln -s "$PROJECT/subdir" "$PROJECT/link_to_subdir"
expect_file_allowed "Edit symlink pointing inside project" \
  "$PROJECT/link_to_subdir/file.txt"

# Symlink chain: project/a -> project/b -> /tmp/outside
OUTSIDE_FILE2="$TMPDIR_BASE/outside2.txt"
echo "secret2" > "$OUTSIDE_FILE2"
ln -s "$OUTSIDE_FILE2" "$PROJECT/subdir/chain_end"
ln -s "$PROJECT/subdir/chain_end" "$PROJECT/chain_start"

expect_file_blocked "Edit chained symlink escaping project" \
  "$PROJECT/chain_start"

echo ""
