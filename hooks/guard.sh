#!/bin/bash
set -euo pipefail

# Load sibling library modules. Resolve this script's directory so the
# source path works whether guard.sh is invoked directly, through a
# symlink to the script itself, or through a CLAUDE_PLUGIN_ROOT that
# differs from $PWD. A plain `dirname "${BASH_SOURCE[0]}"` would
# return the SYMLINK's directory when guard.sh itself is symlinked
# (e.g. installed as `/some/path/link/guard.sh -> /real/hooks/guard.sh`),
# so the sourced `lib/` siblings would be looked up in the wrong
# directory. Chase the symlink chain to the real file before taking
# its directory. Portable across Linux and macOS (no `readlink -f`
# dependency). Reported by Copilot review on PR #15.
_guard_source="${BASH_SOURCE[0]}"
while [ -L "$_guard_source" ]; do
  _guard_target="$(readlink "$_guard_source")"
  case "$_guard_target" in
    /*) _guard_source="$_guard_target" ;;
    *)  _guard_source="$(dirname "$_guard_source")/$_guard_target" ;;
  esac
done
_GUARD_DIR="$(cd "$(dirname "$_guard_source")" && pwd)"
unset _guard_source _guard_target
# shellcheck source=lib/tokenize.sh
source "$_GUARD_DIR/lib/tokenize.sh"
# shellcheck source=lib/wrapper_opts.sh
source "$_GUARD_DIR/lib/wrapper_opts.sh"
# shellcheck source=lib/command_name.sh
source "$_GUARD_DIR/lib/command_name.sh"
# shellcheck source=lib/git_walkers.sh
source "$_GUARD_DIR/lib/git_walkers.sh"
# shellcheck source=lib/shell_exec_walkers.sh
source "$_GUARD_DIR/lib/shell_exec_walkers.sh"
# shellcheck source=lib/cd_destructive_walker.sh
source "$_GUARD_DIR/lib/cd_destructive_walker.sh"
# shellcheck source=lib/expansion_blocks.sh
source "$_GUARD_DIR/lib/expansion_blocks.sh"
# shellcheck source=lib/paths.sh
source "$_GUARD_DIR/lib/paths.sh"
# shellcheck source=lib/heredoc.sh
source "$_GUARD_DIR/lib/heredoc.sh"
# shellcheck source=lib/detectors/inplace.sh
source "$_GUARD_DIR/lib/detectors/inplace.sh"
# shellcheck source=lib/detectors/destructive.sh
source "$_GUARD_DIR/lib/detectors/destructive.sh"
# shellcheck source=lib/detectors/permissions.sh
source "$_GUARD_DIR/lib/detectors/permissions.sh"
# shellcheck source=lib/detectors/write_targets.sh
source "$_GUARD_DIR/lib/detectors/write_targets.sh"
# shellcheck source=lib/detectors/write_targets_b.sh
source "$_GUARD_DIR/lib/detectors/write_targets_b.sh"
# shellcheck source=lib/options.sh
source "$_GUARD_DIR/lib/options.sh"
# shellcheck source=lib/remote_dispatch.sh
source "$_GUARD_DIR/lib/remote_dispatch.sh"
# shellcheck source=lib/subcmd_flags.sh
source "$_GUARD_DIR/lib/subcmd_flags.sh"

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
EVENT_CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

if [ -z "$COMMAND" ] && [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Use cwd from the hook event if provided, so relative paths resolve correctly.
# EFFECTIVE_CWD is used to resolve relative paths in commands.
if [ -n "$EVENT_CWD" ]; then
  EFFECTIVE_CWD="$EVENT_CWD"
else
  EFFECTIVE_CWD=""
fi

# If CLAUDE_PROJECT_DIR is not set, fall back to pwd with a warning.
# We warn rather than block because blocking would break usability in
# environments where the variable is simply not configured yet.
if [ -z "${CLAUDE_PROJECT_DIR:-}" ]; then
  echo "WARNING: CLAUDE_PROJECT_DIR is not set, falling back to pwd ($(pwd)). Set CLAUDE_PROJECT_DIR for reliable boundary enforcement." >&2
fi
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
# Ensure PROJECT_DIR has no trailing slash for consistent comparison
PROJECT_DIR="${PROJECT_DIR%/}"

# EFFECTIVE_CWD: where relative paths in commands resolve to.
# Uses cwd from hook event if provided, otherwise PROJECT_DIR.
if [ -z "$EFFECTIVE_CWD" ]; then
  EFFECTIVE_CWD="$PROJECT_DIR"
fi

# resolve_path moved to hooks/lib/paths.sh.

# Resolve PROJECT_DIR itself so symlinks (e.g. /var -> /private/var on macOS) match
PROJECT_DIR=$(resolve_path "$PROJECT_DIR")

# --- Load path allowlist from hooks/allowlist.conf ---
# Patterns listed there bypass the boundary check. Kept in a separate file
# so users can inspect/extend without editing the guard logic. See the
# warning at the top of allowlist.conf — broad entries create bypass risk.
declare -a ALLOWLIST_PATTERNS=()
ALLOWLIST_FILE="${CLAUDE_PLUGIN_ROOT:-$(cd "$_GUARD_DIR/.." && pwd)}/hooks/allowlist.conf"
# Resolve HOME so `~` in patterns matches the canonical form that
# resolve_path produces for checked paths (handles macOS /var ->
# /private/var symlink so `~/.claude/**` compares correctly).
_ALLOWLIST_HOME=$(resolve_path "$HOME")
if [ -f "$ALLOWLIST_FILE" ]; then
  while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    line="${raw_line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    # Expand leading ~ to the resolved $HOME
    if [[ "$line" == "~/"* ]]; then
      line="$_ALLOWLIST_HOME/${line#\~/}"
    elif [[ "$line" == "~" ]]; then
      line="$_ALLOWLIST_HOME"
    fi
    ALLOWLIST_PATTERNS+=("$line")
  done < "$ALLOWLIST_FILE"
fi

# Precomputed parallel arrays filled after glob_to_regex is defined.
# See the precompute loop later in the file.
ALLOWLIST_REGEXES=()
ALLOWLIST_BASE_REGEXES=()

# glob_to_regex moved to hooks/lib/tokenize.sh (sourced at top of file).

# --- Precompute allowlist regexes once at load time ---
# is_allowlisted is invoked many times per command and many commands
# per session. Compiling glob_to_regex inside the hot loop wastes
# cycles on identical work across every invocation. Compile once
# here and reuse the cached regexes in is_allowlisted below.
# Reported by Copilot review on commit aa6409b (guard.sh:298).
_awl_i=0
while [ $_awl_i -lt ${#ALLOWLIST_PATTERNS[@]} ]; do
  _awl_p="${ALLOWLIST_PATTERNS[$_awl_i]}"
  ALLOWLIST_REGEXES+=("$(glob_to_regex "$_awl_p")")
  if [[ "$_awl_p" == *"/**" ]]; then
    ALLOWLIST_BASE_REGEXES+=("$(glob_to_regex "${_awl_p%/**}")")
  else
    ALLOWLIST_BASE_REGEXES+=("")
  fi
  _awl_i=$((_awl_i+1))
done
unset _awl_i _awl_p

# --- Check whether a resolved path is on the allowlist ---
# Fails closed: empty allowlist means nothing is exempt.
# A pattern ending in `/**` also matches the directory itself (gitignore-like
# semantics: `memory/**` allows both `memory` and its contents).
# strip_command_name_prefix moved to hooks/lib/command_name.sh.

# strip_command_name_quotes moved to hooks/lib/command_name.sh.

# command_name_is moved to hooks/lib/command_name.sh.

# is_discard_target moved to hooks/lib/paths.sh.

# is_shell_token / is_source_token moved to hooks/lib/command_name.sh.

# is_allowlisted moved to hooks/lib/paths.sh.

# Check if the effective working directory is outside the project
EFFECTIVE_CWD_RESOLVED=$(resolve_path "$EFFECTIVE_CWD")
CWD_OUTSIDE_PROJECT=0
CWD_IN_ALLOWLIST=0
if [[ "$EFFECTIVE_CWD_RESOLVED/" != "$PROJECT_DIR/"* ]]; then
  CWD_OUTSIDE_PROJECT=1
  if is_allowlisted "$EFFECTIVE_CWD_RESOLVED"; then
    CWD_IN_ALLOWLIST=1
  fi
fi

# strip_quotes moved to hooks/lib/tokenize.sh (sourced at top of file).

# expand_path moved to hooks/lib/paths.sh.

# tokenize_args moved to hooks/lib/tokenize.sh (sourced at top of file).

# extract_option_values moved to hooks/lib/options.sh.


# is_inside_project / is_write_permitted moved to hooks/lib/paths.sh.

# --- Edit/Write tool: check file_path boundary ---
if [ -n "$FILE_PATH" ]; then
  FILE_PATH=$(expand_path "$FILE_PATH")
  if [[ "$FILE_PATH" != /* ]]; then
    FILE_PATH="$PROJECT_DIR/$FILE_PATH"
  fi
  RESOLVED=$(resolve_path "$FILE_PATH")
  # Fully dereference symlinks so a symlink inside the project pointing
  # outside is caught (e.g. project/link -> /tmp/secret).
  # Loop handles chained symlinks (a -> b -> /outside).
  max_depth=20
  while [[ -L "$RESOLVED" && $max_depth -gt 0 ]]; do
    link_target=$(readlink "$RESOLVED")
    if [[ "$link_target" == /* ]]; then
      RESOLVED=$(resolve_path "$link_target")
    else
      RESOLVED=$(resolve_path "$(dirname "$RESOLVED")/$link_target")
    fi
    max_depth=$((max_depth - 1))
  done
  # Fail-closed: if symlink chain is too deep or circular, block
  if [[ -L "$RESOLVED" ]]; then
    echo "BLOCKED: Symlink chain too deep or circular at '$RESOLVED'. Ask user for explicit permission." >&2
    exit 2
  fi
  # Canonicalize the final path (resolve /var -> /private/var on macOS)
  if [[ -e "$RESOLVED" ]]; then
    RESOLVED="$(cd "$(dirname "$RESOLVED")" && pwd -P)/$(basename "$RESOLVED")"
  fi
  if ! is_write_permitted "$RESOLVED"; then
    echo "BLOCKED: File '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
    exit 2
  fi
  exit 0
fi

# blank_quoted_heredoc_bodies moved to hooks/lib/heredoc.sh.

# --- Check a single (non-chained) command against all guards ---
check_single_command() {
  local CMD="$1"

  # Strip leading/trailing whitespace
  CMD="$(echo "$CMD" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"

  # Skip empty commands
  if [ -z "$CMD" ]; then
    return 0
  fi

  # Snapshot the command BEFORE sudo-strip and any other normalization,
  # so extract_subcmd_flag_payloads can see the wrapper and its option-
  # with-value flags (e.g. `sudo -u root tar --to-command='<payload>'`).
  # The literal sudo-strip below removes only the bare `sudo ` token,
  # leaving `-u root` behind — which would mis-identify the verb in
  # the subcmd-flag scan. Reported by Copilot review on PR #23
  # (guard.sh:897).
  local _CMD_PRE_STRIP="$CMD"

  # --- Strip sudo prefix and its option-with-value pairs ---
  # Bare `${CMD#sudo }` left orphaned options like `-u root` in front
  # of the verb, which then mis-led the wrapper-walk in
  # strip_command_name_prefix / strip_command_name_quotes /
  # command_name_is — `root` got treated as the verb and the install
  # / /bin/<name> / "<name>" normalisations all fell through. The
  # helper below walks sudo's options-with-value (-u USER, --user=USER,
  # -g GROUP, …) and value-less flags so `sudo -u root install …`
  # collapses cleanly to `install …` before any downstream walker
  # runs. env / nice / ionice / timeout / chrt are NOT literal-stripped
  # — _cn_find_verb_idx (and its _sf_/_rd_ siblings) handle their
  # opt-with-value pairs in place. Reported by Codex round-4 on PR #23.
  CMD=$(strip_sudo_wrapper_with_opts "$CMD")
  CMD="$(echo "$CMD" | sed 's/^[[:space:]]*//')"

  # --- Block shell-opening sudo invocations ---
  # `sudo -i` / `sudo -s` / `sudo --login` / `sudo --shell` open a
  # privileged interactive shell whose subsequent commands cannot be
  # inspected by this guard — strictly more dangerous than a bare
  # `bash` invocation, which the existing shell-execute walker
  # already blocks. _cn_is_sudo_shell_opener also detects clustered
  # forms (`sudo -ni` / `-in` / `-nis`), quoted forms (`sudo "-i"`),
  # and outer-wrapper-prefixed forms (`env -u FOO sudo -i`), all of
  # which Codex round-3 found slipped past the earlier regex. Runs
  # on _CMD_PRE_STRIP so the original wrapper + sudo + flag layout
  # is still visible. If empty CMD remains after sudo-strip but the
  # original was bare `sudo` / `sudo -l` / `sudo -V` / `sudo -v`,
  # this returns 1 and we fall through to the harmless-empty
  # ALLOW. Reported by Codex review rounds 2–3 on PR #24 (P2).
  if _cn_is_sudo_shell_opener "$_CMD_PRE_STRIP"; then
    echo "BLOCKED: 'sudo -i' / 'sudo -s' / 'sudo --login' / 'sudo --shell' (also clustered like -ni / -nis, quoted, or wrapper-prefixed) opens a privileged interactive shell whose subsequent commands cannot be inspected. Ask user for explicit permission." >&2
    exit 2
  fi
  if [ -z "$CMD" ]; then
    return 0
  fi

  # --- Snapshot raw CMD before alias-escape / paren normalization ---
  # Alias normalization below strips `\` that precedes `[a-zA-Z_]`. That
  # breaks detection of a backslash-escaped heredoc delimiter `<<\EOF`
  # (bash treats it as quoted → literal body), which would be rewritten
  # to `<<EOF` (unquoted → expandable body) and wrongly trip the
  # substitution detector on literal backticks / $(...) in the body.
  # blank_quoted_heredoc_bodies is computed from this raw copy.
  local CMD_RAW="$CMD"

  # --- Normalize command-name prefixes for detection regexes ---
  # All destructive-command detection uses `(^|[[:space:]])<name>($|[[:space:]])`
  # regexes on the raw CMD string. That pattern misses three trivial aliases:
  #   (rm …)           — subshell grouping puts `(` before the name
  #   \rm …            — backslash disables alias lookup but still runs `rm`
  #   /bin/rm …        — absolute path to the same binary
  # Normalize these into the bare command form before any detection runs.
  # This only touches the string used for matching — argument extraction below
  # operates on the normalized CMD too, so paths are not mangled.
  # Strip subshell grouping parens only when they sit at a token boundary so
  # that `$(…)` (command substitution) is NOT mangled — that form is caught
  # by a dedicated check below. `(rm …)` → `rm …`, `( rm … )` → `rm …`,
  # `$(foo)` stays as is because the `(` is preceded by `$`, not space/start.
  CMD="$(printf '%s' "$CMD" | sed -E 's/(^|[[:space:]])\(+/\1/g; s/\)+($|[[:space:]])/\1/g')"
  # Strip a backslash that precedes a shell-word character (alias escape).
  CMD="$(printf '%s' "$CMD" | sed -E 's/\\([a-zA-Z_])/\1/g')"
  # Strip the common binary path prefix from the command-name token so
  # that `/bin/rm` is recognised as `rm` by every command-name regex.
  # MUST NOT touch operand or redirect-target tokens — see the helper
  # docstring for the bypass shape this guards against (Codex review
  # on commit e01df86, bypass A). The previous sed-based fallback for
  # the start-of-CMD case is preserved so that a CMD whose tokenizer
  # output is empty (defensively impossible but cheap) still gets the
  # leading prefix stripped.
  # Strip surrounding quotes from the command-name token so that
  # `"rm" /etc/x` / `'rm' /etc/x` / `"/bin/rm" /etc/x` are still
  # recognised by bare-name detectors. bash strips these quotes at
  # exec time, invoking the bare binary either way. Must run before
  # the /bin/-prefix passes so those see the bare path.
  CMD="$(strip_command_name_quotes "$CMD")"
  CMD="$(printf '%s' "$CMD" | sed -E 's#^/(usr/local/bin|usr/bin|bin|sbin|usr/sbin)/##')"
  CMD="$(strip_command_name_prefix "$CMD")"
  # Trim duplicated whitespace introduced by the substitutions.
  CMD="$(printf '%s' "$CMD" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

  # --- Build a heredoc-sanitized view for expansion-scans ---
  # $VAR and $(...)/backtick inside a *quoted* heredoc body are literal
  # bytes written to the heredoc's stdin target, not shell expansions.
  # Scanning them trips false positives on legitimate writes to an
  # allowlisted path (see blank_quoted_heredoc_bodies above). Any
  # command-name / path / redirect scan still uses the original CMD.
  local CMD_EXPAND_SCAN
  CMD_EXPAND_SCAN=$(blank_quoted_heredoc_bodies "$CMD_RAW")

  # Parallel command-name view: heredoc bodies blanked AND command-name
  # normalisations re-applied. Used by detectors that match on the live
  # command-line form (interpreter -c/-e flags, awk system(), etc.) and
  # would otherwise false-positive on those same patterns sitting inside
  # a quoted-heredoc body that bash never executes (e.g. a tee/cat
  # commit-message body that merely *mentions* `awk … system(…)` or
  # `python -c`). Source MUST be CMD_RAW for the same reason as
  # CMD_EXPAND_SCAN — the alias-escape pass that strips `\` before a
  # letter would otherwise downgrade `<<\EOF` to `<<EOF` and re-leak
  # body bytes into the blanker.
  local CMD_BLANKED
  CMD_BLANKED=$(blank_quoted_heredoc_bodies "$CMD_RAW")
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/(^|[[:space:]])\(+/\1/g; s/\)+($|[[:space:]])/\1/g')"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/\\([a-zA-Z_])/\1/g')"
  CMD_BLANKED="$(strip_command_name_quotes "$CMD_BLANKED")"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's#^/(usr/local/bin|usr/bin|bin|sbin|usr/sbin)/##')"
  CMD_BLANKED=$(strip_command_name_prefix "$CMD_BLANKED")
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

  # --- Fail closed on unexpanded $VAR outside single quotes ---
  block_unexpanded_var

  # --- Tokenize the command once (quote-aware) for option/redirect parsing ---
  local -a CMD_TOKENS=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS+=("$tok")
  done < <(tokenize_args "$CMD")

  # CMD_TOKENS_SCAN is the parallel token stream built from CMD_BLANKED
  # (computed above near the top of check_single_command, alongside
  # CMD_EXPAND_SCAN). Used by detectors that walk tokens looking for a
  # marker word (sed, truncate, `>`-redirect operator) and would
  # otherwise pick up heredoc body bytes as if they were live commands.
  # See the comment on CMD_BLANKED for why the source MUST be CMD_RAW
  # (alias-escape would silently downgrade `<<\EOF` to its unquoted
  # twin and re-leak body bytes).
  local -a CMD_TOKENS_SCAN=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS_SCAN+=("$tok")
  done < <(tokenize_args "$CMD_BLANKED")

  # --- Block command substitution outside single quotes ---
  block_command_substitution

  # --- cd-outside + destructive-cwd walkers (lib/cd_destructive_walker.sh) ---
  if handle_cd_and_track_outside_context; then
    return 0
  fi
  block_destructive_in_outside_context

  # --- git destructive walkers (extracted to hooks/lib/git_walkers.sh) ---
  block_git_C_destructive
  block_git_worktree_add_outside

  # --- Shell / interpreter execution walkers (lib/shell_exec_walkers.sh) ---
  block_nested_shell_and_eval

  block_interpreter_inline_code
  block_pipe_to_shell

  block_shell_script_execution

  # --- Neutralise remote-dispatch commands before path walkers run ---
  # Issue #21. ssh / scp / docker exec / kubectl exec / etc. dispatch
  # their operands to a remote host or foreign (container/namespace)
  # filesystem. The boundary plugin protects the LOCAL filesystem, so
  # those operands must be removed before the cp/tee/rm/redirect/...
  # walkers run — otherwise a quoted remote command like
  # `ssh host "docker cp /tmp/x container:/y"` produces a false-positive
  # block on `/tmp/x` (the cp regex matches the literal ` cp ` inside
  # the quoted argument). Policy checks earlier in this function
  # (bash -c, $VAR, $(...), heredoc-fed-shell, script execution) MUST
  # remain on the original CMD because those events happen LOCALLY,
  # before ssh / docker ever see the argument string. The rewrite here
  # only narrows what the path walkers see; CMD_TOKENS / CMD_BLANKED /
  # CMD_TOKENS_SCAN are regenerated so every detector sees a consistent
  # view. Generic for the whole class — see hooks/lib/remote_dispatch.sh.
  CMD=$(rewrite_remote_dispatch "$CMD")
  CMD_BLANKED=$(rewrite_remote_dispatch "$CMD_BLANKED")
  CMD_TOKENS=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS+=("$tok")
  done < <(tokenize_args "$CMD")
  CMD_TOKENS_SCAN=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS_SCAN+=("$tok")
  done < <(tokenize_args "$CMD_BLANKED")

  # --- Validate argument-as-command flag values recursively ---
  # Tools like `tar --to-command=<cmd>` / `rsync -e <cmd>` /
  # `git -c <exec-key>=<cmd>` execute the flag value as a local shell
  # command. The walkers below only see flag NAMES — not VALUES — so a
  # destructive payload would slip past them. Extract every recognised
  # payload from this (post-split) subcommand and dispatch it through
  # check_single_command recursively, reusing the entire detector
  # pipeline. Generic for the whole class — see hooks/lib/subcmd_flags.sh.
  local _sf_payload
  while IFS= read -r _sf_payload; do
    [ -n "$_sf_payload" ] && check_single_command "$_sf_payload"
  done < <(extract_subcmd_flag_payloads "$_CMD_PRE_STRIP")

  # xargs, find-delete, rm, mv, cp, ln moved to hooks/lib/detectors/destructive.sh.
  run_destructive_detectors


  # install, rsync, tar, unzip, cpio, tee, curl, wget, dd, redirect
  # moved to hooks/lib/detectors/write_targets.sh.
  run_write_target_detectors
  run_write_target_detectors_b


  # sed -i / truncate detectors moved to hooks/lib/detectors/inplace.sh.
  run_inplace_detectors


  # chmod / chown moved to hooks/lib/detectors/destructive.sh.
  run_permissions_detectors
}

# --- Split command into sub-commands and check each ---
# Split on ;, &&, ||, and | (but not inside quoted strings)
# This is a basic splitter that handles common cases.
# split_and_check moved to hooks/lib/options.sh.


# --- Main entry point: split chained commands and check each ---
split_and_check "$COMMAND"

exit 0
