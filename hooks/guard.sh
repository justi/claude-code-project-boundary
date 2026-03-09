#!/bin/bash
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$COMMAND" ]; then
  exit 0
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

# --- Portable realpath in pure bash ---
# macOS realpath does not support -m (non-existent path resolution).
# This pure-bash implementation handles .., . and works with non-existent paths.
# For non-existent paths, it resolves the nearest existing ancestor via pwd -P
# to handle symlinks (e.g. /var -> /private/var on macOS).
resolve_path() {
  local p="$1"
  # Make absolute
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi
  # Normalize: resolve . and .. segments
  local -a parts=()
  local IFS='/'
  for segment in $p; do
    if [[ "$segment" == ".." ]]; then
      [[ ${#parts[@]} -gt 0 ]] && unset 'parts[${#parts[@]}-1]'
    elif [[ "$segment" != "." && -n "$segment" ]]; then
      parts+=("$segment")
    fi
  done
  local normalized="/${parts[*]}"
  normalized="${normalized// //}"
  # Walk up to find the nearest existing ancestor directory and resolve symlinks
  local check="$normalized"
  local tail=""
  while [[ ! -e "$check" && "$check" != "/" ]]; do
    tail="/$(basename "$check")$tail"
    check="$(dirname "$check")"
  done
  if [[ -d "$check" ]]; then
    local real_ancestor
    real_ancestor=$(cd "$check" && pwd -P)
    echo "${real_ancestor}${tail}"
  else
    echo "$normalized"
  fi
}

# Resolve PROJECT_DIR itself so symlinks (e.g. /var -> /private/var on macOS) match
PROJECT_DIR=$(resolve_path "$PROJECT_DIR")

# --- Expand ~ and $HOME in a command argument ---
expand_path() {
  local p="$1"
  # Remove surrounding quotes (single or double)
  p="${p%\"}"
  p="${p#\"}"
  p="${p%\'}"
  p="${p#\'}"
  # Expand ~ at start
  if [[ "$p" == "~/"* ]]; then
    p="$HOME/${p#\~/}"
  elif [[ "$p" == "~" ]]; then
    p="$HOME"
  fi
  # Expand $HOME
  p="${p/\$HOME/$HOME}"
  # Expand ${HOME}
  p="${p/\$\{HOME\}/$HOME}"
  echo "$p"
}

# --- Check if a resolved path is inside the project directory ---
is_inside_project() {
  local resolved="$1"
  # Add trailing slash to both sides so /tmp/project-other doesn't match /tmp/project
  if [[ "$resolved/" == "$PROJECT_DIR/"* ]]; then
    return 0
  fi
  return 1
}

# --- Extract non-flag arguments from a command (skip the command name itself) ---
extract_path_args() {
  local cmd_body="$1"
  echo "$cmd_body" | tr ' ' '\n' | grep -v '^-' || true
}

# --- Check a single (non-chained) command against all guards ---
check_single_command() {
  local CMD="$1"

  # Strip leading/trailing whitespace
  CMD="$(echo "$CMD" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"

  # Skip empty commands
  if [ -z "$CMD" ]; then
    return 0
  fi

  # --- Strip sudo prefix ---
  if [[ "$CMD" =~ ^sudo[[:space:]]+ ]]; then
    CMD="${CMD#sudo }"
    CMD="$(echo "$CMD" | sed 's/^[[:space:]]*//')"
  fi

  # --- Always blocked (dangerous regardless of location) ---
  local ALWAYS_BLOCKED=(
    "git push.*--force"
    "git push.*-f($|[[:space:]])"
    "git reset --hard"
    "git checkout \."
    "git clean.*-f"
    "drop_table"
    "drop table"
    "truncate table"
    "rails db:drop"
    "rails db:reset"
    "rake db:drop"
    "rake db:reset"
    "mkfs\."
    "dd if="
    "(^|[[:space:]])format($|[[:space:]]).*disk"
  )

  for pattern in "${ALWAYS_BLOCKED[@]}"; do
    if echo "$CMD" | grep -qiE "$pattern"; then
      echo "BLOCKED: '$CMD' matches dangerous pattern '$pattern'. This command is always blocked. Ask user for explicit permission." >&2
      exit 2
    fi
  done

  # --- xargs with dangerous commands ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])xargs($|[[:space:]])'; then
    # Check if xargs is followed by a dangerous command
    local xargs_cmd
    xargs_cmd=$(echo "$CMD" | sed -E 's/.*xargs[[:space:]]+((-[^ ]*[[:space:]]+)*)//' | awk '{print $1}')
    case "$xargs_cmd" in
      rm|mv|cp|chmod|chown|tee|ln)
        echo "BLOCKED: 'xargs $xargs_cmd' is blocked because xargs arguments cannot be validated. Ask user for explicit permission." >&2
        exit 2
        ;;
    esac
  fi

  # --- find with -delete or -exec rm/mv outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])find($|[[:space:]])'; then
    if echo "$CMD" | grep -qE '(-delete|-exec[[:space:]]+(rm|mv))'; then
      # Extract the find path (first non-flag argument after 'find')
      local find_path
      find_path=$(echo "$CMD" | sed -E 's/.*find[[:space:]]+//' | awk '{print $1}')
      if [ -n "$find_path" ]; then
        find_path=$(expand_path "$find_path")
        if [[ "$find_path" != /* ]]; then
          find_path="$PROJECT_DIR/$find_path"
        fi
        local resolved_find
        resolved_find=$(resolve_path "$find_path")
        if ! is_inside_project "$resolved_find"; then
          echo "BLOCKED: 'find' with destructive action targets '$resolved_find' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
          exit 2
        fi
      fi
    fi
  fi

  # --- File deletion: allowed inside project, blocked outside ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])rm($|[[:space:]])'; then
    # Extract paths from rm command (skip flags)
    PATHS=$(echo "$CMD" | grep -oE '(^|[[:space:]])rm[[:space:]]+.*' | sed 's/^[[:space:]]*rm[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

    for TARGET in $PATHS; do
      TARGET=$(expand_path "$TARGET")
      # Resolve to absolute path
      if [[ "$TARGET" != /* ]]; then
        TARGET="$PROJECT_DIR/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'rm' targets '$RESOLVED' which is OUTSIDE project directory '$PROJECT_DIR'. File deletion is only allowed within the project. Ask user for explicit permission." >&2
        exit 2
      fi

      # Block deleting the project root itself
      if [[ "$RESOLVED" == "$PROJECT_DIR" ]]; then
        echo "BLOCKED: Cannot delete the project root directory itself." >&2
        exit 2
      fi
    done
  fi

  # --- Moving files outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])mv($|[[:space:]])'; then
    MV_ARGS=$(echo "$CMD" | grep -oE '(^|[[:space:]])mv[[:space:]]+.*' | sed 's/^[[:space:]]*mv[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

    for TARGET in $MV_ARGS; do
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$PROJECT_DIR/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'mv' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done
  fi

  # --- cp command: check all non-flag arguments ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])cp($|[[:space:]])'; then
    CP_ARGS=$(echo "$CMD" | grep -oE '(^|[[:space:]])cp[[:space:]]+.*' | sed 's/^[[:space:]]*cp[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

    for TARGET in $CP_ARGS; do
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$PROJECT_DIR/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'cp' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done
  fi

  # --- ln command: check all non-flag arguments ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])ln($|[[:space:]])'; then
    LN_ARGS=$(echo "$CMD" | grep -oE '(^|[[:space:]])ln[[:space:]]+.*' | sed 's/^[[:space:]]*ln[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

    for TARGET in $LN_ARGS; do
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$PROJECT_DIR/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'ln' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done
  fi

  # --- tee command: extract file arguments, block if outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])tee($|[[:space:]])'; then
    TEE_ARGS=$(echo "$CMD" | grep -oE '(^|[[:space:]])tee[[:space:]]+.*' | sed 's/^[[:space:]]*tee[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

    for TARGET in $TEE_ARGS; do
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$PROJECT_DIR/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'tee' targets '$RESOLVED' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done
  fi

  # --- curl -o / curl --output outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])curl($|[[:space:]])'; then
    local curl_output=""
    # Match -o <file> or --output <file> or --output=<file>
    if echo "$CMD" | grep -qE '(^|[[:space:]])-o[[:space:]]'; then
      curl_output=$(echo "$CMD" | sed -E 's/.*[[:space:]]-o[[:space:]]+([^ ]+).*/\1/')
    elif echo "$CMD" | grep -qE '(^|[[:space:]])--output[[:space:]]'; then
      curl_output=$(echo "$CMD" | sed -E 's/.*--output[[:space:]]+([^ ]+).*/\1/')
    elif echo "$CMD" | grep -qE '(^|[[:space:]])--output='; then
      curl_output=$(echo "$CMD" | sed -E 's/.*--output=([^ ]+).*/\1/')
    fi
    if [ -n "$curl_output" ]; then
      curl_output=$(expand_path "$curl_output")
      if [[ "$curl_output" != /* ]]; then
        curl_output="$PROJECT_DIR/$curl_output"
      fi
      local resolved_curl
      resolved_curl=$(resolve_path "$curl_output")
      if ! is_inside_project "$resolved_curl"; then
        echo "BLOCKED: 'curl' output file '$resolved_curl' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
  fi

  # --- wget -O / wget --output-document outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])wget($|[[:space:]])'; then
    local wget_output=""
    if echo "$CMD" | grep -qE '(^|[[:space:]])-O[[:space:]]'; then
      wget_output=$(echo "$CMD" | sed -E 's/.*[[:space:]]-O[[:space:]]+([^ ]+).*/\1/')
    elif echo "$CMD" | grep -qE '(^|[[:space:]])--output-document[[:space:]]'; then
      wget_output=$(echo "$CMD" | sed -E 's/.*--output-document[[:space:]]+([^ ]+).*/\1/')
    elif echo "$CMD" | grep -qE '(^|[[:space:]])--output-document='; then
      wget_output=$(echo "$CMD" | sed -E 's/.*--output-document=([^ ]+).*/\1/')
    fi
    if [ -n "$wget_output" ]; then
      wget_output=$(expand_path "$wget_output")
      if [[ "$wget_output" != /* ]]; then
        wget_output="$PROJECT_DIR/$wget_output"
      fi
      local resolved_wget
      resolved_wget=$(resolve_path "$wget_output")
      if ! is_inside_project "$resolved_wget"; then
        echo "BLOCKED: 'wget' output file '$resolved_wget' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
  fi

  # --- Writing to files outside project via redirection (> and >>) ---
  if echo "$CMD" | grep -qE '>{1,2}\s*/|>{1,2}\s*~|>{1,2}\s*\$HOME|>{1,2}\s*"[/~]|>{1,2}\s*'"'"'[/~]'; then
    # Extract redirect targets for both > and >>
    REDIR_TARGET=$(echo "$CMD" | grep -oE '>{1,2}\s*[^ ]+' | sed 's/^>*[[:space:]]*//')
    if [ -n "$REDIR_TARGET" ]; then
      REDIR_TARGET=$(expand_path "$REDIR_TARGET")
      if [[ "$REDIR_TARGET" != /* ]]; then
        REDIR_TARGET="$PROJECT_DIR/$REDIR_TARGET"
      fi
      RESOLVED=$(resolve_path "$REDIR_TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: Redirect target '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
  fi

  # --- Chmod/chown outside project ---
  for CMD_NAME in chmod chown; do
    if echo "$CMD" | grep -qE "(^|[[:space:]])${CMD_NAME}($|[[:space:]])"; then
      PATHS=$(echo "$CMD" | grep -oE "(^|[[:space:]])${CMD_NAME}[[:space:]]+.*" | sed "s/^[[:space:]]*${CMD_NAME}[[:space:]]*//" | tr ' ' '\n' | grep -v '^-' | grep -v '^[0-9]')
      for TARGET in $PATHS; do
        TARGET=$(expand_path "$TARGET")
        if [[ "$TARGET" != /* ]]; then
          TARGET="$PROJECT_DIR/$TARGET"
        fi
        RESOLVED=$(resolve_path "$TARGET")

        if ! is_inside_project "$RESOLVED"; then
          echo "BLOCKED: '${CMD_NAME}' targets '$RESOLVED' which is OUTSIDE project directory. Ask user for explicit permission." >&2
          exit 2
        fi
      done
    fi
  done
}

# --- Split command into sub-commands and check each ---
# Split on ;, &&, ||, and | (but not inside quoted strings)
# This is a basic splitter that handles common cases.
split_and_check() {
  local full_cmd="$1"

  # Use awk to split on ;, &&, ||, | while respecting quotes
  # We replace delimiters with a unique separator, then split
  local -a subcmds=()
  local current=""
  local in_single_quote=0
  local in_double_quote=0
  local i=0
  local len=${#full_cmd}
  local ch prev_ch=""

  while [ $i -lt $len ]; do
    ch="${full_cmd:$i:1}"

    # Handle quotes
    if [ "$ch" = "'" ] && [ $in_double_quote -eq 0 ]; then
      if [ $in_single_quote -eq 0 ]; then
        in_single_quote=1
      else
        in_single_quote=0
      fi
      current="${current}${ch}"
      prev_ch="$ch"
      i=$((i + 1))
      continue
    fi

    if [ "$ch" = '"' ] && [ $in_single_quote -eq 0 ]; then
      if [ $in_double_quote -eq 0 ]; then
        in_double_quote=1
      else
        in_double_quote=0
      fi
      current="${current}${ch}"
      prev_ch="$ch"
      i=$((i + 1))
      continue
    fi

    # Only split when not inside quotes
    if [ $in_single_quote -eq 0 ] && [ $in_double_quote -eq 0 ]; then
      # Check for && or ||
      if [ $i -lt $((len - 1)) ]; then
        local two_char="${full_cmd:$i:2}"
        if [ "$two_char" = "&&" ] || [ "$two_char" = "||" ]; then
          subcmds+=("$current")
          current=""
          i=$((i + 2))
          prev_ch=""
          continue
        fi
      fi

      # Check for ; or |
      if [ "$ch" = ";" ] || [ "$ch" = "|" ]; then
        subcmds+=("$current")
        current=""
        prev_ch="$ch"
        i=$((i + 1))
        continue
      fi
    fi

    current="${current}${ch}"
    prev_ch="$ch"
    i=$((i + 1))
  done

  # Add the last sub-command
  if [ -n "$current" ]; then
    subcmds+=("$current")
  fi

  # Check each sub-command
  for subcmd in "${subcmds[@]}"; do
    check_single_command "$subcmd"
  done
}

# --- Main entry point: split chained commands and check each ---
split_and_check "$COMMAND"

exit 0
