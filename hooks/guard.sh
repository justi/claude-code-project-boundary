#!/bin/bash
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$COMMAND" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
# Ensure PROJECT_DIR has no trailing slash for consistent comparison
PROJECT_DIR="${PROJECT_DIR%/}"

# --- Portable realpath that works on macOS ---
# macOS realpath does not support -m (non-existent path resolution).
# Try grealpath (GNU coreutils), then fall back to python3.
resolve_path() {
  local p="$1"
  if command -v grealpath >/dev/null 2>&1; then
    grealpath -m "$p" 2>/dev/null && return
  fi
  python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$p" 2>/dev/null && return
  # Last resort: echo the path as-is
  echo "$p"
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

# --- Always blocked (dangerous regardless of location) ---
ALWAYS_BLOCKED=(
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
  if echo "$COMMAND" | grep -qiE "$pattern"; then
    echo "BLOCKED: '$COMMAND' matches dangerous pattern '$pattern'. This command is always blocked. Ask user for explicit permission." >&2
    exit 2
  fi
done

# --- File deletion: allowed inside project, blocked outside ---
if echo "$COMMAND" | grep -qE '(^|[[:space:]])rm($|[[:space:]])'; then
  # Extract paths from rm command (skip flags)
  PATHS=$(echo "$COMMAND" | grep -oE '(^|[[:space:]])rm[[:space:]]+.*' | sed 's/^[[:space:]]*rm[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

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

# --- Moving/copying files outside project ---
if echo "$COMMAND" | grep -qE '(^|[[:space:]])mv($|[[:space:]])'; then
  # Extract all non-flag arguments from mv
  MV_ARGS=$(echo "$COMMAND" | grep -oE '(^|[[:space:]])mv[[:space:]]+.*' | sed 's/^[[:space:]]*mv[[:space:]]*//' | tr ' ' '\n' | grep -v '^-')

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

# --- Writing to files outside project via redirection (> and >>) ---
if echo "$COMMAND" | grep -qE '>{1,2}\s*/|>{1,2}\s*~|>{1,2}\s*\$HOME|>{1,2}\s*"[/~]|>{1,2}\s*'"'"'[/~]'; then
  # Extract redirect targets for both > and >>
  REDIR_TARGET=$(echo "$COMMAND" | grep -oE '>{1,2}\s*[^ ]+' | sed 's/^>*[[:space:]]*//')
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
  if echo "$COMMAND" | grep -qE "(^|[[:space:]])${CMD_NAME}($|[[:space:]])"; then
    PATHS=$(echo "$COMMAND" | grep -oE "(^|[[:space:]])${CMD_NAME}[[:space:]]+.*" | sed "s/^[[:space:]]*${CMD_NAME}[[:space:]]*//" | tr ' ' '\n' | grep -v '^-' | grep -v '^[0-9]')
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

exit 0
