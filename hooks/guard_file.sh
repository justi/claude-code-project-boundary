#!/bin/bash
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

if [ -z "${CLAUDE_PROJECT_DIR:-}" ]; then
  echo "WARNING: CLAUDE_PROJECT_DIR is not set, falling back to pwd ($(pwd)). Set CLAUDE_PROJECT_DIR for reliable boundary enforcement." >&2
fi
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
PROJECT_DIR="${PROJECT_DIR%/}"

# --- Portable realpath in pure bash (same as guard.sh) ---
resolve_path() {
  local p="$1"
  if [[ "$p" != /* ]]; then
    p="$(pwd)/$p"
  fi
  local -a parts=()
  local IFS='/'
  for segment in $p; do
    if [[ "$segment" == ".." ]]; then
      [[ ${#parts[@]} -gt 0 ]] && unset 'parts[${#parts[@]}-1]'
    elif [[ "$segment" != "." && -n "$segment" ]]; then
      parts+=("$segment")
    fi
  done
  local IFS='/'
  local normalized="/${parts[*]}"
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

# --- Expand ~ and $HOME ---
expand_path() {
  local p="$1"
  p="${p%\"}"
  p="${p#\"}"
  p="${p%\'}"
  p="${p#\'}"
  if [[ "$p" == "~/"* ]]; then
    p="$HOME/${p#\~/}"
  elif [[ "$p" == "~" ]]; then
    p="$HOME"
  fi
  p="${p/\$HOME/$HOME}"
  p="${p/\$\{HOME\}/$HOME}"
  echo "$p"
}

PROJECT_DIR=$(resolve_path "$PROJECT_DIR")

FILE_PATH=$(expand_path "$FILE_PATH")
if [[ "$FILE_PATH" != /* ]]; then
  FILE_PATH="$PROJECT_DIR/$FILE_PATH"
fi
RESOLVED=$(resolve_path "$FILE_PATH")

if [[ "$RESOLVED/" != "$PROJECT_DIR/"* ]]; then
  echo "BLOCKED: File '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
  exit 2
fi

exit 0
