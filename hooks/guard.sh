#!/bin/bash
set -euo pipefail

# Load sibling library modules. Resolve this script's directory so the
# source path works whether guard.sh is invoked directly, via symlink,
# or through CLAUDE_PLUGIN_ROOT — we always load lib/ from next to the
# current script file, not from $PWD or $CLAUDE_PLUGIN_ROOT which may
# differ at invocation time.
_GUARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/tokenize.sh
source "$_GUARD_DIR/lib/tokenize.sh"

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
  # Normalize: collapse `.` and `//` segments only. DO NOT lexically resolve
  # `..`, because that would skip over a symlinked intermediate directory
  # (e.g. `memory/linkdir/../x` with `linkdir -> /tmp` is `/tmp/x` at the
  # OS level, not `memory/x`). `..` is left for physical resolution via
  # `cd $check && pwd -P` below, which honors symlink semantics correctly.
  local -a parts=()
  local IFS='/'
  for segment in $p; do
    if [[ "$segment" != "." && -n "$segment" ]]; then
      parts+=("$segment")
    fi
  done
  local IFS='/'
  local normalized
  if [[ ${#parts[@]} -eq 0 ]]; then
    normalized="/"
  else
    normalized="/${parts[*]}"
  fi
  # Walk up to find the nearest existing ancestor directory and resolve symlinks
  local check="$normalized"
  local tail=""
  while [[ ! -e "$check" && "$check" != "/" ]]; do
    tail="/$(basename "$check")$tail"
    check="$(dirname "$check")"
  done
  local combined
  if [[ -d "$check" ]]; then
    # `check` is a directory (possibly via symlink) — canonicalize it.
    # `cd && pwd -P` follows symlinks fully, so `.../linkdir -> /etc`
    # resolves to `/etc`. This is essential: if left unresolved, the
    # subsequent lexical `..` pass would incorrectly pop `linkdir` and
    # leave the caller inside the allowlisted dir.
    local real_ancestor
    real_ancestor=$(cd -P "$check" && pwd -P)
    combined="${real_ancestor}${tail}"
  elif [[ -e "$check" ]]; then
    # File exists — canonicalize the directory component so that intermediate
    # symlinks are fully dereferenced (macOS /var -> /private/var is one
    # case; more importantly, a user-created symlink inside an allowlisted
    # dir like `memory/linkdir -> /etc` resolves here, otherwise the
    # allowlist matches the unresolved path and permits the write).
    local _f_dir _f_base
    _f_dir=$(dirname "$check")
    _f_base=$(basename "$check")
    if [[ -d "$_f_dir" ]]; then
      local _real_f_dir
      _real_f_dir=$(cd -P "$_f_dir" && pwd -P)
      combined="${_real_f_dir}/${_f_base}${tail}"
    else
      combined="$normalized"
    fi
  else
    combined="$normalized"
  fi
  # Final pass: apply lexical `..` resolution on the combined result.
  # This is SAFE here (unlike at the top of the function) because the
  # ancestor has been physically canonicalized — no symlinks remain in
  # the prefix, so `..` cannot silently cross one. This step collapses
  # path-traversal attempts like `$PROJECT/safe/../../etc/passwd` into
  # `/etc/passwd` for the boundary check.
  local -a _final=()
  local IFS='/'
  for _seg in $combined; do
    if [[ "$_seg" == ".." ]]; then
      [[ ${#_final[@]} -gt 0 ]] && unset '_final[${#_final[@]}-1]'
    elif [[ -n "$_seg" ]]; then
      _final+=("$_seg")
    fi
  done
  if [[ ${#_final[@]} -eq 0 ]]; then
    echo "/"
  else
    echo "/${_final[*]}"
  fi
}

# Resolve PROJECT_DIR itself so symlinks (e.g. /var -> /private/var on macOS) match
PROJECT_DIR=$(resolve_path "$PROJECT_DIR")

# --- Load path allowlist from hooks/allowlist.conf ---
# Patterns listed there bypass the boundary check. Kept in a separate file
# so users can inspect/extend without editing the guard logic. See the
# warning at the top of allowlist.conf — broad entries create bypass risk.
declare -a ALLOWLIST_PATTERNS=()
ALLOWLIST_FILE="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/hooks/allowlist.conf"
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
# --- Detect shell/source tokens by basename (handles any absolute path) ---
# `/opt/homebrew/bin/bash`, `/nix/store/.../bin/bash`, `/bin/bash` all
# count as the shell `bash`. Without basename matching, the exec guard
# only fires for paths in the hard-coded normalization list.
# Strip a binary path prefix (/bin/, /sbin/, /usr/bin/, /usr/sbin/,
# /usr/local/bin/) from the command-name token of CMD only — not from
# any argument or operand. Walks past common runtime wrappers
# (sudo/env/nice/...), VAR=val assignments, and flags to find the real
# command-name position. The strip is a single in-place replacement of
# the prefixed token, leaving the rest of CMD (including operands
# that legitimately reference `/bin/<name>` as paths) untouched.
#
# Required because the previous "match whitespace before /bin/"
# normalisation also matched the whitespace BEFORE every operand,
# rewriting `rm /bin/sh` to `rm sh`, `tee /bin/owned` to `tee owned`,
# etc., which then resolved into the project and bypassed the
# boundary (Codex review on commit e01df86 — bypass A).
strip_command_name_prefix() {
  local cmd="$1"
  local -a toks=()
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    toks+=("$t")
  done < <(tokenize_args "$cmd")

  local idx=-1 i
  local prev_was_timeout=0
  for i in "${!toks[@]}"; do
    local raw="${toks[$i]}"
    local t
    t=$(strip_quotes "$raw")
    # `timeout` takes a duration operand (e.g. `timeout 5 cmd`,
    # `timeout 1.5s cmd`); skip one extra token after it.
    if [ $prev_was_timeout -eq 1 ]; then
      prev_was_timeout=0
      case "$t" in
        [0-9]*) continue ;;
      esac
    fi
    case "$t" in
      timeout)
        prev_was_timeout=1; continue ;;
      sudo|env|/bin/env|/usr/bin/env|nice|nohup|time|stdbuf|ionice|chrt|taskset|command|builtin|exec)
        continue ;;
    esac
    case "$t" in
      [A-Za-z_]*=*) continue ;;
      -*) continue ;;
    esac
    idx=$i
    break
  done

  [[ $idx -lt 0 ]] && { printf '%s' "$cmd"; return; }

  local first
  first=$(strip_quotes "${toks[$idx]}")
  case "$first" in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*) ;;
    *) printf '%s' "$cmd"; return ;;
  esac

  local cmdname="${first##*/}"

  # Replace first occurrence of $first in $cmd with $cmdname.
  # Pattern matching here treats $first verbatim (it cannot contain
  # bash glob metacharacters in any realistic command-name position).
  local prefix="${cmd%%${first}*}"
  if [ "$prefix" = "$cmd" ]; then
    printf '%s' "$cmd"; return
  fi
  local rest="${cmd:$((${#prefix} + ${#first}))}"
  printf '%s%s%s' "$prefix" "$cmdname" "$rest"
}

strip_command_name_quotes() {
  # If the command-name token of $1 is wrapped in matching single or
  # double quotes (e.g. "rm", 'rm', "/bin/rm"), replace that token
  # with its unquoted form so downstream detectors that match on bare
  # names recognise it. bash strips surrounding quotes from a command
  # word at exec time, so the quoted form invokes the same binary —
  # failing to recognise it here would leak every bare-name detector
  # (rm, mv, cp, ln, chmod, chown, tee, curl, wget, find, sed,
  # truncate, rsync) past the guard. Walks tokens using the same
  # wrapper / env-var / flag skipping rules as strip_command_name_prefix.
  # Reported by Copilot review on commit 22112ba (guard.sh:1078, 1503).
  local cmd="$1"
  local -a toks=()
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    toks+=("$t")
  done < <(tokenize_args "$cmd")

  local idx=-1 i prev_was_timeout=0
  for i in "${!toks[@]}"; do
    local raw="${toks[$i]}"
    local t
    t=$(strip_quotes "$raw")
    if [ $prev_was_timeout -eq 1 ]; then
      prev_was_timeout=0
      case "$t" in
        [0-9]*) continue ;;
      esac
    fi
    case "$t" in
      timeout)
        prev_was_timeout=1; continue ;;
      sudo|env|/bin/env|/usr/bin/env|nice|nohup|time|stdbuf|ionice|chrt|taskset|command|builtin|exec)
        continue ;;
    esac
    case "$t" in
      [A-Za-z_]*=*) continue ;;
      -*) continue ;;
    esac
    idx=$i
    break
  done

  [[ $idx -lt 0 ]] && { printf '%s' "$cmd"; return; }

  local raw="${toks[$idx]}"
  # Only rewrite when the raw token is itself surrounded by matching
  # single or double quotes — tokenize_args preserves the wrapping
  # quote bytes on the token, so `"rm"` / `'rm'` / `"/bin/rm"` all
  # match. Tokens without surrounding quotes (bare `rm` or
  # partially-quoted like `"rm"abc`) are left alone.
  case "$raw" in
    \"?*\") ;;
    \'?*\') ;;
    *) printf '%s' "$cmd"; return ;;
  esac

  local bare="${raw:1:${#raw}-2}"

  # Replace first occurrence of $raw in $cmd with $bare.
  local prefix="${cmd%%${raw}*}"
  if [ "$prefix" = "$cmd" ]; then
    printf '%s' "$cmd"; return
  fi
  local rest="${cmd:$((${#prefix} + ${#raw}))}"
  printf '%s%s%s' "$prefix" "$bare" "$rest"
}

command_name_is() {
  # Return 0 iff the post-wrapper command-name token of $CMD equals $1.
  # Walks $CMD tokens using the same rules as strip_command_name_prefix:
  # skip `timeout <dur>`, sudo/env/nice/nohup/time/stdbuf/ionice/chrt/
  # taskset/command/builtin/exec wrappers, VAR=val environment prefixes
  # and -flag tokens. Any /bin/, /sbin/, /usr/bin/, /usr/sbin/,
  # /usr/local/bin/ prefix on the command-name token is stripped before
  # comparison, so `/usr/bin/install` is recognised as `install`.
  #
  # Why: several detectors (install, rsync, ...) use a bare
  # `(^|[[:space:]])CMDNAME($|[[:space:]])` regex that matches the
  # word anywhere in the command. For common names that are also
  # package-manager subcommands (npm install / bundle install /
  # poetry install / etc.) this produces false positives. Use this
  # helper to require the actual command-name position.
  local target=$1
  local -a toks=()
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    toks+=("$t")
  done < <(tokenize_args "$CMD")
  local i prev_was_timeout=0
  for i in "${!toks[@]}"; do
    local raw="${toks[$i]}" t
    t=$(strip_quotes "$raw")
    if [ $prev_was_timeout -eq 1 ]; then
      prev_was_timeout=0
      case "$t" in
        [0-9]*) continue ;;
      esac
    fi
    case "$t" in
      timeout)
        prev_was_timeout=1; continue ;;
      sudo|env|/bin/env|/usr/bin/env|nice|nohup|time|stdbuf|ionice|chrt|taskset|command|builtin|exec)
        continue ;;
    esac
    case "$t" in
      [A-Za-z_]*=*) continue ;;
      -*) continue ;;
    esac
    case "$t" in
      /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*) t="${t##*/}" ;;
    esac
    [ "$t" = "$target" ]
    return
  done
  return 1
}

is_discard_target() {
  # Return 0 iff $1 is a POSIX bit-bucket write target whose bytes are
  # guaranteed to be discarded with no real filesystem write.
  #
  # /dev/null is the canonical bit-bucket on every POSIX system
  # (Linux, macOS, BSD) at the same path. Writes to it are accepted
  # by the kernel and dropped — there is no filesystem target, no
  # parent directory mutation, no symlink side-effect. Callers that
  # KNOW they are writing a target (redirect operators, `tee`,
  # `curl -o`, `wget -O`, `dd of=`) can short-circuit here before
  # invoking is_write_permitted, so probe and silencing workflows
  # like `curl -o /dev/null` and `2>/dev/null` don't require a
  # per-project allowlist entry.
  #
  # IMPORTANT: this must NOT be used from call sites that do an
  # in-place edit via temp-file + rename (`sed -i`, `truncate`) or
  # from `cp/mv/ln/install/rsync` targets — those DO write under
  # the parent directory of the nominal target (e.g. sed -i creates
  # a temp file in /dev/ before renaming over /dev/null), and the
  # boundary check must still fire there. See is_write_permitted
  # docstring for the full separation of write semantics.
  [ "$1" = "/dev/null" ]
}

is_shell_token() {
  local _t="$1"
  local _base="${_t##*/}"
  case "$_base" in
    bash|sh|zsh|ksh|dash|fish) return 0 ;;
  esac
  return 1
}
is_source_token() {
  case "$1" in
    source|.) return 0 ;;
  esac
  return 1
}

is_allowlisted() {
  local path="$1"
  local i=0 n=${#ALLOWLIST_REGEXES[@]}
  while [ $i -lt $n ]; do
    local regex="${ALLOWLIST_REGEXES[$i]}"
    if [[ "$path" =~ $regex ]]; then
      return 0
    fi
    local base_regex="${ALLOWLIST_BASE_REGEXES[$i]}"
    if [ -n "$base_regex" ] && [[ "$path" =~ $base_regex ]]; then
      return 0
    fi
    i=$((i+1))
  done
  return 1
}

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
  printf '%s\n' "$p"
}

# tokenize_args moved to hooks/lib/tokenize.sh (sourced at top of file).

# --- Extract all option values from CMD_TOKENS ---
# Usage: extract_option_values <short> <long>
#   short: e.g. "-o", or "" to skip
#   long:  e.g. "--output", or "" to skip
# Supports: "-o value", "--output value", "--output=value".
# Option flags are matched after stripping surrounding quotes so that
# `curl "-o" /etc/passwd` also matches.
# Returns EVERY occurrence (one per line) so callers can validate each one.
# This is fail-closed and handles both "last-wins" tools (tar, cp/mv)
# and positional tools (curl -o applies to each URL) — if any single
# occurrence is outside the project boundary, we block.
# Returns 0 if at least one found, 1 otherwise.
extract_option_values() {
  local short="$1"
  local long="$2"
  local i=0 n=${#CMD_TOKENS[@]}
  local found=1
  while [ $i -lt $n ]; do
    local raw_tok="${CMD_TOKENS[$i]}"
    local tok
    tok=$(strip_quotes "$raw_tok")
    if [ -n "$short" ] && [ "$tok" = "$short" ] && [ $((i + 1)) -lt $n ]; then
      printf '%s\n' "${CMD_TOKENS[$((i + 1))]}"
      found=0
    fi
    if [ -n "$long" ]; then
      if [ "$tok" = "$long" ] && [ $((i + 1)) -lt $n ]; then
        printf '%s\n' "${CMD_TOKENS[$((i + 1))]}"
        found=0
      fi
      if [[ "$tok" == "${long}="* ]]; then
        printf '%s\n' "${tok#${long}=}"
        found=0
      fi
    fi
    i=$((i + 1))
  done
  return $found
}

# --- Check if a resolved path is inside the project directory ---
# STRICT: allowlist does NOT apply here. Use in destructive contexts where
# the allowlist must not grant an exception: rm, chmod/chown, cd-outside,
# find -delete/-exec rm, and executing a script file.
is_inside_project() {
  local resolved="$1"
  # Add trailing slash to both sides so /tmp/project-other doesn't match /tmp/project
  if [[ "$resolved/" == "$PROJECT_DIR/"* ]]; then
    return 0
  fi
  return 1
}

# --- Check if a resolved path is a permitted WRITE target ---
# Permitted = inside the project OR matches a write-allowlist pattern
# (hooks/allowlist.conf). Use in write contexts: Edit/Write, redirect,
# tee, cp/mv/ln/install/rsync targets, tar -C, unzip -d, cpio -D,
# curl -o, wget -O, dd of=, sed -i, truncate.
#
# NOT for destructive ops (rm, chmod/chown, find -delete, cd+destructive,
# script execution). The allowlist is a WRITE exception, not a general
# boundary exception.
is_write_permitted() {
  local resolved="$1"

  # Dereference leaf symlinks BEFORE the inside-project check. Without
  # this, a symlink that lives inside the project but points outside
  # is treated as in-project and every write-style Bash detector
  # (tee, sed -i, truncate, curl -o, wget -O, dd of=) that funnels
  # through this function lets the write land at the outside target.
  # The Edit/Write tool branch already derefs upstream; this brings
  # the Bash-side paths to parity (Copilot review on PR #12 / 7641a412).
  # Loop limit + post-loop check fail-closed on circular chains.
  local deref="$resolved"
  local depth=20
  while [[ -L "$deref" && $depth -gt 0 ]]; do
    local link_target
    link_target=$(readlink "$deref")
    if [[ "$link_target" == /* ]]; then
      deref=$(resolve_path "$link_target")
    else
      deref=$(resolve_path "$(dirname "$deref")/$link_target")
    fi
    depth=$((depth - 1))
  done
  if [[ -L "$deref" ]]; then
    return 1
  fi

  if is_inside_project "$deref"; then
    return 0
  fi
  if is_allowlisted "$deref"; then
    # Allowlisted paths previously needed their own deref pass to avoid
    # `ln -sf /etc/passwd memory/link && tee memory/link`. Now that the
    # entry deref above already canonicalised the leaf, the allowlist
    # check sees the ultimate OS-level path — same protection, no
    # second loop needed.
    return 0
  fi
  return 1
}

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

# --- Blank out bodies of quoted/escaped heredocs for substitution scan ---
# When bash reads a heredoc whose delimiter is quoted or backslash-escaped
# (`<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<-'EOF'`), it does NOT perform
# parameter/command/arithmetic expansion in the body. Backticks and
# $(...) in such a body are therefore literal bytes written to stdin,
# not command substitutions. The substitution detector further down
# must not fire on those bytes, otherwise a legitimate
#   cat > <allowlisted>/file <<'EOF'
#   `echo hi`
#   EOF
# is wrongly blocked as "command substitution with backticks".
#
# This helper returns a copy of the input in which every quoted-heredoc
# body is overwritten with spaces (newlines preserved so byte offsets
# and line counts remain aligned). Unquoted heredoc bodies are left
# untouched — bash DOES expand them, so substitution detection must
# still fire there. Ambiguous / malformed input falls through to
# returning the original (= fail closed on the main scan).
#
# Note: shell-stdin-heredoc blocking for `bash <<...` / `sh <<...` is
# done elsewhere (shell_reads_from_stdin) on the original CMD and is
# unaffected by this sanitization.
blank_quoted_heredoc_bodies() {
  local s="$1"
  local n=${#s}
  case "$s" in *"<<"*) ;; *) printf '%s' "$s"; return 0 ;; esac

  # Build line index: LS[k]=start, LE[k]=offset of terminating '\n' (or n).
  local -a LS=() LE=()
  local i=0 ls=0
  while [ $i -lt $n ]; do
    if [ "${s:$i:1}" = $'\n' ]; then
      LS+=("$ls"); LE+=("$i"); ls=$((i+1))
    fi
    i=$((i+1))
  done
  LS+=("$ls"); LE+=("$n")
  local num_lines=${#LS[@]}

  # Queue of pending heredocs: parallel arrays.
  local -a HD=() HQ=() HI=() HB=()   # delim, quoted, indented(<<-), body_start
  local -a BS=() BE=()               # ranges to blank: [BS[k], BE[k])

  local li=0
  while [ $li -lt $num_lines ]; do
    local lstart=${LS[$li]} lend=${LE[$li]}
    local line="${s:$lstart:$((lend-lstart))}"

    if [ ${#HD[@]} -eq 0 ]; then
      # Command context — scan for `<<` openers outside quotes.
      local ci=0 clen=${#line} sq=0 dq=0 esc=0
      while [ $ci -lt $clen ]; do
        local c="${line:$ci:1}"
        if [ $esc -eq 1 ]; then esc=0; ci=$((ci+1)); continue; fi
        if [ "$c" = "\\" ] && [ $sq -eq 0 ]; then esc=1; ci=$((ci+1)); continue; fi
        if [ "$c" = "'" ] && [ $dq -eq 0 ]; then sq=$((1-sq)); ci=$((ci+1)); continue; fi
        if [ "$c" = '"' ] && [ $sq -eq 0 ]; then dq=$((1-dq)); ci=$((ci+1)); continue; fi
        if [ $sq -eq 0 ] && [ $dq -eq 0 ] && [ "$c" = "<" ] && [ $((ci+1)) -lt $clen ] && [ "${line:$((ci+1)):1}" = "<" ]; then
          # Skip `<<<` here-string — not a heredoc.
          if [ $((ci+2)) -lt $clen ] && [ "${line:$((ci+2)):1}" = "<" ]; then
            ci=$((ci+3)); continue
          fi
          local p=$((ci+2)) ind=0
          if [ $p -lt $clen ] && [ "${line:$p:1}" = "-" ]; then ind=1; p=$((p+1)); fi
          while [ $p -lt $clen ]; do
            local ws="${line:$p:1}"
            [ "$ws" = " " ] || [ "$ws" = $'\t' ] || break
            p=$((p+1))
          done
          if [ $p -ge $clen ]; then
            # Delimiter on next line — give up and return original (fail closed).
            printf '%s' "$s"; return 0
          fi
          local f="${line:$p:1}" delim="" q=0 j=0
          case "$f" in
            "'")
              j=$((p+1))
              while [ $j -lt $clen ] && [ "${line:$j:1}" != "'" ]; do j=$((j+1)); done
              if [ $j -ge $clen ]; then printf '%s' "$s"; return 0; fi
              delim="${line:$((p+1)):$((j-p-1))}"; q=1; p=$((j+1)) ;;
            '"')
              j=$((p+1))
              while [ $j -lt $clen ] && [ "${line:$j:1}" != '"' ]; do j=$((j+1)); done
              if [ $j -ge $clen ]; then printf '%s' "$s"; return 0; fi
              delim="${line:$((p+1)):$((j-p-1))}"; q=1; p=$((j+1)) ;;
            "\\")
              p=$((p+1)); j=$p
              while [ $j -lt $clen ] && [[ "${line:$j:1}" =~ [A-Za-z0-9_.+:=,/@%^-] ]]; do j=$((j+1)); done
              delim="${line:$p:$((j-p))}"; q=1; p=$j ;;
            *)
              j=$p
              while [ $j -lt $clen ] && [[ "${line:$j:1}" =~ [A-Za-z0-9_.+:=,/@%^-] ]]; do j=$((j+1)); done
              delim="${line:$p:$((j-p))}"; q=0; p=$j ;;
          esac
          if [ -z "$delim" ]; then printf '%s' "$s"; return 0; fi
          HD+=("$delim"); HQ+=("$q"); HI+=("$ind"); HB+=("-1")
          ci=$p; continue
        fi
        ci=$((ci+1))
      done
      # Only the queue HEAD's body starts on the line after this opener.
      # Subsequent heredocs' bodies begin on the line AFTER their
      # predecessor's terminator — we defer their body_start until the
      # predecessor is popped (see the matching block in body context
      # below). Previously we set body_start = lend+1 for every heredoc
      # on this line, so a later quoted heredoc's blank range covered
      # bytes belonging to an earlier unquoted body, hiding $(...) /
      # backtick / $VAR in the unquoted body from fail-closed scans.
      # Reported by Copilot review on commit aa6409b.
      if [ ${#HB[@]} -gt 0 ] && [ "${HB[0]}" = "-1" ]; then
        HB[0]=$((lend+1))
        [ $li -eq $((num_lines-1)) ] && HB[0]=$n
      fi
    else
      # Body context — check for terminator of queue head.
      local hd="${HD[0]}" hq="${HQ[0]}" hi_flag="${HI[0]}" hbs="${HB[0]}"
      local cmp="$line"
      if [ "$hi_flag" = "1" ]; then
        while [ ${#cmp} -gt 0 ] && [ "${cmp:0:1}" = $'\t' ]; do cmp="${cmp:1}"; done
      fi
      if [ "$cmp" = "$hd" ]; then
        if [ "$hq" = "1" ] && [ "$hbs" != "-1" ] && [ $lstart -gt $hbs ]; then
          BS+=("$hbs"); BE+=("$lstart")
        fi
        HD=("${HD[@]:1}"); HQ=("${HQ[@]:1}"); HI=("${HI[@]:1}"); HB=("${HB[@]:1}")
        # The predecessor just popped; the next queue head's body starts
        # on the line AFTER this terminator line. Matches the deferred
        # body_start in the opener-context block above.
        if [ ${#HD[@]} -gt 0 ] && [ "${HB[0]}" = "-1" ]; then
          HB[0]=$((lend+1))
          [ $li -eq $((num_lines-1)) ] && HB[0]=$n
        fi
      fi
    fi
    li=$((li+1))
  done

  # Any heredoc still open at EOF: blank remainder if quoted (tolerant of
  # trailing newlines / missing terminator).
  local qi=0
  while [ $qi -lt ${#HD[@]} ]; do
    if [ "${HQ[$qi]}" = "1" ] && [ "${HB[$qi]}" != "-1" ]; then
      local hbs="${HB[$qi]}"
      [ $n -gt $hbs ] && { BS+=("$hbs"); BE+=("$n"); }
    fi
    qi=$((qi+1))
  done

  if [ ${#BS[@]} -eq 0 ]; then printf '%s' "$s"; return 0; fi

  # Emit output: copy bytes, replace blanked ranges with space.
  # Newlines inside body ranges are preserved by default so byte
  # offsets and line counts remain aligned for line-based scanners.
  # Pass "blank_newlines" as the second arg to also replace body
  # newlines with spaces — needed by split_and_check, which would
  # otherwise treat a newline INSIDE a quoted heredoc body as a
  # command separator and slice the heredoc into pseudo-subcommands.
  local blank_nl="${2:-preserve}"
  local out="" pos=0 bi=0 nb=${#BS[@]}
  while [ $bi -lt $nb ]; do
    local bs=${BS[$bi]} be=${BE[$bi]}
    # In blank_newlines mode, also subsume the newline that immediately
    # PRECEDES the body — that newline ends the heredoc opener line
    # syntactically (it's not a command separator and not a body byte
    # either). Without subsuming it, split_and_check would treat it as
    # a real newline-separator and slice the heredoc opener away from
    # its body, exposing the raw body to downstream walkers.
    if [ "$blank_nl" = "blank_newlines" ] && [ $bs -gt 0 ] && [ "${s:$((bs-1)):1}" = $'\n' ]; then
      bs=$((bs-1))
    fi
    if [ $pos -lt $bs ]; then out+="${s:$pos:$((bs-pos))}"; fi
    local k=0 blen=$((be-bs))
    while [ $k -lt $blen ]; do
      local bc="${s:$((bs+k)):1}"
      if [ "$bc" = $'\n' ] && [ "$blank_nl" != "blank_newlines" ]; then
        out+=$'\n'
      else
        out+=" "
      fi
      k=$((k+1))
    done
    pos=$be; bi=$((bi+1))
  done
  if [ $pos -lt $n ]; then out+="${s:$pos:$((n-pos))}"; fi
  printf '%s' "$out"
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

  # --- Fail closed on unexpanded $VAR outside single quotes ---
  # `expand_path` only handles ~, $HOME, ${HOME}. Any other $VAR is kept
  # verbatim and then joined under $EFFECTIVE_CWD, so it looks "inside the
  # project" to the guard while Bash expands it at exec time. Treat it like
  # `$(…)`: if the value cannot be inspected, refuse.
  local vi=0 vlen=${#CMD_EXPAND_SCAN}
  local vin_sq=0 vin_dq=0 vin_esc=0
  while [ $vi -lt $vlen ]; do
    local vc="${CMD_EXPAND_SCAN:$vi:1}"
    if [ $vin_esc -eq 1 ]; then vin_esc=0; vi=$((vi+1)); continue; fi
    if [ "$vc" = "\\" ] && [ $vin_sq -eq 0 ]; then vin_esc=1; vi=$((vi+1)); continue; fi
    if [ "$vc" = "'" ] && [ $vin_dq -eq 0 ]; then vin_sq=$((1-vin_sq)); vi=$((vi+1)); continue; fi
    if [ "$vc" = '"' ] && [ $vin_sq -eq 0 ]; then vin_dq=$((1-vin_dq)); vi=$((vi+1)); continue; fi
    if [ $vin_sq -eq 0 ] && [ "$vc" = "\$" ] && [ $((vi+1)) -lt $vlen ]; then
      local vnext="${CMD_EXPAND_SCAN:$((vi+1)):1}"
      # Explicit passthroughs — NOT parameter expansions:
      #   $(...)   — command substitution, caught by the substitution detector
      #   $'...'   — ANSI-C quoted literal (escape decoding, no expansion)
      #   $"..."   — i18n string literal (no parameter expansion)
      # Arithmetic `$((...))` is handled by the substitution detector.
      if [ "$vnext" = "(" ] || [ "$vnext" = "'" ] || [ "$vnext" = '"' ]; then
        :
      # Allow $HOME / ${HOME} — expand_path handles them.
      elif [[ "$vnext" =~ [A-Za-z_] ]]; then
        local rest="${CMD_EXPAND_SCAN:$((vi+1))}"
        local vname="${rest%%[^A-Za-z0-9_]*}"
        if [ "$vname" != "HOME" ]; then
          echo "BLOCKED: Variable expansion '\$${vname}' cannot be safely inspected. Ask user for explicit permission." >&2
          exit 2
        fi
      elif [ "$vnext" = "{" ]; then
        local rest="${CMD_EXPAND_SCAN:$((vi+2))}"
        local vname="${rest%%\}*}"
        if [ "$vname" != "HOME" ]; then
          echo "BLOCKED: Variable expansion '\${${vname}}' cannot be safely inspected. Ask user for explicit permission." >&2
          exit 2
        fi
      # Positional ($0..$9) and special ($@ $* $# $? $$ $! $-) parameters.
      # These expand at exec time to values the guard cannot inspect —
      # e.g. `set -- /etc/passwd; rm $1` looks like `rm $1` (treated as a
      # relative filename inside cwd) to the regex checks, but bash
      # expands $1 to /etc/passwd at execution. Same fail-closed rule as
      # $FOO applies — every non-HOME expansion is refused.
      elif [[ "$vnext" =~ [0-9@*#?!\$\-] ]]; then
        echo "BLOCKED: Shell parameter expansion '\$${vnext}' cannot be safely inspected. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
    vi=$((vi+1))
  done

  # --- Tokenize the command once (quote-aware) for option/redirect parsing ---
  local -a CMD_TOKENS=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS+=("$tok")
  done < <(tokenize_args "$CMD")

  # Parallel token stream built from a heredoc-blanked copy of the
  # command. Used by detectors that walk tokens looking for a marker
  # word (sed, truncate, ">"-redirect operator) and would otherwise
  # pick up heredoc body bytes as if they were live commands.
  #
  # Source MUST be CMD_RAW, not CMD: the alias-escape pass that strips
  # `\` before a letter (so `\rm` → `rm`) also turns `<<\EOF` into
  # `<<EOF` — i.e. silently downgrades a backslash-escaped (= quoted)
  # heredoc delimiter to its unquoted twin. blank_quoted_heredoc_bodies
  # would then see an unquoted heredoc and refuse to blank the body,
  # re-leaking body bytes into every downstream walker. Blanking BEFORE
  # the alias-escape strip preserves the heredoc-quoting semantics that
  # bash itself uses.
  #
  # The remaining normalisation passes are then re-applied on the
  # blanked view so that `\rm`, subshell parens, and `/bin/` prefixes
  # in the live command-line are still recognised by detectors. Body
  # bytes are already spaces by this point, so the alias-escape strip
  # cannot leak through them.
  local CMD_BLANKED
  CMD_BLANKED=$(blank_quoted_heredoc_bodies "$CMD_RAW")
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/(^|[[:space:]])\(+/\1/g; s/\)+($|[[:space:]])/\1/g')"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/\\([a-zA-Z_])/\1/g')"
  # Strip surrounding quotes from the command-name token — same reason
  # as for CMD (line ~907). Without this, detectors that walk
  # CMD_TOKENS_SCAN (sed -i, truncate, redirect-target) miss a quoted
  # command even after heredoc blanking.
  CMD_BLANKED="$(strip_command_name_quotes "$CMD_BLANKED")"
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's#^/(usr/local/bin|usr/bin|bin|sbin|usr/sbin)/##')"
  # Tokenize-aware /bin/ strip on CMD_BLANKED — MUST match the logic
  # used on CMD (line 757). The previous broad sed
  #   s#([^<>|&;[:space:]])[[:space:]]+/(bin|...)/#\1 #g
  # stripped the prefix from ANY operand whose preceding char was a
  # regular non-separator (closing quote, letter, digit), rewriting
  # absolute outside-project targets to bare relative names. Since
  # CMD_TOKENS_SCAN feeds the sed -i / truncate / redirect walkers,
  # `sed -i '...' /usr/bin/owned` and `truncate -s 0 /bin/bash` slipped
  # past the boundary check (Copilot review on commit aa6409b).
  CMD_BLANKED=$(strip_command_name_prefix "$CMD_BLANKED")
  CMD_BLANKED="$(printf '%s' "$CMD_BLANKED" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  local -a CMD_TOKENS_SCAN=()
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    CMD_TOKENS_SCAN+=("$tok")
  done < <(tokenize_args "$CMD_BLANKED")

  # --- Block command substitution outside single quotes ---
  # `$(...)` and backticks are expanded by bash (even inside double quotes),
  # so the guard cannot know the final target. Single quotes keep them literal,
  # so only block when they appear outside single quotes. Arithmetic expansion
  # `$((...))` is allowed — it's a numeric computation, not a command.
  # Similar rationale to blocking `bash -c` / `eval` — the inner command is
  # uninspectable.
  local ci=0 clen=${#CMD_EXPAND_SCAN}
  local cin_sq=0 cin_dq=0 cin_esc=0
  while [ $ci -lt $clen ]; do
    local cc="${CMD_EXPAND_SCAN:$ci:1}"
    if [ $cin_esc -eq 1 ]; then
      cin_esc=0
      ci=$((ci + 1))
      continue
    fi
    if [ "$cc" = "\\" ] && [ $cin_sq -eq 0 ]; then
      cin_esc=1
      ci=$((ci + 1))
      continue
    fi
    # Single quotes are only delimiters when NOT inside double quotes
    if [ "$cc" = "'" ] && [ $cin_dq -eq 0 ]; then
      cin_sq=$(( 1 - cin_sq ))
      ci=$((ci + 1))
      continue
    fi
    # Double quotes are only delimiters when NOT inside single quotes
    if [ "$cc" = '"' ] && [ $cin_sq -eq 0 ]; then
      cin_dq=$(( 1 - cin_dq ))
      ci=$((ci + 1))
      continue
    fi
    if [ $cin_sq -eq 0 ]; then
      if [ "$cc" = "\`" ]; then
        echo "BLOCKED: Command substitution with backticks cannot be safely inspected. Ask user for explicit permission." >&2
        exit 2
      fi
      if [ "$cc" = "\$" ] && [ $((ci + 1)) -lt $clen ] && [ "${CMD_EXPAND_SCAN:$((ci + 1)):1}" = "(" ]; then
        # Skip arithmetic expansion $((...)): next-next char is also (
        if [ $((ci + 2)) -ge $clen ] || [ "${CMD_EXPAND_SCAN:$((ci + 2)):1}" != "(" ]; then
          echo "BLOCKED: Command substitution '\$(...)' cannot be safely inspected. Ask user for explicit permission." >&2
          exit 2
        fi
      fi
    fi
    ci=$((ci + 1))
  done

  # --- Block cd outside project followed by destructive commands ---
  if [[ "$CMD" =~ ^cd($|[[:space:]]) ]]; then
    local cd_target
    # cd takes a single argument, so grab everything after 'cd ' as the target
    # (including spaces if quoted). Not using tokenize_args because cd doesn't
    # take multiple path arguments.
    cd_target=$(echo "$CMD" | sed 's/^cd[[:space:]]*//')
    # cd with no args or cd ~ goes to $HOME
    if [[ -z "$cd_target" || "$cd_target" == "~" ]]; then
      cd_target="$HOME"
    else
      cd_target=$(expand_path "$cd_target")
    fi
    if [[ "$cd_target" != /* ]]; then
      cd_target="$EFFECTIVE_CWD/$cd_target"
    fi
    local resolved_cd
    resolved_cd=$(resolve_path "$cd_target")
    EFFECTIVE_CWD="$resolved_cd"
    # STRICT: cd-outside triggers the destructive-subcommand guard.
    # Allowlist must not weaken this — `cd memory && git clean -fd` should
    # still block. But write-style commands (`cd memory && tee note.md`)
    # should reach their per-command is_write_permitted check, so we track
    # allowlist-context in a separate flag.
    if ! is_inside_project "$resolved_cd"; then
      export _GUARD_CD_OUTSIDE=1
      CWD_OUTSIDE_PROJECT=1
      if is_allowlisted "$resolved_cd"; then
        export _GUARD_CD_IN_ALLOWLIST=1
        CWD_IN_ALLOWLIST=1
      else
        export _GUARD_CD_IN_ALLOWLIST=0
        CWD_IN_ALLOWLIST=0
      fi
    else
      export _GUARD_CD_OUTSIDE=0
      CWD_OUTSIDE_PROJECT=0
      export _GUARD_CD_IN_ALLOWLIST=0
      CWD_IN_ALLOWLIST=0
    fi
    return 0
  fi

  # Block destructive commands when running outside the project
  # (either via cd in a chained command, or via cwd from the hook event)
  local outside_context=0
  if [[ "${_GUARD_CD_OUTSIDE:-0}" == "1" || "$CWD_OUTSIDE_PROJECT" == "1" ]]; then
    outside_context=1
  fi
  local cwd_in_allowlist=0
  if [[ "${_GUARD_CD_IN_ALLOWLIST:-0}" == "1" || "${CWD_IN_ALLOWLIST:-0}" == "1" ]]; then
    cwd_in_allowlist=1
  fi

  if [[ "$outside_context" == "1" ]]; then
    # When cwd is in an allowlisted dir, only block TRULY destructive ops
    # (rm/mv/chmod/chown/find+delete). Write-style commands (tee, curl -o,
    # wget -O, cp, ln, redirects) must reach their per-command path check
    # which uses is_write_permitted. Without this split, `cd memory && tee
    # note.md` would be blocked even though note.md is inside an allowlisted
    # path. `cp` and `ln` fall into the strict bucket because their own
    # per-command checks are strict anyway, and bundling them here preserves
    # earlier behavior.
    local destructive_cmds
    if [[ "$cwd_in_allowlist" == "1" ]]; then
      # In allowlisted cwd, relax only `tee` (per-command check already
      # validates all non-flag args via is_write_permitted). curl/wget
      # STAY strict because their validators only cover a subset of
      # output options (-o/--output and -O/--output-document); the
      # directory-prefix forms `wget -P` and `curl --output-dir` are
      # not independently checked, so leaving them open in allowlisted
      # cwd would allow writes to /etc etc.
      destructive_cmds="rm|mv|cp|ln|chmod|chown|find|curl|wget"
    else
      destructive_cmds="rm|mv|cp|ln|chmod|chown|tee|find|curl|wget"
    fi
    if echo "$CMD" | grep -qE "(^|[[:space:]])($destructive_cmds)($|[[:space:]])"; then
      echo "BLOCKED: Destructive command outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # Destructive git subcommands
    # git clean only destructive with -f/--force AND without -n/--dry-run
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+clean([[:space:]]|$)'; then
      local has_force=0
      local is_dry_run=0
      if echo "$CMD" | grep -qE '(^|[[:space:]])--force([[:space:]]|$)' || \
         echo "$CMD" | grep -qE '(^|[[:space:]])-[a-zA-Z]*f[a-zA-Z]*([[:space:]]|$)'; then
        has_force=1
      fi
      if echo "$CMD" | grep -qE '(^|[[:space:]])--dry-run([[:space:]]|$)' || \
         echo "$CMD" | grep -qE '(^|[[:space:]])-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
        is_dry_run=1
      fi
      if [[ "$has_force" == "1" && "$is_dry_run" == "0" ]]; then
        echo "BLOCKED: Destructive 'git clean' outside project directory. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
    # git checkout . and git checkout -- .
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+checkout([[:space:]]+--)?[[:space:]]+\.([[:space:]]|$)'; then
      echo "BLOCKED: Destructive 'git checkout .' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git reset --hard
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+reset[[:space:]]+--hard'; then
      echo "BLOCKED: Destructive 'git reset --hard' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git push --force / -f
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+push[[:space:]]+.*(--force|-f)([[:space:]]|$)'; then
      echo "BLOCKED: Destructive 'git push --force' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git restore . / git restore -- . / git restore --worktree .
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+restore([[:space:]]+(--worktree|--staged|--))*[[:space:]]+\.([[:space:]]|$)'; then
      echo "BLOCKED: Destructive 'git restore .' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git stash drop / clear
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+stash[[:space:]]+(drop|clear)'; then
      echo "BLOCKED: Destructive 'git stash drop/clear' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git branch -D / --delete --force
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+branch[[:space:]]+(-D|--delete[[:space:]]+--force)'; then
      echo "BLOCKED: Destructive 'git branch -D' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # git reflog expire --all or --expire=now
    if echo "$CMD" | grep -qE '(^|[[:space:]])git[[:space:]]+reflog[[:space:]]+expire'; then
      echo "BLOCKED: Destructive 'git reflog expire' outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
    # Destructive rails/rake subcommands
    if echo "$CMD" | grep -qE '(^|[[:space:]])(rails|rake)[[:space:]]+db:(drop|reset)'; then
      echo "BLOCKED: Destructive rails/rake command outside project directory. Ask user for explicit permission." >&2
      exit 2
    fi
  fi

  # --- Block nested shell execution (bash -c, sh -c, eval) ---
  # Match: bash -c, sh -c, bash -lc, bash -ec, /bin/bash -c, /bin/sh -c, /usr/bin/env bash -c
  if echo "$CMD" | grep -qE '(^|[[:space:]])(/usr/bin/env[[:space:]]+)?(/bin/)?(bash|sh)[[:space:]]+-[a-zA-Z]*c[[:space:]]'; then
    echo "BLOCKED: Nested shell execution ('bash -c' / 'sh -c') cannot be safely inspected. Ask user for explicit permission." >&2
    exit 2
  fi
  if echo "$CMD" | grep -qE '(^|[[:space:]])eval[[:space:]]'; then
    echo "BLOCKED: 'eval' cannot be safely inspected. Ask user for explicit permission." >&2
    exit 2
  fi

  # --- Block non-shell interpreters with inline code flags ---
  # python/perl/ruby/node/php/osascript all accept code on argv. The inner
  # string cannot be inspected, so the same fail-closed rule as `bash -c`
  # applies. Flags covered: -c (python), -e (perl/ruby/node), --eval,
  # --execute, -E (perl alias). A dedicated rule catches `awk 'BEGIN{system(
  # "…")}'` and similar because awk programs are the first non-option arg,
  # not behind a flag — so we detect the `system(` marker in the CMD string.
  if echo "$CMD" | grep -qE '(^|[[:space:]])(python|python2|python3|perl|ruby|node|nodejs|deno|bun|php|osascript|Rscript)[[:space:]]+(-[a-zA-Z]*[ceE]|--eval|--execute)([[:space:]]|=|$)'; then
    echo "BLOCKED: Non-shell interpreter with inline code flag cannot be safely inspected. Ask user for explicit permission." >&2
    exit 2
  fi
  # Dedicated PHP rule — `-r`, `-R`, `--run` execute inline code. Cannot
  # be added to the shared regex above because `-r` is a module-preload
  # flag in ruby/node (no code execution), so a generic `r` letter would
  # false-positive on `ruby -r json` / `node -r dotenv`. The matcher
  # accepts attached forms (`-rcode`, `-Rcode`), quoted-attached
  # (`-r'code'`), clustered-ending (`-ar`, `-aR`), and the long alias
  # `--run`. Attached form was originally missed (guard.sh:1087 regex
  # required a boundary char immediately after the `[rR]`, so
  # `-rsystem('x')` slipped past). Re-reported by Copilot review on
  # commit aa6409b (guard.sh:1068).
  if echo "$CMD" | grep -qE '(^|[[:space:]])php[[:space:]]+(-[rR][^[:space:]=]*|-[a-zA-Z]*[rR]|--run)([[:space:]]|=|$|'\''|")'; then
    echo "BLOCKED: 'php -r/-R/--run' inline code cannot be safely inspected. Ask user for explicit permission." >&2
    exit 2
  fi
  if echo "$CMD" | grep -qE '(^|[[:space:]])(g?awk|mawk|nawk)([[:space:]]|$)'; then
    if echo "$CMD" | grep -qE 'system[[:space:]]*\(|\|[[:space:]]*&?[[:space:]]*"?(sh|bash)'; then
      echo "BLOCKED: awk program with 'system()' / shell pipe cannot be safely inspected. Ask user for explicit permission." >&2
      exit 2
    fi
  fi

  # --- Block piping to sh/bash (e.g. echo "rm -rf /" | sh) ---
  # Match bare shell invocations: sh, bash, /bin/sh, /bin/bash,
  # and with flags: sh -s, bash --login, etc.
  # But NOT: bash script.sh, bash -x script.sh (running a script file)
  if echo "$CMD" | grep -qE '^(/bin/)?(sh|bash)$'; then
    echo "BLOCKED: Piping to 'sh'/'bash' cannot be safely inspected. Ask user for explicit permission." >&2
    exit 2
  fi
  # Match shell with only flags (no script file): sh -s, bash --login, sh -s -- args
  if echo "$CMD" | grep -qE '^(/bin/)?(sh|bash)[[:space:]]+-'; then
    # Check if all args are flags (start with -), not a script path
    local shell_args
    shell_args=$(echo "$CMD" | sed -E 's/^(\/bin\/)?(sh|bash)[[:space:]]+//')
    local has_script=0
    for shell_token in $shell_args; do
      case "$shell_token" in
        --) break ;;  # everything after -- is args to the script/stdin
        -*) continue ;;
        *) has_script=1; break ;;
      esac
    done
    if [[ $has_script -eq 0 ]]; then
      echo "BLOCKED: Piping to 'sh'/'bash' cannot be safely inspected. Ask user for explicit permission." >&2
      exit 2
    fi
  fi

  # --- Block executing script files outside the project ---
  # Catches: `bash /tmp/x.sh`, `sh ~/x.sh`, `zsh|ksh|dash|fish /tmp/x.sh`,
  # `source /tmp/x.sh`, `. /tmp/x.sh`. Inline-code forms (`bash -c ...`)
  # are caught by the nested-shell block above; this covers the
  # complementary case where the script is a path argument.
  #
  # STRICT project-root check (no allowlist). Allowlist grants WRITE to
  # specific paths (e.g. memory/); if execute inherited that, a write-
  # allowlisted dir would become an RCE escape hatch:
  #   `echo 'rm -rf $HOME' > memory/x.sh && bash memory/x.sh`.
  # Walk CMD_TOKENS to locate the shell/source invocation, possibly buried
  # behind an `env [flags] [VAR=val]*` wrapper. Once found, scan for the
  # script-path operand — honoring flags that consume the next token
  # (-O / -o for bash set options). Finally, dereference symlinks on the
  # script path so a `project/link.sh -> /tmp/evil.sh` bait is caught.
  # Re-tokenize the command with redirect operators (< << <<< <<-) spaced
  # out so that attached forms like `bash</tmp/x.sh`, `bash<<EOF`, and
  # `bash<<<'rm -rf /'` don't slip past as single unsplit tokens.
  local _exec_cmd
  _exec_cmd=$(printf '%s' "$CMD" | sed -E 's/(<<-|<<<|<<|<)/ \1 /g')
  local -a CMD_TOKENS_EXEC=()
  while IFS= read -r _etok; do
    [[ -z "$_etok" ]] && continue
    CMD_TOKENS_EXEC+=("$_etok")
  done < <(tokenize_args "$_exec_cmd")

  # A parallel token stream built from a heredoc-blanked copy of CMD.
  # Used ONLY by the `_saw_redir`/`exec_kind` scans below, which otherwise
  # would treat a quoted-heredoc body byte like "bash" or "source" as a
  # shell token and false-positive with
  #   "Stdin redirection feeding shell cannot be safely inspected"
  # on perfectly innocuous text like a git-commit body mentioning `bash`.
  # Real shell-stdin attacks (`bash << /tmp/x`, `< /tmp/x bash`,
  # `bash <<'EOF' ... EOF`, `bash <<<'rm -rf /'`, attached `bash</tmp/x>`)
  # still appear in this stream because their shell token sits OUTSIDE
  # any heredoc body, so the fail-closed detectors keep firing.
  local _exec_cmd_scan
  _exec_cmd_scan=$(blank_quoted_heredoc_bodies "$CMD" \
                   | sed -E 's/(<<-|<<<|<<|<)/ \1 /g')
  local -a CMD_TOKENS_EXEC_SCAN=()
  while IFS= read -r _etok; do
    [[ -z "$_etok" ]] && continue
    CMD_TOKENS_EXEC_SCAN+=("$_etok")
  done < <(tokenize_args "$_exec_cmd_scan")

  local exec_kind="" exec_shell_idx=-1
  local _ti=0 _tn=${#CMD_TOKENS_EXEC[@]}

  # Fail-closed on ANY stdin redirect (< << <<< <<-) that appears before
  # a shell/source token — regardless of leading wrappers or VAR=val.
  # Bash allows redirections to sit anywhere in the command-prefix, so
  # `FOO=1 < /tmp/evil.sh bash`, `nice < /tmp/evil.sh bash`, and a bare
  # `< /tmp/evil.sh bash` all feed the shell from an uninspectable source.
  local _rk=0 _saw_redir=0
  local _tn_scan=${#CMD_TOKENS_EXEC_SCAN[@]}
  while [ $_rk -lt $_tn_scan ]; do
    local _rtok_chk
    _rtok_chk=$(strip_quotes "${CMD_TOKENS_EXEC_SCAN[$_rk]}")
    case "$_rtok_chk" in
      \<|\<\<|\<\<\<|\<\<-) _saw_redir=1 ;;
      *)
        if [ $_saw_redir -eq 1 ] && { is_shell_token "$_rtok_chk" || is_source_token "$_rtok_chk"; }; then
          echo "BLOCKED: Stdin redirection feeding shell cannot be safely inspected. Ask user for explicit permission." >&2
          exit 2
        fi
        ;;
    esac
    _rk=$((_rk + 1))
  done

  # Fail-closed on `env -S <str>`, `env --split-string=<str>`, `env -C <dir>`,
  # `env --chdir=<dir>`: all of these either hide the real command inside a
  # split string or change the cwd so relative script paths no longer match
  # what Bash actually executes.
  if [ $_tn -gt 0 ]; then
    local _env_first
    _env_first=$(strip_quotes "${CMD_TOKENS_EXEC[0]}")
    if [[ "$_env_first" == "env" || "$_env_first" == "/usr/bin/env" ]]; then
      local _envk=1
      while [ $_envk -lt $_tn ]; do
        local _envtok
        _envtok=$(strip_quotes "${CMD_TOKENS_EXEC[$_envk]}")
        case "$_envtok" in
          -S|-S*|--split-string|--split-string=*|-C|-C*|--chdir|--chdir=*)
            echo "BLOCKED: 'env -S/--split-string/-C/--chdir' cannot be safely inspected. Ask user for explicit permission." >&2
            exit 2 ;;
        esac
        _envk=$((_envk + 1))
      done
    fi
  fi

  # Walk past common runtime wrappers (env, command, nice, nohup, timeout,
  # time, stdbuf, ionice, chrt, taskset) and any leftover sudo flags
  # (sudo itself is already stripped at the top of check_single_command,
  # but its own short flags can remain in the token stream as `-E` etc.).
  # We only advance past token 0 when it is a recognized wrapper or looks
  # like a flag / VAR=val — this avoids false positives on invocations
  # like `echo bash`, where `bash` is an argument, not the command.
  # Categorize the leading token so we know how aggressively to skip.
  # "env_like" — env / leading flags / leading VAR=val. env has many flag
  #   and operand forms (-i, -u NAME, FOO=bar), so we skip greedily until
  #   a shell token appears.
  # "wrapper" — nice/nohup/timeout/time/command/stdbuf/ionice/chrt/taskset.
  #   These take at most a few flags + 0–1 positional (e.g. timeout's
  #   duration). First non-flag non-numeric token is the wrapper's command
  #   operand — stop there. Avoids false positives like
  #   `time echo bash /tmp/x` where `bash` is echo's arg, not a shell.
  # Greedy skip: walk past wrappers / flags / VAR=val / operands until
  # a shell or source token appears. Known tradeoff — this over-blocks
  # `time echo bash /tmp/x` (bash is an arg to echo, not a shell), but
  # precise per-wrapper operand grammars would miss real bypasses like
  # `timeout -s TERM 10 bash /tmp/x` and `stdbuf -o L bash /tmp/x` where
  # flag operands are non-numeric. Security over precision for this case.
  local _advance=0
  if [ $_tn -gt 0 ]; then
    local _t0
    _t0=$(strip_quotes "${CMD_TOKENS_EXEC[0]}")
    case "$_t0" in
      env|/usr/bin/env|command|builtin|exec|nice|nohup|timeout|time|stdbuf|ionice|chrt|taskset)
        _advance=1 ;;
      -*|+*) _advance=1 ;;
      *=*) _advance=1 ;;
    esac
  fi
  if [ $_advance -eq 1 ]; then
    _ti=1
    while [ $_ti -lt $_tn ]; do
      local _tok
      _tok=$(strip_quotes "${CMD_TOKENS_EXEC[$_ti]}")
      if is_shell_token "$_tok" || is_source_token "$_tok"; then
        break
      fi
      _ti=$((_ti + 1))
    done
  fi
  if [ $_ti -lt $_tn ]; then
    local _cmd_tok
    _cmd_tok=$(strip_quotes "${CMD_TOKENS_EXEC[$_ti]}")
    if is_shell_token "$_cmd_tok"; then
      exec_kind="shell"; exec_shell_idx=$_ti
    elif is_source_token "$_cmd_tok"; then
      exec_kind="source"; exec_shell_idx=$_ti
    fi
  fi
  if [ -n "$exec_kind" ]; then
    local exec_target=""
    local ei=$((exec_shell_idx + 1)) en=${#CMD_TOKENS_EXEC[@]}
    local seen_ddash=0
    while [ $ei -lt $en ]; do
      local etok
      etok=$(strip_quotes "${CMD_TOKENS_EXEC[$ei]}")
      if [ $seen_ddash -eq 0 ]; then
        case "$etok" in
          --) seen_ddash=1; ei=$((ei + 1)); continue ;;
          # bash/sh -O/+O and -o/+o take the next token as operand
          -O|+O|-o|+o) ei=$((ei + 2)); continue ;;
          # Bash accepts both `-x` (enable) and `+x` (disable) forms
          -*|+*|'') ei=$((ei + 1)); continue ;;
          # fd prefix for a redirect operator (e.g. `bash 0<file`, `bash 2>&1`).
          # Skip — the operator itself is handled on the next iteration.
          [0-9]|[0-9][0-9])
            ei=$((ei + 1)); continue ;;
          # Stdin redirection variants: bash executes whatever is piped in.
          # `<< EOF` / `<<< "str"` content can't be inspected — fail closed.
          # `< file` — validate `file` as exec target (treat next token as script).
          \<\<|\<\<-|\<\<\<)
            echo "BLOCKED: Shell invoked with heredoc/here-string (<<, <<-, <<<) cannot be safely inspected. Ask user for explicit permission." >&2
            exit 2 ;;
          \<)
            ei=$((ei + 1))
            if [ $ei -lt $en ]; then
              local _next_tok
              _next_tok=$(strip_quotes "${CMD_TOKENS_EXEC[$ei]}")
              # `bash < <(cmd)` — process substitution on stdin is a hidden
              # command source. Fail closed.
              case "$_next_tok" in
                \<|\<\(*|\(*|\&*)
                  # `< <(cmd)` process substitution, `<(...)` direct, or
                  # `<&N` fd duplicate — all uninspectable sources.
                  echo "BLOCKED: Shell stdin from process substitution / fd duplicate cannot be safely inspected. Ask user for explicit permission." >&2
                  exit 2 ;;
                *)
                  exec_target="$_next_tok" ;;
              esac
            fi
            break ;;
        esac
      fi
      exec_target="$etok"
      break
    done
    if [ -n "$exec_target" ]; then
      exec_target=$(expand_path "$exec_target")
      if [[ "$exec_target" != /* ]]; then
        exec_target="$EFFECTIVE_CWD/$exec_target"
      fi
      local exec_resolved
      exec_resolved=$(resolve_path "$exec_target")
      # Dereference symlinks on the leaf — bash follows them at exec time,
      # so a project-local symlink pointing outside must be caught.
      local _exec_depth=20
      while [[ -L "$exec_resolved" && $_exec_depth -gt 0 ]]; do
        local _exec_link
        _exec_link=$(readlink "$exec_resolved")
        if [[ "$_exec_link" == /* ]]; then
          exec_resolved=$(resolve_path "$_exec_link")
        else
          exec_resolved=$(resolve_path "$(dirname "$exec_resolved")/$_exec_link")
        fi
        _exec_depth=$((_exec_depth - 1))
      done
      if [[ -L "$exec_resolved" ]]; then
        echo "BLOCKED: Script symlink chain too deep or circular at '$exec_resolved'. Ask user for explicit permission." >&2
        exit 2
      fi
      if [[ "$exec_resolved/" != "$PROJECT_DIR/"* ]]; then
        echo "BLOCKED: Executing script '$exec_resolved' is OUTSIDE project directory '$PROJECT_DIR'. Allowlist does not cover execute. Ask user for explicit permission." >&2
        exit 2
      fi
    fi
  fi

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
      # Extract ALL find paths (non-option arguments after 'find')
      # Skip options like -L, -H, -P that come before the paths
      local -a find_paths=()
      local find_args
      find_args=$(echo "$CMD" | sed -E 's/.*find[[:space:]]+//')
      local past_options=0
      while IFS= read -r find_token; do
        [[ -z "$find_token" ]] && continue
        case "$find_token" in
          -L|-H|-P|-O*)
            [[ $past_options -eq 0 ]] && continue
            break ;;  # expression starts
          -*)  break ;;  # expression starts
          *)
            past_options=1
            find_paths+=("$find_token") ;;
        esac
      done < <(tokenize_args "$find_args")
      [[ ${#find_paths[@]} -eq 0 ]] && find_paths=(".")
      for find_path in "${find_paths[@]}"; do
        find_path=$(expand_path "$find_path")
        if [[ "$find_path" != /* ]]; then
          find_path="$EFFECTIVE_CWD/$find_path"
        fi
        local resolved_find
        resolved_find=$(resolve_path "$find_path")
        # STRICT: find -delete/-exec rm are destructive; allowlist must not apply.
        if ! is_inside_project "$resolved_find"; then
          echo "BLOCKED: 'find' with destructive action targets '$resolved_find' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
          exit 2
        fi
      done
    fi
  fi

  # --- File deletion: allowed inside project, blocked outside ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])rm($|[[:space:]])'; then
    # Extract paths from rm command (skip flags)
    local rm_raw
    rm_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])rm[[:space:]]+.*' | sed 's/^[[:space:]]*rm[[:space:]]*//')

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      TARGET=$(expand_path "$TARGET")
      # Resolve to absolute path
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      # STRICT: rm is destructive; allowlist grants WRITE, not DELETE.
      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'rm' targets '$RESOLVED' which is OUTSIDE project directory '$PROJECT_DIR'. File deletion is only allowed within the project. Ask user for explicit permission." >&2
        exit 2
      fi

      # Block deleting the project root itself
      if [[ "$RESOLVED" == "$PROJECT_DIR" ]]; then
        echo "BLOCKED: Cannot delete the project root directory itself." >&2
        exit 2
      fi
    done < <(tokenize_args "$rm_raw")
  fi

  # --- Moving files outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])mv($|[[:space:]])'; then
    # Check -t / --target-directory
    while IFS= read -r mv_target_dir; do
      [ -z "$mv_target_dir" ] && continue
      mv_target_dir=$(expand_path "$mv_target_dir")
      [[ "$mv_target_dir" != /* ]] && mv_target_dir="$EFFECTIVE_CWD/$mv_target_dir"
      local resolved_mv_td
      resolved_mv_td=$(resolve_path "$mv_target_dir")
      # STRICT: mv with -t still deletes sources from their original paths.
      # Allowing an allowlisted dir as dest could pair with an outside-project
      # source (caught by the per-arg strict loop below) — keep both ends tight.
      if ! is_inside_project "$resolved_mv_td"; then
        echo "BLOCKED: 'mv --target-directory' targets '$resolved_mv_td' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-t" "--target-directory" || true)
    local mv_raw
    mv_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])mv[[:space:]]+.*' | sed 's/^[[:space:]]*mv[[:space:]]*//')

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      # STRICT: mv deletes the source; allowlist must not apply, otherwise
      # `mv memory/foo project/foo` would destructively empty the memory dir
      # (allowlist grants WRITE, not move/delete).
      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'mv' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$mv_raw")
  fi

  # --- cp command: check all non-flag arguments ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])cp($|[[:space:]])'; then
    # Check -t / --target-directory
    while IFS= read -r cp_target_dir; do
      [ -z "$cp_target_dir" ] && continue
      cp_target_dir=$(expand_path "$cp_target_dir")
      [[ "$cp_target_dir" != /* ]] && cp_target_dir="$EFFECTIVE_CWD/$cp_target_dir"
      local resolved_cp_td
      resolved_cp_td=$(resolve_path "$cp_target_dir")
      if ! is_inside_project "$resolved_cp_td"; then
        echo "BLOCKED: 'cp --target-directory' targets '$resolved_cp_td' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-t" "--target-directory" || true)
    local cp_raw
    cp_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])cp[[:space:]]+.*' | sed 's/^[[:space:]]*cp[[:space:]]*//')

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'cp' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$cp_raw")
  fi

  # --- ln command: check all non-flag arguments ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])ln($|[[:space:]])'; then
    local ln_raw
    ln_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])ln[[:space:]]+.*' | sed 's/^[[:space:]]*ln[[:space:]]*//')

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'ln' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$ln_raw")
  fi

  # --- install command: like cp, check all non-flag path arguments ---
  # Must be tokenize-aware: the word `install` appears as a subcommand
  # in package managers (npm install / bundle install / poetry install
  # / cargo install / composer install / etc.), which are NOT the GNU
  # install binary and must not be blocked. Only fire when `install`
  # is the actual command-name token.
  if command_name_is install; then
    local install_raw
    install_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])install[[:space:]]+.*' | sed 's/^[[:space:]]*install[[:space:]]*//')
    # Skip mode arg (numeric, after -m/--mode), owner arg (after -o), group (after -g)
    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      # Skip pure numeric (mode) or user:group patterns
      if [[ "$TARGET" =~ ^[0-9]+$ ]] || [[ "$TARGET" =~ ^[a-zA-Z_][a-zA-Z0-9_]*(:[a-zA-Z_][a-zA-Z0-9_]*)?$ ]]; then
        continue
      fi
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")
      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'install' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$install_raw")
  fi

  # --- rsync command: check all non-flag path arguments ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])rsync($|[[:space:]])'; then
    local rsync_raw
    rsync_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])rsync[[:space:]]+.*' | sed 's/^[[:space:]]*rsync[[:space:]]*//')
    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      # Skip remote paths (user@host:/path or host:/path)
      if [[ "$TARGET" =~ : ]]; then
        continue
      fi
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")
      if ! is_inside_project "$RESOLVED"; then
        echo "BLOCKED: 'rsync' argument '$RESOLVED' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$rsync_raw")
  fi

  # --- tar: check every -C / --directory=PATH for extraction ---
  # tar allows multiple -C switches and the *last* one wins, so we must
  # validate every occurrence — not just the first.
  if echo "$CMD" | grep -qE '(^|[[:space:]])tar($|[[:space:]])'; then
    local ti=0 tn=${#CMD_TOKENS[@]}
    while [ $ti -lt $tn ]; do
      local ttok
      ttok=$(strip_quotes "${CMD_TOKENS[$ti]}")
      local tar_dir=""
      if [ "$ttok" = "-C" ] || [ "$ttok" = "--directory" ]; then
        if [ $((ti + 1)) -lt $tn ]; then
          tar_dir="${CMD_TOKENS[$((ti + 1))]}"
          ti=$((ti + 2))
        else
          ti=$((ti + 1))
        fi
      elif [[ "$ttok" == "--directory="* ]]; then
        tar_dir="${ttok#--directory=}"
        ti=$((ti + 1))
      else
        ti=$((ti + 1))
        continue
      fi
      if [ -n "$tar_dir" ]; then
        tar_dir=$(expand_path "$tar_dir")
        if [[ "$tar_dir" != /* ]]; then
          tar_dir="$EFFECTIVE_CWD/$tar_dir"
        fi
        local resolved_tar
        resolved_tar=$(resolve_path "$tar_dir")
        if ! is_write_permitted "$resolved_tar"; then
          echo "BLOCKED: 'tar -C' targets '$resolved_tar' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
          exit 2
        fi
      fi
    done
  fi

  # --- unzip -d PATH ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])unzip($|[[:space:]])'; then
    while IFS= read -r unzip_dir; do
      [ -z "$unzip_dir" ] && continue
      unzip_dir=$(expand_path "$unzip_dir")
      if [[ "$unzip_dir" != /* ]]; then
        unzip_dir="$EFFECTIVE_CWD/$unzip_dir"
      fi
      local resolved_unzip
      resolved_unzip=$(resolve_path "$unzip_dir")
      if ! is_write_permitted "$resolved_unzip"; then
        echo "BLOCKED: 'unzip -d' targets '$resolved_unzip' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-d" "" || true)
  fi

  # --- cpio -D PATH ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])cpio($|[[:space:]])'; then
    while IFS= read -r cpio_dir; do
      [ -z "$cpio_dir" ] && continue
      cpio_dir=$(expand_path "$cpio_dir")
      if [[ "$cpio_dir" != /* ]]; then
        cpio_dir="$EFFECTIVE_CWD/$cpio_dir"
      fi
      local resolved_cpio
      resolved_cpio=$(resolve_path "$cpio_dir")
      if ! is_write_permitted "$resolved_cpio"; then
        echo "BLOCKED: 'cpio -D' targets '$resolved_cpio' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-D" "" || true)
  fi

  # --- tee command: extract file arguments, block if outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])tee($|[[:space:]])'; then
    local tee_raw
    tee_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])tee[[:space:]]+.*' | sed 's/^[[:space:]]*tee[[:space:]]*//')

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      TARGET=$(expand_path "$TARGET")
      if [[ "$TARGET" != /* ]]; then
        TARGET="$EFFECTIVE_CWD/$TARGET"
      fi
      RESOLVED=$(resolve_path "$TARGET")

      # /dev/null is a discard sink for tee (`echo x | tee /dev/null`).
      is_discard_target "$RESOLVED" && continue
      if ! is_write_permitted "$RESOLVED"; then
        echo "BLOCKED: 'tee' targets '$RESOLVED' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(tokenize_args "$tee_raw")
  fi

  # --- curl -o / curl --output outside project ---
  # curl -o is positional: `curl -o out1 URL1 -o out2 URL2` writes each URL
  # to its corresponding output. Validate EVERY occurrence.
  if echo "$CMD" | grep -qE '(^|[[:space:]])curl($|[[:space:]])'; then
    while IFS= read -r curl_output; do
      [ -z "$curl_output" ] && continue
      curl_output=$(expand_path "$curl_output")
      if [[ "$curl_output" != /* ]]; then
        curl_output="$EFFECTIVE_CWD/$curl_output"
      fi
      local resolved_curl
      resolved_curl=$(resolve_path "$curl_output")
      # /dev/null is a discard sink for HTTP probes (`curl -o /dev/null -w %{http_code}`).
      is_discard_target "$resolved_curl" && continue
      if ! is_write_permitted "$resolved_curl"; then
        echo "BLOCKED: 'curl' output file '$resolved_curl' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-o" "--output" || true)
  fi

  # --- wget -O / wget --output-document outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])wget($|[[:space:]])'; then
    while IFS= read -r wget_output; do
      [ -z "$wget_output" ] && continue
      wget_output=$(expand_path "$wget_output")
      if [[ "$wget_output" != /* ]]; then
        wget_output="$EFFECTIVE_CWD/$wget_output"
      fi
      local resolved_wget
      resolved_wget=$(resolve_path "$wget_output")
      # /dev/null is a discard sink (`wget -O /dev/null URL`).
      is_discard_target "$resolved_wget" && continue
      if ! is_write_permitted "$resolved_wget"; then
        echo "BLOCKED: 'wget' output file '$resolved_wget' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
    done < <(extract_option_values "-O" "--output-document" || true)
  fi

  # --- dd of= outside project ---
  # dd accepts repeated key=value operands and the last one wins, so we must
  # validate every of= occurrence — not just the first.
  if echo "$CMD" | grep -qE '(^|[[:space:]])dd($|[[:space:]])'; then
    for raw_tok in "${CMD_TOKENS[@]}"; do
      local tok
      tok=$(strip_quotes "$raw_tok")
      if [[ "$tok" == of=* ]]; then
        local dd_output="${tok#of=}"
        if [ -n "$dd_output" ]; then
          dd_output=$(expand_path "$dd_output")
          if [[ "$dd_output" != /* ]]; then
            dd_output="$EFFECTIVE_CWD/$dd_output"
          fi
          local resolved_dd
          resolved_dd=$(resolve_path "$dd_output")
          # /dev/null is a discard sink (`dd if=x of=/dev/null`).
          if ! is_discard_target "$resolved_dd"; then
            if ! is_write_permitted "$resolved_dd"; then
              echo "BLOCKED: 'dd' output '$resolved_dd' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
              exit 2
            fi
          fi
        fi
      fi
    done
  fi

  # --- Writing to files outside project via redirection ---
  # Walk tokens and scan each one for an unquoted > operator anywhere
  # (not just at the start). This catches both separated forms (`> file`,
  # `2>> file`) and attached forms (`>file`, `x>file`, `"a">file`).
  # Skips fd-to-fd redirects like 2>&1 (target starts with &).
  #
  # Iterate the heredoc-blanked token stream so a quoted-heredoc body
  # mentioning "> /etc/foo" is not mistaken for a real redirect. Real
  # redirects sit OUTSIDE any heredoc body and survive the blanking
  # pass; an unquoted heredoc opener like `cat > /etc/x <<EOF ...EOF`
  # still has the `>` and `/etc/x` in the command-context portion that
  # is not blanked, so it stays caught.
  local ri=0 rn=${#CMD_TOKENS_SCAN[@]}
  while [ $ri -lt $rn ]; do
    local rtok="${CMD_TOKENS_SCAN[$ri]}"
    local REDIR_TARGET=""

    # Scan the token for an unquoted > (respecting ' and " quotes and
    # backslash escapes). `\>` outside single quotes is a literal >, not
    # a redirect operator.
    local j=0 tlen=${#rtok}
    local tin_sq=0 tin_dq=0
    local tin_esc=0
    local redir_pos=-1
    while [ $j -lt $tlen ]; do
      local tc="${rtok:$j:1}"
      if [ $tin_esc -eq 1 ]; then
        tin_esc=0
        j=$((j + 1))
        continue
      fi
      if [ "$tc" = "\\" ] && [ $tin_sq -eq 0 ]; then
        tin_esc=1
        j=$((j + 1))
        continue
      fi
      if [ "$tc" = "'" ] && [ $tin_dq -eq 0 ]; then
        tin_sq=$(( 1 - tin_sq ))
      elif [ "$tc" = '"' ] && [ $tin_sq -eq 0 ]; then
        tin_dq=$(( 1 - tin_dq ))
      elif [ "$tc" = ">" ] && [ $tin_sq -eq 0 ] && [ $tin_dq -eq 0 ]; then
        redir_pos=$j
        break
      fi
      j=$((j + 1))
    done

    if [ $redir_pos -lt 0 ]; then
      ri=$((ri + 1))
      continue
    fi

    # Found > at redir_pos. Extend past a second > if present (>>).
    local op_end=$((redir_pos + 1))
    if [ $op_end -lt $tlen ] && [ "${rtok:$op_end:1}" = ">" ]; then
      op_end=$((op_end + 1))
    fi
    # Also consume a trailing | (Bash clobber operator: >| or >>|).
    if [ $op_end -lt $tlen ] && [ "${rtok:$op_end:1}" = "|" ]; then
      op_end=$((op_end + 1))
    fi

    # Extract target: rest of token if any, otherwise next token
    local rest="${rtok:$op_end}"
    if [ -z "$rest" ]; then
      if [ $((ri + 1)) -lt $rn ]; then
        REDIR_TARGET="${CMD_TOKENS_SCAN[$((ri + 1))]}"
        ri=$((ri + 2))
      else
        ri=$((ri + 1))
      fi
    elif [[ "$rest" == \&* ]]; then
      # fd-to-fd redirect like 2>&1, no file target
      ri=$((ri + 1))
    else
      REDIR_TARGET="$rest"
      ri=$((ri + 1))
    fi

    if [ -n "$REDIR_TARGET" ]; then
      # Block process substitution — `> >(cmd)` runs `cmd` which the guard
      # cannot safely inspect, similar to nested shells.
      if [[ "$REDIR_TARGET" == \(* ]] || [[ "$REDIR_TARGET" == \>\(* ]] || [[ "$REDIR_TARGET" == \<\(* ]]; then
        echo "BLOCKED: Process substitution redirect '$REDIR_TARGET' cannot be safely inspected. Ask user for explicit permission." >&2
        exit 2
      fi
      REDIR_TARGET=$(expand_path "$REDIR_TARGET")
      if [[ "$REDIR_TARGET" != /* ]]; then
        REDIR_TARGET="$EFFECTIVE_CWD/$REDIR_TARGET"
      fi
      local resolved_redir
      resolved_redir=$(resolve_path "$REDIR_TARGET")
      # Follow symlinks so that `echo x > project/link` where
      # `link -> /etc/passwd` is caught. resolve_path only canonicalizes
      # the dirname, not the basename — a symlink leaf slips through.
      local redir_depth=20
      while [[ -L "$resolved_redir" && $redir_depth -gt 0 ]]; do
        local redir_link
        redir_link=$(readlink "$resolved_redir")
        if [[ "$redir_link" == /* ]]; then
          resolved_redir=$(resolve_path "$redir_link")
        else
          resolved_redir=$(resolve_path "$(dirname "$resolved_redir")/$redir_link")
        fi
        redir_depth=$((redir_depth - 1))
      done
      if [[ -L "$resolved_redir" ]]; then
        echo "BLOCKED: Redirect target symlink chain too deep or circular at '$resolved_redir'. Ask user for explicit permission." >&2
        exit 2
      fi
      # /dev/null is a discard sink for every redirect form
      # (`> /dev/null`, `2> /dev/null`, `&> /dev/null`, `2>&1 > /dev/null`).
      if ! is_discard_target "$resolved_redir"; then
        if ! is_write_permitted "$resolved_redir"; then
          echo "BLOCKED: Redirect target '$resolved_redir' is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
          exit 2
        fi
      fi
    fi
  done

  # --- sed -i: in-place edits on file arguments ---
  # GNU `sed -i`, BSD `sed -i ''`, and `sed -iSUFFIX` all rewrite the file(s)
  # passed as positional args. The non-in-place form is read-only and is left
  # alone. We only engage when -i / --in-place is actually present.
  # Use the heredoc-blanked view here: a commit-message body that
  # mentions "sed -i" must not be parsed as a real sed call.
  if echo "$CMD_BLANKED" | grep -qE '(^|[[:space:]])sed($|[[:space:]])'; then
    local sed_has_i=0
    for raw_tok in "${CMD_TOKENS_SCAN[@]}"; do
      local tok
      tok=$(strip_quotes "$raw_tok")
      if [[ "$tok" == -i* ]] || [[ "$tok" == --in-place* ]]; then
        sed_has_i=1
        break
      fi
    done
    if [ "$sed_has_i" -eq 1 ]; then
      # Positional tracking (replaces the old regex-based script heuristic,
      # which blocked legitimate programs like `/pat/d`, `/pat/p`, `y/…/…/`
      # because they start with `/` or other path-like bytes and looked
      # like absolute paths to the validator).
      #
      # sed grammar with -i:
      #   sed [options] [-e script]... [-f script-file]... [SCRIPT] FILE...
      # The positional SCRIPT exists only when NO -e/-f was supplied. When
      # -e/-f is present, every positional is a FILE. Pre-scan the token
      # stream to learn which regime applies, then walk positionals:
      #   - if no -e/-f seen: skip the first positional (it's SCRIPT)
      #   - every remaining positional is a FILE → is_write_permitted
      local has_explicit_script=0
      local pi=1 pn=${#CMD_TOKENS_SCAN[@]}
      while [ $pi -lt $pn ]; do
        local ptok
        ptok=$(strip_quotes "${CMD_TOKENS_SCAN[$pi]}")
        case "$ptok" in
          -e|-f|--expression|--file)
            has_explicit_script=1; pi=$((pi + 2)); continue ;;
          --expression=*|--file=*)
            has_explicit_script=1; pi=$((pi + 1)); continue ;;
        esac
        pi=$((pi + 1))
      done

      local script_skipped=0
      local sed_seen_dashdash=0
      local si=1 sn=${#CMD_TOKENS_SCAN[@]}
      while [ $si -lt $sn ]; do
        local stok
        stok=$(strip_quotes "${CMD_TOKENS_SCAN[$si]}")
        # POSIX `--` ends option parsing — every token after this is a
        # positional operand even if it starts with `-`. Without this, a
        # file operand named `-owned` was silently skipped as an
        # unknown flag (Copilot review on PR #12).
        if [ $sed_seen_dashdash -eq 0 ]; then
          # Consume flag+value pairs and bare flags (incl. BSD's empty `''`
          # backup-extension argument that follows a bare `-i`).
          case "$stok" in
            --)
              sed_seen_dashdash=1; si=$((si + 1)); continue ;;
            -e|-f|--expression|--file)
              si=$((si + 2)); continue ;;
            -*|'') si=$((si + 1)); continue ;;
          esac
        fi
        # First positional is SCRIPT only when no -e/-f was supplied.
        if [ "$has_explicit_script" -eq 0 ] && [ "$script_skipped" -eq 0 ]; then
          script_skipped=1
          si=$((si + 1)); continue
        fi
        local sexp
        sexp=$(expand_path "$stok")
        if [[ "$sexp" != /* ]]; then
          sexp="$EFFECTIVE_CWD/$sexp"
        fi
        local sresolved
        sresolved=$(resolve_path "$sexp")
        if ! is_write_permitted "$sresolved"; then
          echo "BLOCKED: 'sed -i' targets '$sresolved' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
          exit 2
        fi
        si=$((si + 1))
      done
    fi
  fi

  # --- truncate: always rewrites the target file(s) ---
  # Heredoc-blanked view as above — body bytes mentioning "truncate" are
  # not a real call.
  if echo "$CMD_BLANKED" | grep -qE '(^|[[:space:]])truncate($|[[:space:]])'; then
    local tri=1 trn=${#CMD_TOKENS_SCAN[@]}
    local trunc_seen_dashdash=0
    while [ $tri -lt $trn ]; do
      local trtok
      trtok=$(strip_quotes "${CMD_TOKENS_SCAN[$tri]}")
      # POSIX `--` ends option parsing — every token after this is a
      # positional file operand even if it starts with `-`. Same fix as
      # the sed -i walker above (Copilot review on PR #12).
      if [ $trunc_seen_dashdash -eq 0 ]; then
        case "$trtok" in
          --)
            trunc_seen_dashdash=1; tri=$((tri + 1)); continue ;;
          -s|--size|-r|--reference|-o|--io-blocks)
            tri=$((tri + 2)); continue ;;
          -*|'') tri=$((tri + 1)); continue ;;
        esac
      fi
      # No bare size-literal skip here: GNU truncate requires size to
      # travel with -s/--size — either separately (consumed by the flag
      # case above, +2) or attached as `-sN` / `--size=N` (caught by the
      # `-*` case). Any remaining non-option token is a FILE operand.
      # The previous `^[+=<>%]?[0-9]` skip wrongly dropped digit-leading
      # filenames like `123.log` or `2024-04-22.log`, letting the target
      # escape the boundary check (Codex round — P2 bypass).
      local trexp
      trexp=$(expand_path "$trtok")
      if [[ "$trexp" != /* ]]; then
        trexp="$EFFECTIVE_CWD/$trexp"
      fi
      local trresolved
      trresolved=$(resolve_path "$trexp")
      if ! is_write_permitted "$trresolved"; then
        echo "BLOCKED: 'truncate' targets '$trresolved' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
        exit 2
      fi
      tri=$((tri + 1))
    done
  fi

  # --- Chmod/chown outside project ---
  for CMD_NAME in chmod chown; do
    if echo "$CMD" | grep -qE "(^|[[:space:]])${CMD_NAME}($|[[:space:]])"; then
      # Extract args after command name, skip flags, then skip the first
      # non-flag token (mode for chmod, owner[:group] for chown)
      local perm_raw
      perm_raw=$(echo "$CMD" | grep -oE "(^|[[:space:]])${CMD_NAME}[[:space:]]+.*" | sed "s/^[[:space:]]*${CMD_NAME}[[:space:]]*//")
      local skipped_first=0

      while IFS= read -r TARGET; do
        [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
        if [[ $skipped_first -eq 0 ]]; then
          skipped_first=1
          continue
        fi
        TARGET=$(expand_path "$TARGET")
        if [[ "$TARGET" != /* ]]; then
          TARGET="$EFFECTIVE_CWD/$TARGET"
        fi
        RESOLVED=$(resolve_path "$TARGET")

        # STRICT: chmod/chown can weaponize permissions; allowlist must not apply.
        if ! is_inside_project "$RESOLVED"; then
          echo "BLOCKED: '${CMD_NAME}' targets '$RESOLVED' which is OUTSIDE project directory. Ask user for explicit permission." >&2
          exit 2
        fi
      done < <(tokenize_args "$perm_raw")
    fi
  done
}

# --- Split command into sub-commands and check each ---
# Split on ;, &&, ||, and | (but not inside quoted strings)
# This is a basic splitter that handles common cases.
split_and_check() {
  local full_cmd="$1"
  export _GUARD_CD_OUTSIDE=0
  export _GUARD_CD_IN_ALLOWLIST=0
  local -a subcmds=()
  local current=""
  local in_single_quote=0
  local in_double_quote=0
  local i=0
  local len=${#full_cmd}
  local ch prev_ch=""

  # Use a heredoc-blanked copy to detect operator positions. Quoted
  # heredoc bodies (`<<'EOF'` / `<<"EOF"` / `<<\EOF`) get spaces in
  # `scan_cmd` (byte offsets preserved), so `&&` / `||` / `;` / `|`
  # inside such bodies are NOT treated as command separators. Without
  # this, a body line like `X=/etc/x && rm $X` would split into two
  # pseudo-commands; the second (`rm $X\nEOF`) loses heredoc context
  # and the $VAR detector false-positives.
  local scan_cmd
  scan_cmd=$(blank_quoted_heredoc_bodies "$full_cmd" blank_newlines)
  # Defensive: if helper returned a different length (it should not),
  # fall back to scanning full_cmd directly to preserve original
  # semantics.
  if [ ${#scan_cmd} -ne $len ]; then
    scan_cmd="$full_cmd"
  fi

  while [ $i -lt $len ]; do
    ch="${scan_cmd:$i:1}"
    local raw_ch="${full_cmd:$i:1}"

    # Handle quotes
    if [ "$ch" = "'" ] && [ $in_double_quote -eq 0 ]; then
      if [ $in_single_quote -eq 0 ]; then
        in_single_quote=1
      else
        in_single_quote=0
      fi
      current="${current}${raw_ch}"
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
      current="${current}${raw_ch}"
      prev_ch="$ch"
      i=$((i + 1))
      continue
    fi

    # Only split when not inside quotes
    if [ $in_single_quote -eq 0 ] && [ $in_double_quote -eq 0 ]; then
      # Check for && or ||
      if [ $i -lt $((len - 1)) ]; then
        local two_char="${scan_cmd:$i:2}"
        if [ "$two_char" = "&&" ] || [ "$two_char" = "||" ]; then
          subcmds+=("$current")
          current=""
          i=$((i + 2))
          prev_ch=""
          continue
        fi
      fi

      # Check for ; or literal newline — bash treats both as command
      # terminators. Without splitting on newline, a multi-line command
      # like `echo ok\nbash /tmp/evil.sh` reaches every "first-token"
      # detector as a single subcommand whose name is `echo`, hiding
      # the script-execute on the second line. scan_cmd has heredoc
      # body bytes blanked (with newlines preserved), but body
      # newlines were never command separators in bash anyway — they
      # are part of the heredoc payload. The split here uses scan_cmd,
      # so a newline INSIDE a quoted heredoc body is still a blanked
      # space-equivalent (no, actually preserved newlines per the
      # helper) but the surrounding heredoc terminator/delimiter
      # parsing keeps the body single-subcommand because the
      # tokenizer downstream re-reads CMD verbatim. In practice: split
      # on newlines outside quotes / heredoc bodies.
      if [ "$ch" = ";" ] || [ "$ch" = $'\n' ]; then
        subcmds+=("$current")
        current=""
        prev_ch="$ch"
        i=$((i + 1))
        continue
      fi

      # Check for | — but not if it's part of the Bash clobber operator >| or >>|
      if [ "$ch" = "|" ]; then
        # Look at the trailing chars of current (trimmed) to detect > or >>
        local trimmed="${current%"${current##*[![:space:]]}"}"
        if [[ "$trimmed" == *\> ]]; then
          # Part of >| or >>| — keep it as a redirect operator, not a pipe
          current="${current}${raw_ch}"
          prev_ch="$ch"
          i=$((i + 1))
          continue
        fi
        subcmds+=("$current")
        current=""
        prev_ch="$ch"
        i=$((i + 1))
        continue
      fi
    fi

    current="${current}${raw_ch}"
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
