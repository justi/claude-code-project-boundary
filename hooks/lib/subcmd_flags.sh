#!/bin/bash
# project-boundary guard — subcmd_flags module
# =============================================
# Some tools take a SHELL COMMAND as the value of a specific flag and
# execute it locally at runtime. The guard's path / destructive walkers
# only see flag NAMES — not flag VALUES — so a destructive command
# hidden in such a value slips past every detector. Same side-channel
# class as `find -exec <cmd>` (already covered) and the remote-dispatch
# verbs from issue #21 (ssh / docker exec / kubectl exec): an opaque
# command argument that the surface walker never opens.
#
# Affected sinks (added incrementally per the §Security-bypass TDD flow
# in CLAUDE.md):
#
#   tar -xf … --to-command=<cmd>          [section 29]
#   rsync -e / --rsh=<cmd>                [section 30]
#   git -c core.sshCommand=<cmd>          [section 31]
#
# The rewrite is intentionally simple: pull each sub-command value out
# of the original command string and re-emit it as a sibling statement
# joined by `;`. The downstream split_and_check splitter picks the new
# statement up automatically and dispatches it through the normal
# check_single_command pipeline — so every existing destructive /
# write-target walker validates the payload without any per-tool
# duplication of detection logic.
#
#   tar -xf foo.tar --to-command='rm /etc/x'
#     → tar -xf foo.tar --to-command='rm /etc/x' ; rm /etc/x
#
# The original verb invocation is preserved verbatim. The walkers
# already ignore the literal `rm /etc/x` bytes inside the quoted
# `--to-command=` value (they only match command names at token-start
# positions, not inside a single arg token), so the original side of
# the rewrite produces no extra detector hits — only the appended
# sibling statement is validated as a real command.
#
# Pure (no caller-scope dependencies); returns the rewritten command
# string on stdout. Depends on hooks/lib/tokenize.sh (tokenize_args,
# strip_quotes).

# --- Sink table ---
# Format: "<verb>|<short_flag>|<long_flag_no_eq>|<kind>|<key_regex>"
#
#   verb         - command-name token after wrapper-skip
#   short_flag   - short option that consumes the next token (e.g. "-e");
#                  empty if none. Attached form `-eVALUE` also recognised.
#   long_flag    - long option without trailing `=` (e.g. "--to-command");
#                  empty if none. Both `--flag=VALUE` and `--flag VALUE`
#                  shapes are recognised.
#   kind         - "value":     value IS the shell command directly.
#                  "git-config": value is `key=cmd`; only the rows whose
#                                key matches <key_regex> are exec sinks.
#   key_regex    - bash extended regex; used only when kind=git-config.
declare -a SUBCMD_FLAG_SINKS=(
  "tar||--to-command|value|"
  "rsync|-e|--rsh|value|"
  "git|-c||git-config|^core\\.sshCommand$"
)

# --- Find verb token index, skipping wrappers / VAR=val / flags ---
# Mirrors _rd_find_verb_idx in remote_dispatch.sh. Reads from the
# module-local _SF_TOKS array (set by expand_subcmd_flags before
# calling). Uses a global rather than `local -n` because macOS ships
# bash 3.2 which lacks nameref support.
_sf_find_verb_idx() {
  local i prev_was_timeout=0
  for i in "${!_SF_TOKS[@]}"; do
    local raw="${_SF_TOKS[$i]}" t
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
    printf '%d' "$i"
    return
  done
  printf -- '-1'
}

# --- Strip /bin/, /sbin/, /usr/bin/, /usr/sbin/, /usr/local/bin/ prefix ---
_sf_strip_path_prefix() {
  local n="$1"
  case "$n" in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*) printf '%s' "${n##*/}" ;;
    *) printf '%s' "$n" ;;
  esac
}

# --- Main entry: append sub-command values as sibling statements ---
# In:  full CMD string
# Out: CMD string with each recognised flag-value re-emitted after a
#      `;` separator; unchanged when no sink row matches the verb or
#      when no recognised flag carries a value.
expand_subcmd_flags() {
  local cmd="$1"
  _SF_TOKS=()
  local t
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    _SF_TOKS+=("$t")
  done < <(tokenize_args "$cmd")

  local verb_idx
  verb_idx=$(_sf_find_verb_idx)
  [ "$verb_idx" -lt 0 ] && { printf '%s' "$cmd"; return; }

  local verb
  verb=$(strip_quotes "${_SF_TOKS[$verb_idx]}")
  verb=$(_sf_strip_path_prefix "$verb")

  # Match a sink row by verb. First match wins; the table currently
  # has at most one row per verb.
  local row sink_short="" sink_long="" sink_kind="" sink_key_regex=""
  local matched=0
  for row in "${SUBCMD_FLAG_SINKS[@]}"; do
    local r_verb="${row%%|*}"
    if [ "$r_verb" = "$verb" ]; then
      local rest="${row#*|}"
      sink_short="${rest%%|*}"; rest="${rest#*|}"
      sink_long="${rest%%|*}"; rest="${rest#*|}"
      sink_kind="${rest%%|*}"; rest="${rest#*|}"
      sink_key_regex="$rest"
      matched=1
      break
    fi
  done
  [ $matched -eq 0 ] && { printf '%s' "$cmd"; return; }

  # Walk tokens after the verb, collect every flag-value that the
  # sink row recognises.
  local -a payloads=()
  local i=$((verb_idx + 1)) n=${#_SF_TOKS[@]}
  while [ $i -lt $n ]; do
    local raw="${_SF_TOKS[$i]}" tok val="" hit=0
    tok=$(strip_quotes "$raw")

    if [ -n "$sink_long" ] && [[ "$tok" == "${sink_long}="* ]]; then
      val="${tok#${sink_long}=}"
      val=$(strip_quotes "$val")
      hit=1; i=$((i + 1))
    elif [ -n "$sink_long" ] && [ "$tok" = "$sink_long" ] && [ $((i + 1)) -lt $n ]; then
      val=$(strip_quotes "${_SF_TOKS[$((i + 1))]}")
      hit=1; i=$((i + 2))
    elif [ -n "$sink_short" ] && [ "$tok" = "$sink_short" ] && [ $((i + 1)) -lt $n ]; then
      val=$(strip_quotes "${_SF_TOKS[$((i + 1))]}")
      hit=1; i=$((i + 2))
    elif [ -n "$sink_short" ] && [[ "$tok" == "${sink_short}"* ]] && [ "$tok" != "$sink_short" ]; then
      val="${tok#${sink_short}}"
      val=$(strip_quotes "$val")
      hit=1; i=$((i + 1))
    else
      i=$((i + 1)); continue
    fi

    [ $hit -eq 0 ] && continue
    [ -z "$val" ] && continue

    if [ "$sink_kind" = "git-config" ]; then
      # Value shape is `key=subcmd`. Without an `=` it is not a config
      # assignment and cannot be an exec sink.
      case "$val" in *=*) ;; *) continue ;; esac
      local key="${val%%=*}"
      local subcmd_val="${val#*=}"
      if [[ "$key" =~ $sink_key_regex ]]; then
        payloads+=("$subcmd_val")
      fi
    else
      payloads+=("$val")
    fi
  done

  if [ ${#payloads[@]} -eq 0 ]; then
    printf '%s' "$cmd"
    return
  fi

  # Append each payload as a sibling statement. split_and_check splits
  # on `;` and dispatches each sub-command separately, so the existing
  # detectors validate the payloads without any per-tool plumbing.
  printf '%s' "$cmd"
  local p
  for p in "${payloads[@]}"; do
    printf ' ; %s' "$p"
  done
}
