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
#   git -c <other-exec-key>=<cmd>         [section 32]
#       core.editor / core.pager / pager.<cmd> / sequence.editor /
#       gpg.program / gpg.ssh.program / credential.helper /
#       diff.external / mergetool.<tool>.cmd
#   git -c <additional-exec-keys>         [section 35]
#       core.askPass / core.fsmonitor / uploadpack.packObjectsHook /
#       filter.<n>.clean / filter.<n>.smudge / filter.<n>.process /
#       diff.<n>.command / diff.<n>.textconv / merge.<n>.driver
#   git -c <bang-prefixed-exec-keys>      [section 36]
#       gpg.openpgp.program / gpg.x509.program /
#       submodule.<n>.update (with leading `!`)
#
# The mechanism is intentionally simple: extract each sub-command
# value from a single (post-split) command and emit one payload per
# line on stdout. The caller — check_single_command in guard.sh —
# recursively dispatches each payload through itself, so every
# existing destructive / write-target walker validates the payload
# without any per-tool duplication of detection logic.
#
#   tar -xf foo.tar --to-command='<destructive-payload>'
#     → check_single_command "<destructive-payload>"
#
# Must run PER SUBCOMMAND (i.e. inside check_single_command, AFTER
# split_and_check has split the chained command line on `;` / `&&`
# / `||` / `|` / newline). Routing the extraction earlier — before
# the splitter — would only catch the FIRST verb of a chained
# command, leaving any sink in a later subcommand undetected
# (Copilot review on PR #23, options.sh:92).
#
# Pure (no caller-scope dependencies). Depends on
# hooks/lib/tokenize.sh (tokenize_args, strip_quotes).

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
  "git|-c||git-config|^(core\\.(sshCommand|editor|pager|askPass|fsmonitor)|pager\\..+|sequence\\.editor|gpg\\.(program|ssh\\.program|openpgp\\.program|x509\\.program)|credential\\.helper|diff\\.(external|.+\\.(command|textconv))|mergetool\\..+\\.cmd|merge\\..+\\.driver|filter\\..+\\.(clean|smudge|process)|uploadpack\\.packObjectsHook|submodule\\..+\\.update|alias\\..+)$"
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

# --- Main entry: extract sub-command flag values from one subcommand ---
# In:  single (post-split) command string
# Out: zero or more payload strings on stdout, one per line. Empty
#      output when no sink row matches the verb or no recognised flag
#      carries a value. Caller dispatches each payload through
#      check_single_command recursively.
extract_subcmd_flag_payloads() {
  local cmd="$1"
  _SF_TOKS=()
  local t
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    _SF_TOKS+=("$t")
  done < <(tokenize_args "$cmd")

  local verb_idx
  verb_idx=$(_sf_find_verb_idx)
  [ "$verb_idx" -lt 0 ] && return

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
  [ $matched -eq 0 ] && return

  # Walk tokens after the verb, emit every flag-value that the sink
  # row recognises (one payload per line on stdout).
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
    elif [ -n "$sink_short" ] \
        && [ "$tok" != "$sink_short" ] \
        && [[ "$tok" == -[!-]*"${sink_short#-}" ]] \
        && [ $((i + 1)) -lt $n ]; then
      # Clustered short-flag form: `-avze <val>` where the cluster's
      # last char matches the sink's short-flag letter and consumes
      # the next token as its value (Copilot review on PR #23,
      # subcmd_flags.sh:167). Excludes long flags (`--rsh`) via
      # `-[!-]*` and the bare short flag via the inequality test.
      val=$(strip_quotes "${_SF_TOKS[$((i + 1))]}")
      hit=1; i=$((i + 2))
    else
      i=$((i + 1)); continue
    fi

    [ $hit -eq 0 ] && continue
    # Skip empty / whitespace-only values; they cannot be exec sinks
    # (Codex review on PR #23, Q4).
    [[ -z "${val//[[:space:]]/}" ]] && continue

    if [ "$sink_kind" = "git-config" ]; then
      # Value shape is `key=subcmd`. Without an `=` it is not a config
      # assignment and cannot be an exec sink.
      case "$val" in *=*) ;; *) continue ;; esac
      local key="${val%%=*}"
      local subcmd_val="${val#*=}"
      # The token tokenizer keeps surrounding quotes around an
      # attached value (e.g. `--c-flag-token` looks like
      # `key='!cmd ...'` with the quotes intact). Strip them here so
      # the bang-prefix check below sees the real first character.
      subcmd_val=$(strip_quotes "$subcmd_val")
      # git config keys are case-insensitive (`Core.SshCommand` ==
      # `core.sshCommand`); enable nocasematch around the regex test
      # so case-folded variants are not a bypass route. Save / restore
      # the previous state to avoid leaking the option to callers.
      # Reported by Copilot review on PR #23 (subcmd_flags.sh:203).
      local _sf_nocase_was_on=0
      shopt -q nocasematch && _sf_nocase_was_on=1
      shopt -s nocasematch
      local _sf_key_match=0
      [[ "$key" =~ $sink_key_regex ]] && _sf_key_match=1
      [ $_sf_nocase_was_on -eq 1 ] || shopt -u nocasematch
      if [ $_sf_key_match -eq 1 ]; then
        # Bang-required keys: only an exec sink when the value
        # starts with `!`; other values are reserved words or
        # internal subcommand names (e.g. `submodule.<n>.update`
        # accepts `rebase`/`merge`/`checkout`/`none`; `alias.<n>`
        # without bang is a git-internal subcommand alias). Strip
        # the bang before dispatching; skip altogether if missing.
        local _sf_bang_match=0
        shopt -s nocasematch
        { [[ "$key" =~ ^submodule\..+\.update$ ]] || [[ "$key" =~ ^alias\..+$ ]]; } && _sf_bang_match=1
        [ $_sf_nocase_was_on -eq 1 ] || shopt -u nocasematch
        if [ $_sf_bang_match -eq 1 ]; then
          case "$subcmd_val" in
            '!'*) printf '%s\n' "${subcmd_val#!}" ;;
          esac
        else
          printf '%s\n' "$subcmd_val"
        fi
      fi
    else
      printf '%s\n' "$val"
    fi
  done
}
