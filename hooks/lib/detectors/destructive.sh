#!/bin/bash
# project-boundary guard — detectors: destructive path tools
# ===========================================================
# Boundary checks for commands that destructively touch filesystem
# paths: xargs-dispatched destructive commands, `find -delete` /
# `find -exec rm`, and the core path-argument walkers for rm, mv,
# cp, and ln. All use STRICT boundary semantics (is_inside_project);
# allowlist does NOT apply because these destroy or move data.
#
# Dispatched from hooks/guard.sh check_single_command; dynamic scope
# provides: CMD, EFFECTIVE_CWD, PROJECT_DIR, helpers from
# hooks/lib/tokenize.sh + hooks/lib/paths.sh +
# extract_option_values from hooks/lib/options.sh.
#
# Each detector calls `exit 2` on a boundary violation.

run_destructive_detectors() {
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
      local find_token
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
      local find_path
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

    # --- find -fprint / -fls / -fprintf write target (round-5) ---
    # `find ... -fprint FILE` truncates FILE and writes matching
    # paths into it (find opens with O_WRONLY|O_CREAT|O_TRUNC).
    # `-fls` (long-listing) and `-fprintf FILE FORMAT` have the
    # same write semantics. The find walker above only handled
    # destructive-action verbs (-delete / -exec rm); the print-to-
    # file actions slipped through.
    if echo "$CMD" | grep -qE '(\-fprint|\-fls|\-fprintf)([[:space:]]|$)'; then
      local fpi=1 fpn=${#CMD_TOKENS_SCAN[@]}
      while [ $fpi -lt $fpn ]; do
        local fptok
        fptok=$(strip_quotes "${CMD_TOKENS_SCAN[$fpi]}")
        case "$fptok" in
          -fprint|-fls|-fprintf)
            if [ $((fpi + 1)) -lt $fpn ]; then
              local fpval fpexp fpres
              fpval=$(strip_quotes "${CMD_TOKENS_SCAN[$((fpi + 1))]}")
              fpexp=$(expand_path "$fpval")
              if [[ "$fpexp" != /* ]]; then
                fpexp="$EFFECTIVE_CWD/$fpexp"
              fi
              fpres=$(resolve_path "$fpexp")
              if ! is_write_permitted "$fpres"; then
                echo "BLOCKED: 'find ${fptok}' targets '$fpres' which is OUTSIDE project directory '$PROJECT_DIR'. Ask user for explicit permission." >&2
                exit 2
              fi
            fi
            ;;
        esac
        fpi=$((fpi + 1))
      done
    fi
  fi

  # --- shred / wipe / srm / bcwipe: destructive overwrite (and ---
  # optional unlink with -u). Same destruction semantics as rm/dd,
  # so STRICT boundary (allowlist must not grant DESTROY-CONTENTS).
  # `wipe` (Berke Durak), `srm` (Sourceforge secure-delete) and
  # `bcwipe` (Jetico) are popular drop-in alternatives — round-5
  # pentest found the trigger missed all three.
  # Walker accepts -n N / -s N / --iterations / --size as flag+value
  # pairs and consumes bare flags otherwise; remaining positionals
  # are FILE operands. /usr/bin/, /bin/, /usr/local/bin/, and
  # /opt/homebrew/bin/ absolute-path forms also match.
  # Anchor on command_name_is so substrings ("echo wipe", "npm run
  # wipe", "printf 'srm: %s'") don't false-positive on the trigger
  # (Codex round-5 P2). _cn_strip_path_prefix already normalises
  # /opt/homebrew/bin/ etc. so absolute-path forms still match.
  local destr_cmd=""
  local _DC
  for _DC in shred wipe srm bcwipe; do
    if command_name_is "$_DC"; then
      destr_cmd="$_DC"
      break
    fi
  done
  if [ -n "$destr_cmd" ]; then
    local shi=1 shn=${#CMD_TOKENS_SCAN[@]}
    local shred_seen_dashdash=0
    while [ $shi -lt $shn ]; do
      local shtok
      shtok=$(strip_quotes "${CMD_TOKENS_SCAN[$shi]}")
      if [ $shred_seen_dashdash -eq 0 ]; then
        case "$shtok" in
          --)
            shred_seen_dashdash=1; shi=$((shi + 1)); continue ;;
          -n|-s|--iterations|--size|--random-source)
            shi=$((shi + 2)); continue ;;
          -*|'')
            shi=$((shi + 1)); continue ;;
        esac
      fi
      local shexp shresolved
      shexp=$(expand_path "$shtok")
      if [[ "$shexp" != /* ]]; then
        shexp="$EFFECTIVE_CWD/$shexp"
      fi
      shresolved=$(resolve_path "$shexp")
      if ! is_inside_project "$shresolved"; then
        echo "BLOCKED: '$destr_cmd' targets '$shresolved' which is OUTSIDE project directory '$PROJECT_DIR'. Destructive overwrite is only allowed within the project. Ask user for explicit permission." >&2
        exit 2
      fi
      shi=$((shi + 1))
    done
  fi

  # --- File deletion: allowed inside project, blocked outside ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])rm($|[[:space:]])'; then
    # Extract paths from rm command (skip flags)
    local rm_raw
    rm_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])rm[[:space:]]+.*' | sed 's/^[[:space:]]*rm[[:space:]]*//' || true)

    local TARGET RESOLVED
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
    local mv_target_dir
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
    mv_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])mv[[:space:]]+.*' | sed 's/^[[:space:]]*mv[[:space:]]*//' || true)

    local TARGET RESOLVED
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
    local cp_target_dir
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
    cp_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])cp[[:space:]]+.*' | sed 's/^[[:space:]]*cp[[:space:]]*//' || true)

    local TARGET RESOLVED
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
    ln_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])ln[[:space:]]+.*' | sed 's/^[[:space:]]*ln[[:space:]]*//' || true)

    local TARGET RESOLVED
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
}

# --- chmod / chown boundary check ---
# Weaponizable permission changes on files outside the project are
# blocked. STRICT: allowlist does not apply because an attacker who
# can chmod an allowlisted dir's sibling path can still pivot.
# Separate function because chmod/chown originally run at a later
# position in check_single_command than the xargs..ln cluster; this
# lets us preserve the original evaluation order from the caller.
run_permissions_detectors() {
  local CMD_NAME TARGET RESOLVED
  for CMD_NAME in chmod chown chgrp; do
    if echo "$CMD" | grep -qE "(^|[[:space:]])${CMD_NAME}($|[[:space:]])"; then
      # Extract args after command name, skip flags, then skip the first
      # non-flag token (mode for chmod, owner[:group] for chown)
      local perm_raw
      perm_raw=$(echo "$CMD" | grep -oE "(^|[[:space:]])${CMD_NAME}[[:space:]]+.*" | sed "s/^[[:space:]]*${CMD_NAME}[[:space:]]*//" || true)
      local skipped_first=0
      local skip_next=0
      local has_reference=0
      # When `--reference` (any form) is present, the spec operand
      # is supplied via the referenced file — there is NO positional
      # spec. Skipping the first positional as spec would silently
      # let the actual TARGET escape the boundary check (Codex r5 P1).
      if echo "$perm_raw" | grep -qE '(^|[[:space:]])\-\-reference(=|[[:space:]]|$)'; then
        has_reference=1
      fi

      while IFS= read -r TARGET; do
        [[ -z "$TARGET" ]] && continue
        if [[ $skip_next -eq 1 ]]; then
          skip_next=0
          continue
        fi
        case "$TARGET" in
          --reference) skip_next=1; continue ;;
          --reference=*) continue ;;
          -*) continue ;;
        esac
        if [[ $skipped_first -eq 0 && $has_reference -eq 0 ]]; then
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

  # --- setfattr: Linux extended attributes (round-5 pentest) ---
  # Modifies xattrs in user.* / system.* namespaces; an attacker
  # who can flip these on /etc/shadow can pivot. STRICT.
  # Grammar: setfattr -n NAME -v VALUE FILE | -x NAME FILE
  # Value-bearing flags: -n / --name, -v / --value, -x / --remove
  # (and the `--name=` / `--value=` / `--remove=` long-attached
  # forms). `--restore=DUMP` uses an embedded value — the FILE
  # operand list is then empty, so leave that case untouched.
  if command_name_is "setfattr"; then
    local sfi=1 sfn=${#CMD_TOKENS_SCAN[@]}
    local sf_seen_dashdash=0
    while [ $sfi -lt $sfn ]; do
      local sftok
      sftok=$(strip_quotes "${CMD_TOKENS_SCAN[$sfi]}")
      if [ $sf_seen_dashdash -eq 0 ]; then
        case "$sftok" in
          --) sf_seen_dashdash=1; sfi=$((sfi + 1)); continue ;;
          -n|--name|-v|--value|-x|--remove) sfi=$((sfi + 2)); continue ;;
          --name=*|--value=*|--remove=*|--restore=*) sfi=$((sfi + 1)); continue ;;
          -*|'') sfi=$((sfi + 1)); continue ;;
        esac
      fi
      local sfexp sfres
      sfexp=$(expand_path "$sftok")
      if [[ "$sfexp" != /* ]]; then
        sfexp="$EFFECTIVE_CWD/$sfexp"
      fi
      sfres=$(resolve_path "$sfexp")
      if ! is_inside_project "$sfres"; then
        echo "BLOCKED: 'setfattr' targets '$sfres' which is OUTSIDE project directory. Ask user for explicit permission." >&2
        exit 2
      fi
      sfi=$((sfi + 1))
    done
  fi

  # --- chflags: BSD/macOS file flags (round-5 pentest) ---
  # Modifies uchg/schg/uappnd/etc. flags. Same threat profile
  # as chmod. STRICT.
  # Grammar: chflags [-R|-H|-L|-P|-h] FLAGS FILE...
  # First non-flag positional is FLAGS spec (skip), rest are FILEs.
  if command_name_is "chflags"; then
    local cfi=1 cfn=${#CMD_TOKENS_SCAN[@]}
    local cf_seen_dashdash=0
    local cf_skipped_flags=0
    while [ $cfi -lt $cfn ]; do
      local cftok
      cftok=$(strip_quotes "${CMD_TOKENS_SCAN[$cfi]}")
      if [ $cf_seen_dashdash -eq 0 ]; then
        case "$cftok" in
          --) cf_seen_dashdash=1; cfi=$((cfi + 1)); continue ;;
          -*|'') cfi=$((cfi + 1)); continue ;;
        esac
      fi
      if [ $cf_skipped_flags -eq 0 ]; then
        cf_skipped_flags=1
        cfi=$((cfi + 1)); continue
      fi
      local cfexp cfres
      cfexp=$(expand_path "$cftok")
      if [[ "$cfexp" != /* ]]; then
        cfexp="$EFFECTIVE_CWD/$cfexp"
      fi
      cfres=$(resolve_path "$cfexp")
      if ! is_inside_project "$cfres"; then
        echo "BLOCKED: 'chflags' targets '$cfres' which is OUTSIDE project directory. Ask user for explicit permission." >&2
        exit 2
      fi
      cfi=$((cfi + 1))
    done
  fi
}
