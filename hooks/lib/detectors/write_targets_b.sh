#!/bin/bash
# project-boundary guard — write-target detectors (part B)
# =========================================================
# Continuation of hooks/lib/detectors/write_targets.sh — split for
# the 500-line file budget. This half covers tee, curl -o,
# wget -O, dd of=, and the catch-all redirect walker.
#
# Same dynamic-scope contract as part A: reads CMD, CMD_BLANKED,
# CMD_TOKENS, CMD_TOKENS_SCAN, EFFECTIVE_CWD, PROJECT_DIR;
# helpers from hooks/lib/tokenize.sh + paths.sh + command_name.sh
# + options.sh. Each detector calls `exit 2` on violation.

run_write_target_detectors_b() {
  local TARGET RESOLVED

  # --- tee command: extract file arguments, block if outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])tee($|[[:space:]])'; then
    local tee_raw
    tee_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])tee[[:space:]]+.*' | sed 's/^[[:space:]]*tee[[:space:]]*//' || true)

    while IFS= read -r TARGET; do
      [[ -z "$TARGET" || "$TARGET" == -* ]] && continue
      RESOLVED=$(resolve_command_path "$TARGET")
      # /dev/null is a discard sink for tee (`echo x | tee /dev/null`).
      is_discard_target "$RESOLVED" && continue
      block_unless_path_allowed write tee "$RESOLVED"
    done < <(tokenize_args "$tee_raw")
  fi

  # --- curl -o / curl --output outside project ---
  # curl -o is positional: `curl -o out1 URL1 -o out2 URL2` writes each URL
  # to its corresponding output. Validate EVERY occurrence.
  if echo "$CMD" | grep -qE '(^|[[:space:]])curl($|[[:space:]])'; then
    local curl_output resolved_curl
    while IFS= read -r curl_output; do
      [ -z "$curl_output" ] && continue
      resolved_curl=$(resolve_command_path "$curl_output")
      # /dev/null is a discard sink for HTTP probes (`curl -o /dev/null -w %{http_code}`).
      is_discard_target "$resolved_curl" && continue
      block_unless_path_allowed write "curl output file" "$resolved_curl"
    done < <(extract_option_values "-o" "--output" || true)
  fi

  # --- wget -O / wget --output-document outside project ---
  if echo "$CMD" | grep -qE '(^|[[:space:]])wget($|[[:space:]])'; then
    local wget_output
    while IFS= read -r wget_output; do
      [ -z "$wget_output" ] && continue
      local resolved_wget
      resolved_wget=$(resolve_command_path "$wget_output")
      # /dev/null is a discard sink (`wget -O /dev/null URL`).
      is_discard_target "$resolved_wget" && continue
      block_unless_path_allowed write "wget output file" "$resolved_wget"
    done < <(extract_option_values "-O" "--output-document" || true)
  fi

  # --- dd of= outside project ---
  # dd accepts repeated key=value operands and the last one wins, so we must
  # validate every of= occurrence — not just the first.
  if echo "$CMD" | grep -qE '(^|[[:space:]])dd($|[[:space:]])'; then
    local raw_tok
    for raw_tok in "${CMD_TOKENS[@]}"; do
      local tok
      tok=$(strip_quotes "$raw_tok")
      if [[ "$tok" == of=* ]]; then
        local dd_output="${tok#of=}"
        if [ -n "$dd_output" ]; then
          local resolved_dd
          resolved_dd=$(resolve_command_path "$dd_output")
          # /dev/null is a discard sink (`dd if=x of=/dev/null`).
          is_discard_target "$resolved_dd" && continue
          block_unless_path_allowed write "dd output" "$resolved_dd"
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
      local resolved_redir
      resolved_redir=$(resolve_command_path "$REDIR_TARGET")
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
      is_discard_target "$resolved_redir" || \
        block_unless_path_allowed write "Redirect target" "$resolved_redir"
    fi
  done

  # --- pg_dump -f / mysqldump --result-file: DB dump output (r5) ---
  # Database dump tools accept an explicit output-file flag that
  # bypasses the redirect walker. Both write a SQL dump to FILE;
  # outside-project FILE is a boundary violation.
  local PG_CMD
  for PG_CMD in pg_dump pg_dumpall; do
    if command_name_is "$PG_CMD"; then
      local pgi=1 pgn=${#CMD_TOKENS_SCAN[@]}
      while [ $pgi -lt $pgn ]; do
        local pgtok
        pgtok=$(strip_quotes "${CMD_TOKENS_SCAN[$pgi]}")
        local pgfile=""
        case "$pgtok" in
          -f|--file)
            if [ $((pgi + 1)) -lt $pgn ]; then
              pgfile=$(strip_quotes "${CMD_TOKENS_SCAN[$((pgi + 1))]}")
              pgi=$((pgi + 1))
            fi
            ;;
          -f?*)
            pgfile="${pgtok#-f}" ;;
          --file=*)
            pgfile="${pgtok#--file=}" ;;
        esac
        [ -n "$pgfile" ] && validate_command_path write "$PG_CMD -f" "$pgfile"
        pgi=$((pgi + 1))
      done
    fi
  done

  # --- psql -o / -L: query output + session log (round-5 follow) ---
  if command_name_is "psql"; then
    local pqi=1 pqn=${#CMD_TOKENS_SCAN[@]}
    while [ $pqi -lt $pqn ]; do
      local pqtok
      pqtok=$(strip_quotes "${CMD_TOKENS_SCAN[$pqi]}")
      local pqfile="" pqkind=""
      case "$pqtok" in
        -o|--output)
          pqkind="-o"
          if [ $((pqi + 1)) -lt $pqn ]; then
            pqfile=$(strip_quotes "${CMD_TOKENS_SCAN[$((pqi + 1))]}")
            pqi=$((pqi + 1))
          fi
          ;;
        -o?*)
          pqkind="-o"; pqfile="${pqtok#-o}" ;;
        --output=*)
          pqkind="--output"; pqfile="${pqtok#--output=}" ;;
        -L|--log-file)
          pqkind="-L"
          if [ $((pqi + 1)) -lt $pqn ]; then
            pqfile=$(strip_quotes "${CMD_TOKENS_SCAN[$((pqi + 1))]}")
            pqi=$((pqi + 1))
          fi
          ;;
        -L?*)
          pqkind="-L"; pqfile="${pqtok#-L}" ;;
        --log-file=*)
          pqkind="--log-file"; pqfile="${pqtok#--log-file=}" ;;
      esac
      [ -n "$pqfile" ] && validate_command_path write "psql $pqkind" "$pqfile"
      pqi=$((pqi + 1))
    done
  fi

  # --- mysql --tee=FILE: session echo to file (round-5 follow) ---
  if command_name_is "mysql"; then
    local msi=1 msn=${#CMD_TOKENS_SCAN[@]}
    while [ $msi -lt $msn ]; do
      local mstok
      mstok=$(strip_quotes "${CMD_TOKENS_SCAN[$msi]}")
      local msfile=""
      case "$mstok" in
        --tee)
          if [ $((msi + 1)) -lt $msn ]; then
            local msnext
            msnext=$(strip_quotes "${CMD_TOKENS_SCAN[$((msi + 1))]}")
            case "$msnext" in
              -*) ;;
              *) msfile="$msnext"; msi=$((msi + 1)) ;;
            esac
          fi
          ;;
        --tee=*)
          msfile="${mstok#--tee=}" ;;
      esac
      [ -n "$msfile" ] && validate_command_path write "mysql --tee" "$msfile"
      msi=$((msi + 1))
    done
  fi
  if command_name_is "mysqldump"; then
    local myi=1 myn=${#CMD_TOKENS_SCAN[@]}
    while [ $myi -lt $myn ]; do
      local mytok
      mytok=$(strip_quotes "${CMD_TOKENS_SCAN[$myi]}")
      local myfile=""
      case "$mytok" in
        -r|--result-file)
          if [ $((myi + 1)) -lt $myn ]; then
            myfile=$(strip_quotes "${CMD_TOKENS_SCAN[$((myi + 1))]}")
            myi=$((myi + 1))
          fi
          ;;
        --result-file=*)
          myfile="${mytok#--result-file=}" ;;
      esac
      [ -n "$myfile" ] && validate_command_path write "mysqldump --result-file" "$myfile"
      myi=$((myi + 1))
    done
  fi

  # --- mktemp -p<dir> / --tmpdir=<dir>: temp file/dir creation ---
  # `mktemp -p DIR TEMPLATE` and `mktemp --tmpdir=DIR TEMPLATE`
  # create a temp file or directory inside DIR. Outside-project DIR
  # is a write outside the boundary. Bare `mktemp` (no -p / --tmpdir)
  # uses the default temp dir (/tmp or $TMPDIR) and is left ALLOWED —
  # test harnesses (incl. helpers.sh) rely on the default form.
  if command_name_is "mktemp"; then
    local mti=1 mtn=${#CMD_TOKENS_SCAN[@]}
    while [ $mti -lt $mtn ]; do
      local mttok
      mttok=$(strip_quotes "${CMD_TOKENS_SCAN[$mti]}")
      local mtdir=""
      case "$mttok" in
        -p)
          if [ $((mti + 1)) -lt $mtn ]; then
            mtdir=$(strip_quotes "${CMD_TOKENS_SCAN[$((mti + 1))]}")
            mti=$((mti + 1))
          fi
          ;;
        -p?*)
          mtdir="${mttok#-p}"
          ;;
        --tmpdir)
          if [ $((mti + 1)) -lt $mtn ]; then
            local mtnext
            mtnext=$(strip_quotes "${CMD_TOKENS_SCAN[$((mti + 1))]}")
            case "$mtnext" in
              -*) ;;
              *) mtdir="$mtnext"; mti=$((mti + 1)) ;;
            esac
          fi
          ;;
        --tmpdir=*)
          mtdir="${mttok#--tmpdir=}"
          ;;
        */*)
          # Positional template with embedded path component:
          # mktemp /etc/tmp.XXX writes into /etc. Validate the
          # template's dirname (Codex r5 P1).
          mtdir=$(dirname -- "$mttok")
          ;;
      esac
      [ -n "$mtdir" ] && validate_command_path write "mktemp dir" "$mtdir"
      mti=$((mti + 1))
    done
  fi

  # --- mkfifo / mknod: create special filesystem entry (round-5) ---
  # `mkfifo PATH...` creates a named pipe at each PATH; `mknod PATH
  # TYPE MAJOR MINOR` creates a device node at PATH (only the first
  # positional is a path — the rest are spec). Outside-project PATH
  # is a real boundary violation, but no walker covered it.
  # Value-bearing flags: -m / --mode (and `--mode=...`), -Z /
  # --context (SELinux on GNU). is_write_permitted (allowlist OK).
  local SPECIAL_CMD
  for SPECIAL_CMD in mkfifo mknod; do
    if command_name_is "$SPECIAL_CMD"; then
      local sci=1 scn=${#CMD_TOKENS_SCAN[@]}
      local sc_seen_dashdash=0
      while [ $sci -lt $scn ]; do
        local sctok
        sctok=$(strip_quotes "${CMD_TOKENS_SCAN[$sci]}")
        if [ $sc_seen_dashdash -eq 0 ]; then
          case "$sctok" in
            --) sc_seen_dashdash=1; sci=$((sci + 1)); continue ;;
            -m|--mode|-Z|--context) sci=$((sci + 2)); continue ;;
            --mode=*|--context=*) sci=$((sci + 1)); continue ;;
            -F)
              # BSD `mknod -F FORMAT` (bsd / freebsd / linux / solaris).
              # mkfifo has no -F — gate the pair-skip on the verb so
              # mkfifo doesn't accidentally swallow a real positional.
              if [ "$SPECIAL_CMD" = "mknod" ]; then
                sci=$((sci + 2)); continue
              fi ;;
            -*|'') sci=$((sci + 1)); continue ;;
          esac
        fi
        validate_command_path write "$SPECIAL_CMD" "$sctok"
        # mknod has only one PATH positional; mkfifo accepts many.
        [ "$SPECIAL_CMD" = "mknod" ] && break
        sci=$((sci + 1))
      done
    fi
  done
}
