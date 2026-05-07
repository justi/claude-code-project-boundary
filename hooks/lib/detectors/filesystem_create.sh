#!/bin/bash
# project-boundary guard — filesystem-entry creation detectors
# ============================================================
# mktemp -p<dir> / --tmpdir, mkfifo, mknod create a temp file or
# special FS entry whose location can land outside the project.
# Split out of write_targets_b.sh by domain (Codex r5 finding #4).
#
# Same dynamic-scope contract as the rest of detectors/:
# reads CMD, CMD_BLANKED, CMD_TOKENS, CMD_TOKENS_SCAN,
# EFFECTIVE_CWD, PROJECT_DIR; helpers from
# hooks/lib/tokenize.sh + paths.sh + command_name.sh +
# options.sh. Calls `exit 2` on violation.

run_filesystem_create_detectors() {
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
