#!/bin/bash
# project-boundary guard — detectors: write targets
# ==================================================
# Boundary checks for commands whose write semantics this cluster
# evaluates. Two different checks are used depending on the command:
#
#   STRICT (is_inside_project, allowlist does NOT apply):
#     install, rsync — both perform real filesystem writes AND
#     can be pointed at outside-project destinations explicitly;
#     allowlist would let them write to ~/.claude/**/memory from
#     arbitrary sources, which is not the intended use.
#
#   WRITE-PERMITTED (is_write_permitted, allowlist applies):
#     tar -C, unzip -d, cpio -D, tee, curl -o / --output,
#     wget -O / --output-document, dd of=, Bash redirect walker
#
# The five write-permitted detectors that accept a single target
# path (redirect, tee, curl, wget, dd) short-circuit via
# is_discard_target when the resolved target is the POSIX
# bit-bucket (/dev/null).
#
# Dispatched from hooks/guard.sh check_single_command; dynamic
# scope provides: CMD, CMD_TOKENS, CMD_TOKENS_SCAN, EFFECTIVE_CWD,
# PROJECT_DIR, plus helpers from hooks/lib/tokenize.sh +
# hooks/lib/paths.sh + hooks/lib/command_name.sh +
# extract_option_values from hooks/lib/options.sh.
#
# Each detector calls `exit 2` on a boundary violation.

run_write_target_detectors() {
  local TARGET RESOLVED

  # --- install command: like cp, check all non-flag path arguments ---
  # Must be tokenize-aware: the word `install` appears as a subcommand
  # in package managers (npm install / bundle install / poetry install
  # / cargo install / composer install / etc.), which are NOT the GNU
  # install binary and must not be blocked. Only fire when `install`
  # is the actual command-name token.
  if command_name_is install; then
    local install_raw
    install_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])install[[:space:]]+.*' | sed 's/^[[:space:]]*install[[:space:]]*//' || true)
    # Skip the next token when the current one is a value-bearing flag
    # (-m/--mode, -o/--owner, -g/--group). An earlier walker skipped
    # tokens matching mode regex ^[0-9]+$ or owner[:group] regex
    # unconditionally — that discarded legitimate file operands whose
    # bare name happened to match (e.g. `install src 0755`,
    # `install src root_wheel`) and became a boundary bypass when
    # EFFECTIVE_CWD sat outside the project. install grammar puts
    # mode/owner/group ONLY as the value of those flags, so explicit
    # pair-tracking is safe.
    #
    # POSIX `--` end-of-options is also tracked: after the terminator,
    # every token is a positional operand even when its name begins
    # with `-`. Without this, a file operand like `-owned` slipped
    # past the flag-skip case and never reached is_inside_project.
    local install_skip_next=0
    local install_seen_dashdash=0
    while IFS= read -r TARGET; do
      if [ "$install_skip_next" -eq 1 ]; then
        install_skip_next=0
        continue
      fi
      [[ -z "$TARGET" ]] && continue
      # Strip quotes for every flag test so `"--help"` and `--help`
      # behave identically (bash strips quotes at exec time). The
      # attached form `--name=value` is validated only when `name`
      # is on a white-list of options that actually point at a write
      # target — currently `--target-directory=`. All other -*
      # tokens (--mode=, --owner=, --group=, ...) are skipped as
      # flags; their values are not paths even when syntactically
      # path-shaped (e.g. `--mode=/0644`).
      if [ $install_seen_dashdash -eq 0 ]; then
        local install_tok
        install_tok=$(strip_quotes "$TARGET")
        if [ "$install_tok" = "--" ]; then
          install_seen_dashdash=1
          continue
        fi
        if [[ "$install_tok" == -* ]]; then
          if [[ "$install_tok" == --target-directory=* ]]; then
            validate_command_path strict "install --target-directory" "${install_tok#*=}"
            continue
          fi
          case "$install_tok" in
            -m|--mode|-o|--owner|-g|--group)
              install_skip_next=1 ;;
          esac
          continue
        fi
      fi
      validate_command_path strict install "$TARGET"
    done < <(tokenize_args "$install_raw")
  fi

  # --- mkdir: directory creation outside project ---
  # `mkdir <path>` (and `mkdir -p`) creates filesystem structure
  # outside the project — a "dropper" enabling later writes there.
  # The plugin's contract is "blocks outside, allows inside", so
  # creating directories outside violates the boundary even though
  # mkdir doesn't destroy existing files.
  #
  # Uses command_name_is to avoid false-positives on subcommands
  # named `mkdir` (none in widespread use, but consistent with the
  # `install` walker pattern).
  #
  # Walker handles -m MODE / -Z CTX / --mode= / --context= flag
  # forms and POSIX `--`. Boundary uses is_inside_project: STRICT
  # (creating dirs outside isn't a write to a known target file,
  # so allowlist semantics don't naturally apply — fail closed).
  if command_name_is mkdir; then
    local mkdir_raw
    mkdir_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])mkdir[[:space:]]+.*' | sed 's/^[[:space:]]*mkdir[[:space:]]*//' || true)
    # Strip leading wrappers (sudo, env, /bin/) so the tokenize parses
    # the post-mkdir args. command_name_is already matched mkdir so the
    # token is real.
    local mkdir_skip_next=0
    local mkdir_seen_dashdash=0
    while IFS= read -r TARGET; do
      if [ "$mkdir_skip_next" -eq 1 ]; then
        mkdir_skip_next=0
        continue
      fi
      [[ -z "$TARGET" ]] && continue
      if [ $mkdir_seen_dashdash -eq 0 ]; then
        local mkdir_tok
        mkdir_tok=$(strip_quotes "$TARGET")
        if [ "$mkdir_tok" = "--" ]; then
          mkdir_seen_dashdash=1
          continue
        fi
        if [[ "$mkdir_tok" == -* ]]; then
          case "$mkdir_tok" in
            -m|--mode|-Z|--context)
              mkdir_skip_next=1 ;;
            --mode=*|--context=*)
              : ;;
          esac
          continue
        fi
      fi
      validate_command_path strict mkdir "$TARGET"
    done < <(tokenize_args "$mkdir_raw")
  fi

  # --- rsync command: check all non-flag path arguments ---
  if command_name_is "rsync"; then
    local rsync_raw
    rsync_raw=$(echo "$CMD" | grep -oE '(^|[[:space:]])rsync[[:space:]]+.*' | sed 's/^[[:space:]]*rsync[[:space:]]*//' || true)
    # Track POSIX `--` end-of-options. After it, every token is a
    # positional operand even when its name begins with `-`. Without
    # this, a file operand like `-owned` slipped past the
    # `[[ "$TARGET" == -* ]] && continue` flag-skip and never
    # reached is_inside_project.
    local rsync_seen_dashdash=0
    while IFS= read -r TARGET; do
      [[ -z "$TARGET" ]] && continue
      if [ $rsync_seen_dashdash -eq 0 ]; then
        # Same white-list approach as the install walker. The
        # attached options that actually point at a filesystem
        # write target are:
        #   --log-file=         (writes the run log)
        #   --partial-dir=      (writes partial transfers)
        #   --backup-dir=       (writes backups before overwrite)
        #   --temp-dir=         (writes scratch during transfer)
        #   --write-batch=      (writes batch file)
        #   --only-write-batch= (writes batch file, no transfer)
        #
        # Other slash-bearing options like --exclude=PATTERN,
        # --rsync-path=REMOTE_BIN, --read-batch=PATH (read-only),
        # and the read-only --*-from= filter file flags are
        # skipped as ordinary flags so the detector does not
        # over-match.
        local rsync_tok
        rsync_tok=$(strip_quotes "$TARGET")
        if [ "$rsync_tok" = "--" ]; then
          rsync_seen_dashdash=1
          continue
        fi
        if [[ "$rsync_tok" == -* ]]; then
          case "$rsync_tok" in
            --log-file=*|--partial-dir=*|--backup-dir=*|--temp-dir=*|--write-batch=*|--only-write-batch=*)
              validate_command_path strict "rsync ${rsync_tok%%=*}" "${rsync_tok#*=}"
              ;;
          esac
          continue
        fi
      fi
      # Skip remote rsync paths. Remote syntax requires the `:` to live
      # in the FIRST path segment (before any `/`):
      #   host:path           user@host:path
      #   host::module/path   (daemon form)
      #   rsync://host/path   (URL form)
      # A local path may legitimately contain `:` AFTER a slash
      # (e.g. `../tmp/a:b`); a raw `=~ :` test would skip it and bypass
      # the boundary check.
      case "$TARGET" in
        rsync://*) continue ;;
      esac
      _rsync_first_seg="${TARGET%%/*}"
      case "$_rsync_first_seg" in
        *:*) continue ;;
      esac
      unset _rsync_first_seg
      validate_command_path strict rsync "$TARGET"
    done < <(tokenize_args "$rsync_raw")
  fi

  # --- tar: check every -C / --directory=PATH for extraction ---
  # tar allows multiple -C switches and the *last* one wins, so we must
  # validate every occurrence — not just the first.
  #
  # Mode-aware: -C is only a write target in EXTRACT mode (-x / --extract
  # / --get). For -c/--create, -r/--append, -u/--update, -A/--catenate,
  # tar READS source files from -C; for -t/--list and -d/--diff/--compare
  # tar reads only — none of these write into -C. The previous unconditional
  # check false-positived legitimate `tar -tf archive.tar -C /tmp`,
  # `tar -cf out.tar -C /tmp file`, etc.
  #
  # Conservative default: when the mode flag is absent or unrecognised,
  # KEEP the prior block — preserves coverage of any tar invocation
  # whose mode this walker didn't classify.
  if command_name_is "tar"; then
    local tar_mode="" ti=1 tn=${#CMD_TOKENS[@]}
    while [ $ti -lt $tn ] && [ -z "$tar_mode" ]; do
      local mtok
      mtok=$(strip_quotes "${CMD_TOKENS[$ti]}")
      case "$mtok" in
        --extract|--get)
          tar_mode=extract ;;
        --list|--diff|--compare|--create|--append|--update|--catenate|--concatenate|--delete|--test-label)
          tar_mode=read_or_nonC ;;
        --*)
          : ;;
        -*)
          # Short cluster: scan letters. Mode chars are mutually exclusive
          # in tar grammar, so the first one we hit wins.
          local _rest="${mtok#-}" _ch
          while [ -n "$_rest" ]; do
            _ch="${_rest:0:1}"
            _rest="${_rest:1}"
            case "$_ch" in
              x) tar_mode=extract; break ;;
              t|c|r|u|A|d) tar_mode=read_or_nonC; break ;;
            esac
          done
          ;;
      esac
      ti=$((ti + 1))
    done

    # Only enforce -C when mode=extract OR mode=unknown (fail-closed for
    # uncategorised invocations).
    if [ "$tar_mode" != "read_or_nonC" ]; then
      ti=0
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
        [ -n "$tar_dir" ] && validate_command_path write "tar -C" "$tar_dir"
      done
    fi
  fi

  # --- unzip -d PATH ---
  # unzip writes into -d only when extracting. The read-only mode
  # flags don't extract anything:
  #   -l   list contents
  #   -v   verbose list
  #   -t   test archive integrity
  #   -p   pipe extract to stdout
  #   -Z   zipinfo mode (entirely different option grammar)
  # In these modes -d is either ignored or has unrelated semantics.
  # Skip the walker so `unzip -l archive.zip -d /tmp` doesn't false-fire.
  if command_name_is "unzip"; then
    local unzip_readonly=0 ui=1 un=${#CMD_TOKENS[@]}
    while [ $ui -lt $un ]; do
      local utok
      utok=$(strip_quotes "${CMD_TOKENS[$ui]}")
      case "$utok" in
        --) break ;;
        -*)
          # short cluster: scan letters; long forms aren't part of unzip's
          # documented grammar (it uses single-dash multi-char like -aa),
          # but keep the cluster scan defensive.
          local _u_rest="${utok#-}" _u_ch
          while [ -n "$_u_rest" ]; do
            _u_ch="${_u_rest:0:1}"
            _u_rest="${_u_rest:1}"
            case "$_u_ch" in
              l|v|t|p|Z) unzip_readonly=1 ;;
            esac
          done
          ;;
      esac
      ui=$((ui + 1))
    done
    if [ "$unzip_readonly" -eq 0 ]; then
      local unzip_dir
      while IFS= read -r unzip_dir; do
        [ -z "$unzip_dir" ] && continue
        validate_command_path write "unzip -d" "$unzip_dir"
      done < <(extract_option_values "-d" "" || true)
    fi
  fi

  # --- cpio -D PATH ---
  if command_name_is "cpio"; then
    local cpio_dir
    while IFS= read -r cpio_dir; do
      [ -z "$cpio_dir" ] && continue
      validate_command_path write "cpio -D" "$cpio_dir"
    done < <(extract_option_values "-D" "" || true)
  fi

  # --- 7z / 7za / 7zr / 7zz: -o<dir> extract dest + a/u/d/rn archive ---
  # 7-Zip's spec mandates ATTACHED form `-o<dir>` (no space). The unzip
  # walker uses extract_option_values which only matches separated
  # `-o VAL` / `--output=VAL`, so the attached form slipped through
  # entirely. Round-4 pentest discovered the gap.
  #
  # Two write paths to cover:
  #   - extraction destination: any token of the form `-o<dir>`
  #   - write-mode verbs: a (add), u (update), d (delete), rn (rename)
  #     — the next non-flag positional after the verb is the ARCHIVE
  #     and is created/rewritten in place.
  #
  # Read-only verbs (x/e w/o -o, l, t, b, h, i) write at most into
  # the existing in-project cwd, which is already bounded by the
  # project-boundary check on EFFECTIVE_CWD.
  if command_name_matches "7z|7za|7zr|7zz|7zzs"; then
    # Pre-pass: locate verb (first non-flag positional after binary).
    # The verb gates Pass 1 (-o<dir>) and Pass 1b (-w<path>): for
    # read-only verbs (l/t/h/i/b) -o is unused (no extraction) and -w
    # is unused (no temp work). Previously these passes ran for every
    # verb and false-positived `7z l archive.7z -o/tmp` and
    # `7z t archive.7z -o/tmp`.
    local zn=${#CMD_TOKENS_SCAN[@]}
    local zci=1 zcmd=""
    while [ $zci -lt $zn ]; do
      local zct
      zct=$(strip_quotes "${CMD_TOKENS_SCAN[$zci]}")
      case "$zct" in
        -*|'') zci=$((zci + 1)); continue ;;
        *)     zcmd="$zct"; break ;;
      esac
    done
    local z_readonly_verb=0
    case "$zcmd" in
      l|t|h|i|b) z_readonly_verb=1 ;;
    esac

    # Pass 1: -o<dir> extraction destination — both attached
    # (`-o<dir>`, no space) and split (`-o <dir>`, space) forms.
    # 7-Zip docs mandate attached, but most builds also accept split,
    # so fail-closed covers both.
    if [ "$z_readonly_verb" -eq 0 ]; then
    local zi=1
    while [ $zi -lt $zn ]; do
      local ztok
      ztok=$(strip_quotes "${CMD_TOKENS_SCAN[$zi]}")
      local zdir=""
      if [[ "$ztok" == -o?* ]]; then
        zdir="${ztok#-o}"
      elif [ "$ztok" = "-o" ] && [ $((zi + 1)) -lt $zn ]; then
        zdir=$(strip_quotes "${CMD_TOKENS_SCAN[$((zi + 1))]}")
        zi=$((zi + 1))
      fi
      [ -n "$zdir" ] && validate_command_path write "7z -o<dir>" "$zdir"
      zi=$((zi + 1))
    done
    # Pass 1b: -w<path> working-directory (Codex round-4 follow-up).
    # `-w[<path>]` selects 7z's temp/work dir for intermediate files.
    # An outside-project <path> is a real boundary violation (analogous
    # to `-o<dir>`). Bare `-w` with no value uses the system default
    # and is left ALLOWED. Both attached and split forms are covered.
    local wzi=1
    while [ $wzi -lt $zn ]; do
      local wztok
      wztok=$(strip_quotes "${CMD_TOKENS_SCAN[$wzi]}")
      local wdir=""
      if [[ "$wztok" == -w?* ]]; then
        wdir="${wztok#-w}"
      elif [ "$wztok" = "-w" ] && [ $((wzi + 1)) -lt $zn ]; then
        wdir=$(strip_quotes "${CMD_TOKENS_SCAN[$((wzi + 1))]}")
        wzi=$((wzi + 1))
      fi
      [ -n "$wdir" ] && validate_command_path write "7z -w<path>" "$wdir"
      wzi=$((wzi + 1))
    done
    fi
    # Pass 2: if verb is a write-mode verb, validate the next positional
    # as ARCHIVE. zci/zcmd were already resolved in the pre-pass above.
    case "$zcmd" in
      a|u|d|rn)
        local zai=$((zci + 1))
        local zai_seen_dashdash=0
        while [ $zai -lt $zn ]; do
          local zat
          zat=$(strip_quotes "${CMD_TOKENS_SCAN[$zai]}")
          if [ $zai_seen_dashdash -eq 0 ]; then
            case "$zat" in
              --)
                zai_seen_dashdash=1; zai=$((zai + 1)); continue ;;
              -*|'') zai=$((zai + 1)); continue ;;
            esac
          fi
          validate_command_path write "7z $zcmd archive" "$zat"
          break
        done
        ;;
    esac
  fi

}
