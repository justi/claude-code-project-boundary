#!/bin/bash
# project-boundary guard — download write-target detectors
# =========================================================
# curl -o / wget -O download targets. Split out of
# write_targets_b.sh by domain (Codex r5 finding #4).
#
# Same dynamic-scope contract as the rest of detectors/:
# reads CMD, CMD_BLANKED, CMD_TOKENS, CMD_TOKENS_SCAN,
# EFFECTIVE_CWD, PROJECT_DIR; helpers from
# hooks/lib/tokenize.sh + paths.sh + command_name.sh +
# options.sh. Calls `exit 2` on violation.

run_download_detectors() {
  local TARGET RESOLVED

  # --- curl -o / curl --output outside project ---
  # curl -o is positional: `curl -o out1 URL1 -o out2 URL2` writes each URL
  # to its corresponding output. Validate EVERY occurrence.
  if command_name_is "curl"; then
    local curl_output resolved_curl
    while IFS= read -r curl_output; do
      [ -z "$curl_output" ] && continue
      resolved_curl=$(resolve_command_path "$curl_output")
      # /dev/null is a discard sink for HTTP probes (`curl -o /dev/null -w %{http_code}`).
      is_discard_target "$resolved_curl" && continue
      block_unless_path_allowed write "curl output file" "$resolved_curl"
    done < <(extract_option_values "-o" "--output" || true)

    # curl --output-dir DIR prepends DIR to the per-URL output filename
    # selected by -O/--remote-name (URL basename) or a relative -o path.
    # The -o walker above only sees the explicit -o value, so
    # `curl --output-dir /tmp -O URL` and the attached `--output-dir=`
    # form bypassed the boundary entirely.
    #
    # Gate: --output-dir is only used by curl when -O/--remote-name is
    # present OR -o has a relative value. Without those, curl ignores
    # --output-dir entirely (HEAD-only `-I`, `-o /abs/path`, plain GET
    # to stdout, etc.). Validating unconditionally false-positived
    # those cases.
    local curl_outdir_active=0
    local _coi=1 _con=${#CMD_TOKENS[@]}
    while [ $_coi -lt $_con ]; do
      local _cotok
      _cotok=$(strip_quotes "${CMD_TOKENS[$_coi]}")
      case "$_cotok" in
        --) break ;;
        -O|--remote-name|--remote-name-all)
          curl_outdir_active=1; break ;;
        -o|--output)
          if [ $((_coi + 1)) -lt $_con ]; then
            local _coval
            _coval=$(strip_quotes "${CMD_TOKENS[$((_coi + 1))]}")
            case "$_coval" in
              /*) : ;;
              *)  curl_outdir_active=1; break ;;
            esac
          fi
          _coi=$((_coi + 2)); continue ;;
        --output=*)
          local _coval="${_cotok#--output=}"
          case "$_coval" in
            /*) : ;;
            *)  curl_outdir_active=1; break ;;
          esac
          ;;
        -o?*)
          local _coval="${_cotok#-o}"
          case "$_coval" in
            /*) : ;;
            *)  curl_outdir_active=1; break ;;
          esac
          ;;
      esac
      _coi=$((_coi + 1))
    done
    if [ "$curl_outdir_active" -eq 1 ]; then
      local curl_outdir
      while IFS= read -r curl_outdir; do
        [ -z "$curl_outdir" ] && continue
        validate_command_path write "curl --output-dir" "$curl_outdir"
      done < <(extract_option_values "" "--output-dir" || true)
    fi
  fi

  # --- wget -O / wget --output-document outside project ---
  if command_name_is "wget"; then
    local wget_output
    while IFS= read -r wget_output; do
      [ -z "$wget_output" ] && continue
      local resolved_wget
      resolved_wget=$(resolve_command_path "$wget_output")
      # /dev/null is a discard sink (`wget -O /dev/null URL`).
      is_discard_target "$resolved_wget" && continue
      block_unless_path_allowed write "wget output file" "$resolved_wget"
    done < <(extract_option_values "-O" "--output-document" || true)

    # wget -P / --directory-prefix DIR prepends DIR to the URL-derived
    # output filename. Without -O, every downloaded file lands under DIR;
    # an outside-project DIR is a real boundary write. The -O walker
    # above does not cover this — `wget -P /tmp URL` slipped through
    # entirely (cd_destructive_walker comment at lib/cd_destructive_walker.sh
    # already flagged this gap for allowlisted-cwd, but the unguarded
    # in-project case was never wired up).
    local wget_pdir
    while IFS= read -r wget_pdir; do
      [ -z "$wget_pdir" ] && continue
      validate_command_path write "wget -P" "$wget_pdir"
    done < <(extract_option_values "-P" "--directory-prefix" || true)
  fi
}
