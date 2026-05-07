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
  fi
}
