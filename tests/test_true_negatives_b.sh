#!/bin/bash
# True negatives (part B) — common Claude workflows + /dev/null
# exemption + heredoc-body false-positive regression pins.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  True negatives (part B)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# ============================================================
# Common Claude workflows — must stay allowed
# ------------------------------------------------------------
# Day-to-day commands Claude issues across Ruby / Python / Node / PHP /
# Go / git / build / test / package-manager workflows. These are
# legitimate inside-project operations or read-only queries that must
# never be false-positively blocked by any tightening of the guard.
# Patterns distilled from real assistant sessions + CLAUDE.md hints
# (hook discipline, test-before-advise rule, TDD flow).
# ============================================================
echo "--- common Claude workflows (git / pkg mgr / test / lint / run) ---"

# --- git: the bread-and-butter. Read-only / in-project mutations. ---
expect_allowed "git status"           "git status"
expect_allowed "git status -uall"     "git status -uall"
expect_allowed "git diff"             "git diff"
expect_allowed "git diff --staged"    "git diff --staged"
expect_allowed "git log --oneline -5" "git log --oneline -5"
expect_allowed "git log main..HEAD"   "git log main..HEAD"
expect_allowed "git show HEAD"        "git show HEAD"
expect_allowed "git blame guard.sh"   "git blame $PROJECT/hooks/guard.sh"
expect_allowed "git branch"           "git branch"
expect_allowed "git branch -a"        "git branch -a"
expect_allowed "git rev-parse HEAD"   "git rev-parse HEAD"
expect_allowed "git rev-parse --short HEAD" "git rev-parse --short HEAD"
expect_allowed "git add PROJECT/file" "git add $PROJECT/README.md"
expect_allowed "git stash list"       "git stash list"
expect_allowed "git remote -v"        "git remote -v"
expect_allowed "git fetch origin"     "git fetch origin"

# --- gh CLI: PR / issue / release operations on remote, read mostly. ---
expect_allowed "gh pr view 12"                  "gh pr view 12"
expect_allowed "gh pr list"                     "gh pr list"
expect_allowed "gh release list"                "gh release list"
expect_allowed "gh api /repos/o/r/pulls/1"      "gh api /repos/o/r/pulls/1"

# --- package managers: install/update inside project. ---
expect_allowed "npm install"          "npm install"
expect_allowed "npm ci"               "npm ci"
expect_allowed "npm run build"        "npm run build"
expect_allowed "npm test"             "npm test"
expect_allowed "yarn install"         "yarn install"
expect_allowed "pnpm install"         "pnpm install"
expect_allowed "bundle install"       "bundle install"
expect_allowed "bundle exec rspec"    "bundle exec rspec"
expect_allowed "bundle exec rubocop"  "bundle exec rubocop"
expect_allowed "pip install -r requirements.txt" "pip install -r $PROJECT/requirements.txt"
expect_allowed "poetry install"       "poetry install"
expect_allowed "uv sync"              "uv sync"
expect_allowed "cargo build"          "cargo build"
expect_allowed "cargo test"           "cargo test"
expect_allowed "go build ./..."       "go build ./..."
expect_allowed "go test ./..."        "go test ./..."
expect_allowed "mix deps.get"         "mix deps.get"
expect_allowed "composer install"     "composer install"

# --- test runners: fine-grained invocations that MUST pass. ---
expect_allowed "rspec spec/foo_spec.rb"        "rspec $PROJECT/spec/foo_spec.rb"
expect_allowed "pytest tests/"                 "pytest $PROJECT/tests/"
expect_allowed "pytest -k pattern"             "pytest -k 'sed or truncate'"
expect_allowed "jest --watch"                  "jest --watch"
expect_allowed "vitest run"                    "vitest run"
expect_allowed "bash tests/test_guard.sh"      "bash $PROJECT/tests/test_guard.sh"

# --- language runtimes without inline-code flags: safe ---
expect_allowed "ruby script.rb"                 "ruby $PROJECT/script.rb"
expect_allowed "ruby -v"                        "ruby -v"
expect_allowed "ruby --version"                 "ruby --version"
expect_allowed "python script.py"               "python $PROJECT/script.py"
expect_allowed "python3 -V"                     "python3 -V"
expect_allowed "python -m pytest"               "python -m pytest"
expect_allowed "python -m venv .venv"           "python -m venv $PROJECT/.venv"
expect_allowed "node script.js"                 "node $PROJECT/script.js"
expect_allowed "node --version"                 "node --version"
expect_allowed "deno run script.ts"             "deno run $PROJECT/script.ts"
expect_allowed "bun run script.ts"              "bun run $PROJECT/script.ts"
expect_allowed "perl -v"                        "perl -v"
expect_allowed "perl script.pl"                 "perl $PROJECT/script.pl"
expect_allowed "php -v"                         "php -v"
expect_allowed "php -l file.php"                "php -l $PROJECT/file.php"
expect_allowed "php script.php"                 "php $PROJECT/script.php"

# --- linters / formatters: read or rewrite in-project files. ---
expect_allowed "eslint src/"                    "eslint $PROJECT/src/"
expect_allowed "prettier --write src/"          "prettier --write $PROJECT/src/"
expect_allowed "black ."                        "black $PROJECT/"
expect_allowed "ruff check"                     "ruff check"
expect_allowed "shellcheck hooks/guard.sh"      "shellcheck $PROJECT/hooks/guard.sh"

# --- sed/awk without destructive flags: read-only projections. ---
expect_allowed "sed -n print range"             "sed -n '10,20p' $PROJECT/README.md"
expect_allowed "sed pipeline (no -i)"           "cat $PROJECT/README.md | sed 's/old/new/'"
expect_allowed "awk projection"                 "awk '{print \$1}' $PROJECT/README.md"
expect_allowed "awk -F delimiter"               "awk -F: '{print \$1}' $PROJECT/README.md"

# --- CLAUDE.md hint: heredoc commit flow must pass (never block) ---
expect_allowed "git commit -F - heredoc"        "git commit -F - <<'EOF'
title

body with details
EOF"

# --- textual-arg false-positives ---
# Documentation / commit messages / echo / printf that mention shell-
# opener / interpreter patterns as STRING CONTENT, not as exec. The
# guard's substring walkers (block_nested_shell_and_eval,
# block_interpreter_inline_code) used to match the pattern anywhere in
# CMD; gating each on CMD_VERB removes the false-positive without
# loosening real-exec detection.
expect_allowed "echo 'avoid bash -c' > docs/fp.md (text content)" \
  "echo \"avoid bash -c in examples\" > $PROJECT/docs/fp.md"
expect_allowed "printf 'avoid sh -c\\n' > docs/fp.md (text content)" \
  "printf 'avoid sh -c in examples\\n' > $PROJECT/docs/fp.md"
expect_allowed "echo 'do not use eval' > docs/fp.md (text content)" \
  "echo \"do not use eval here\" > $PROJECT/docs/fp.md"
expect_allowed "git commit -m 'explain eval risk' (text in -m value)" \
  "git commit -m \"docs: explain eval risk\""
expect_allowed "git commit -m 'awk system() caveat' (text in -m value)" \
  "git commit -m \"docs: awk system caveat\""
expect_allowed "git commit -m 'docker exec sh -c example' (text in -m value)" \
  "git commit -m \"docs: docker exec app sh -c example\""
expect_allowed "echo 'avoid node -e' > docs/fp.md (text content)" \
  "echo \"avoid node -e examples\" > $PROJECT/docs/fp.md"
expect_allowed "git commit -m 'avoid python -c' (text in -m value)" \
  "git commit -m \"docs: avoid python -c examples\""
expect_allowed "echo 'avoid php -r' > docs/fp.md (text content)" \
  "echo \"avoid php -r examples\" > $PROJECT/docs/fp.md"

# --- destructive verb names mentioned in metadata text-as-arg ---
# rm / tee walkers used to fire on substring match anywhere in CMD,
# overblocking commit messages / tag annotations / git notes / gh PR
# bodies that merely mention the verb name. Verb-gate them on a
# positive list (rm / tee themselves + remote-dispatch wrappers that
# legitimately carry foreign-fs rm/tee invocations).
expect_allowed "git commit -m mentions rm" \
  "git commit -m \"docs: mention rm /etc/passwd\""
expect_allowed "git commit -m mentions tee" \
  "git commit -m \"docs: mention tee /etc/app.conf\""
expect_allowed "git tag -a annotated mentions rm" \
  "git tag -a v-test -m \"mention rm /etc/passwd\""
expect_allowed "git tag -a annotated mentions tee" \
  "git tag -a v-test -m \"mention tee /etc/app.conf\""
expect_allowed "git notes add mentions rm" \
  "git notes add -m \"mention rm /etc/passwd\""
expect_allowed "git notes add mentions tee" \
  "git notes add -m \"mention tee /etc/app.conf\""
expect_allowed "gh pr comment body mentions rm" \
  "gh pr comment 1 --body \"mention rm /etc/passwd\""
expect_allowed "gh pr comment body mentions tee" \
  "gh pr comment 1 --body \"mention tee /etc/app.conf\""

# --- psql bare meta-commands with no file argument ---
# psql -c '\g' is send-query (alias of ;), no file. psql -c '\o'
# without an argument resets the output redirection to stdout.
# Neither writes a local file. The walker used to fail-closed on the
# meta name regardless of arg shape; refined to allow the bare form
# (meta with no payload after).
expect_allowed "psql -c bare \\g (send query, no file)" \
  "psql -c '\\g'"
expect_allowed "psql -c bare \\o (reset output to stdout)" \
  "psql -c '\\o'"
expect_allowed "psql -c bare \\gx (send + expanded display)" \
  "psql -c '\\gx'"
expect_allowed "psql -c bare \\s (history to stdout)" \
  "psql -c '\\s'"
expect_allowed "psql --command attached bare \\g" \
  "psql --command='\\g'"

# --- alias variants (--message / --title / --notes / --comment / ---
# --description / --body) — same metadata-text class as -m / --body
# above. Covered by the rm/tee verb-gate (verb=git/gh, walker skips).
# Pinned to keep the verb-gate in place if anyone tightens the
# walker again.
expect_allowed "git commit --message rm" \
  "git commit --message \"mention rm /etc/passwd\""
expect_allowed "git tag -a v --message tee" \
  "git tag -a v2 --message \"mention tee /etc/app.conf\""
expect_allowed "git notes add --message rm" \
  "git notes add --message \"mention rm /etc/passwd\""
expect_allowed "git merge --message rm main" \
  "git merge --message \"mention rm /etc/passwd\" main"
expect_allowed "gh pr create --title rm" \
  "gh pr create --title \"mention rm /etc/passwd\" --body \"body\""
expect_allowed "gh pr create --body tee" \
  "gh pr create --title \"title\" --body \"mention tee /etc/app.conf\""
expect_allowed "gh pr review --comment rm" \
  "gh pr review 1 --comment --body \"mention rm /etc/passwd\""
expect_allowed "gh issue comment --body rm" \
  "gh issue comment 1 --body \"mention rm /etc/passwd\""
expect_allowed "gh release create --notes rm" \
  "gh release create v1 --notes \"mention rm /etc/passwd\""
expect_allowed "gh repo edit --description tee" \
  "gh repo edit --description \"mention tee /etc/app.conf\""

# --- misc safe: env/version probes, file listing, basic queries ---
expect_allowed "env"                            "env"
expect_allowed "pwd"                            "pwd"
expect_allowed "whoami"                         "whoami"
expect_allowed "date"                           "date"
expect_allowed "ls PROJECT"                     "ls $PROJECT"
expect_allowed "ls -la PROJECT/hooks"           "ls -la $PROJECT/hooks"
expect_allowed "cat PROJECT/README.md"          "cat $PROJECT/README.md"
expect_allowed "head -20 PROJECT/CHANGELOG.md"  "head -20 $PROJECT/CHANGELOG.md"
expect_allowed "tail -f PROJECT/log.txt"        "tail -f $PROJECT/log.txt"
expect_allowed "wc -l PROJECT/guard.sh"         "wc -l $PROJECT/hooks/guard.sh"
expect_allowed "grep pattern PROJECT/file"      "grep pattern $PROJECT/README.md"

echo ""

# ============================================================
# /dev/null exemption — universal POSIX bit-bucket
# ------------------------------------------------------------
# /dev/null discards every byte written to it and exists on every
# POSIX system at the same path. is_write_permitted itself is NOT
# permissive for /dev/null — it still treats the path as outside
# any project. The exemption is applied at specific walker call
# sites (redirect, tee, curl -o, wget -O, dd of=) by short-
# circuiting via is_discard_target BEFORE is_write_permitted runs,
# so legitimate probe and silencing workflows pass without loosening
# the shared helper for every caller.
# ============================================================
echo "--- /dev/null exemption (universal bit-bucket) ---"

expect_allowed "curl -o /dev/null (HTTP probe / status check)" \
  "curl -o /dev/null -w '%{http_code}' https://example.com/"

expect_allowed "wget -O /dev/null (HTTP probe)" \
  "wget -O /dev/null https://example.com/"

expect_allowed "redirect > /dev/null (silence stdout)" \
  "echo noisy > /dev/null"

expect_allowed "redirect 2> /dev/null (silence stderr)" \
  "some_cmd 2> /dev/null"

expect_allowed "redirect &> /dev/null (silence both)" \
  "some_cmd &> /dev/null"

expect_allowed "tee /dev/null (no-op tee)" \
  "echo x | tee /dev/null"

expect_allowed "dd of=/dev/null (discard)" \
  "dd if=$PROJECT/README.md of=/dev/null bs=1"

# Counterexamples — non-discard contexts must STAY blocked even when the
# target happens to be /dev/null. Codex review on the proof-of-concept
# flagged that sed -i rewrites via a temp file + rename in the target's
# parent directory (/dev/), so /dev/null must not be uniformly exempted.
# These regression assertions keep the narrow-scope design honest.
expect_blocked "sed -i /dev/null (writes temp file under /dev/)" \
  "sed -i 's/a/b/' /dev/null"

expect_blocked "truncate -s 0 /dev/null (modifies real file node)" \
  "truncate -s 0 /dev/null"

expect_blocked "cp src /dev/null (destination, real filesystem write)" \
  "cp $PROJECT/README.md /dev/null"

expect_blocked "mv src /dev/null (destination, real filesystem write)" \
  "mv $PROJECT/README.md /dev/null"

expect_blocked "ln -sf src /dev/null (symlink target replaces device node)" \
  "ln -sf $PROJECT/README.md /dev/null"

echo ""

# ============================================================
# Bare destructive commands with no path arguments must pass
# ------------------------------------------------------------
# Under `set -euo pipefail` the raw-arg extraction pipelines used a
# `grep -oE '(^|whitespace)CMD(whitespace).*' | sed ...` pattern.
# grep exits 1 when it finds no match (bare `rm`, `mv`, ...), and
# pipefail then propagated that exit into the overall command
# substitution, which set -e turned into an abort of the whole
# guard run (exit 1 rather than 0). Users would see the hook fail
# with no diagnostic while bash itself would print its own usage
# error for the bare command. Reported by Copilot review on PR #16;
# fixed in the detector modules by appending `|| true` to every
# raw-arg extraction pipeline.
# ============================================================
echo "--- bare destructive commands must not abort the guard ---"

expect_allowed "bare rm (no args — bash prints usage)"       "rm"
expect_allowed "bare mv (no args)"                            "mv"
expect_allowed "bare cp (no args)"                            "cp"
expect_allowed "bare ln (no args)"                            "ln"
expect_allowed "bare install (no args)"                       "install"
expect_allowed "bare chmod (no args)"                         "chmod"
expect_allowed "bare chown (no args)"                         "chown"
expect_allowed "bare tee (no args)"                           "tee"

echo ""

# ============================================================
# <<\EOF backslash-escaped heredoc delimiter: sed/truncate/redirect
# walkers must NOT false-positive on body bytes.
# ------------------------------------------------------------
# Copilot review on commit aa6409b flagged a theoretical concern that
# the alias-escape strip (`\rm` -> `rm`) would also rewrite `<<\EOF`
# to `<<EOF` and break blank_quoted_heredoc_bodies for the CMD_BLANKED
# view. The guard avoids this by deriving CMD_BLANKED from CMD_RAW
# (pre-normalization), not from the alias-stripped CMD (guard.sh:848,
# documented at 833-840). These positives lock in that behavior for
# the specific detectors Copilot named.
# ============================================================
echo "--- <<\\EOF body must not trigger sed/truncate/redirect walkers ---"

expect_allowed 'sed -i mention in <<\EOF body (literal, not a live sed)' \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF
sed -i 's/x/y/' /etc/passwd
EOF"

expect_allowed 'truncate mention in <<\EOF body (literal text)' \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF
truncate -s 0 /etc/passwd
EOF"

expect_allowed 'redirect > mention in <<\EOF body (literal text)' \
  "cat > $PROJECT/tests/scratch.txt <<\\EOF
echo hi > /etc/passwd
EOF"

# Indented form <<-\EOF follows the same bash semantics.
expect_allowed 'sed -i mention in <<-\EOF body (indented backslash form)' \
  "cat > $PROJECT/tests/scratch.txt <<-\\EOF
	sed -i 's/x/y/' /etc/passwd
	EOF"

echo ""

# ============================================================
# Quoted POSIX `--` end-of-options terminator
# ------------------------------------------------------------
# bash strips the surrounding quotes from a command word at exec
# time, so `'--'` and `"--"` reach the invoked tool as a bare
# `--`. Path walkers must normalize via strip_quotes before
# comparing the token against the literal `--`, otherwise
# legitimate in-project installs / rsyncs / etc. that happen to
# quote the terminator are wrongly blocked. Reported by Codex
# review on commit b460e57 (write_targets.sh:69-70).
# ============================================================
echo "--- quoted POSIX -- terminator must not false-positive ---"

expect_allowed_cwd "install '--' src dest (single-quoted --, cwd=/tmp)" \
  "install '--' $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" "/tmp"

expect_allowed_cwd "install \"--\" src dest (double-quoted --, cwd=/tmp)" \
  "install \"--\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" "/tmp"

expect_allowed_cwd "rsync '--' src dest (single-quoted --, cwd=/tmp)" \
  "rsync '--' $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" "/tmp"

expect_allowed_cwd "rsync \"--\" src dest (double-quoted --, cwd=/tmp)" \
  "rsync \"--\" $PROJECT/CHANGELOG.md $PROJECT/tests/scratch.txt" "/tmp"

echo ""

# ============================================================
# Inline-interpreter / awk-system detector must skip quoted-heredoc body
# ------------------------------------------------------------
# `python -c`, `ruby -e`, `node --eval`, `php -r/-R/--run`, and
# `awk '... system(...) ...'` are unconditionally fail-closed when they
# appear as live command-line forms. The detectors used to scan the
# CMD view that has command-name normalisation but NOT
# blank_quoted_heredoc_bodies — so a tee/cat heredoc whose body merely
# *mentioned* one of these patterns (e.g. a commit message describing
# the rule, a doc string, a code review draft) was wrongly rejected.
#
# Concrete false positive: `git commit -F - <<'EOF' ... awk … system(…)
# ... EOF` blocked the tooling's own commit messages even though the
# body is literal stdin bytes that bash never executes.
# ============================================================
echo "--- inline-interpreter / awk detectors must skip quoted-heredoc body ---"

expect_allowed "tee with quoted-heredoc body mentioning awk system() (data)" \
  "tee $PROJECT/tests/scratch_awksys.txt <<'EOF'
awk 'BEGIN{system(\"ls\")}'
EOF"

expect_allowed "tee with quoted-heredoc body mentioning python -c (data)" \
  "tee $PROJECT/tests/scratch_pyc.txt <<'EOF'
The python -c form is fail-closed.
EOF"

expect_allowed "tee with quoted-heredoc body mentioning ruby -e (data)" \
  "tee $PROJECT/tests/scratch_rbe.txt <<'EOF'
Use ruby -e 'puts 1' is uninspectable.
EOF"

expect_allowed "tee with quoted-heredoc body mentioning php -r (data)" \
  "tee $PROJECT/tests/scratch_phpr.txt <<'EOF'
The php -r 'echo 1;' inline form is blocked.
EOF"

expect_allowed "tee with quoted-heredoc body mentioning awk pipe to sh (data)" \
  "tee $PROJECT/tests/scratch_awksh.txt <<'EOF'
awk '{print}' | sh is also caught.
EOF"

# Live forms — must still be BLOCKED. Locks the regression so the fix
# does not over-relax the detector beyond the heredoc body case.
expect_blocked "live awk 'BEGIN{system(...)}' on command line" \
  "awk 'BEGIN{system(\"ls\")}' $PROJECT/CHANGELOG.md"

expect_blocked "live python -c on command line" \
  "python -c 'print(1)'"

echo ""
echo "--- Remote-dispatch class: arguments target a remote/foreign filesystem ---"
# Issue #21. The boundary plugin protects the LOCAL filesystem; commands that
# dispatch their operands to a remote host or container filesystem must not
# trip the local-path walkers. Generic shape: a verb (or two-word verb) marks
# the operands as remote, and the local-side surface (if any) is the only
# part the guard validates.

# A) Pure remote-fs tools — every operand is remote.
expect_allowed "scp upload to host:/path" \
  "scp ./local.md remote-host:/tmp/draft.md"

expect_allowed "scp download from host:/path to local cwd" \
  "scp remote-host:/tmp/draft.md ."

expect_allowed "scp -i key upload" \
  "scp -i ~/.ssh/id_ed25519 ./local.md user@remote-host:/tmp/draft.md"

expect_allowed "rcp upload" \
  "rcp ./local.md remote-host:/tmp/draft.md"

expect_allowed "sftp batch put" \
  "sftp -b /tmp/batch.txt user@remote-host"

# B) ssh with quoted remote command — opaque after host.
expect_allowed "ssh + quoted docker cp inside" \
  "ssh remote-host \"docker cp /tmp/draft.md container:/tmp/\""

expect_allowed "ssh + quoted chained remote commands" \
  "ssh remote-host \"docker cp /tmp/x.md c:/tmp/ && docker exec c bin/rails runner /tmp/x.rb\""

expect_allowed "ssh + remote rm of /etc/x (remote fs, not local)" \
  "ssh user@host \"rm -rf /etc/old\""

expect_allowed "ssh + remote tee to /var/log" \
  "ssh user@host \"tee /var/log/app.log\""

# C) docker cp host<->container — only the local operand is checked.
expect_allowed "docker cp local-to-container" \
  "docker cp /tmp/draft.md container_id:/tmp/draft.md"

expect_allowed "docker cp container-to-local cwd" \
  "docker cp container_id:/tmp/x.log ."

expect_allowed "podman cp local-to-container" \
  "podman cp /tmp/x.md mycontainer:/data/x.md"

expect_allowed "kubectl cp local-to-pod" \
  "kubectl cp /tmp/x.md mypod:/data/x.md"

expect_allowed "kubectl cp pod-to-local cwd" \
  "kubectl cp mypod:/data/x.md ."

# D) docker/podman exec — opaque after container id.
expect_allowed "docker exec running rm on container fs" \
  "docker exec container_id rm -rf /var/cache"

expect_allowed "docker exec running tee inside container" \
  "docker exec -i container_id tee /etc/app.conf"

expect_allowed "podman exec running mv inside container" \
  "podman exec mycontainer mv /etc/a /etc/b"

# D-asymmetry) docker exec + sh -c is INTENTIONALLY blocked.
# rewrite_remote_dispatch neutralises operands of remote-dispatch
# verbs, so plain path forms (D above) are ALLOWED. But
# block_nested_shell_and_eval runs BEFORE the rewrite and matches
# `sh -c ` / `bash -c ` as a raw substring on the original CMD —
# remote/container forms with an inline shell payload trip that
# walker. Fail-closed over-block, not a bypass. See the comment on
# block_nested_shell_and_eval in shell_exec_walkers.sh for why this
# ordering is preserved.
expect_allowed "docker exec ctr rm -rf /tmp/x (path operand neutralised)" \
  "docker exec ctr rm -rf /tmp/pb_escape_target"
expect_blocked "docker exec ctr sh -c '...' (intentional fail-closed over-block)" \
  "docker exec ctr sh -c 'rm -rf /tmp/pb_escape_target'"

# E) docker / podman run — NOT collapsed (bind mounts can surface host
# paths into the container; collapsing would let `-v /tmp:/data alpine
# tee /data/x.md` write to host /tmp without a boundary check). The
# existing walkers fire — false positives on no-mount runs are
# accepted as the conservative default until mount-source parsing
# lands. (Copilot review on PR #22.)
expect_blocked "docker run rm inside container — blocked (no host-mount parser yet)" \
  "docker run --rm alpine rm -rf /var/cache"

expect_blocked "docker run with bind mount writing to host via container path" \
  "docker run --rm -v /tmp:/data alpine tee /data/x.md"

# F) kubectl exec / oc exec — opaque after pod and after `--`.
expect_allowed "kubectl exec rm inside pod" \
  "kubectl exec mypod -- rm -rf /var/cache"

expect_allowed "kubectl exec -c container rm" \
  "kubectl exec mypod -c app -- rm -rf /tmp/x"

# Same intentional over-block as docker exec + sh -c above: the shell
# opener is detected before remote-dispatch neutralisation.
expect_blocked "kubectl exec sh -c '...' (intentional fail-closed over-block)" \
  "kubectl exec deploy/app -- sh -c 'rm -rf /tmp/pb_escape_target'"

expect_allowed "oc exec rm inside pod" \
  "oc exec mypod -- rm -rf /var/cache"

# G) lxc exec — opaque after container (foreign fs).
expect_allowed "lxc exec rm" \
  "lxc exec mycontainer -- rm -rf /var/cache"

# nsenter / chroot execute on the LOCAL host (different namespace /
# apparent root) — the inner command can still touch host paths
# outside the project, so they are NOT in the dispatch list and the
# rm walker stays in effect. (Copilot review on PR #22.)
expect_blocked "nsenter rm — local host, walker stays in effect" \
  "nsenter -t 1234 -m -u -n rm -rf /tmp/foo"

expect_blocked "chroot rm — local host, walker stays in effect" \
  "chroot /mnt/sysimage rm -rf /etc/foo"

# Lock: remote-dispatch ONLY blanks remote portion. The LOCAL prefix of a
# chained command must still get a strict check. These verify the patch
# does not over-relax destructive ops.
expect_blocked "scp before destructive local rm /etc — local rm still blocked" \
  "scp ./x remote-host:/tmp/x && rm -rf /etc/foo"

expect_blocked "ssh before destructive local rm /etc — local rm still blocked" \
  "ssh host \"echo hi\" && rm -rf /etc/foo"

expect_blocked "docker exec before destructive local rm /etc" \
  "docker exec c ls && rm -rf /etc/foo"

# Lock: bare names that COINCIDE with remote-dispatch verbs but lack the
# dispatch shape (no quoted remote-cmd, no container operand) are still
# subject to the normal walkers — we only relax when the dispatch shape
# is unambiguous.
expect_blocked "ssh-shaped local cp via cp command-name still blocked" \
  "cp /etc/passwd $PROJECT/leak"

# Lock: docker cp / kubectl cp DOWNLOAD mode — local destination outside
# project must still be blocked. The remote_dispatch rewrite preserves
# the local-side dst operand for the cp walker so this case stays caught.
expect_blocked "docker cp download to /etc destination" \
  "docker cp container_id:/tmp/x /etc/owned"

expect_blocked "kubectl cp download to /etc destination" \
  "kubectl cp mypod:/tmp/x /etc/owned"

expect_blocked "podman cp download to outside-project destination" \
  "podman cp mycontainer:/tmp/x /private/tmp/outside.md"

# Lock: kubectl/oc cp flags-with-value can appear AFTER the positionals
# (cobra/pflag allows this). Without per-verb flag-value awareness, the
# flag's value would shadow the real destination and the rewrite would
# emit `cp <flag-value>` (often a relative name resolving inside the
# project). The walker must consume `--namespace default`, `-c name`,
# `--kubeconfig <path>`, etc. as a single flag+value pair so the real
# local destination still gets validated. (Copilot review on PR #22.)
expect_blocked "kubectl cp download with trailing --namespace default" \
  "kubectl cp mypod:/tmp/x /etc/owned --namespace default"

expect_blocked "kubectl cp download with leading --namespace default" \
  "kubectl cp --namespace default mypod:/tmp/x /etc/owned"

expect_blocked "kubectl cp download with trailing --namespace=default attached" \
  "kubectl cp mypod:/tmp/x /etc/owned --namespace=default"

expect_blocked "kubectl cp download with -n short flag" \
  "kubectl cp mypod:/tmp/x /etc/owned -n default"

expect_blocked "kubectl cp download with -c container flag" \
  "kubectl cp mypod:/tmp/x /etc/owned -c app"

expect_blocked "oc cp download with trailing --namespace default" \
  "oc cp mypod:/tmp/x /etc/owned --namespace default"

# Lock for the upload side: same flag layout must NOT trip a false
# positive on the local source.
expect_allowed "kubectl cp upload with trailing --namespace default" \
  "kubectl cp /tmp/x.md mypod:/data/x.md --namespace default"

echo ""

# ============================================================
# tar -C in non-extract modes: -C is source cwd or unused
# ------------------------------------------------------------
# The tar walker previously treated -C as a write target in
# every mode. In list (-t), diff (-d), create (-c), append
# (-r), update (-u), catenate (-A) modes tar READS from -C
# (or ignores it for path-prefix only) and the actual archive
# is the -f operand — outside-project -C is therefore a
# legitimate source location, not a boundary write.
# ============================================================
echo "--- tar -C non-extract modes (-C is source cwd, not write target) ---"

expect_allowed "tar -tf archive -C /tmp (list)" \
  "tar -tf archive.tar -C /tmp"
expect_allowed "tar -tvf archive -C /tmp (verbose list)" \
  "tar -tvf archive.tar -C /tmp"
expect_allowed "tar -df archive -C /tmp (diff/compare)" \
  "tar -df archive.tar -C /tmp"
expect_allowed "tar -cf out.tar -C /tmp file (create reads from -C)" \
  "tar -cf $PROJECT/out.tar -C /tmp somefile"
expect_allowed "tar --list -C /tmp" \
  "tar --list -f archive.tar -C /tmp"
expect_allowed "tar --create -f out.tar -C /tmp file" \
  "tar --create -f $PROJECT/out.tar -C /tmp somefile"

# Extract mode and the conservative default (no mode token) MUST
# still block outside-project -C.
expect_blocked "tar -xf archive -C /tmp (extract still blocked)" \
  "tar -xf archive.tar -C /tmp"
expect_blocked "tar --extract -C /tmp (long extract still blocked)" \
  "tar --extract -f archive.tar -C /tmp"
expect_blocked "tar -C /tmp -xf archive (any order, extract)" \
  "tar -C /tmp -xf archive.tar"

echo ""

# ============================================================
# unzip -d skipped in read-only modes (-l/-v/-t/-p/-Z)
# ------------------------------------------------------------
# `unzip -l archive.zip -d /tmp` lists contents; -d is unused
# (or has zipinfo-specific semantics for -Z). Previously the
# walker validated -d unconditionally and false-positived.
# ============================================================
echo "--- unzip -d in read-only modes (no extraction, -d unused) ---"

expect_allowed "unzip -l -d /tmp (list)" \
  "unzip -l archive.zip -d /tmp"
expect_allowed "unzip -v -d /tmp (verbose list)" \
  "unzip -v archive.zip -d /tmp"
expect_allowed "unzip -t -d /tmp (test integrity)" \
  "unzip -t archive.zip -d /tmp"
expect_allowed "unzip -p -d /tmp (pipe to stdout)" \
  "unzip -p archive.zip -d /tmp"
expect_allowed "unzip -Z -d /tmp (zipinfo mode)" \
  "unzip -Z archive.zip -d /tmp"

# Extraction (no read-only flag) MUST still block.
expect_blocked "unzip -d /tmp archive (extract still blocked)" \
  "unzip archive.zip -d /tmp"
expect_blocked "unzip -o -d /tmp archive (extract overwrite still blocked)" \
  "unzip -o archive.zip -d /tmp"

echo ""

# ============================================================
# 7z -o<dir>/-w<path> skipped for read-only verbs (l/t/h/i/b)
# ------------------------------------------------------------
# `7z l archive.7z -o/tmp` and `7z t archive.7z -o/tmp` list
# and test the archive — neither extracts to -o<dir> nor uses
# -w<path>. The walker previously validated -o/-w for every
# verb and false-positived these.
# ============================================================
echo "--- 7z read-only verbs (-o / -w skipped) ---"

expect_allowed "7z l archive.7z -o/tmp (list)" \
  "7z l archive.7z -o/tmp"
expect_allowed "7z t archive.7z -o/tmp (test)" \
  "7z t archive.7z -o/tmp"
expect_allowed "7z h archive.7z -o/tmp (hash)" \
  "7z h archive.7z -o/tmp"
expect_allowed "7z l archive.7z -w/tmp (list, -w ignored)" \
  "7z l archive.7z -w/tmp"

# Write verbs MUST still block -o<dir> outside.
expect_blocked "7z x archive.7z -o/tmp (extract still blocked)" \
  "7z x archive.7z -o/tmp"
expect_blocked "7z e archive.7z -o/tmp (extract-flat still blocked)" \
  "7z e archive.7z -o/tmp"

echo ""

# ============================================================
# cpio -t (list mode): -D is unused, no extraction
# ------------------------------------------------------------
# `cpio -it -D /tmp < archive.cpio` prints a table of contents
# without extracting anything. -D is unused in list mode.
# ============================================================
echo "--- cpio -t list mode (-D unused) ---"

expect_allowed "cpio -it -D /tmp (list)" \
  "cpio -it -D /tmp"
expect_allowed "cpio --list -D /tmp (long form)" \
  "cpio --list -D /tmp"
expect_allowed "cpio -i -t -D /tmp (separated -t)" \
  "cpio -i -t -D /tmp"

# Extract mode (no -t) MUST still block.
expect_blocked "cpio -i -D /tmp (extract still blocked)" \
  "cpio -i -D /tmp"
expect_blocked "cpio -id -D /tmp (extract with create-dirs still blocked)" \
  "cpio -id -D /tmp"

echo ""
