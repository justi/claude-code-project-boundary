#!/bin/bash
# True-negative tests: real workflows inside project must NOT be disturbed.
# These tests verify that legitimate destructive operations on files/dirs
# whose paths contain spaces are allowed when they resolve inside the project.
# They guard against false positives from future security tightening.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  True-negative tests (real workflows)"
echo "  PROJECT_DIR=$PROJECT"
echo "========================================"
echo ""

# Ensure the subdir with space exists so ancestor resolution finds it
mkdir -p "$PROJECT/dir with space"
mkdir -p "$PROJECT/dir with space/src"
mkdir -p "$PROJECT/dir with space/dst"
mkdir -p "$PROJECT/dir with space/bin"
mkdir -p "$PROJECT/dir with space/dist"

echo "--- curl: all option forms with quoted space inside project ---"

expect_allowed 'curl -o quoted space inside project' \
  "curl -o \"$PROJECT/dir with space/out.txt\" http://x"

expect_allowed 'curl --output quoted space inside project' \
  "curl --output \"$PROJECT/dir with space/out.txt\" http://x"

expect_allowed 'curl --output= quoted space inside project' \
  "curl --output=\"$PROJECT/dir with space/out.txt\" http://x"

echo ""
echo "--- wget: all option forms with quoted space inside project ---"

expect_allowed 'wget -O quoted space inside project' \
  "wget -O \"$PROJECT/dir with space/out.txt\" http://x"

expect_allowed 'wget --output-document quoted space inside project' \
  "wget --output-document \"$PROJECT/dir with space/out.txt\" http://x"

expect_allowed 'wget --output-document= quoted space inside project' \
  "wget --output-document=\"$PROJECT/dir with space/out.txt\" http://x"

echo ""
echo "--- tar / unzip / cpio: archive extraction inside project ---"

expect_allowed 'tar -C quoted space inside project' \
  "tar -C \"$PROJECT/dir with space\" -xf archive.tar"

expect_allowed 'tar --directory quoted space inside project' \
  "tar --directory \"$PROJECT/dir with space\" -xf archive.tar"

expect_allowed 'tar --directory= quoted space inside project' \
  "tar --directory=\"$PROJECT/dir with space\" -xf archive.tar"

expect_allowed 'unzip -d quoted space inside project' \
  "unzip -d \"$PROJECT/dir with space\" archive.zip"

expect_allowed 'cpio -D quoted space inside project' \
  "cpio -D \"$PROJECT/dir with space\" -i"

echo ""
echo "--- mv / cp: --target-directory and -t inside project ---"

expect_allowed 'mv -t quoted space inside project' \
  "mv -t \"$PROJECT/dir with space\" a.txt"

expect_allowed 'mv --target-directory quoted space inside project' \
  "mv --target-directory \"$PROJECT/dir with space\" a.txt"

expect_allowed 'mv --target-directory= quoted space inside project' \
  "mv --target-directory=\"$PROJECT/dir with space\" a.txt"

expect_allowed 'cp -t quoted space inside project' \
  "cp -t \"$PROJECT/dir with space\" a.txt"

expect_allowed 'cp --target-directory= quoted space inside project' \
  "cp --target-directory=\"$PROJECT/dir with space\" a.txt"

echo ""
echo "--- dd: of= inside project ---"

expect_allowed 'dd of= quoted space inside project' \
  "dd if=/dev/zero of=\"$PROJECT/dir with space/file.bin\" bs=1M count=1"

echo ""
echo "--- Redirects: all forms writing inside project ---"

expect_allowed 'redirect > quoted space inside project' \
  "echo x > \"$PROJECT/dir with space/out.txt\""

expect_allowed 'redirect >> quoted space inside project' \
  "echo x >> \"$PROJECT/dir with space/log.txt\""

expect_allowed 'redirect 1> quoted space inside project' \
  "echo x 1> \"$PROJECT/dir with space/out.txt\""

expect_allowed 'redirect 2> quoted space inside project' \
  "echo x 2> \"$PROJECT/dir with space/err.txt\""

expect_allowed 'redirect 2>> quoted space inside project' \
  "echo x 2>> \"$PROJECT/dir with space/err.log\""

expect_allowed 'redirect &> quoted space inside project' \
  "echo x &> \"$PROJECT/dir with space/all.txt\""

expect_allowed 'redirect &>> quoted space inside project' \
  "echo x &>> \"$PROJECT/dir with space/all.log\""

echo ""
echo "--- Realistic workflows: common commands project owners run ---"

expect_allowed 'build log workflow: echo > with space path' \
  "echo 'build ok' > \"$PROJECT/dir with space/build.log\""

expect_allowed 'append log: echo >> with space path' \
  "echo 'step done' >> \"$PROJECT/dir with space/build.log\""

expect_allowed 'extract release inside project' \
  "tar -C \"$PROJECT/dir with space\" -xzf release.tar.gz"

expect_allowed 'sync assets inside project' \
  "rsync -av \"$PROJECT/dir with space/src/\" \"$PROJECT/dir with space/dst/\""

expect_allowed 'install binary inside project' \
  "install -m 755 \"$PROJECT/dir with space/bin/app\" \"$PROJECT/dir with space/dist/app\""

expect_allowed 'save curl response inside project' \
  "curl -sL https://example.com/file.json -o \"$PROJECT/dir with space/data.json\""

expect_allowed 'dd raw write inside project' \
  "dd if=/dev/urandom of=\"$PROJECT/dir with space/random.bin\" bs=1M count=1"

echo ""

echo "--- executing scripts inside project must still work ---"

expect_allowed 'bash ./tests/test_guard.sh (relative inside project)' \
  "bash ./tests/test_guard.sh"

expect_allowed 'bash PROJECT/script.sh (absolute inside project)' \
  "bash $PROJECT/script.sh"

expect_allowed 'sh PROJECT/script.sh' \
  "sh $PROJECT/script.sh"

expect_allowed 'zsh PROJECT/script.sh' \
  "zsh $PROJECT/script.sh"

expect_allowed 'bash -x PROJECT/script.sh (with flag)' \
  "bash -x $PROJECT/script.sh"

# Known limitation: `bash -- PROJECT/script.sh` is false-positively blocked
# by the older piping-to-shell heuristic (predates this PR). Rare in practice.

expect_allowed 'source PROJECT/venv/bin/activate (relative allowed inside)' \
  "source $PROJECT/venv/bin/activate"

expect_allowed '. PROJECT/utils.sh' \
  ". $PROJECT/utils.sh"

# Positive cases for the sed -i script recognizer.
# Codex finding: the script-skip heuristic only matched s///-style
# substitutions and numeric addresses, so any OTHER valid sed program
# (address-pattern delete, BSD -i '' extension, transliteration, block)
# was treated as a file path and wrongly blocked. Real in-project
# edits use those forms all the time.
echo ""
echo "--- sed -i non-substitute scripts in project (must not false-positive) ---"

expect_allowed "sed -i '/debug/d' PROJECT/file (delete by pattern)" \
  "sed -i '/debug/d' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i '/foo/p' PROJECT/file (print by pattern)" \
  "sed -i '/foo/p' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i 'y/abc/xyz/' PROJECT/file (transliterate)" \
  "sed -i 'y/abc/xyz/' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i '' '/foo/d' PROJECT/file (BSD empty extension)" \
  "sed -i '' '/foo/d' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i.bak '/foo/d' PROJECT/file (attached extension)" \
  "sed -i.bak '/foo/d' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i -e '/foo/d' PROJECT/file (-e explicit expression)" \
  "sed -i -e '/foo/d' $PROJECT/tests/scratch.txt"

expect_allowed "sed -i 's/a/b/' PROJECT/file (classic substitute still OK)" \
  "sed -i 's/a/b/' $PROJECT/tests/scratch.txt"

# Regressions: sed -i targeting outside the project must STILL be blocked.
echo ""
echo "--- sed -i outside project (regressions must stay blocked) ---"
# These are block-expected — use a conditional wrapper.
_sed_block() {
  local label="$1" cmd="$2"
  TOTAL=$((TOTAL + 1))
  run_guard "$cmd"
  local rc=$?
  if [ "$rc" -eq 2 ]; then echo "PASS: $label"; PASS=$((PASS + 1))
  else echo "FAIL: $label -- expected BLOCKED got $rc"; FAIL=$((FAIL + 1)); fi
}
_sed_block "sed -i '/foo/d' /etc/passwd_test (outside, pattern-delete)" \
  "sed -i '/foo/d' /etc/passwd_test"
_sed_block "sed -i '' '/foo/d' /etc/passwd_test (BSD, outside)" \
  "sed -i '' '/foo/d' /etc/passwd_test"
_sed_block "sed -i -e '/foo/d' /etc/passwd_test (-e, outside)" \
  "sed -i -e '/foo/d' /etc/passwd_test"
_sed_block "sed -i 's/a/b/' /etc/passwd_test (substitute, outside — already worked)" \
  "sed -i 's/a/b/' /etc/passwd_test"

echo ""
echo '--- $VAR / positional-parameter positive cases ---'
# Positive cases for the broadened $VAR / positional-parameter detector.
# Must allow literal dollar-delimited forms that are NOT parameter
# expansion: ANSI-C quoting ($'...'), i18n strings ($"..."), arithmetic
# $((...)), a literal `$` inside single quotes, and $HOME itself.
expect_allowed "printf with ANSI-C quoted literal \$'\\n'" \
  "printf 'hi'\$'\\n' > $PROJECT/tests/scratch.txt"

expect_allowed "echo i18n string \$\"Hello\"" \
  "echo \$\"Hello\" > $PROJECT/tests/scratch.txt"

expect_allowed "arithmetic \$((1+2)) in redirect" \
  "echo \$((1+2)) > $PROJECT/tests/scratch.txt"

expect_allowed "literal \$ inside single quotes" \
  "echo 'cost: \$1' > $PROJECT/tests/scratch.txt"

echo ""

# ----------------------------------------------------------------------
# Quoted-heredoc body containing && / ; / || must not false-positive on
# $VAR or positional-parameter detectors.
#
# Root cause: split_and_check splits the full CMD on &&/||/; without
# heredoc awareness. A body line like `X=/etc/x && rm $X` becomes two
# pseudo-commands; the second (`rm $X\nBODY`) loses heredoc context and
# the $VAR detector fires even though bash never expands a quoted
# heredoc body.
# ----------------------------------------------------------------------
echo "--- quoted heredoc body with shell operators (must not false-positive) ---"

expect_allowed "gh pr edit --body-file - <<'BODY' with && in body" \
  "gh pr edit 12 --body-file - <<'BODY'
- Variable indirection: X=/etc/x && rm \$X
BODY"

expect_allowed "cat > PROJECT/file <<'EOF' with && and \$1 in body" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF'
echo a && rm \$1
EOF"

expect_allowed "cat > PROJECT/file <<'EOF' with ; and \$@ in body" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF'
foo; echo \$@
EOF"

expect_allowed "cat > PROJECT/file <<'EOF' with || and \$X in body" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF'
true || rm \$X
EOF"

echo ""

# ----------------------------------------------------------------------
# Quoted-heredoc body containing a shell-token WORD (bash/sh/source)
# must not false-positive on the stdin-redirect-feeds-shell detector.
#
# Root cause: that detector tokenizes the entire CMD (including
# heredoc body bytes), sets _saw_redir=1 on the opening `<<`, then
# fires on any later token that matches is_shell_token / is_source_token
# — even when that token is plain prose inside a quoted body that bash
# never executes. Surfaced when writing a git-commit message body that
# mentions the word "bash".
#
# Regression coverage for the genuine shell-stdin attacks (must stay
# BLOCKED) lives in test_bash_guard.sh / test_bypass_reproducers.sh —
# the fix below preserves them by tokenizing a heredoc-blanked copy of
# the CMD only for this scan.
# ----------------------------------------------------------------------
echo "--- quoted heredoc body with shell-token words (must not false-positive) ---"

expect_allowed "git commit -F - <<'EOF' body mentions 'bash'" \
  "git commit -F - <<'EOF'
fix bash heredoc parsing
EOF"

expect_allowed "cat > PROJECT/file <<'EOF' body mentions 'sh'" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF'
some sh notes
EOF"

expect_allowed "git commit -F - <<'EOF' body mentions 'source'" \
  "git commit -F - <<'EOF'
note about source code
EOF"

echo ""

# Regression: the genuine shell-stdin attacks must STAY BLOCKED. These
# are the FN cases the fix above must not weaken.
echo "--- shell-stdin attacks (must stay BLOCKED — regression for FP fix above) ---"

expect_blocked "FN: < /tmp/x bash (leading redirect feeds shell)" \
  "< /tmp/x bash"

expect_blocked "FN: FOO=1 < /tmp/x bash (redirect after VAR=val)" \
  "FOO=1 < /tmp/x bash"

expect_blocked "FN: nice < /tmp/x bash (redirect after wrapper)" \
  "nice < /tmp/x bash"

echo ""

# ----------------------------------------------------------------------
# Quoted-heredoc body parsed by file/redirect detectors as if it were
# a real command. Same root cause class as the two FPs already fixed
# in v1.4.1 (positional/$VAR detector, shell-stdin detector): a
# detector that walks CMD or CMD_TOKENS without a heredoc-aware view
# picks up body bytes as if they were live tokens.
#
# Triggered repeatedly during the v1.5.0 audit when commit-message
# bodies happened to contain example commands. Real attacks are
# unaffected because the interpreter / target token sits OUTSIDE any
# heredoc body in genuine attacks; the fix only blanks body bytes.
# ----------------------------------------------------------------------
echo "--- quoted heredoc body parsed by file/redirect detectors (FP) ---"

expect_allowed "git commit -F - body mentions sed -i with outside path" \
  "git commit -F - <<'EOF'
example: sed -i 's/a/b/' /etc/foo
EOF"

expect_allowed "git commit -F - body mentions truncate with outside path" \
  "git commit -F - <<'EOF'
example: truncate -s 0 /etc/log
EOF"

expect_allowed "git commit -F - body mentions redirect to /bin/owned" \
  "git commit -F - <<'EOF'
collapsing > /bin/owned should not bypass guard
EOF"

expect_allowed "cat > PROJECT/file <<'EOF' body has redirect example" \
  "cat > $PROJECT/tests/scratch.txt <<'EOF'
note: writing > /etc/passwd is forbidden
EOF"

echo ""

# Regression: real attacks of the same shape must STAY BLOCKED.
echo "--- file/redirect attacks (must stay BLOCKED — regression for FP fix above) ---"

expect_blocked "FN: real sed -i targets /etc (no heredoc)" \
  "cd /tmp && sed -i 's/a/b/' /etc/passwd_test"

expect_blocked "FN: real truncate targets /etc (no heredoc)" \
  "cd /tmp && truncate -s 0 /etc/passwd_test"

expect_blocked "FN: real redirect to /bin/owned (no heredoc)" \
  "echo x > /bin/owned"

expect_blocked "FN: real redirect inside unquoted heredoc opener" \
  "cat > /etc/passwd_test <<EOF
content
EOF"

echo ""

# ----------------------------------------------------------------------
# Backslash-escaped heredoc delimiter (<<\EOF) regression. Bash treats
# <<\EOF identically to <<'EOF' — body is opaque, no expansions. But
# CMD normalization strips `\` before a letter (the alias-escape fix:
# `\rm` → `rm`), which silently turns `<<\EOF` into `<<EOF` (unquoted).
# Then blank_quoted_heredoc_bodies sees an unquoted heredoc and does
# NOT blank the body, so the downstream sed-i / truncate / redirect /
# $VAR detectors all parse body bytes again — every FP closed in
# v1.4.1 / v1.5.1 reappears for the backslash-escaped form.
#
# Reported by Copilot review on PR #12 (commit 7641a412).
# Fix: build the blanked scan view from CMD_RAW (preserving the
# backslash-escaped delimiter) rather than from the post-normalisation
# CMD. The other normalisation passes are then applied to the blanked
# view — backslash-stripping is safe at that point because body bytes
# are already replaced with spaces.
# ----------------------------------------------------------------------
echo "--- backslash-escaped heredoc body (must not false-positive) ---"

expect_allowed "git commit -F - <<\\EOF body mentions sed -i /etc/foo" \
  'git commit -F - <<\EOF
example: sed -i '"'"'s/a/b/'"'"' /etc/foo
EOF'

expect_allowed "cat <<\\EOF body has redirect example" \
  'cat <<\EOF
note: > /etc/passwd would be bad
EOF'

expect_allowed "git commit -F - <<\\EOF body mentions \$1" \
  'git commit -F - <<\EOF
parameter $1 should not fire
EOF'

expect_allowed "cat > PROJECT/file <<-\\EOF (indented backslash form)" \
  "cat > $PROJECT/tests/scratch.txt <<-\\EOF
	example: rm \$X
	EOF"

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
  "scp ./local.md ragnarok:/tmp/draft.md"

expect_allowed "scp download from host:/path to local cwd" \
  "scp ragnarok:/tmp/draft.md ."

expect_allowed "scp -i key upload" \
  "scp -i ~/.ssh/id_ed25519 ./local.md user@ragnarok:/tmp/draft.md"

expect_allowed "rcp upload" \
  "rcp ./local.md ragnarok:/tmp/draft.md"

expect_allowed "sftp batch put" \
  "sftp -b /tmp/batch.txt user@ragnarok"

# B) ssh with quoted remote command — opaque after host.
expect_allowed "ssh + quoted docker cp inside" \
  "ssh ragnarok \"docker cp /tmp/draft.md container:/tmp/\""

expect_allowed "ssh + quoted chained remote commands" \
  "ssh ragnarok \"docker cp /tmp/x.md c:/tmp/ && docker exec c bin/rails runner /tmp/x.rb\""

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

# E) docker/podman run — opaque after image.
expect_allowed "docker run with rm inside" \
  "docker run --rm alpine rm -rf /var/cache"

expect_allowed "docker run with bind mount and tee inside" \
  "docker run --rm -v /tmp:/data alpine tee /data/x.md"

# F) kubectl exec / oc exec — opaque after pod and after `--`.
expect_allowed "kubectl exec rm inside pod" \
  "kubectl exec mypod -- rm -rf /var/cache"

expect_allowed "kubectl exec -c container rm" \
  "kubectl exec mypod -c app -- rm -rf /tmp/x"

expect_allowed "oc exec rm inside pod" \
  "oc exec mypod -- rm -rf /var/cache"

# G) lxc exec / nsenter / chroot — opaque after target.
expect_allowed "lxc exec rm" \
  "lxc exec mycontainer -- rm -rf /var/cache"

expect_allowed "nsenter into pid running rm" \
  "nsenter -t 1234 -m -u -n rm -rf /tmp/foo"

# Lock: remote-dispatch ONLY blanks remote portion. The LOCAL prefix of a
# chained command must still get a strict check. These verify the patch
# does not over-relax destructive ops.
expect_blocked "scp before destructive local rm /etc — local rm still blocked" \
  "scp ./x ragnarok:/tmp/x && rm -rf /etc/foo"

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

echo ""
