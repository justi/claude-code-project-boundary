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
