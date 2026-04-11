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
