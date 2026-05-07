#!/bin/bash
# bash advanced suite (part B).
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  bash advanced (part B)"
echo "========================================"
echo ""

expect_blocked 'dd of= quoted space traversal' \
  "dd if=/dev/zero of=\"$PROJECT/safe /../../etc/passwd\""

expect_allowed 'dd of= quoted space inside project' \
  "dd if=/dev/zero of=\"$PROJECT/dir with space/file.bin\""

# mv/cp --target-directory / -t
expect_blocked 'mv --target-directory= quoted space traversal' \
  "mv --target-directory=\"$PROJECT/safe /../../tmp\" a.txt"

expect_blocked 'mv --target-directory quoted space traversal (separated)' \
  "mv --target-directory \"$PROJECT/safe /../../tmp\" a.txt"

expect_blocked 'cp --target-directory= quoted space traversal' \
  "cp --target-directory=\"$PROJECT/safe /../../tmp\" a.txt"

expect_blocked 'cp --target-directory quoted space traversal (separated)' \
  "cp --target-directory \"$PROJECT/safe /../../tmp\" a.txt"

expect_blocked 'mv -t quoted space traversal' \
  "mv -t \"$PROJECT/safe /../../tmp\" a.txt"

expect_blocked 'cp -t quoted space traversal' \
  "cp -t \"$PROJECT/safe /../../tmp\" a.txt"

expect_allowed 'mv -t quoted space inside project' \
  "mv -t \"$PROJECT/dir with space\" a.txt"

# Redirect > / >>
expect_blocked 'redirect > quoted space traversal' \
  "echo x > \"$PROJECT/safe /../../etc/passwd\""

expect_blocked 'redirect >> quoted space traversal' \
  "echo x >> \"$PROJECT/safe /../../etc/passwd\""

expect_allowed 'redirect > quoted space inside project' \
  "echo x > \"$PROJECT/dir with space/out.txt\""

# fd-prefixed redirects: 1>, 2>, 2>>, &>, &>>
expect_blocked 'redirect 1> quoted space traversal' \
  "echo x 1> \"$PROJECT/safe /../../etc/passwd\""

expect_blocked 'redirect 2> quoted space traversal' \
  "echo x 2> \"$PROJECT/safe /../../etc/passwd\""

expect_blocked 'redirect 2>> quoted space traversal' \
  "echo x 2>> \"$PROJECT/safe /../../etc/passwd\""

expect_blocked 'redirect &> quoted space traversal' \
  "echo x &> \"$PROJECT/safe /../../etc/passwd\""

expect_blocked 'redirect 2>file attached form outside project' \
  "echo x 2>/etc/passwd"

expect_allowed 'redirect 2> inside project' \
  "echo x 2> \"$PROJECT/dir with space/err.txt\""

expect_allowed 'redirect &> inside project' \
  "echo x &> \"$PROJECT/dir with space/all.txt\""

# fd-to-fd redirect must not be treated as a file target
expect_allowed 'redirect 2>&1 (fd-to-fd, not a file)' \
  "echo x 2>&1"

# Repeated options: last one wins — must validate all occurrences
expect_blocked 'tar repeated -C last wins to outside' \
  "tar -C \"$PROJECT\" -C /etc -xf archive.tar"

expect_blocked 'tar repeated -C first inside, second outside' \
  "tar -C \"$PROJECT/dir with space\" -C /tmp -xf archive.tar"

expect_allowed 'tar repeated -C both inside project' \
  "tar -C \"$PROJECT\" -C \"$PROJECT/dir with space\" -xf archive.tar"

expect_blocked 'dd repeated of= last wins to outside' \
  "dd if=/dev/zero of=\"$PROJECT/ok\" of=/etc/passwd"

expect_blocked 'dd repeated of= first inside, second outside' \
  "dd if=/dev/zero of=\"$PROJECT/dir with space/ok\" of=/etc/passwd"

# Repeated -o/-O/-t options with last-wins bypass: extract_option_value
# must return the LAST match so the effective value is validated.
expect_blocked 'curl repeated -o last wins to outside' \
  "curl -o \"$PROJECT/ok.txt\" -o /etc/passwd http://x"

expect_blocked 'curl repeated --output last wins to outside' \
  "curl --output \"$PROJECT/ok.txt\" --output /etc/passwd http://x"

expect_blocked 'wget repeated -O last wins to outside' \
  "wget -O \"$PROJECT/ok.txt\" -O /etc/passwd http://x"

expect_blocked 'wget repeated --output-document last wins to outside' \
  "wget --output-document \"$PROJECT/ok.txt\" --output-document /etc/passwd http://x"

expect_blocked 'mv repeated -t last wins to outside' \
  "mv -t \"$PROJECT\" -t /etc a.txt"

expect_blocked 'cp repeated --target-directory last wins to outside' \
  "cp --target-directory \"$PROJECT\" --target-directory /etc a.txt"

# Attached-form redirects (no whitespace before >)
expect_blocked 'redirect x>file no whitespace traversal' \
  "echo x>/etc/passwd"

expect_blocked 'redirect x>>file no whitespace traversal' \
  "echo x>>/etc/passwd"

expect_blocked 'redirect "x">file quoted no whitespace' \
  'echo "x">/etc/passwd'

expect_blocked 'redirect x>file attached to token with quoted space path' \
  "echo x>\"$PROJECT/safe /../../etc/passwd\""

expect_allowed 'redirect x>file no whitespace inside project' \
  "echo x>\"$PROJECT/dir with space/out.txt\""

# Quoted option flags: tokenize_args preserves quotes, so flag matching
# must strip them first. Otherwise curl "-o" /etc/passwd bypasses.
expect_blocked 'curl with quoted -o flag' \
  'curl "-o" /etc/passwd http://x'

expect_blocked 'curl with quoted --output flag' \
  'curl "--output" /etc/passwd http://x'

expect_blocked 'curl with quoted --output=value' \
  'curl "--output=/etc/passwd" http://x'

expect_blocked 'wget with quoted -O flag' \
  'wget "-O" /etc/passwd http://x'

expect_blocked 'tar with quoted -C flag' \
  'tar "-C" /etc -xf a.tar'

expect_blocked 'tar with quoted --directory= value' \
  'tar "--directory=/etc" -xf a.tar'

expect_blocked 'dd with quoted of= token' \
  'dd if=/dev/zero "of=/etc/passwd"'

expect_blocked 'mv with quoted -t flag' \
  'mv "-t" /etc a.txt'

expect_blocked 'cp with quoted --target-directory= value' \
  'cp "--target-directory=/etc" a.txt'

# Bash clobber operator >| / >>| — | is part of the operator, not a pipe
expect_blocked 'clobber >| to outside project' \
  'echo x >| /etc/passwd'

expect_blocked 'clobber >|file attached to outside' \
  'echo x >|/etc/passwd'

expect_blocked 'clobber >>| append to outside' \
  'echo x >>| /etc/passwd'

expect_allowed 'clobber >| inside project' \
  "echo x >| \"$PROJECT/dir with space/out.txt\""

# Process substitution > >(cmd) — uninspectable, must block
expect_blocked 'process substitution > >(tee outside)' \
  'echo x > >(tee /etc/passwd)'

expect_blocked 'process substitution attached >(cmd)' \
  'echo x >>(tee /etc/passwd)'

# Positional curl -o: validate EVERY occurrence, not just last
expect_blocked 'curl positional -o first outside second inside' \
  "curl -o /etc/passwd http://a -o \"$PROJECT/out\" http://b"

expect_blocked 'curl positional -o first inside second outside' \
  "curl -o \"$PROJECT/out\" http://a -o /etc/passwd http://b"

expect_allowed 'curl positional -o both inside project' \
  "curl -o \"$PROJECT/a\" http://a -o \"$PROJECT/b\" http://b"

# Positional wget -O (same semantics concern)
expect_blocked 'wget positional -O first outside second inside' \
  "wget -O /etc/passwd http://a -O \"$PROJECT/out\" http://b"

# Backslash-escaped > is a literal, not a redirect
expect_allowed 'backslash-escaped > not a redirect' \
  'echo \>/etc/passwd'

expect_allowed 'backslash-escaped >> not a redirect' \
  'echo \>\>/etc/passwd'

echo ""

# ============================================================
# 46. cwd from hook event payload
# ============================================================
echo "--- cwd from hook event ---"

expect_blocked_cwd "rm relative file with cwd=/tmp" \
  "rm relative.txt" "/tmp"

expect_allowed_cwd "rm relative file with cwd=project" \
  "rm relative.txt" "$PROJECT"

expect_blocked_cwd "mv file with cwd=/tmp" \
  "mv a.txt b.txt" "/tmp"

expect_allowed_cwd "mv file with cwd=project" \
  "mv a.txt b.txt" "$PROJECT"

# Destructive git/rails/rake with cwd outside project
expect_blocked_cwd "git clean with cwd=/tmp" \
  "git clean -fd" "/tmp"

expect_blocked_cwd "git reset --hard with cwd=/tmp" \
  "git reset --hard HEAD~1" "/tmp"

expect_blocked_cwd "git checkout . with cwd=/tmp" \
  "git checkout ." "/tmp"

expect_blocked_cwd "git checkout -- . with cwd=/tmp" \
  "git checkout -- ." "/tmp"

# git clean dry-run variants — safe, allowed
expect_allowed_cwd "git clean -nfd (dry-run) with cwd=/tmp" \
  "git clean -nfd" "/tmp"

expect_allowed_cwd "git clean --dry-run -fd with cwd=/tmp" \
  "git clean --dry-run -fd" "/tmp"

# git clean without -f is a no-op (git refuses) — should not be blocked
expect_allowed_cwd "git clean (no -f) with cwd=/tmp" \
  "git clean" "/tmp"

expect_blocked_cwd "git push --force with cwd=/tmp" \
  "git push --force origin main" "/tmp"

expect_blocked_cwd "rails db:drop with cwd=/tmp" \
  "rails db:drop" "/tmp"

expect_blocked_cwd "rake db:reset with cwd=/tmp" \
  "rake db:reset" "/tmp"

# More destructive git commands after cd outside project
expect_blocked_cwd "git restore . with cwd=/tmp" \
  "git restore ." "/tmp"

expect_blocked_cwd "git restore -- . with cwd=/tmp" \
  "git restore -- ." "/tmp"

expect_blocked_cwd "git stash drop with cwd=/tmp" \
  "git stash drop" "/tmp"

expect_blocked_cwd "git stash clear with cwd=/tmp" \
  "git stash clear" "/tmp"

expect_blocked_cwd "git branch -D with cwd=/tmp" \
  "git branch -D feature" "/tmp"

expect_blocked_cwd "git reflog expire with cwd=/tmp" \
  "git reflog expire --expire=now --all" "/tmp"

# Safe git with cwd outside project — allowed
expect_allowed_cwd "git status with cwd=/tmp (safe)" \
  "git status" "/tmp"

expect_allowed_cwd "git log with cwd=/tmp (safe)" \
  "git log" "/tmp"

# cd back into project from outside cwd — should allow
expect_allowed_cwd "cd to project && rm file (cwd=/tmp)" \
  "cd $PROJECT && rm file.txt" "/tmp"

expect_allowed_cwd "cd to project && git clean (cwd=/tmp)" \
  "cd $PROJECT && git clean -fd" "/tmp"

# dd with cwd outside — of= inside project should be allowed
expect_allowed_cwd "dd of= inside project (cwd=/tmp)" \
  "dd if=/dev/zero of=$PROJECT/file.bin bs=1M count=1" "/tmp"

# dd with cwd outside — of= outside project should be blocked
expect_blocked_cwd "dd of=/etc/file (cwd=/tmp)" \
  "dd if=/dev/zero of=/etc/file bs=1M count=1" "/tmp"

echo ""

# ============================================================
# 47. Previously always-blocked commands are now allowed inside project
# ============================================================
echo "--- Removed global blocks (regression guard) ---"

expect_allowed "git push --force (inside project)" \
  "git push --force origin main"

expect_allowed "git reset --hard (inside project)" \
  "git reset --hard HEAD~1"

expect_allowed "git checkout . (inside project)" \
  "git checkout ."

expect_allowed "git clean -fd (inside project)" \
  "git clean -fd"

expect_allowed "rails db:drop (inside project)" \
  "rails db:drop"

expect_allowed "rake db:reset (inside project)" \
  "rake db:reset"

echo ""

# ============================================================
# 48. Tokens that look like echo flags (printf vs echo safety)
# ============================================================
echo "--- Tokens resembling echo flags ---"

expect_blocked "rm with -n flag-like filename outside project" \
  "rm /etc/-n"

expect_blocked "mv -n flag-like path outside project" \
  "mv -n /etc/passwd $PROJECT/file"

expect_allowed "rm -n flag-like filename inside project" \
  "rm $PROJECT/-n"

echo ""

# ============================================================
# 49. Pipe to shell with flags (sed ERE portability)
# ============================================================
echo "--- Pipe to shell with flags (ERE portability) ---"

expect_blocked "pipe to bash -i" \
  'echo "cmd" | bash -i'

expect_blocked "pipe to sh -s" \
  'echo "cmd" | sh -s'

expect_blocked "pipe to /bin/bash --login" \
  'echo "cmd" | /bin/bash --login'

expect_blocked "pipe to bash -l" \
  'echo "cmd" | bash -l'

echo ""

# ============================================================
# 50. Variable expansion is fail-closed (only $HOME allowed)
#
# The guard cannot inspect what `$P`, `${FILE}`, `$1`, `$@`, etc. resolve
# to at exec time, so every non-HOME parameter expansion is refused with
# the same fail-closed contract as `$(...)`. Documents the rule users
# hit when they write `P=/path/to/file; grep X "$P"` style commands.
# ============================================================
echo "--- Variable expansion (fail-closed; only \$HOME allowed) ---"

# BLOCKED — bare $VAR, ${VAR}, with attached/separated path forms
expect_blocked "bare \$P operand"             'rm $P'
expect_blocked "braced \${FILE} operand"      'cat ${FILE}'
expect_blocked "\$VAR concatenated with path" 'rm $P/file'
expect_blocked "\${VAR}/path concatenation"   'rm ${P}/file'
expect_blocked "\$VAR inside double quotes"   'grep X "$P"'
expect_blocked "\$VAR with underscore name"   'rm $foo_bar'
expect_blocked "\$VAR as redirect target"     'echo x > $OUT'
expect_blocked "\$VAR in for-loop body"       'for f in a b; do rm $f; done'

# BLOCKED — positional and special parameters
expect_blocked "positional \$1"               'rm $1'
expect_blocked "special \$@"                  'rm $@'
expect_blocked "special \$*"                  'rm $*'
expect_blocked "special \$?"                  'echo $?'
expect_blocked "special \$!"                  'echo $!'
expect_blocked "special \$\$"                 'echo $$'
expect_blocked "special \$#"                  'echo $#'

# ALLOWED — $HOME passthrough (then resolved by expand_path)
expect_allowed "bare \$HOME in echo"          'echo $HOME'
expect_allowed "braced \${HOME} in echo"      'echo ${HOME}'

# ALLOWED — non-expansion forms that share the $X prefix
expect_allowed "ANSI-C quoted literal \$'...'"   "echo \$'literal\\n'"
expect_allowed 'i18n quoted literal $"..."'      'echo $"some string"'

# ALLOWED — literal $ (escaped or single-quoted)
expect_allowed "backslash-escaped \\\$VAR"    'echo \$VAR'
expect_allowed "single-quoted \$VAR"          "echo '\$VAR'"

# ALLOWED — \$VAR inside a quoted heredoc body (body bytes blanked)
expect_allowed "\$VAR inside quoted heredoc body" \
  "git commit -F - <<'EOF'
title

body mentions \$VAR and \${FILE}
EOF"

echo ""
