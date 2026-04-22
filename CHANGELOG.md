# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.5.0] — 2026-04-22

### Security — closes 3 bypass categories from Copilot review on PR #12

- **Path-prefix normalization corrupted redirect targets (C1)** — `check_single_command` strips common binary path prefixes (`/bin/`, `/usr/bin/`, `/sbin/`, `/usr/sbin/`, `/usr/local/bin/`) so that `/bin/rm` is recognised as `rm` by command-name detectors. The single regex `(^|whitespace)/(bin|...)/` matched the whitespace AFTER a redirect operator too, so `echo x > /bin/owned` was rewritten to `echo x > owned`, the redirect target collapsed to a relative inside-project path, and the boundary check passed — while the parser physically wrote outside the project. Split into two passes that match only at command position: `^/(bin|...)/` (start of CMD) and `[^<>|&;[:space:]]\s+/(bin|...)/` (after a non-redirect, non-pipe, non-separator character). Subcommand separators are already split off by `split_and_check`, so a `/bin/foo` appearing here is unambiguous: command-position (stripped) or argument/redirect target (preserved).
- **End-of-options ignored by `sed -i` and `truncate` walkers (C2 + C3)** — both file-walkers treated any token starting with `-` as an option and skipped it. POSIX `--` ends option parsing: every token after it is a positional operand even when its name begins with `-`. So `cd /tmp && sed -i 's/a/b/' -- -owned` (and the truncate analogue) silently skipped `-owned` as an unknown flag, never reaching `is_write_permitted`. Each walker now carries a `seen_dashdash` flag; once set, the option-dispatch case is bypassed and every remaining token is validated as a file operand. Same fix shape in two detectors.
- **PHP inline-code flag bypass (C4)** — the non-shell-interpreter detector lists `php` in its command-name alternation, but the flag pattern `-[a-zA-Z]*[ceE]|--eval|--execute` matches none of php's actual inline-code flags (`-r`, `-R`, `--run`). So `php -r 'system("rm /etc/x")'` reached the parser unchecked despite the block comment claiming php was covered. Added a dedicated php-only check matching `(-[a-zA-Z]*[rR]|--run)` followed by whitespace, `=`, end-of-string, or a quote. Cannot fold into the shared regex because `-r` is a module-preload flag in ruby and node — generic `r` would false-positive on `ruby -r json` / `node -r dotenv`.

### Tests

- `tests/test_bypass_reproducers.sh` — 3 new categories (4 + 2 + 4 reproducers), plus 8 positive cases protecting legitimate command-position path prefixes, sentinel use with in-project operands, and module-preload flags in ruby/node.
- Full suite: **543 passed / 0 failed.**

### Notes

- All three findings originally surfaced in Copilot review on PR #12. Each closure follows the project's TDD flow: failing reproducer first, then patch, with positive cases against regression.

## [1.4.1] — 2026-04-22

### Fixed — false positives

- **Heredoc-body operators split into pseudo-commands** — `split_and_check` segmented the full `CMD` on `&&` / `||` / `;` / `|` without heredoc awareness, so a quoted-heredoc body line like `X=/etc/x && rm $X` was rotated into two pseudo-commands. The second (`rm $X\nEOF`) lost heredoc context, `blank_quoted_heredoc_bodies` found no opener, and the `$VAR` detector wrongly fired on a byte the parser never expands. Fix: tokenize a heredoc-blanked copy of the command for operator-position detection while preserving original bytes in each subcommand slice. Defensive fallback: if the helper returns a different length than the input, scan the raw `CMD` (preserving original semantics over silent mis-splitting). Surfaced when using `gh pr edit --body-file -` with a body that mentions shell operators alongside `$VAR` examples — exactly the kind of content this guard is documented to allow under `<<'EOF'`.
- **Shell-token word inside heredoc body** — the stdin-redirect-feeds-shell detector tokenized the entire `CMD` including quoted-heredoc body bytes, set `_saw_redir=1` on the opening `<<`, then fired on any later token matching `is_shell_token` / `is_source_token`. So a `git commit -F - <<'EOF'` whose body mentioned the word "bash", "sh", "source" etc. was refused with `"Stdin redirection feeding shell cannot be safely inspected"` even though the parser never executes a single byte of that body. Fix: build a parallel `CMD_TOKENS_EXEC_SCAN` from a heredoc-blanked copy of the command, used ONLY by the `_saw_redir` loop. Genuine shell-stdin attacks (`< /tmp/x bash`, `FOO=1 < /tmp/x bash`, `nice < /tmp/x bash`, `bash <<'EOF' … EOF`, `bash <<<'rm -rf /'`, attached `bash</tmp/x>`) keep firing because the interpreter token sits OUTSIDE any heredoc body and is not blanked.

### Tests

- `tests/test_true_negatives.sh` — 4 positive cases for heredoc-body operators (`&&`, `||`, `;` combined with `$X` / `$1` / `$@`); 3 positive cases for shell-token words in body (`bash`, `sh`, `source`); 3 regression cases for the genuine stdin-redirect attacks (leading redirect, redirect after VAR=val, redirect after wrapper) that the FP fix must not weaken.
- Full suite: **525 passed / 0 failed**.

### Notes

- Both false positives were surfaced inside this same PR while the model used `git commit -F -` per the SessionStart hint — a meta-confirmation that the hint successfully steers Claude toward the fail-closed path.
- No new bypass categories. No API changes. SemVer patch bump from 1.4.0.

## [1.4.0] — 2026-04-22

### Security — closes 2 further bypasses from `codex review --base main`

- **Positional / special parameter expansion (P1)** — the `$VAR` fail-closed scan only matched `$` followed by `[A-Za-z_]` or `{`. Every other shell parameter slipped through, so `set -- /etc/passwd; rm $1` was accepted while bash expanded the path at exec time. The detector now also fires on `$` followed by digit, `@`, `*`, `#`, `?`, `!`, `$`, `-`, catching `$0..$9`, `$@`, `$*`, `$#`, `$?`, `$$`, `$!`, `$-`. Explicit passthroughs added for `$(`, `$'…'`, `$"…"` (not parameter expansion).
- **`truncate` digit-leading filename (P2)** — the size-literal skip regex also matched filenames whose basename started with a digit. In an outside cwd, `truncate -s 0 123.log` zeroed `/tmp/123.log` because the target was skipped as if it were a size. The bare-digit skip is removed; GNU/BSD size values always travel with `-s` (consumed as flag+value pair) or attach as `-sN` / `--size=N` (caught by `-*`). Every remaining non-option token is a file operand.

### Fixed — false positives

- **Quoted / escaped heredoc body** — the `$(…)` / backtick / `$VAR` detector scanned the whole `CMD` and fired on bytes inside `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<-'EOF'` bodies even though bash does not expand them. Canonical auto-memory writes like `cat > memory/note.md <<'EOF' … \`x\` … EOF` were refused despite the allowlisted target. New `blank_quoted_heredoc_bodies` helper neutralises such bodies (preserving byte offsets and newlines) for the expansion detectors only; command-name, path and redirect scans still see the original `CMD`. `CMD_RAW` is snapshot before the alias-escape normalisation so `<<\EOF` is recognised as quoted. Unquoted `<<EOF` bodies and `bash <<'EOF'` / `sh <<\EOF` script-execute remain strict.
- **`sed -i` non-substitute programs** — the script-shape heuristic (`^s[/|,]…[/|,]` or `^[0-9]`) blocked every other valid program, so `sed -i '/debug/d' src/file`, `sed -i '' '/foo/d' file` (BSD), `sed -i.bak '/foo/d' file`, and `sed -i 'y/abc/xyz/' file` were rejected — `/debug/d` looked like an absolute outside path to the validator. Replaced by grammar-aware positional tracking: if no `-e/-f/--expression=/--file=` is present, the first non-flag positional is the script (skipped); every other positional is a file routed to `is_write_permitted`. Regressions covering `-i*` variants targeting `/etc` stay blocked.

### Tests

- `tests/test_bypass_reproducers.sh` — 2 new categories (positional parameters, truncate digit-leading).
- `tests/test_allowlist.sh` — 5 quoted-heredoc positive cases + 4 regressions (unquoted body, shell-stdin-heredoc).
- `tests/test_true_negatives.sh` — sed non-substitute positive cases (pattern-delete, pattern-print, transliterate, BSD empty extension, attached `-i.bak`, explicit `-e`) + blocked regressions; `$VAR` positive cases (ANSI-C quoting, i18n strings, arithmetic, literal `$` in single quotes).
- Full suite: **515 passed / 0 failed**.

## [1.3.0] — 2026-04-22

### Security — closes 8th bypass category + symlink/redirect/wrapper hardening

Addresses 13 rounds of `codex review` findings on top of the 1.2.0 set.

- **Script execution outside project (8th bypass category)** — `bash /tmp/x.sh`, `sh`, `zsh|ksh|dash|fish`, `source`, `.` now refuse paths outside `CLAUDE_PROJECT_DIR`. Covers `env bash …`, `/usr/bin/env …`, `env -i`, `env -u NAME`, `env FOO=1 …`, `sudo -E bash …` (after sudo-strip), `command|builtin|exec bash …`, `nice|nohup|timeout|time|stdbuf|ionice|chrt|taskset` wrappers, shell basename detection for non-standard paths (Homebrew `/opt/homebrew/bin/bash`, Nix, etc.), `bash -O extglob` / `-o pipefail` / `+x` / `+O` flag-with-operand forms, `bash -- script.sh` end-of-options, **and** shell-stdin execution via `<`, `<<`, `<<<`, `<<-`, attached (`bash<file`, `bash<<EOF`), fd-prefixed (`bash 0<file`), fd-duplicate (`bash <&3`), process substitution (`bash < <(cmd)`), leading redirects (`< /tmp/x bash`, `FOO=1 < /tmp/x bash`, `nice < /tmp/x bash`). `env -S` / `--split-string` / `-C` / `--chdir` are fail-closed (hidden command or cwd change).
- **Execute is strict** — writes to an allowlisted path don't grant execute: `bash ~/.claude/projects/*/memory/evil.sh` is blocked even though `Write` on that path is allowed. Prevents the allowlist from becoming an RCE escape hatch.
- **Symlink-pivot through allowlisted dirs** — `is_write_permitted` now dereferences leaf symlinks when the allowlist matches, so `tee memory/link` or `truncate memory/link` with `link -> /etc/passwd` fail closed.
- **Symlink + `..` combined traversal** — `resolve_path` now does physical ancestor canonicalization (`cd -P ... && pwd -P`) and only applies lexical `..` *after* the symlink-free ancestor is known. Previously `memory/linkdir/../owned` with `linkdir -> /etc` could lexically collapse to `memory/owned` and match the allowlist while bash physically wrote to `/`.
- **Intermediate-symlink canonicalization** — `resolve_path` canonicalizes the directory of an existing file-leaf, so `memory/linkdir/passwd` where `linkdir -> /etc` resolves to `/etc/passwd` before the allowlist check (and gets blocked).

### Added — path write-allowlist

`hooks/allowlist.conf` — paths matching its glob patterns bypass the boundary for **write** operations only (`Edit/Write`, `tee`, `curl -o`, `wget -O`, `dd of=`, `sed -i`, `truncate`, `tar -C`, `unzip -d`, `cpio -D`, redirects). Destructive ops (`rm`, `chmod`, `chown`, `mv`, `find -delete`, `cd` + destructive-git, script execute) stay strict regardless of the allowlist.

- Default: `~/.claude/projects/*/memory/**` (Claude Code auto-memory).
- Custom glob-to-regex matcher enforces path-segment semantics: `*` does not match `/`, `**` does, consistent with gitignore conventions. Patterns ending `/**` also match the directory itself.
- `HOME` is resolved with `pwd -P` at load so patterns compare correctly against canonical paths on systems where `/var -> /private/var` (macOS) or similar.
- README documents the feature with a bold **do not mass-add** warning about non-obvious Claude-found workarounds.

### Added — SessionStart hint

`hooks/session_hint.md` — single short paragraph injected into every Claude Code session by a `SessionStart` hook. Steers Claude away from the common fail-closed `git commit -m "$(cat <<EOF)"` idiom toward `git commit -F -` / `git commit -F <file>`. Enforced byte budget (800 B) via `tests/test_session_hint.sh`; discipline rules in `CLAUDE.md`.

### Added

- `tests/test_allowlist.sh` — allowlist positive + negative cases, write-vs-destructive split, HOME isolation via `TMPDIR_BASE`.
- `tests/test_session_hint.sh` — budget guard.
- `CLAUDE.md` — plugin-dev notes (session-hint discipline, allowlist discipline, security-bypass TDD flow).
- `.gitignore` — excludes `.claude/` so workstation-specific permissions don't leak into history.

### Test hermeticity

- Allowlist and script-execute tests now point `HOME` at `$TMPDIR_BASE/fake_home*` so the suite never creates or removes files under the developer's real `~/.claude`.

### Verified

- Test suite: **477 passed, 0 failed**.
- `codex review --uncommitted` iterated 13 times; each finding closed by an added reproducer + fix, not by argument.

## [1.2.0] — 2026-04-21

### Security — closes 7 bypass categories in `hooks/guard.sh`

Each bypass previously let a command reach a path **outside**
`CLAUDE_PROJECT_DIR` while the guard returned exit 0. Every one is
covered by a reproducer in `tests/test_bypass_reproducers.sh` that
flips from FAIL to PASS with this release.

- **Subshell-prefix bypass** — `(rm /etc/x)` / `( rm /etc/x )` no longer
  slip past the destructive-command regexes. Subshell parens are
  stripped at token boundaries; `$(…)` is preserved and still blocked
  by the existing command-substitution rule.
- **Backslash-escape bypass** — `\rm`, `\tee`, etc. are normalized to
  their bare form before detection (backslash only disables alias
  lookup; the binary still runs).
- **Absolute-path bypass** — `/bin/rm`, `/usr/bin/curl -o …`,
  `/usr/local/bin/tee …` are normalized so the regexes see the bare
  command name.
- **Non-shell interpreters** — `python` / `python3` / `perl` / `ruby` /
  `node` / `nodejs` / `deno` / `bun` / `php` / `osascript` / `Rscript`
  with `-c` / `-e` / `-E` / `--eval` / `--execute` are now refused for
  the same reason as `bash -c`: the inline code cannot be inspected.
  `awk` is blocked when its program contains `system(` or a pipe to
  `sh` / `bash`.
- **Variable-indirection bypass** — an unexpanded `$VAR` outside single
  quotes is now fail-closed, mirroring the existing rule for `$(…)`.
  `$HOME` and `${HOME}` remain allowed because `expand_path` resolves
  them.
- **Unlisted destructive tools** — `sed -i` / `--in-place` and
  `truncate` now have dedicated path-argument validators. Option
  values (`-e script`, `-s size`, `-r reference`) are skipped.
- **Redirect through inside-project symlink** — the Bash redirect path
  now follows symlinks with the same readlink loop used by the
  `Edit` / `Write` branch (max depth 20, fail-closed on cycles), so
  `echo x > project/link` where `link -> /etc/passwd` is caught.

### Added

- `tests/test_bypass_reproducers.sh` — 18 tests, one per concrete
  bypass variant, wired into the runner. Future regressions in the
  same categories will fail immediately.

### Verified

- Test suite: **381 passed, 0 failed**.

## [1.1.0] — prior release

- Published `Edit` / `Write` / `MultiEdit` tool guards to the
  marketplace (logic existed earlier, this release made it reach
  installed clients).
- Blocked command substitution (`$(…)`, backticks) outside single
  quotes.
- True-negative test suite for real workflows with spaces in paths.
- Fix: option extractors no longer bypass boundary check on quoted
  paths with spaces.

## [1.0.0] — initial

- `Bash` tool guard covering `rm`, `mv`, `cp`, `ln`, `tee`, `find`,
  `curl`, `wget`, `chmod`, `chown`, `xargs`, redirects, `cd` chaining,
  `bash -c` / `sh -c` / `eval`, piping to shells, destructive `git`
  subcommands outside the project.
