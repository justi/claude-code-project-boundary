# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
