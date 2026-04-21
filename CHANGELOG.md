# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
