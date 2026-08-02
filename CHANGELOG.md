# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.11.0] — 2026-08-02

### Added — narrow execute exception for Claude Code skill scripts

- **`.py` / `.sh` helper scripts under `~/.claude/skills/` are now execute-only exempt** from the strict outside-project execute block in `block_shell_script_execution`. Skills that ship helper scripts (e.g. reader-knowledge-audit's `render-report.py`, reader-knowledge-audit-loop-hook's `arm.sh`) were previously unusable from any project other than the one the skill happened to be developed in, since the exec walker has no allowlist by design (an execute-allowlisted write dir would become an RCE escape hatch). The exception is scoped tightly to `~/.claude/skills/**/*.py` and `~/.claude/skills/**/*.sh` and covers execute only — the Write/Edit/MultiEdit hooks still block any write to that path, so nothing new can land there through Claude's own tool calls.

## [1.10.0] — 2026-05-14

### Added — platform & defense-in-depth

- **Windows-smoke CI job** (#29) on `windows-latest` under MSYS2 bash. Runs a minimal end-to-end smoke covering Windows-native path handling (`C:\…`, `C:/…`, UNC `\\server\share`), informational shell flags (`bash --version`, `sh --version`), and the NTFS junction regression anchor.
- **`jq` behaviour canary** at hook entry (#32 hardening). The hook challenges `jq` on every invocation with a randomised key/value JSON object and requires the value echoed back through `.<key>`. A trivial shim (`jq() { echo ""; }`) cannot reproduce a per-call random value, so the parser used to extract `tool_input` is provably real `jq`. Pairs with the existing hard-dep check that fails closed when `jq` is absent.
- **Per-token Windows path rewrite in COMMAND** (#34 / sec 108–110). `tee C:\Windows\…`, `rm C:/Users/x/.ssh/id_rsa`, redirects to drive-letter paths, quoted forms, and UNC `\\server\share\…` are rewritten per-token via `cygpath -u` (MSYS2) before walkers run. On non-MSYS2 shells these shapes fail closed because they don't match the POSIX absolute-path pattern.
- **NTFS reparse-point regression anchor** (#31 close). Junctions and symbolic links inside the project are traversed to their physical target by `cd -P` in `resolve_path` — MSYS2 implements it via Win32 `SetCurrentDirectory` which follows reparse points. Anchored by 3 expect_blocked tests in `tests/test_windows_smoke.sh` (PowerShell `New-Item -ItemType Junction` creation, `fsutil reparsepoint query` confirmation).

### Security — closed bypass categories

- **sec 108 / sec 110 — Windows-native path tokens in Bash COMMAND.** `echo x > C:\Users\foo\test.txt`, quoted forms (`tee 'C:\…'`, `tee "C:/…"`), and forward-slash drive paths slipped past walkers because the POSIX `[[ != /* ]]` test treated them as relative. Per-token cygpath rewrite at the COMMAND-token boundary (commit `1ac00ae`) covers all attached and quoted shapes.
- **sec 109 — `file_path` drive-relative and `file://` URI.** Edit / Write / MultiEdit input `C:foo` (drive-relative without slash) and `file:///etc/passwd` no longer slip past the normalization branch. The drive-relative shape carries an accepted false-positive risk for POSIX files literally named `c:something` — rare in practice.
- **sec 111 — `-V` flag whitelist removed from pipe-to-shell.** The informational-flag whitelist that exempts `--help` / `--version` was too generous: `-V` is a real subcommand verb on tools that take piped script input. Codex sweep 4 #1.
- **sec 112 — `extract_option_values` attached short `-X<val>`.** The library helper matched `-X VAL` (split short) and `--long=VAL` (attached long) but missed `-X<val>` (attached short), so any walker delegating to it lost coverage for that shape. Cross-tool fix in `hooks/lib/options.sh`.
- **sec 113 — install / rsync / unzip / cpio walkers read `CMD_BLANKED`** (#20). Quoted heredoc bodies mentioning a write-flag (`<<'EOF' … unzip x -d /etc/dst … EOF`) false-positived because the walkers grep'd raw `CMD`. Switching to `CMD_BLANKED` / `CMD_TOKENS_SCAN` (heredoc-body wiped) mirrors the sec 99 fix shape used for rm/tee.
- **sec 114 — `install -t<dir>` attached short bypass** (Codex sweep 5 Q4). The install walker's in-line flag-skip loop discarded every `-*` token except `--target-directory=`; `install -t/tmp src dst` fell into the generic skip branch and never reached the boundary check.

### Tests & quality

- **Anti-facade skill v2.1.0 dogfooded.** F10 empirical execution requirement (run `git stash` + test, capture exit code) caught a candidate fix (sec 115 — NTFS reparse-point bypass) defending against a non-existing bypass. Pre-fix CI run on the revert branch demonstrated all 3 junction expect_blocked assertions already PASS — protection comes from `cd -P` in `resolve_path`, not from the proposed helper. Fix reverted (commit `8c2cecc`), tests kept as regression-anchor, lesson recorded in the skill's missed-bug log.
- **External Codex verification** of the sec 112–114 cluster surfaced 2 LOW findings the in-session audit missed: coverage gap in tar/zip heredoc-body tests (closed in `2ab4c75`) and structural parallel-walker maintenance risk in install/rsync (logged, not exploitable).
- Suite total: **1583 / 1583 green** on Linux/macOS (up from 1444 baseline → +139); windows-smoke job **15 / 15 green** (12 baseline → +3 junction).
- Issue #30 (lib/paths.sh + tokenize.sh Windows path-shape audit) closed as won't fix — design choice is "validate at the entry boundary"; helpers fail-closed on garbage paths.

## [1.9.0] — 2026-05-03

### Fixed — closes issue #21 (remote-dispatch false positives)

- **`ssh "<remote-cmd>"` no longer false-positives.** The local-path walkers (cp / tee / rm / redirect / …) used to match the literal command bytes inside the quoted argument, so workflows like `ssh host "docker cp /tmp/x container:/y && docker exec c bin/rails runner /tmp/x"` returned `BLOCKED: 'cp' argument '/private/tmp/x' is OUTSIDE …`. Generic neutralisation in `hooks/lib/remote_dispatch.sh` rewrites recognised remote-dispatch verbs before the walkers run, so only the **local** surface is policed.
- Three universal shapes covered:
  - **Network-copy tools** — `scp` / `rcp` / `sftp`. Operands of the universal `<host>:<path>` / `<host>::<module>` / `rsync://…` form are no longer walked as local paths.
  - **Remote-command dispatch** — `ssh`, `docker exec`, `podman exec`, `kubectl exec`, `oc exec`, `crictl exec`, `lxc exec`. The trailing command string runs on a foreign filesystem; collapsing CMD to the verb prefix removes the false positive while keeping all earlier policy checks (`bash -c`, `$VAR`, `$(...)`, heredoc-fed shell, script execution) untouched — those still fire on the original CMD because they happen LOCALLY before ssh / docker ever sees the argument string.
  - **Remote file copy with mixed operands** — `docker cp`, `podman cp`, `kubectl cp`, `oc cp`. The rewrite preserves the local DESTINATION operand (last positional, when not remote-shaped) so the cp walker still catches downloads to `/etc/owned`. Source operands are dropped — local source is a read (not policed), remote source is a foreign filesystem.

### Hardening — Copilot review follow-ups on PR #22

- **`nsenter` / `chroot` deliberately NOT in the dispatch list.** Both execute on the local host (different namespace / apparent root), so their command operands can still touch host paths outside the project. Collapsing them would have been a security regression: `chroot / rm -rf /etc` would no longer block. Round-1 fix on Copilot review removed them.
- **`docker run` / `podman run` / `buildah run` deliberately NOT in the dispatch list either.** The `-v src:dst` / `--volume` / `--mount type=bind,…` flags can bind-mount host paths into the container, turning a container-side write into a host-fs write. With CMD collapsed, `docker run -v /tmp:/data alpine tee /data/x.md` would silently write host `/tmp/x.md`. Pending host-mount-source parsing in a follow-up — until then, leaving them subject to the existing walkers errs on the safe side.
- **`kubectl cp` / `oc cp` flag-value bypass closed.** cobra/pflag lets flags appear before AND after positionals, so `kubectl cp pod:/x /etc/owned --namespace default` slipped past the previous walker (the value `default` became the last positional, rewrite emitted `cp default` → resolved inside project → ALLOWED, while the real download destination `/etc/owned` was never validated). Round-2 fix added a per-verb table of flags that consume the next token (short + long forms, including POSIX `--` end-of-options and `--flag=value` attached form). Regression tests pin every shape of the bypass.

### Tests

- 39 new cases across `tests/test_true_negatives.sh` covering each remote-dispatch verb plus the 3 sub-classes (collapse / remote-only / cp-positional). 4 lock tests confirm chained `scp ./x remote-host:/y && rm -rf /etc/foo` keeps blocking the local rm; 7 regression tests for `kubectl cp` / `oc cp` flag-value layouts (leading, trailing, attached, short flag, POSIX `--`).
- Suite total: **873 / 873 green** (was 834 baseline → +39).

## [1.8.0] — 2026-04-27

### Security — closes 3 bypass categories in `install` / `rsync` walkers

- **A. `install` POSIX double-dash bypass** — the `install` walker treated `--` as just another flag-looking token and walked past it, so a quoted `"--"` (or even bare `--`) followed by an outside-project target slipped through. Reproducers added first (`c571b91`), fix in `b460e57`: detect end-of-options and validate the next operand against the project boundary like any other write target.
- **B. `rsync` POSIX double-dash bypass** — same shape as A in the `rsync` walker (`d8c40c1` reproducers, `5b11dbe` fix). The follow-up `ce011af` strips surrounding quotes before the `--` test in both walkers so `"--"` and `'--'` cannot smuggle the marker past the comparison.
- **C. `install` mode/user_group flag-skip bypass** — the walker's flag-skip logic for `-m MODE` / `-o OWNER` / `-g GROUP` consumed the *next* token without validating it, so an attacker could feed an outside-project path as the "value" and the real target after it was never scanned. Reproducers in `f34fb48`, fix in `bab3ffe`.

### Hardening — Codex review follow-ups on the C-class fix

- **Surgical flag-skip with quote-aware comparison** (`bb9e2c3`, `f76ec34`) — the iteration on top of the C-class fix went through two extremes before settling: `ce011af` ran every flag test on the strip_quotes view (P1: quoted attached path-options like `"--target-directory=/tmp/out"` were also stripped of their `--` and treated as non-flags); `bb9e2c3` reverted the flag-skip to the raw token (P2: quoted plain flags like `"--help"` and `"--mode" 0755 src dst` were misread as pathname operands and blocked from outside cwd). The settled shape (`f76ec34`) keeps the strip_quotes view for both the `--` terminator test and the `-*` flag-skip, and routes attached `--name=PATH` values through path validation when (and only when) `name` is on the write-target white-list (see next bullet). Mode/owner/group VALUES are deliberately not path-validated — `--mode=`, `--owner=`, `--group=`, `-mPATH`, etc. are skipped as ordinary flags.
- **Replace `=/` heuristic with explicit write-target option white-list** (`00d7300`) — the prior heuristic treated *any* `--name=value` starting with `/` as a write target, producing false positives on read-only options that happen to take an absolute path. Replaced with an explicit white-list of rsync/install options that actually write.
- **Add rsync batch-file write options to white-list** (`8141400`) — Codex flagged that `--write-batch=FILE` and `--only-write-batch=FILE` were missing from the white-list; both write to disk and now block when the target is outside the project.

### Refactor

- **`hooks/guard.sh` — decompose `check_single_command` into detector clusters** (#16, `6a7779e`). No behavior change; smaller functions per detector family make the next bypass closure easier to land surgically.
- **`hooks/guard.sh` — extract tokenize / command_name / paths / heredoc modules** (#15, `38cdde0`).
- **`tests/test_bypass_reproducers.sh` split into core + recent** (`c4a70e0`) — the file had grown past 1000 lines; splitting keeps the suite readable and lets new reproducers land without churning the whole file.

### Tests

- New reproducers across `tests/test_bypass_reproducers_recent.sh` for each of the 3 closures (each FAILED first, per the project TDD flow). Section 27 added in the Copilot follow-up commit pins the attached-flag behavior contract (short / long / quoted forms for `-m`/`-o`/`-g`, and the explicit "no path-validation for mode/owner/group VALUES" rule) so future doc drift is caught by the suite, not just by review.
- `tests/test_true_negatives.sh` extended with positive cases for legitimate flag-attached paths and quoted operands.
- `tests/test_bash_advanced.sh` §50 added documenting the `$VAR` / `${VAR}` fail-closed contract (BLOCKED: bare, braced, positional, special parameters; ALLOWED: `$HOME` passthrough, ANSI-C `$'…'`, i18n `$"…"`, backslash-escaped, single-quoted, quoted-heredoc body).
- Full suite: **821 passed / 0 failed.**

### Notes

- All three closures follow `CLAUDE.md §Security-bypass TDD flow`: one bypass per commit, reproducer FAILS first, then the patch. Codex review on each commit drove the four hardening follow-ups above; each is its own commit so regression bisect stays clean.

## [1.7.0] — 2026-04-23

### Security — closes 3 bypass categories from Codex review on commit e01df86

- **A. Path-prefix strip on operands (not just command-name)** — the v1.5.0 narrowing of the `/bin/` strip matched "command position OR after a non-redirect, non-pipe, non-separator character". The second clause looked only at the immediately preceding character, which for ordinary operands is just the trailing letter of the previous token. So `rm /bin/sh`, `tee /bin/owned`, `mv x /sbin/owned`, `curl -o /bin/owned`, `ln -sf x /usr/local/bin/owned` all had their outside-system path rewritten to a bare leaf which then resolved into `EFFECTIVE_CWD/leaf` — passing the boundary while bash itself hit the original system path. Replaced the second sed pass with `strip_command_name_prefix`, a tokenize-aware helper that walks past sudo/env/nice/nohup/time/stdbuf/ionice/chrt/taskset/command/builtin/exec, VAR=val assignments, flags, and `timeout`'s numeric duration, then strips the prefix from the next "real" token only. Operand and redirect-target tokens are preserved verbatim. Wrapper combinations (`nice /bin/rm`, `timeout 5 /bin/rm`, `env /bin/rm`, `env FOO=bar /bin/rm`, `nohup /bin/curl -o`) all stay BLOCKED with regression coverage.
- **B. Heredoc-delimiter parser stops at hyphen / dot** — the blanking helper parsed the heredoc delimiter using `[A-Za-z0-9_]`, which rejects characters that bash itself allows in a word. For backslash-escaped or unquoted delimiters containing a hyphen / dot / etc. (`<<\EOF-1`, `<<EOF.1`, `<<-\TAG-X`), the parser captured only the leading run, never matched the real terminator, and overblanked the rest of CMD — including any LIVE command that bash would actually execute after the real terminator. Widened the char class to `[A-Za-z0-9_.+:=,/@%^-]` so the parser walks the same characters bash treats as a word. Quoted forms (`<<'TAG'`, `<<"TAG"`) were unaffected.
- **C. Newline as command separator ignored by `split_and_check`** — bash treats a newline outside quotes as a command terminator equivalent to `;`, but the splitter only recognised `&&`, `||`, `;`, `|`. A multi-line command like `echo ok\nbash /tmp/evil.sh` reached every "first-token" detector as a single subcommand named `echo`, hiding the script-execute on the second line. Added newline to the operator set. Two helper changes preserve the body-aware FP coverage from v1.4.1 / v1.5.1 / v1.6.0: (1) `blank_quoted_heredoc_bodies` grew an optional `blank_newlines` argument that also blanks newlines inside quoted-heredoc bodies; (2) in that mode, the body range extends one byte backward to subsume the newline that ENDS the heredoc opener line — that newline is syntactic line-terminator for the opener, not a command separator and not a body byte either. `split_and_check` passes `blank_newlines`; every other call site keeps the default preserve mode so byte offsets used by the expansion-detector stay aligned with their line-based scanner.

### Tests

- `tests/test_bypass_reproducers.sh` — 6 reproducers for A (operand strip across rm/tee/mv/ln/curl/sed paths), 3 for B (backslash + hyphen, redirect after such heredoc, indented backslash + hyphen), 3 for C (script-execute on second line, source on second line, `/bin/bash` on second line). 11 positive cases covering legitimate command-position prefix use, benign hyphenated delimiter, ordinary multi-line in-project sequences, quoted-heredoc bodies with newlines, and 5 wrapper + `/bin/<cmd>` regression cases.
- Full suite: **589 passed / 0 failed.**

### Notes

- All three findings come from Codex review on commit e01df86. Each closure follows the project TDD flow: failing reproducer commit first, then fix commit. Codex's POC for B included an additional `cat <<\EOF-1\nbody\nEOF-1\nrm /bin/sh` that combines B and A; the chained POC stays BLOCKED after this release.

## [1.6.0] — 2026-04-23

### Security — closes write-through-inside-project-symlink bypass (Copilot review on PR #12)

- **`is_write_permitted` returned true for inside-project symlinks pointing outside** — the function checked `is_inside_project` on the lexical path with no leaf dereference. Every Bash-side write detector (`tee`, `sed -i`, `truncate`, `curl -o`, `wget -O`, `dd of=`) called `is_write_permitted` directly, so a symlink that lived inside the project but pointed outside was treated as in-project and the write landed at the outside target. Concrete shape: create an inside-project symlink to `/etc/passwd_test`, then any of the six tools writing to that symlink ended up writing to `/etc/passwd_test`.
- **Fix**: moved the leaf-dereference loop to the top of `is_write_permitted` (single source of truth). The inside-project and allowlist checks now both operate on the canonicalised OS-level path. The Edit/Write tool branch already derefed upstream; this brings Bash-side paths to parity. Fail-closed on circular / too-deep chains preserved (depth-20 cap, post-loop `-L` check). Allowlist branch's previously-needed inner deref loop is now redundant and removed.

### Fixed — false positive (backslash-escaped heredoc delimiter)

- **`<<\EOF` body bytes leaked into file/redirect detectors** — the alias-escape pass that strips `\` before any letter (so `\rm` → `rm`) also turned `<<\EOF` into `<<EOF`, downgrading a backslash-escaped (= quoted) heredoc delimiter to its unquoted twin. `blank_quoted_heredoc_bodies` then saw an unquoted heredoc and refused to blank the body, so the file/redirect walkers parsed body bytes as live commands. Every false positive closed in v1.4.1 / v1.5.1 reappeared for the backslash-escaped form.
- **Fix**: build `CMD_BLANKED` from `CMD_RAW` (before normalisation), then re-apply the normalisation passes on the blanked view. Body bytes are spaces by the time the alias-escape strip runs, so it cannot leak through them; live command-line forms (`\rm`, subshell parens, `/bin/` prefixes) are still recognised by downstream detectors. Brings the file/redirect scan view to parity with `CMD_EXPAND_SCAN`, which has been correctly sourced from `CMD_RAW` since v1.4.1.

### Tests

- `tests/test_bypass_reproducers.sh` — 6 reproducers for the symlink-write bypass (one per affected tool), 2 positive cases (regular in-project file, symlink resolving to in-project target).
- `tests/test_true_negatives.sh` — 4 positive cases for backslash-escaped heredoc bodies (commit message mentioning `sed -i`, `> /etc/passwd`, `$1`, indented `<<-\EOF`).
- Full suite: **565 passed / 0 failed.**

### Notes

- All findings from Copilot review on commit 7641a412. Each closure follows the project TDD flow: failing reproducer commit first, then fix commit.

## [1.5.1] — 2026-04-23

### Fixed — false positives (file walkers + redirect-target scanner)

- **File walkers and redirect scanner parsed heredoc body bytes** — same root cause class as the two FPs already fixed in v1.4.1. Three more body-blind detectors (`sed -i` walker, `truncate` walker, redirect-target scanner) walked `CMD_TOKENS` directly. A `git commit -F - <<'EOF' ... EOF` body that happened to mention an example command like `sed -i 's/a/b/' /etc/foo`, `truncate -s 0 /etc/log`, or `> /bin/owned` was parsed as if it were a real call, and the commit was refused with an outside-project block. Repeatedly hit during the v1.5.0 audit cycle while writing the audit's own commit messages.

### Implementation — symmetric fix shape, completed

Built a parallel token stream `CMD_TOKENS_SCAN` from a heredoc-blanked copy of the command (via the existing `blank_quoted_heredoc_bodies` helper, which preserves byte offsets so tokenization stays aligned). Routed all three remaining body-blind detectors through it: entry greps use `CMD_BLANKED`, all walks use `CMD_TOKENS_SCAN`. After this release, every body-walking detector goes through a heredoc-aware view — completing the symmetric fix started in v1.4.1.

### Tests

- `tests/test_true_negatives.sh` — 4 positive cases (commit body mentioning `sed -i`, `truncate`, `> /bin/owned`, and a redirect inside a quoted heredoc body); 4 regression cases for the corresponding genuine attacks (real outside-path edits, real redirects, unquoted heredoc opener with outside target) — all must stay BLOCKED.
- Full suite: **551 passed / 0 failed.**

### Notes

- No new bypass categories. No API changes. SemVer patch bump from 1.5.0.

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
