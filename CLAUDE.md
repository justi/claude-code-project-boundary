# project-boundary — plugin development notes

Rules for anyone (Claude included) editing this plugin.

## `hooks/session_hint.md` — context-budget discipline

The contents of `session_hint.md` are `cat`-ed by the SessionStart hook and prepended to **every session's context window** for every user of this plugin. Every byte costs the user tokens forever.

Rules when editing the hint:

1. **Hard budget: 800 bytes of stdout.** Enforced by `tests/test_session_hint.sh`.
2. **One line per quirk.** Prefer the "avoid X, use Y" pattern.
3. **Only add a quirk** if Claude measurably wastes tool calls without it.
4. **Remove obsolete hints** as soon as the underlying guard behavior changes.
5. If you hit the budget, **delete an old hint before adding a new one** — never bump the budget casually.

The test measures `wc -c < session_hint.md` directly.

## `hooks/allowlist.conf` — path-allowlist discipline

Every entry is an escape hatch from the project boundary. See the warning at the top of `allowlist.conf` for the bypass risks. Keep entries narrow, purpose-specific, and comment the reason each one exists.

## Security-bypass TDD flow

When closing a new bypass category in `hooks/guard.sh`, follow this flow strictly, one bypass at a time:

1. **Reproducer first** — add a failing test to `tests/test_bypass_reproducers.sh` (expected: BLOCKED, exit 2).
2. **Confirm bypass exists** — run the suite; new test must FAIL. If it passes immediately, the bypass doesn't exist — stop.
3. **Patch** — modify `hooks/guard.sh`.
4. **Regression** — full `tests/test_guard.sh` must be green.
5. **Positive case** — if the patch is broad, add a test of a legal use that must still PASS, so we don't over-block real workflows.

Don't batch several bypasses into one commit — regression coverage gets muddy.
