# Project Boundary — Claude Code Plugin

Allows destructive operations (rm, mv, chmod) **within your project** but blocks them **outside** the project directory. Built for `dangerouslySkipPermissions` mode where Claude doesn't ask — this plugin is your safety net.

## How it differs from existing plugins

- **[claude-code-safety-net](https://github.com/kenryu42/claude-code-safety-net)** — blocks `rm` everywhere; Project Boundary allows it inside the project so refactoring works normally.
- **[destructive-command-guard](https://github.com/Dicklesworthstone/destructive_command_guard)** — only distinguishes `/tmp` vs everything else; Project Boundary uses `$CLAUDE_PROJECT_DIR` as the actual boundary.
- **[claude-code-damage-control](https://github.com/disler/claude-code-damage-control)** — requires manually listing protected paths; Project Boundary automatically protects everything outside the project.

## What it does

| Operation | Inside project | Outside project |
|-----------|---------------|-----------------|
| `rm`, `rm -rf` | Allowed | **Blocked** |
| `mv` | Allowed | **Blocked** |
| `chmod` / `chown` | Allowed | **Blocked** |
| `>` redirect | Allowed | **Blocked** |
| `git push --force` | **Blocked** | **Blocked** |
| `DROP TABLE` | **Blocked** | **Blocked** |
| `rails db:drop` | **Blocked** | **Blocked** |

## Install

```
/plugin add justi/claude-code-project-boundary
```

## How it works

A lightweight bash PreToolUse hook (~70 lines). Resolves target paths and compares against `$CLAUDE_PROJECT_DIR`. No dependencies — just bash + jq.

## License

MIT
