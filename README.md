# Project Boundary — Claude Code Plugin

**Scope-aware protection for Claude Code.** Allows destructive operations within your project (refactoring, cleanup) but blocks them outside the project directory.

Built for developers using `dangerouslySkipPermissions` mode who need a safety net without constant permission prompts.

## Why?

Existing safety plugins block destructive commands **everywhere** — which breaks normal refactoring workflows. Project Boundary takes a different approach:

| Operation | Inside project | Outside project |
|-----------|---------------|-----------------|
| `rm file.rb` | Allowed | **Blocked** |
| `rm -rf tmp/` | Allowed | **Blocked** |
| `mv old.rb new.rb` | Allowed | **Blocked** |
| `chmod 755 script.sh` | Allowed | **Blocked** |
| `> config.yml` (redirect) | Allowed | **Blocked** |
| `git push --force` | **Blocked** | **Blocked** |
| `DROP TABLE` | **Blocked** | **Blocked** |
| `rails db:drop` | **Blocked** | **Blocked** |

## Install

### From marketplace (recommended)

```
/plugin install project-boundary
```

### Manual

```
/plugin add /path/to/claude-code-project-boundary
```

## What it blocks

### Always blocked (regardless of location)
- `git push --force` / `-f`
- `git reset --hard`
- `git checkout .` / `git clean -f`
- `DROP TABLE` / `TRUNCATE TABLE`
- `rails db:drop` / `rails db:reset`
- `mkfs`, `dd if=`, `format disk`

### Blocked outside project only
- `rm` / `rm -r` / `rm -rf` — file and directory deletion
- `mv` — moving files to outside project
- `>` redirect — writing to files outside project
- `chmod` / `chown` — changing permissions outside project

## How it works

A lightweight bash PreToolUse hook that:
1. Reads the command from Claude's Bash tool input
2. Checks against always-blocked patterns
3. For file operations (`rm`, `mv`, `chmod`, `chown`, redirects) — resolves target paths and compares against `$CLAUDE_PROJECT_DIR`
4. Blocks with exit code 2 if target is outside project, allows with exit code 0 if inside

No dependencies. No Python. No Node. Just bash + jq.

## Configuration

No configuration needed. The plugin automatically uses `$CLAUDE_PROJECT_DIR` set by Claude Code.

## License

MIT
