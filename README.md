# Project Boundary — Claude Code Plugin

Allows destructive operations **within your project** but blocks them **outside** the project directory. Built for `--dangerously-skip-permissions` mode where Claude doesn't ask — this plugin is your safety net.

## How it differs from existing plugins

- **[claude-code-safety-net](https://github.com/kenryu42/claude-code-safety-net)** — blocks `rm` everywhere; Project Boundary allows it inside the project so refactoring works normally.
- **[destructive-command-guard](https://github.com/Dicklesworthstone/destructive_command_guard)** — only distinguishes `/tmp` vs everything else; Project Boundary uses `$CLAUDE_PROJECT_DIR` as the actual boundary.
- **[claude-code-damage-control](https://github.com/disler/claude-code-damage-control)** — requires manually listing protected paths; Project Boundary automatically protects everything outside the project.

## What it does

### Always blocked (regardless of location)

| Command | Example |
|---------|---------|
| `git push --force` / `-f` | `git push --force origin main` |
| `git reset --hard` | `git reset --hard HEAD~1` |
| `git checkout .` | `git checkout .` |
| `git clean -f` | `git clean -fd` |
| `DROP TABLE` / `TRUNCATE TABLE` | `DROP TABLE users;` |
| `rails db:drop` / `db:reset` | `rails db:drop` |
| `rake db:drop` / `db:reset` | `rake db:drop` |
| `mkfs.*` | `mkfs.ext4 /dev/sda1` |
| `dd if=` | `dd if=/dev/zero of=/dev/sda` |

### Boundary-checked (allowed inside project, blocked outside)

| Operation | Inside project | Outside project |
|-----------|---------------|-----------------|
| `rm`, `rm -rf` | Allowed | **Blocked** |
| `mv` (source and destination) | Allowed | **Blocked** |
| `cp` (source and destination) | Allowed | **Blocked** |
| `ln` (source and target) | Allowed | **Blocked** |
| `chmod` / `chown` | Allowed | **Blocked** |
| `>` / `>>` redirect | Allowed | **Blocked** |
| `tee` / `tee -a` | Allowed | **Blocked** |
| `curl -o` / `curl --output` | Allowed | **Blocked** |
| `wget -O` / `wget --output-document` | Allowed | **Blocked** |
| `find -delete` / `find -exec rm` | Allowed | **Blocked** |

### Always blocked (unsafe to inspect)

| Command | Reason |
|---------|--------|
| `bash -c "..."` / `sh -c "..."` | Nested shell — cannot inspect inner command |
| `eval '...'` | Cannot safely parse evaluated code |
| Piping to `sh` / `bash` | Inner commands invisible to guard |
| `xargs rm/mv/cp/...` | Arguments cannot be validated |

### Additional protections

- **Chained commands** — splits on `;`, `&&`, `||`, `|` and checks each sub-command independently
- **`cd` tracking** — `cd /tmp && rm -rf something` is blocked because `cd` left the project
- **`sudo` prefix** — stripped before checking, so `sudo rm /etc/passwd` is still blocked
- **`find` options** — handles `-L`, `-H`, `-P` before the search path
- **Path traversal** — `..` segments are resolved before boundary check
- **`~` and `$HOME` expansion** — `rm ~/file` and `rm $HOME/file` are correctly detected as outside-project
- **Symlink resolution** — handles macOS `/var` → `/private/var` and similar

### Known limitations

- Paths with spaces in project directory name are not fully supported (space-based argument splitting)
- `$()` subshells and backtick substitution inside arguments are not expanded

## Install

Direct:
```
claude --plugin-dir /path/to/claude-code-project-boundary
```

From marketplace:
```
/plugin marketplace add davepoon/buildwithclaude
/plugin install project-boundary@buildwithclaude
```

## How it works

A pure-bash PreToolUse hook. Splits chained commands, resolves target paths (handling symlinks, `..`, `~`, `$HOME`), and compares against `$CLAUDE_PROJECT_DIR`. Dependencies: bash + jq.

## Testing

```
bash tests/test_guard.sh
```

125 tests covering all guard scenarios. CI runs on Ubuntu and macOS.

## License

MIT
