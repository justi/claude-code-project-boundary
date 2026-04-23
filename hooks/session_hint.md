[project-boundary] Guard blocks `$(...)` (fail-closed, uninspectable). For git commit with multiline body, ALWAYS use stdin heredoc:
  git commit -F - <<'EOF'
  <title>

  <body>
  EOF
Do NOT: `git commit -m "$(cat <<EOF)"` (blocked), write to `.git/COMMIT_*` temp files (triggers Write prompt), write to `/tmp/*_msg.txt` (outside-project blocked). The stdin heredoc is the ONE supported path.
