#!/bin/bash
# Enforces the session_hint.md byte budget. This file's contents are
# `cat`-ed by the SessionStart hook and prepended to every session's
# context window — so it must stay small.
# Sourced by test_guard.sh — requires helpers.sh loaded first.

echo "========================================"
echo "  SessionStart hint budget"
echo "========================================"
echo ""

HINT_FILE="$SCRIPT_DIR/../hooks/session_hint.md"
BUDGET=800  # bytes

TOTAL=$((TOTAL + 1))
if [ ! -f "$HINT_FILE" ]; then
  echo "FAIL: session_hint.md missing at $HINT_FILE"
  FAIL=$((FAIL + 1))
else
  echo "PASS: session_hint.md present"
  PASS=$((PASS + 1))

  TOTAL=$((TOTAL + 1))
  hint_bytes=$(wc -c < "$HINT_FILE" | tr -d ' ')
  if [ "$hint_bytes" -le "$BUDGET" ]; then
    echo "PASS: session hint size $hint_bytes bytes <= $BUDGET budget"
    PASS=$((PASS + 1))
  else
    echo "FAIL: session hint size $hint_bytes bytes > $BUDGET budget — trim before adding more quirks"
    FAIL=$((FAIL + 1))
  fi
fi
