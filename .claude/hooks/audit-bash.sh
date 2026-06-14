#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
mkdir -p "$PROJECT_DIR/artifacts/logs"
INPUT="$(cat)"
COMMAND="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null || true)"
printf '{"event_type":"claude_bash_pretool","timestamp_utc":"%s","command":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$(printf '%s' "$COMMAND" | jq -Rs .)" >> "$PROJECT_DIR/artifacts/logs/claude-bash-audit.jsonl"

exit 0

