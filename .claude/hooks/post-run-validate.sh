#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
mkdir -p "$PROJECT_DIR/artifacts/logs"

INPUT="$(cat 2>/dev/null || true)"
TOOL_NAME=""
TARGET=""
if command -v jq >/dev/null 2>&1; then
  TOOL_NAME="$(printf '%s' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null || true)"
  TARGET="$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""' 2>/dev/null || true)"
fi

# PostToolUse cannot block (the tool already ran); it records an observation and flags
# any write that landed under the read-only evidence roots so the audit trail is meaningful.
STATUS="observed"
case "$TARGET" in
  cases/*|*/cases/*|evidence/*|*/evidence/*) STATUS="violation_write_under_evidence_root" ;;
esac

printf '{"event_type":"claude_post_tool","timestamp_utc":"%s","tool_name":%s,"target":%s,"status":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$(printf '%s' "$TOOL_NAME" | jq -Rs . 2>/dev/null || printf '""')" \
  "$(printf '%s' "$TARGET" | jq -Rs . 2>/dev/null || printf '""')" \
  "$STATUS" >> "$PROJECT_DIR/artifacts/logs/claude-post-tool.jsonl"

exit 0
