#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
mkdir -p "$PROJECT_DIR/artifacts/logs"
printf '{"event_type":"claude_post_tool","timestamp_utc":"%s","status":"observed"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$PROJECT_DIR/artifacts/logs/claude-post-tool.jsonl"

exit 0

