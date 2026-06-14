#!/usr/bin/env bash
set -euo pipefail

INPUT="$(cat)"
TOOL_NAME="$(printf '%s' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null || true)"
TARGET="$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // .tool_input.command // ""' 2>/dev/null || true)"

case "$TOOL_NAME:$TARGET" in
  *cases/*|*evidence/*)
    echo "Blocked: evidence and case directories are read-only. Write only to artifacts/ or docs/." >&2
    exit 2
    ;;
esac

exit 0

