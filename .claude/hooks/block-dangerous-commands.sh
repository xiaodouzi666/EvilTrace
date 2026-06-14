#!/usr/bin/env bash
set -euo pipefail

INPUT="$(cat)"
COMMAND="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null || true)"

if printf '%s' "$COMMAND" | grep -E '\b(rm|mv|chmod|chown|dd|mkfs|mount)\b|>\s*(cases|evidence)/|\|\s*(sh|bash)\b' >/dev/null; then
  echo "Blocked: destructive or evidence-mutating command is not allowed by EvilTrace guardrails." >&2
  exit 2
fi

exit 0

