#!/usr/bin/env bash
set -euo pipefail

# Fail closed: without jq the guardrail cannot parse the command, so deny.
if ! command -v jq >/dev/null 2>&1; then
  echo "Blocked: jq is unavailable; the dangerous-command guardrail cannot be evaluated. Install jq." >&2
  exit 2
fi

INPUT="$(cat)"
COMMAND="$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""')"

[ -z "$COMMAND" ] && exit 0

# Defense-in-depth denylist for raw Bash. (The MCP tool layer is the primary control:
# it exposes only allowlisted read-only forensic binaries and routes every write through
# ensure_write_path.) This blocks: destructive primitives; copy/move/tee/redirect into the
# evidence roots; image rewrites; ownership/permission changes; writable/remount mounts;
# find -delete; and piping into a shell. read-only `mount ... -o ro` is intentionally allowed.
if printf '%s' "$COMMAND" | grep -Eq \
  '\b(rm|shred|truncate)\b|\bdd\b|\bmkfs(\.[A-Za-z0-9]+)?\b|\bchmod\b|\bchown\b|\bmount\b[^|]*\b(rw|remount)\b|\b(mv|cp|install|tee)\b[^|]*\b(cases|evidence)/|\bfind\b[^|]*-delete|>>?[[:space:]]*(cases|evidence)/|\|[[:space:]]*(sh|bash)\b'; then
  echo "Blocked: destructive or evidence-mutating command is not allowed by EvilTrace guardrails." >&2
  exit 2
fi

exit 0
