#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"

# Fail closed: without jq the guardrail cannot parse the tool input, so deny.
if ! command -v jq >/dev/null 2>&1; then
  echo "Blocked: jq is unavailable; the read-only evidence guardrail cannot be evaluated. Install jq." >&2
  exit 2
fi

INPUT="$(cat)"
TARGET="$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""')"

# No path target (or nothing to evaluate) -> nothing to protect here.
[ -z "$TARGET" ] && exit 0

# Resolve to an absolute, normalized path without requiring it to exist.
case "$TARGET" in
  /*) ABS="$TARGET" ;;
  *)  ABS="$PROJECT_DIR/$TARGET" ;;
esac
ABS="$(readlink -m "$ABS" 2>/dev/null || printf '%s' "$ABS")"
ROOT="$(readlink -m "$PROJECT_DIR" 2>/dev/null || printf '%s' "$PROJECT_DIR")"

# Block only when the resolved path is genuinely under the cases/ or evidence/ roots
# (anchored prefix match), so paths like artifacts/showcases/ or src/eviltrace/evidence/
# are NOT false-positives.
for sub in cases evidence; do
  case "$ABS/" in
    "$ROOT/$sub/"*)
      echo "Blocked: $sub/ is read-only evidence. Write only to artifacts/ or docs/." >&2
      exit 2
      ;;
  esac
done

exit 0
