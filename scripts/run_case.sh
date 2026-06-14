#!/usr/bin/env bash
set -euo pipefail

CASE_ID="${1:?case id required}"
CASE_ROOT="${2:?case root required}"
PROFILE="${3:-network-first}"
uv run eviltrace run --case-id "$CASE_ID" --case-root "$CASE_ROOT" --profile "$PROFILE" --max-iterations 5

