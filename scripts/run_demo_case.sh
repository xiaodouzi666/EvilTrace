#!/usr/bin/env bash
set -euo pipefail

uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 3

