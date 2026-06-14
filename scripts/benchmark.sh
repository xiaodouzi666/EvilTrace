#!/usr/bin/env bash
set -euo pipefail

uv run eviltrace benchmark \
  --findings artifacts/reports/sample.findings.json \
  --expected data/ground_truth/nitroba.expected.json \
  --output artifacts/benchmarks/sample.benchmark.json

