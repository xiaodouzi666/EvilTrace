#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/submission
tar --exclude='.venv' --exclude='.git' --exclude='cases/*' -czf artifacts/submission/eviltrace-submission.tar.gz .
echo "Created artifacts/submission/eviltrace-submission.tar.gz"

