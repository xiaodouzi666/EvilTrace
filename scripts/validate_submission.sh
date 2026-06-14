#!/usr/bin/env bash
set -euo pipefail

fail=0

check_file() {
  local path="$1"
  local label="$2"
  if [[ -f "$path" ]]; then
    echo "PASS: $label -> $path"
  else
    echo "FAIL: $label -> $path"
    fail=1
  fi
}

check_dir_nonempty() {
  local path="$1"
  local label="$2"
  if [[ -d "$path" ]] && [[ "$(find "$path" -type f | wc -l)" -gt 0 ]]; then
    echo "PASS: $label -> $path"
  else
    echo "FAIL: $label -> $path"
    fail=1
  fi
}

check_file "LICENSE" "MIT or Apache license"
check_file "README.md" "README"
check_file "docs/architecture.md" "Architecture diagram doc"
check_file "docs/project-story.md" "Written project description"
check_file "docs/dataset-documentation.md" "Dataset documentation"
check_file "docs/accuracy-report.md" "Accuracy report"
check_file "docs/try-it-out.md" "Try-it-out instructions"
check_file "docs/demo-video.md" "Demo video link"
check_dir_nonempty "artifacts/logs" "Agent execution logs"
check_dir_nonempty "artifacts/reports" "Sample reports"

if ! grep -Ei "MIT License|Apache License" LICENSE >/dev/null; then
  echo "FAIL: LICENSE is not MIT or Apache-like"
  fail=1
else
  echo "PASS: LICENSE text"
fi

if ! grep -q "Competition Compliance Map" README.md; then
  echo "FAIL: README missing compliance map"
  fail=1
else
  echo "PASS: README compliance map"
fi

exit "$fail"

