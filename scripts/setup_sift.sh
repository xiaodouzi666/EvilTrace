#!/usr/bin/env bash
set -euo pipefail

echo "Install SIFT Workstation or run this project inside an existing SIFT-compatible Ubuntu environment."
echo "Required: jq (the Claude Code guardrail hooks fail closed without it)."
echo "Optional for full forensic functionality: tshark, sleuthkit (mmls/fls/mactime), evtx_dump, reglookup, volatility3."
echo "On Debian/Ubuntu: sudo apt-get install -y jq tshark sleuthkit"

