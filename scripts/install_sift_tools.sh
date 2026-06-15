#!/usr/bin/env bash
#
# install_sift_tools.sh — install the SIFT/forensic tools EvilTrace uses, on Ubuntu/Debian.
#
# SAFETY: this is purely additive. It installs standard packages from the official apt
# repositories (tshark, jq, sleuthkit) plus their library dependencies. It does NOT remove
# any package, modify or restart any existing service, change system configuration (the one
# debconf answer it sets disables non-root packet capture, i.e. the SAFER option), and it
# never touches the EvilTrace repository or any evidence. Reverse with:
#   sudo apt-get remove tshark sleuthkit jq
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: apt-get not found. This script targets Ubuntu/Debian." >&2
  exit 1
fi

PACKAGES="tshark jq sleuthkit"
echo "==> Will install (additive only, from the official apt repos): ${PACKAGES}"
echo "    tshark   -> real PCAP/DNS/HTTP/stream analysis (Wireshark CLI)"
echo "    jq       -> required by the EvilTrace guardrail hooks (they fail closed without it)"
echo "    sleuthkit-> disk tools (mmls/fls/mactime); usually already present"
echo ""

# Preseed: do NOT grant non-root packet capture. EvilTrace only READS pcap files, so the
# more restrictive (safer) setting is correct and also avoids an interactive prompt.
echo "wireshark-common wireshark-common/install-setuid boolean false" | ${SUDO} debconf-set-selections

export DEBIAN_FRONTEND=noninteractive
${SUDO} apt-get update
${SUDO} apt-get install -y ${PACKAGES}

echo ""
echo "==> Verification:"
ok=1
for b in tshark mmls fls mactime jq; do
  if command -v "$b" >/dev/null 2>&1; then
    printf "  %-9s OK   (%s)\n" "$b" "$(command -v "$b")"
  else
    printf "  %-9s MISSING\n" "$b"
    ok=0
  fi
done
echo ""
command -v tshark >/dev/null 2>&1 && tshark -v | head -1 || true
echo ""
if [ "$ok" -eq 1 ]; then
  echo "All required tools are present. EvilTrace will now use real tshark on the bundled PCAP."
  echo "Tell the assistant it's done and it will re-run the sample and regenerate the artifacts."
else
  echo "Some tools are still missing — check the apt output above and re-run this script."
  exit 1
fi
