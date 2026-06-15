#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
EvilTrace targets the SANS SIFT Workstation (Ubuntu 22.04, system Python 3.10).
tshark, sleuthkit (mmls/fls/mactime), jq, and Volatility 3 (vol) are native on SIFT.

Three ways to get a SIFT environment:

1) Prebuilt VM appliance (easiest): download the SIFT OVA (~8.8 GB) from
   https://www.sans.org/tools/sift-workstation and boot it (VirtualBox/VMware).
   Headless server? Import + run with no GUI:
     VBoxManage import sift.ova --vsys 0 --vmname SIFT --eula accept
     VBoxManage startvm SIFT --type=headless     # access via SSH

2) Install the SIFT toolset onto an existing Ubuntu 22.04 (incl. headless), CLI-only:
     sudo dpkg -i cast-v1.0.19-linux-amd64.deb    # the cast .deb in this repo
     sudo cast install --mode=server teamdfir/sift-saltstack
   NOTE: cast does a system-wide, root apt install (adds the SIFT PPA, many packages).
   Prefer a dedicated/fresh Ubuntu host or a snapshot first; it is not isolated.

3) Just the few tools EvilTrace's bundled demo needs, on this machine:
     bash scripts/install_sift_tools.sh           # installs tshark, jq, sleuthkit

Then run EvilTrace (uv is NOT on SIFT, use pip):
   python3 -m venv .venv && . .venv/bin/activate && pip install -e .[dev]
   eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 3
EOF

