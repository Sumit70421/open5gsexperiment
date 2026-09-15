#!/usr/bin/env bash
# Starts the simulated UE against build/ue.yaml. Requires the gNB (run-gnb.sh)
# to already be running. Needs root (creates a uesimtun* TUN interface).
#
# On success you'll see two PDU sessions come up and two interfaces appear:
#   uesimtun0 -> the "internet" DNN
#   uesimtun1 -> the "ims" DNN      <-- this is the one a real phone uses for
#                                        VoLTE/IMS SIP signaling; if this session
#                                        establishes, your NAS/PDU-session/PCF
#                                        path for VoLTE is working.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f build/ue.yaml ]; then
    echo "[!] build/ue.yaml not found -- run ./render-config.sh first"
    exit 1
fi
if [ ! -x UERANSIM/build/nr-ue ]; then
    echo "[!] UERANSIM not built -- run ./install.sh first"
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Needs root to create the TUN interface -- re-run with sudo"
    exit 1
fi

exec ./UERANSIM/build/nr-ue -c build/ue.yaml
