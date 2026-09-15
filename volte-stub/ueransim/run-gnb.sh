#!/usr/bin/env bash
# Starts the simulated gNB against build/gnb.yaml. Run render-config.sh first
# (and install.sh once, beforehand). Leave this running in its own terminal,
# then run run-ue.sh in another one.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f build/gnb.yaml ]; then
    echo "[!] build/gnb.yaml not found -- run ./render-config.sh first"
    exit 1
fi
if [ ! -x UERANSIM/build/nr-gnb ]; then
    echo "[!] UERANSIM not built -- run ./install.sh first"
    exit 1
fi

exec ./UERANSIM/build/nr-gnb -c build/gnb.yaml
