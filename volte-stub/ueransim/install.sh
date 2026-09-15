#!/usr/bin/env bash
# Builds UERANSIM (RF-less 5G gNB+UE simulator) from source next to this
# script. Run this once on the baremetal host, or on any host that has L3
# reachability to the AMF's NGAP address and the UPF's N3/GTP-U address.
#
# UERANSIM talks real NGAP/NAS/GTP-U to your actual AMF/SMF/UPF -- it is not
# a mock. A successful run is as good a proof of core functionality as a
# real gNB, without needing radio hardware or repeatedly involving your phone.
set -euo pipefail
cd "$(dirname "$0")"

if [ -d UERANSIM ]; then
    echo "[*] UERANSIM/ already exists, pulling latest instead of re-cloning"
    (cd UERANSIM && git pull)
else
    git clone --depth 1 https://github.com/aligungr/UERANSIM.git
fi

cd UERANSIM

echo "[*] Checking build dependencies (cmake, make, g++, libsctp-dev)..."
missing=()
for bin in cmake make g++; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "[!] Missing: ${missing[*]}"
    echo "    On Debian/Ubuntu: sudo apt install build-essential cmake libsctp-dev lksctp-tools"
    exit 1
fi

make -j"$(nproc)"

echo
echo "[OK] Built. Binaries are at:"
echo "     $(pwd)/build/nr-gnb"
echo "     $(pwd)/build/nr-ue"
