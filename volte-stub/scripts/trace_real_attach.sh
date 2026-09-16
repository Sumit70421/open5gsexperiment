#!/usr/bin/env bash
# Live, multiplexed log tail across every layer a real UE attach touches --
# run this ON THE CORE HOST, start it FIRST, then power on / reattach the
# real phone through the real gNB. Every line printed is prefixed with which
# component it came from, so you can read top-to-bottom and see exactly
# where the flow stops: NGAP/NAS attach (AMF) -> PDU session + PCO (SMF) ->
# user plane (UPF) -> SIP (P-CSCF/I-CSCF/S-CSCF).
#
# Why this matters for "nothing shows up on P-CSCF": there is no persistent
# SMF<->P-CSCF connection to test. SMF's p-cscf address is a static value it
# stuffs into the PCO of the PDU Session Establishment Accept ONLY when a UE
# successfully establishes a session on the 'ims' DNN. If the real UE never
# requests that DNN (common on commercial phones without carrier IMS/APN
# config pushed to them), P-CSCF will never see anything -- correctly, not
# as a bug. This script lets you see, per real attach attempt, whether the
# UE ever asked for 'ims' at all, and if so what SMF/UPF/P-CSCF each did
# with it.
#
# Ctrl-C stops all tails cleanly.
set -uo pipefail

OPEN5GS_LOG_DIR="${OPEN5GS_LOG_DIR:-/var/log/open5gs}"

PIDS=()
cleanup() {
    echo
    echo "[*] Stopping trace..."
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

tail_file() {
    local label="$1" path="$2"
    if [ -r "$path" ]; then
        tail -n0 -F "$path" 2>/dev/null | sed -u "s/^/[${label}] /" &
        PIDS+=("$!")
    else
        echo "[!] Can't read $path for [$label] -- skipping (wrong path? run as root/sudo?)"
    fi
}

tail_unit() {
    local label="$1" unit="$2"
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        journalctl -u "$unit" -f -n0 --no-pager 2>/dev/null | sed -u "s/^/[${label}] /" &
        PIDS+=("$!")
    else
        echo "[!] systemd unit '$unit' not active -- skipping [$label]"
    fi
}

echo "=========================================================================="
echo " Tracing AMF / SMF / UPF / P-CSCF / I-CSCF / S-CSCF."
echo " Now power on / trigger reattach on the REAL phone via the real gNB."
echo " Watch for, in order:"
echo "   [AMF]    NGAP Initial UE Message / Registration -- does the phone even"
echo "            reach the AMF at all?"
echo "   [SMF]    PDU Session Establishment for dnn=ims -- does the phone ever"
echo "            REQUEST the ims DNN? If this never appears, the phone isn't"
echo "            asking for it -- check its APN/carrier IMS config, not the core."
echo "   [UPF]    PFCP session establishment for the ims session's UE IP."
echo "   [PCSCF]  Should see a SIP REGISTER arrive the moment the UE has its"
echo "            ims PDU session and PCO-delivered P-CSCF address."
echo "   [ICSCF]/[SCSCF] follow the same REGISTER onward, same as register_test.py"
echo "            already proved works when it reaches them."
echo " Ctrl-C to stop."
echo "=========================================================================="
echo

tail_file  "AMF"   "${OPEN5GS_LOG_DIR}/amf.log"
tail_file  "SMF"   "${OPEN5GS_LOG_DIR}/smf.log"
tail_file  "UPF"   "${OPEN5GS_LOG_DIR}/upf.log"
tail_unit  "PCSCF"  "kamailio_pcscf"
tail_unit  "ICSCF"  "kamailio_icscf"
tail_unit  "SCSCF"  "kamailio_scscf"

wait
