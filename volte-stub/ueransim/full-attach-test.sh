#!/usr/bin/env bash
# One-shot end-to-end test: bring up a virtual gNB + UE, attach to the real
# core, establish PDU sessions for both DNNs, then fire a SIP REGISTER out of
# the "ims" session's own IP straight through the P-CSCF -- the same signaling
# path a real phone would use for VoLTE, minus the phone and the radio.
#
# Requires: ./install.sh and ./render-config.sh already run, and the test
# subscriber provisioned (../scripts/provision_test_subscriber.sh). Must run
# as root (UE needs to create a TUN device).
set -uo pipefail
cd "$(dirname "$0")"
source ./env.sh

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Must run as root (sudo) -- the UE process creates a TUN interface."
    exit 1
fi
if [ ! -f build/gnb.yaml ] || [ ! -f build/ue.yaml ]; then
    echo "[!] Rendered configs missing -- run ./render-config.sh first."
    exit 1
fi

GNB_PID=""
UE_PID=""
cleanup() {
    echo
    echo "[*] Stopping simulated UE/gNB..."
    [ -n "$UE_PID" ] && kill "$UE_PID" 2>/dev/null
    [ -n "$GNB_PID" ] && kill "$GNB_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

mkdir -p build/logs
echo "[1/4] Starting simulated gNB (log: build/logs/gnb.log)..."
./UERANSIM/build/nr-gnb -c build/gnb.yaml > build/logs/gnb.log 2>&1 &
GNB_PID=$!
sleep 2
if ! kill -0 "$GNB_PID" 2>/dev/null; then
    echo "[FAIL] gNB process died immediately. Check build/logs/gnb.log"
    echo "       (common cause: AMF ${AMF_IP}:38412 unreachable/refused)."
    exit 1
fi

echo "[2/4] Starting simulated UE (log: build/logs/ue.log)..."
./UERANSIM/build/nr-ue -c build/ue.yaml > build/logs/ue.log 2>&1 &
UE_PID=$!

echo "[3/4] Waiting for PDU session interfaces (uesimtun0, uesimtun1)..."
IMS_IP=""
for i in $(seq 1 30); do
    if ! kill -0 "$UE_PID" 2>/dev/null; then
        echo "[FAIL] UE process exited. Check build/logs/ue.log"
        echo "       (common causes: subscriber not provisioned in HSS/UDR,"
        echo "        K/OPc mismatch, or PLMN/TAC/slice mismatch with amf.yaml)."
        exit 1
    fi
    if ip addr show uesimtun1 >/dev/null 2>&1; then
        IMS_IP=$(ip -4 addr show uesimtun1 | awk '/inet /{print $2}' | cut -d/ -f1)
        [ -n "$IMS_IP" ] && break
    fi
    sleep 1
done

if [ -z "$IMS_IP" ]; then
    echo "[FAIL] uesimtun1 (the 'ims' DNN session) never came up within 30s."
    echo "       Tail of build/logs/ue.log:"
    tail -n 30 build/logs/ue.log
    exit 1
fi

echo "[OK] 'internet' and 'ims' PDU sessions established."
if ip addr show uesimtun0 >/dev/null 2>&1; then
    DATA_IP=$(ip -4 addr show uesimtun0 | awk '/inet /{print $2}' | cut -d/ -f1)
    echo "     uesimtun0 (${DNN_DATA}) -> ${DATA_IP}"
fi
echo "     uesimtun1 (${DNN_IMS}) -> ${IMS_IP}   <-- this is the VoLTE-carrying session"
echo

echo "[4/4] Sending SIP REGISTER from ${IMS_IP} through P-CSCF ${PCSCF_IP}..."
python3 ../sip/register_test.py \
    --pcscf "$PCSCF_IP" \
    --domain "$IMS_DOMAIN" \
    --impi "${TEST_IMSI}@${IMS_DOMAIN}" \
    --local-ip "$IMS_IP" "$@"
rc=$?

echo
if [ "$rc" -eq 0 ]; then
    echo "=== RESULT: core + IMS signaling path is healthy end-to-end. ==="
    echo "If the real phone still shows no VoLTE icon, the issue is UE-side"
    echo "(APN/IMS settings, carrier config, or AKA credential mismatch)"
    echo "or in the radio path (real gNB/eNB reachability, PLMN selection)."
else
    echo "=== RESULT: something in the core/IMS chain failed -- see above. ==="
fi

echo
echo "Press Ctrl-C to tear down the simulated gNB/UE, or Enter to leave logs and exit."
read -r -t 1 _ || true
exit "$rc"
