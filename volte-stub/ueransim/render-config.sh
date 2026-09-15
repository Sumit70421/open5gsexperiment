#!/usr/bin/env bash
# Renders gnb.yaml.tmpl / ue.yaml.tmpl into build/gnb.yaml + build/ue.yaml
# using the values in env.sh (override any of them via environment variables
# before running, e.g. `GNB_IP=10.0.0.5 ./render-config.sh`).
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

mkdir -p build

render() {
    local src="$1" dst="$2"
    sed \
        -e "s|__AMF_IP__|${AMF_IP}|g" \
        -e "s|__MCC__|${MCC}|g" \
        -e "s|__MNC__|${MNC}|g" \
        -e "s|__TAC__|${TAC}|g" \
        -e "s|__SST__|${SST}|g" \
        -e "s|__SD__|${SD}|g" \
        -e "s|__DNN_DATA__|${DNN_DATA}|g" \
        -e "s|__DNN_IMS__|${DNN_IMS}|g" \
        -e "s|__GNB_IP__|${GNB_IP}|g" \
        -e "s|__TEST_IMSI__|${TEST_IMSI}|g" \
        -e "s|__TEST_KEY__|${TEST_KEY}|g" \
        -e "s|__TEST_OPC__|${TEST_OPC}|g" \
        "$src" > "$dst"
}

render gnb.yaml.tmpl build/gnb.yaml
render ue.yaml.tmpl build/ue.yaml

echo "[*] Rendered build/gnb.yaml and build/ue.yaml"
echo "    gNB will bind ${GNB_IP} and connect to AMF ${AMF_IP}:38412"
echo "    UE will attach as imsi-${TEST_IMSI}, requesting DNNs: ${DNN_DATA}, ${DNN_IMS}"
