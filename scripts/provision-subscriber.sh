#!/usr/bin/env bash
#
# Provision one test subscriber on both sides of the stack:
#   1. Open5GS 5GC (IMSI/K/OPc, both "internet" and "ims" DNNs)  -- via open5gs-dbctl
#   2. pyHSS (the IMS-side subscriber + IMPI/IMPU)                -- via its REST API
#
# Usage:
#   sudo provision-subscriber <imsi> <ki> <opc> [msisdn]
#
# <imsi> must fall inside the supi_range already configured in
# /etc/open5gs/pcf.yaml (001010000000001-001019999999999 by default) or the
# voice/video QoS policy won't apply to it.

set -euo pipefail

IMSI="${1:?usage: provision-subscriber <imsi> <ki> <opc> [msisdn]}"
KI="${2:?need Ki}"
OPC="${3:?need OPc}"
MSISDN="${4:-0000000000}"
REALM="ims.mnc001.mcc001.3gppnetwork.org"
PYHSS_API="http://127.0.0.1:8080"

echo "==> Open5GS: adding IMSI $IMSI (internet + ims DNNs)"
open5gs-dbctl add_ue_with_apn "$IMSI" "$KI" "$OPC" internet
open5gs-dbctl update_apn "$IMSI" ims 1

echo "==> pyHSS: adding subscriber + IMS identity"
echo "    (pyHSS's exact API field names can change between versions --"
echo "     if either call below returns a non-2xx status, open"
echo "     ${PYHSS_API}/docs/ in a browser and provision manually through"
echo "     the Swagger UI using the same IMSI/Ki/OPc/MSISDN instead.)"

http_status() { curl -s -o /tmp/pyhss_resp.json -w '%{http_code}' "$@"; }

st=$(http_status -X PUT "${PYHSS_API}/subscriber/" \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -d "{\"imsi\":\"${IMSI}\",\"enabled\":true,\"msisdn\":\"${MSISDN}\"}")
if [[ "$st" != 2* ]]; then
  echo "    !! PUT /subscriber/ returned HTTP $st: $(cat /tmp/pyhss_resp.json)"
  echo "       -> finish this subscriber's base record at ${PYHSS_API}/docs/"
fi

st=$(http_status -X PUT "${PYHSS_API}/auc/" \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -d "{\"imsi\":\"${IMSI}\",\"ki\":\"${KI}\",\"opc\":\"${OPC}\",\"amf\":\"8000\",\"sqn\":0}")
if [[ "$st" != 2* ]]; then
  echo "    !! PUT /auc/ returned HTTP $st: $(cat /tmp/pyhss_resp.json)"
  echo "       -> finish this subscriber's AuC (Ki/OPc) record at ${PYHSS_API}/docs/"
fi

st=$(http_status -X PUT "${PYHSS_API}/ims_subscriber/" \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -d "{\"msisdn\":\"${MSISDN}\",\"msisdn_list\":\"${MSISDN}\",\"imsi\":\"${IMSI}\"}")
if [[ "$st" != 2* ]]; then
  echo "    !! PUT /ims_subscriber/ returned HTTP $st: $(cat /tmp/pyhss_resp.json)"
  echo "       -> finish the IMS (IMPI/IMPU) record at ${PYHSS_API}/docs/"
fi

echo "==> Done. IMS identities for this subscriber:"
echo "    IMPI: ${IMSI}@${REALM}"
echo "    IMPU: sip:${IMSI}@${REALM}"
echo "    Verify all three records at ${PYHSS_API}/docs/ before testing registration."
