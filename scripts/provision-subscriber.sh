#!/usr/bin/env bash
#
# Provision one subscriber on BOTH sides of the stack in one command -- this
# is the only step needed before that IMSI can register and place an
# audio/video call; nothing else needs touching by hand:
#   1. Open5GS 5GC (IMSI/K/OPc, both "internet" and "ims" DNNs) -- via open5gs-dbctl
#   2. pyHSS: AUC (Ki/OPc/AMF/SQN) + SUBSCRIBER + IMS_SUBSCRIBER    -- via its REST API
#
# Field names and the required creation order below (AUC and APN must exist
# BEFORE the SUBSCRIBER row, which has NOT NULL foreign keys to both) come
# straight from pyHSS's own lib/database.py model definitions, not guessed.
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
APN_ENV=/etc/open5gsexperiment-pyhss-apns.env

echo "==> Open5GS 5GC: adding IMSI $IMSI (internet + ims DNNs)"
# Tolerant of the subscriber already existing (e.g. added through the
# WebUI first, which is a normal thing to do) -- open5gs-dbctl errors on a
# duplicate IMSI, and under set -e that would abort this script before it
# ever reached the IMS/pyHSS side below, which is the part that actually
# still needs doing in that case.
open5gs-dbctl add_ue_with_apn "$IMSI" "$KI" "$OPC" internet \
  || echo "    (IMSI already exists in the 5GC -- fine, assuming it's already provisioned there)"
open5gs-dbctl update_apn "$IMSI" ims 1 \
  || echo "    (ims DNN already present for this IMSI -- fine)"

if [[ ! -f "$APN_ENV" ]]; then
  echo "!! $APN_ENV not found -- install.sh's pyHSS APN bootstrap didn't complete."
  echo "   Fix that first (see install.sh step 12b / 'systemctl status pyhss-apiService'),"
  echo "   then re-run this script. The 5GC side above is already provisioned; only"
  echo "   the IMS/pyHSS side below depends on it."
  exit 1
fi
# shellcheck source=/dev/null
source "$APN_ENV"

http_status() { curl -s -o /tmp/pyhss_resp.json -w '%{http_code}' "$@"; }
put() { http_status -X PUT "${PYHSS_API}$1" -H 'Content-Type: application/json' -d "$2"; }

fail_hint() {
  echo "    !! $1 returned HTTP $2: $(cat /tmp/pyhss_resp.json)"
  echo "       pyHSS's API surface can drift between versions -- if this keeps failing,"
  echo "       finish this record by hand at ${PYHSS_API}/docs/ (Swagger UI) using the"
  echo "       same IMSI/Ki/OPc/MSISDN, then re-run this script; it's safe to re-run."
}

echo "==> pyHSS: adding AuC record (Ki/OPc/AMF)"
st=$(put "/auc/" "{\"imsi\":\"${IMSI}\",\"ki\":\"${KI}\",\"opc\":\"${OPC}\",\"amf\":\"8000\",\"sqn\":0}")
if [[ "$st" != 2* ]]; then
  fail_hint "PUT /auc/" "$st"
  exit 1
fi
AUC_ID="$(jq -r '.auc_id' /tmp/pyhss_resp.json)"

echo "==> pyHSS: adding SUBSCRIBER record (auc_id=$AUC_ID, apns=$APN_ID_INTERNET,$APN_ID_IMS)"
st=$(put "/subscriber/" "{\"imsi\":\"${IMSI}\",\"msisdn\":\"${MSISDN}\",\"enabled\":true,\"auc_id\":${AUC_ID},\"default_apn\":${APN_ID_INTERNET},\"apn_list\":\"${APN_ID_INTERNET},${APN_ID_IMS}\"}")
if [[ "$st" != 2* ]]; then
  fail_hint "PUT /subscriber/" "$st"
  exit 1
fi

echo "==> pyHSS: adding IMS_SUBSCRIBER record (IMPI/IMPU)"
st=$(put "/ims_subscriber/" "{\"msisdn\":\"${MSISDN}\",\"msisdn_list\":\"${MSISDN}\",\"imsi\":\"${IMSI}\"}")
if [[ "$st" != 2* ]]; then
  fail_hint "PUT /ims_subscriber/" "$st"
  exit 1
fi

echo
echo "==> Done -- this subscriber is fully provisioned on both sides, nothing else to add."
echo "    IMPI: ${IMSI}@${REALM}"
echo "    IMPU: sip:${IMSI}@${REALM}"
