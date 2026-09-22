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
MONGO_URI="mongodb://localhost/open5gs"
mongo_count() { mongosh --quiet --eval "$1" "$MONGO_URI" 2>/dev/null | tr -d '[:space:]'; }

# Tolerant of the subscriber already existing (e.g. added through the
# WebUI first, which is a normal thing to do) -- open5gs-dbctl errors on a
# duplicate IMSI, and under set -e that would abort this script before it
# ever reached the IMS/pyHSS side below. But "tolerant" can't just mean
# "ignore the exit code and hope": that would just as happily paper over a
# real failure (bad Mongo connection, wrong argument, etc.) and report
# success anyway. So instead of trusting either open5gs-dbctl call's exit
# code, verify the actual end state in MongoDB directly afterward.
open5gs-dbctl add_ue_with_apn "$IMSI" "$KI" "$OPC" internet 2>/dev/null || true
open5gs-dbctl update_apn "$IMSI" ims 1 2>/dev/null || true

if [[ "$(mongo_count "db.subscribers.countDocuments({imsi:'${IMSI}'})")" != "1" ]]; then
  echo "    !! IMSI ${IMSI} is NOT in the 5GC subscriber DB after attempting to add it."
  echo "       Something is actually wrong (not just 'already existed') -- check manually:"
  echo "       mongosh --eval \"db.subscribers.findOne({imsi:'${IMSI}'})\" ${MONGO_URI}"
  exit 1
fi
if [[ "$(mongo_count "db.subscribers.countDocuments({imsi:'${IMSI}','slice.session.name':'ims'})")" != "1" ]]; then
  echo "    !! IMSI ${IMSI} exists in the 5GC but has no 'ims' DNN session -- stopping."
  echo "       Check: mongosh --eval \"db.subscribers.findOne({imsi:'${IMSI}'})\" ${MONGO_URI}"
  exit 1
fi
echo "    confirmed in MongoDB: ${IMSI} present with both internet + ims DNNs"

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

# Read back what was actually created, rather than just trust the create
# calls' status codes -- confirms the record genuinely exists in pyHSS's
# DB under this IMSI, not just that the API said 2xx at the time.
curl -s "${PYHSS_API}/ims_subscriber/" -o /tmp/pyhss_resp.json
if ! jq -e --arg imsi "$IMSI" '.[] | select(.imsi == $imsi)' /tmp/pyhss_resp.json >/dev/null 2>&1; then
  echo "    !! ${IMSI} was not found in pyHSS's ims_subscriber list on read-back."
  echo "       The create calls above reported success, but something's inconsistent --"
  echo "       check manually at ${PYHSS_API}/docs/ before trusting this subscriber."
  exit 1
fi
echo "    confirmed in pyHSS: ${IMSI} present in ims_subscriber"

echo
echo "==> Done -- verified on both sides, nothing else to add for this subscriber."
echo "    IMPI: ${IMSI}@${REALM}"
echo "    IMPU: sip:${IMSI}@${REALM}"
