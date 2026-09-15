#!/usr/bin/env bash
# Provisions the test subscriber that ueransim/ue.yaml.tmpl expects, so the
# virtual UE can actually authenticate against your HSS/UDR.
#
# IMSI/K/OPc here are the well-known open5gs default test credentials (used
# in every open5gs quickstart) -- not secret, safe to reuse for a lab UE.
# Override via env vars if you want a different test identity.
#
# NOTE: this provisions the 5G/AMF-UDR side (Mongo-backed) subscriber --
# separate from FHoSS's own hss_db (Cx/IMS side). If you're testing with an
# IMSI already provisioned in FHoSS (e.g. via your own add_subscriber.sh),
# this script provisions the matching row on the 5G side so the same
# identity can also attach over NGAP/NAS via UERANSIM.
set -uo pipefail

IMSI="${TEST_IMSI:-001010000000029}"
KEY="${TEST_KEY:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${TEST_OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
SST="${SST:-1}"
SD="${SD:-010203}"
DNN="${DNN_DATA:-internet}"

print_webui_fallback() {
    cat <<EOF

--------------------------------------------------------------------------
Provision imsi-${IMSI} through the open5gs WebUI instead (it's running on
this host per your systemctl status):

  1. Browse to http://<core-host>:3000  (default login admin / 1423)
  2. Subscriber -> Add subscriber
       - IMSI : ${IMSI}
       - K    : ${KEY}
       - OPc  : ${OPC}   (make sure it's set as OPc, not OP)
  3. Under Security / slice config, set:
       - SST : ${SST}   SD : ${SD}
  4. Add TWO DNN sessions on that slice:
       - internet (IPv4v6, default QoS)
       - ims      (IPv4v6, QoS index 5 -- matches pcf.yaml's ims-session default)
  5. Save.

Then confirm both sessions show up (if you locate open5gs-dbctl later):
  open5gs-dbctl showall | grep -A20 ${IMSI}
--------------------------------------------------------------------------
EOF
}

DBCTL=""
if command -v open5gs-dbctl >/dev/null 2>&1; then
    DBCTL="open5gs-dbctl"
else
    echo "[!] open5gs-dbctl not on PATH -- searching for it..."
    found=$(sudo find / -xdev -name "open5gs-dbctl*" -type f 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "[*] Found: $found"
        DBCTL="$found"
    fi
fi

if [ -z "$DBCTL" ]; then
    echo "[!] open5gs-dbctl not found anywhere on this host."
    print_webui_fallback
    exit 1
fi

echo "[*] Adding subscriber imsi-${IMSI} (slice sst=${SST} sd=${SD}, dnn=${DNN}) via $DBCTL..."
if "$DBCTL" add_ue_with_slice "$IMSI" "$KEY" "$OPC" "$SST" "$SD" "$DNN"; then
    echo "[OK] Subscriber added via add_ue_with_slice."
else
    echo "[!] add_ue_with_slice failed or isn't supported by this open5gs-dbctl version."
    echo "    Falling back to a plain add (default slice/DNN, 'internet' only)..."
    if ! "$DBCTL" add "$IMSI" "$KEY" "$OPC"; then
        echo "[!] Plain add also failed (subscriber may already exist, or dbctl hit an error above)."
        print_webui_fallback
        exit 1
    fi
    echo "[OK] Subscriber added with defaults -- you'll need to fix up the slice/DNN below manually."
fi

cat <<EOF

--------------------------------------------------------------------------
IMPORTANT: this subscriber currently has (at most) ONE DNN session
('${DNN}'). The UERANSIM UE config in this stub requests a SECOND DNN
('ims') on the same slice, since that's the session a real phone uses for
VoLTE/IMS SIP signaling.

open5gs-dbctl does not reliably support appending a second DNN session to
an existing subscriber across all versions, so add it through the open5gs
WebUI instead (the safest, schema-correct way):

  1. Browse to http://<core-host>:3000  (default login admin / 1423)
  2. Open subscriber imsi-${IMSI}
  3. Under "APN/DNN" / "Session", add a second session:
       - name : ims
       - type : IPv4v6 (or IPv4, matching smf.yaml's 'ims' subnet entries)
       - QoS index : 5   (matches pcf.yaml's ims-session default)
  4. Save.

Then confirm both sessions show up with:
  ${DBCTL} showall | grep -A20 ${IMSI}
--------------------------------------------------------------------------
EOF
