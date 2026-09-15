#!/usr/bin/env bash
# Provisions the test subscriber that ueransim/ue.yaml.tmpl expects, so the
# virtual UE can actually authenticate against your HSS/UDR.
#
# IMSI/K/OPc here are the well-known open5gs default test credentials (used
# in every open5gs quickstart) -- not secret, safe to reuse for a lab UE.
# Override via env vars if you want a different test identity.
set -euo pipefail

IMSI="${TEST_IMSI:-001010000000001}"
KEY="${TEST_KEY:-465B5CE8B199B49FAA5F0A2EE238A6B}"
OPC="${TEST_OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
SST="${SST:-1}"
SD="${SD:-010203}"
DNN="${DNN_DATA:-internet}"

if ! command -v open5gs-dbctl >/dev/null 2>&1; then
    echo "[!] open5gs-dbctl not found on PATH."
    echo "    It ships with open5gs (usually /usr/lib/open5gs/open5gs-dbctl or"
    echo "    similar depending on your install method). Locate it and either"
    echo "    add it to PATH or run this script with the full path substituted."
    exit 1
fi

echo "[*] Adding subscriber imsi-${IMSI} (slice sst=${SST} sd=${SD}, dnn=${DNN})..."
if open5gs-dbctl add_ue_with_slice "$IMSI" "$KEY" "$OPC" "$SST" "$SD" "$DNN"; then
    echo "[OK] Subscriber added via add_ue_with_slice."
else
    echo "[!] add_ue_with_slice failed or isn't supported by your open5gs-dbctl version."
    echo "    Falling back to a plain add (default slice/DNN, 'internet' only)..."
    open5gs-dbctl add "$IMSI" "$KEY" "$OPC"
    echo "[OK] Subscriber added with defaults -- you'll need to fix up the slice/DNN"
    echo "     below manually."
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
  open5gs-dbctl showall | grep -A20 ${IMSI}
--------------------------------------------------------------------------
EOF
