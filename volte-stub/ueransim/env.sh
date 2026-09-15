#!/usr/bin/env bash
# Values below are read straight out of the coreconfig.zip you supplied
# (amf.yaml / smf.yaml / pcf.yaml). Edit only if your core config changes.

# AMF's NGAP-facing address (amf.yaml: amf.ngap.server[0].address)
export AMF_IP="${AMF_IP:-172.17.9.48}"

# PLMN + TAC the AMF advertises (amf.yaml: amf.plmn_support / amf.tai)
export MCC="${MCC:-001}"
export MNC="${MNC:-01}"
export TAC="${TAC:-1}"

# Slice the AMF/PCF expect (amf.yaml: plmn_support[0].s_nssai, pcf.yaml: policy slice)
export SST="${SST:-1}"
export SD="${SD:-010203}"

# The two DNNs SMF/PCF are provisioned for (smf.yaml: smf.session[].dnn)
export DNN_DATA="${DNN_DATA:-internet}"
export DNN_IMS="${DNN_IMS:-ims}"

# Local address for the simulated gNB (must be reachable to $AMF_IP -- same
# host or same L2/L3 network as the core). Change this to an address that's
# actually assigned to an interface on the machine you run UERANSIM from.
export GNB_IP="${GNB_IP:-172.17.9.50}"

# Test subscriber. These K/OPc values are the well-known open5gs default test
# credentials used in every open5gs quickstart -- NOT secret, safe to commit.
# Must match a subscriber you provisioned with scripts/provision_test_subscriber.sh
# (5G/AMF-UDR side) -- separate from FHoSS's own hss_db (Cx/IMS side).
# Defaults to the IMSI already confirmed working end-to-end against FHoSS via
# sip/register_test.py -- override TEST_IMSI if you provision a different one.
export TEST_IMSI="${TEST_IMSI:-001010000000029}"
export TEST_KEY="${TEST_KEY:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
export TEST_OPC="${TEST_OPC:-E8ED289DEBA952E4283B54E88E6183CA}"

# IMS domain Kamailio is configured for (pcscf.cfg / icscf.cfg / scscf.cfg alias)
export IMS_DOMAIN="${IMS_DOMAIN:-ims.mnc001.mcc001.3gppnetwork.org}"
export PCSCF_IP="${PCSCF_IP:-172.17.9.48}"
