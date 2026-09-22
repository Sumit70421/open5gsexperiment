#!/usr/bin/env bash
#
# Real-time, colour-coded, correctly-attributed log trace across the exact
# path a call/registration takes through this stack:
#
#   UE <-> gNB <-> AMF <-> SMF <-> UPF      (5GC control + user plane)
#              \-> P-CSCF -> I-CSCF -> S-CSCF   (IMS SIP signalling)
#
# All six units are interleaved into ONE chronological stream, so you can
# watch a REGISTER or INVITE walk across NF/CSCF boundaries in real time
# instead of tailing six terminals and eyeballing timestamps.
#
# Why not plain `journalctl -u a -u b -u c -f`: that already interleaves
# correctly, but its default output only shows the syslog identifier, and
# all three Kamailio instances (P/I/S-CSCF) run the SAME kamailio binary --
# their lines are indistinguishable from each other in default text output.
# This uses `-o json` and reads the journal's own SYSTEMD_UNIT field per
# line instead, which is always correct regardless of what the process
# calls itself, then colour-codes and left-pads by that real unit name.
#
# Usage:
#   sudo trace-flow                  # all 6 units (AMF SMF UPF PCSCF ICSCF SCSCF)
#   sudo trace-flow core             # just AMF SMF UPF
#   sudo trace-flow ims              # just PCSCF ICSCF SCSCF
#   sudo trace-flow amf smf pcscf    # any subset, by short name
#
# What to watch for:
#   - A REGISTER from the UE should show up on open5gs-amfd (as PDU session
#     activity for the "ims" DNN) and THEN on kamailio-pcscf within ~1s.
#     If it never reaches kamailio-pcscf: the UE isn't opening the IMS PDU
#     session at all (APN/DNN "ims" not provisioned, or PCF policy missing)
#     -- check with the AMF/SMF lines alone before suspecting IMS.
#   - PCSCF should immediately relay to ICSCF, which does a Cx UAR/LIR to
#     pyHSS then routes to SCSCF (not traced here -- diameter, not SIP --
#     but a stall between PCSCF and ICSCF lines with nothing from ICSCF
#     means the Cx/pyHSS lookup is stuck; check pyhss-diameterService
#     separately with: journalctl -u pyhss-diameterService -f).
#   - SCSCF should send a 401 challenge (Cx MAR/SAR to pyHSS for the AKA
#     vector), the UE re-REGISTERs with credentials, and SCSCF returns 200
#     OK. That 200 OK on kamailio-scscf is the actual "VoLTE/IMS registered"
#     moment -- that's what makes the IMS icon appear on the UE.

set -uo pipefail

declare -A UNIT_OF=(
  [amf]=open5gs-amfd.service
  [smf]=open5gs-smfd.service
  [upf]=open5gs-upfd.service
  [pcscf]=kamailio-pcscf.service
  [icscf]=kamailio-icscf.service
  [scscf]=kamailio-scscf.service
)
CORE_KEYS=(amf smf upf)
IMS_KEYS=(pcscf icscf scscf)
ALL_KEYS=(amf smf upf pcscf icscf scscf)

declare -A COLOR=(
  [open5gs-amfd.service]="1;36"    # cyan
  [open5gs-smfd.service]="1;34"    # blue
  [open5gs-upfd.service]="1;35"    # magenta
  [kamailio-pcscf.service]="1;32"  # green
  [kamailio-icscf.service]="1;33"  # yellow
  [kamailio-scscf.service]="1;31"  # red
)

usage() {
  echo "Usage: sudo trace-flow [core|ims|all|<unit> [<unit> ...]]" >&2
  echo "  units: ${ALL_KEYS[*]}" >&2
  exit 1
}

KEYS=()
if [[ $# -eq 0 ]]; then
  KEYS=("${ALL_KEYS[@]}")
else
  for arg in "$@"; do
    case "$arg" in
      core) KEYS+=("${CORE_KEYS[@]}") ;;
      ims)  KEYS+=("${IMS_KEYS[@]}") ;;
      all)  KEYS+=("${ALL_KEYS[@]}") ;;
      amf|smf|upf|pcscf|icscf|scscf) KEYS+=("$arg") ;;
      *) echo "Unknown unit: $arg" >&2; usage ;;
    esac
  done
fi

JOURNAL_ARGS=()
MAXLEN=0
for k in "${KEYS[@]}"; do
  u="${UNIT_OF[$k]}"
  JOURNAL_ARGS+=(-u "$u")
  (( ${#u} > MAXLEN )) && MAXLEN=${#u}
done

echo "==> Tracing: ${KEYS[*]}  (Ctrl-C to stop)"
echo

# --lines=0: don't dump history first, only stream what happens from now on
# -o json: reliable per-field extraction below instead of parsing text
# stdbuf -oL on jq: line-buffer its stdout so the while-read loop below sees
# each line as soon as journald emits it, not only when jq's output buffer fills
journalctl "${JOURNAL_ARGS[@]}" -f --lines=0 -o json 2>/dev/null \
  | stdbuf -oL jq -r --unbuffered '[.SYSTEMD_UNIT // ._SYSTEMD_UNIT // "unknown", (.MESSAGE | if type == "array" then (implode) else . end)] | @tsv' \
  | while IFS=$'\t' read -r unit msg; do
      c="${COLOR[$unit]:-0}"
      printf "\033[%sm[%-${MAXLEN}s]\033[0m %s\n" "$c" "$unit" "$msg"
    done
