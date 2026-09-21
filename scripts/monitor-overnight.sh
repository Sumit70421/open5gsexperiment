#!/usr/bin/env bash
#
# Run this alongside an overnight call-stability test. It doesn't affect the
# core/IMS in any way -- it just samples every unit's state on an interval
# and appends a line to a log file, so if a call drops during the run you
# have a timestamped record to check against: did any core/IMS service
# restart or die at that moment, or not. That's the actual way to rule the
# core in or out as a suspect -- a promise that "nothing will ever restart"
# isn't something a from-source build can back with certainty, but a log
# that proves whether it did is.
#
# Usage:
#   sudo ./scripts/monitor-overnight.sh [interval_seconds] [logfile]
#
# Stop with Ctrl+C, or run it under systemd-run/screen/tmux/nohup for a
# run that outlives your terminal, e.g.:
#   sudo nohup ./scripts/monitor-overnight.sh 15 /var/log/overnight-$(date +%F).log &

set -euo pipefail

INTERVAL="${1:-15}"
LOGFILE="${2:-/var/log/overnight-$(date +%Y%m%d-%H%M%S).log}"

UNITS=(mongod mysql redis-server open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd \
       open5gs-upfd open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd \
       open5gs-bsfd pyhss-diameterService pyhss-hssService pyhss-apiService \
       kamailio-pcscf kamailio-icscf kamailio-scscf rtpengine)

echo "Logging to $LOGFILE every ${INTERVAL}s. Ctrl+C to stop." >&2
echo "# timestamp unit=state pairs; a unit flipping to 'activating'/'failed'/'inactive' mid-run" >> "$LOGFILE"
echo "# means THAT service restarted or died at that timestamp -- correlate against any observed call drop." >> "$LOGFILE"

PREV_LINE=""
while true; do
  TS="$(date -Is)"
  LINE="$TS"
  for u in "${UNITS[@]}"; do
    st="$(systemctl is-active "$u" 2>/dev/null || echo "not-found")"
    LINE="$LINE $u=$st"
  done

  # Best-effort: active dialog/registration counts from each Kamailio instance,
  # if its control socket is reachable. A drop in these numbers between two
  # samples with no corresponding user hangup is itself a signal.
  for role in pcscf icscf scscf; do
    cnt="$(kamcmd -s "unix:/var/run/kamailio_${role}/kamailio_ctl" dlg.list 2>/dev/null | grep -c '^dlg' || echo "n/a")"
    LINE="$LINE dialogs_${role}=$cnt"
  done

  # Only write a line when something actually changed, plus a heartbeat
  # every ~20 samples, so the log stays small over an 8+ hour run.
  if [[ "$LINE" != "$PREV_LINE" ]] || (( $(date +%s) % (INTERVAL*20) < INTERVAL )); then
    echo "$LINE" >> "$LOGFILE"
    PREV_LINE="$LINE"
  fi

  sleep "$INTERVAL"
done
