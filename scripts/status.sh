#!/usr/bin/env bash
#
# One-shot status check for every core + IMS service this stack installs.
# For anything not active, prints the last few log lines right there so you
# don't need a second command to see why.
#
# Usage:
#   sudo ./scripts/status.sh

set -uo pipefail

UNITS=(
  mongod mysql redis-server
  open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd open5gs-upfd
  open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd open5gs-bsfd
  pyhss-diameterService pyhss-hssService pyhss-apiService
  kamailio-pcscf kamailio-icscf kamailio-scscf
  rtpengine
)

ACTIVE=0
TOTAL=${#UNITS[@]}

for u in "${UNITS[@]}"; do
  st="$(systemctl is-active "$u" 2>/dev/null || true)"
  if [[ "$st" == "active" ]]; then
    printf "  \033[1;32m%-28s active\033[0m\n" "$u"
    ACTIVE=$((ACTIVE + 1))
  else
    printf "  \033[1;31m%-28s %s\033[0m\n" "$u" "${st:-not found}"
    journalctl -u "$u" -n 3 --no-pager 2>/dev/null | sed 's/^/      /'
  fi
done

echo
if [[ $ACTIVE -eq $TOTAL ]]; then
  echo -e "\033[1;32m$ACTIVE/$TOTAL active -- everything is up.\033[0m"
else
  echo -e "\033[1;31m$ACTIVE/$TOTAL active -- $((TOTAL - ACTIVE)) service(s) need attention (see above).\033[0m"
  echo "For more detail on any one: journalctl -u <unit-name> -n 80 --no-pager"
fi
