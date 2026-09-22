#!/usr/bin/env bash
#
# Safely re-deploy ONE already-installed config file from this repo,
# preserving the CORE_IP substitution install.sh applied at first install.
#
# Why this exists: configs/open5gs/*.yaml and configs/kamailio/*/*.cfg in
# this repo are templates written against TEMPLATE_IP (172.17.9.48) --
# install.sh substitutes that for your real CORE_IP the first time it
# deploys them. A plain `cp` of the repo file straight over the deployed
# one silently REVERTS that substitution back to the template IP, breaking
# whatever that file controls (this is exactly what happened to a live
# deployment's GTP-U bind address once -- see git history). Use this
# instead of `cp` for any single-file redeploy after pulling a fix.
#
# Usage:
#   sudo ./scripts/redeploy-config.sh <repo-file> <deployed-file>
# e.g.
#   sudo ./scripts/redeploy-config.sh configs/open5gs/upf.yaml /etc/open5gs/upf.yaml
#   sudo ./scripts/redeploy-config.sh configs/kamailio/pcscf/kamailio_pcscf.cfg /etc/kamailio_pcscf/kamailio_pcscf.cfg

set -euo pipefail

SRC="${1:?usage: redeploy-config.sh <repo-file> <deployed-file>}"
DST="${2:?usage: redeploy-config.sh <repo-file> <deployed-file>}"
TEMPLATE_IP="172.17.9.48"

[[ -f "$SRC" ]] || { echo "!! source file not found: $SRC" >&2; exit 1; }

# Recover the real CORE_IP from whatever is already deployed, if anything
# still references it; otherwise fall back to auto-detection the same way
# install.sh does.
CORE_IP=""
if [[ -f "$DST" ]]; then
  CORE_IP="$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$DST" 2>/dev/null \
             | grep -v "^127\.\|^0\.0\.0\.0$" | head -1 || true)"
fi
if [[ -z "$CORE_IP" ]]; then
  CORE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')" || true
fi
if [[ -z "$CORE_IP" ]]; then
  echo "!! could not determine CORE_IP -- pass it explicitly: CORE_IP=x.x.x.x $0 $SRC $DST" >&2
  exit 1
fi

echo "==> Deploying $SRC -> $DST (substituting $TEMPLATE_IP -> $CORE_IP)"
if [[ "$CORE_IP" != "$TEMPLATE_IP" ]]; then
  sed "s/${TEMPLATE_IP//./\\.}/${CORE_IP}/g" "$SRC" > "$DST"
else
  cp "$SRC" "$DST"
fi
echo "==> Done. Restart whichever service reads $DST to pick this up."
