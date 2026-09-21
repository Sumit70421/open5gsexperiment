#!/usr/bin/env bash
#
# End-to-end bring-up of a 5G SA core (Open5GS) + IMS (Kamailio P/I/S-CSCF +
# pyHSS + rtpengine) on a single fresh Ubuntu 22.04 VM, built from source.
#
# Deploys the config bundle under configs/ (this is the user's own working
# 5G SA core config, plus their Kamailio P/I/S-CSCF config, with the pieces
# that were missing/broken for IMS registration added: an HSS, DNS resolution
# for the 3GPP-style Diameter peer names, and the I-CSCF routing table seed).
#
# Usage:
#   sudo ./scripts/install.sh [CORE_IP]
#
# CORE_IP defaults to this machine's primary IPv4 address. All the uploaded
# configs were hardcoded to 172.17.9.48 (the box they were authored on); this
# script rewrites that IP to CORE_IP throughout the deployed copies (never
# touches the pristine files under configs/) so the same bundle works on any
# VM. If you run this on the exact same 172.17.9.48 host, pass that address
# explicitly or just accept the default (it will be a no-op rewrite).
#
# Safe to re-run: package installs and DB grants are idempotent; source
# builds just rebuild in place.

set -euo pipefail

# --------------------------------------------------------------------------
# 0. Preflight
# --------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 $*" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CFG_O5GS="$REPO_DIR/configs/open5gs"
CFG_KAM="$REPO_DIR/configs/kamailio"

TEMPLATE_IP="172.17.9.48"
CORE_IP="${1:-${CORE_IP:-}}"
if [[ -z "$CORE_IP" ]]; then
  # `|| true` on each attempt matters here: under `set -e -o pipefail`, an
  # unguarded failure (e.g. `ip` not installed at all, not just "no route")
  # would abort the whole script right here, silently, before the fallback
  # below -- or the explicit error message after it -- ever gets to run.
  CORE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')" || true
fi
if [[ -z "$CORE_IP" ]]; then
  CORE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
fi
if [[ -z "$CORE_IP" ]]; then
  echo "Could not auto-detect this machine's IPv4 address. Pass it explicitly: sudo $0 <ip>" >&2
  exit 1
fi

MCC="001"
MNC="01"
REALM="ims.mnc001.mcc001.3gppnetwork.org"
KAMAILIO_TAG="6.1.4"
RTPENGINE_TAG="mr26.2.1.2"
SRC_DIR="/opt/src"
PYHSS_DIR="/opt/pyhss"
PYHSS_DB_NAME="hss_db"
PYHSS_DB_USER="pyhss"
PYHSS_DB_PASS="pyhsspass123"
KAM_DB_PASS="asg123"   # matches the password already baked into the uploaded *.cfg DB_URL lines

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
warn() { echo -e "\033[1;33m!! $*\033[0m" >&2; }
die()  { echo -e "\033[1;31mFATAL: $*\033[0m" >&2; exit 1; }

trap 'die "install.sh failed at line $LINENO. Nothing after that line ran -- fix the reported error and re-run; earlier steps are idempotent."' ERR

# Fetch source for one of the four dependencies: use the pinned copy under
# vendor/<name> if this script's repo was checked out with it (no network
# needed for this step at all), otherwise git clone it (optionally at a
# specific tag/branch) as before.
fetch_source() {
  local name=$1 dest=$2 url=$3 ref=${4:-}
  local vendor_dir="$REPO_DIR/vendor/$name"
  if [[ -d "$vendor_dir" ]]; then
    log "Using vendored $name source from $vendor_dir (no network fetch needed)"
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    cp -a "$vendor_dir" "$dest"
    return
  fi
  if [[ -d "$dest/.git" ]]; then
    log "Updating $name from $url"
    (cd "$dest" && git fetch --tags origin && \
      if [[ -n "$ref" ]]; then git checkout "$ref"; else git reset --hard origin/HEAD; fi)
  else
    log "Cloning $name from $url"
    rm -rf "$dest"
    if [[ -n "$ref" ]]; then
      git clone --depth 1 --branch "$ref" "$url" "$dest"
    else
      git clone --depth 1 "$url" "$dest"
    fi
  fi
}

mkdir -p "$SRC_DIR" /var/log/open5gs

log "Target IP: $CORE_IP (template IP in configs: $TEMPLATE_IP) | PLMN $MCC/$MNC | Kamailio $KAMAILIO_TAG | rtpengine $RTPENGINE_TAG"

# --------------------------------------------------------------------------
# 1. OS packages
# --------------------------------------------------------------------------
log "Installing build/runtime dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update

# Core build tooling
BUILD_PACKAGES=(build-essential git cmake ninja-build meson pkg-config flex bison
  python3 python3-pip python3-venv python3-dev gnupg curl ca-certificates)

# Open5GS build deps
BUILD_PACKAGES+=(libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev
  libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev
  libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn11-dev)

# Kamailio build deps
BUILD_PACKAGES+=(libmysqlclient-dev libxml2-dev libpcre3-dev libradcli-dev)

# libmnl: the actual dependency of Kamailio's ims_ipsec_pcscf module (which the
# P-CSCF config enables via WITH_IPSEC) -- confirmed from its own README, it
# programs IPsec SAs via the kernel's Netlink/XFRM interface through libmnl,
# NOT via ipsec-tools/setkey (that's legacy PF_KEY tooling, dropped from
# Ubuntu's archives, which is why it 404s -- it was never actually needed).
BUILD_PACKAGES+=(libmnl-dev)

# libunistring-dev: Kamailio's websocket module (unistr.h, GNU libunistring)
# needs it for UTF-8 validation of WS frames -- also missing from the
# original list, found the same way as the others: by actually building.
BUILD_PACKAGES+=(libunistring-dev)

# rtpengine daemon build deps (userspace-only build: with_transcoding=no, no
# dkms/kernel module, no recording daemon -- keeps this to plain library deps
# instead of the full packaging toolchain, since the kernel-module/dkms path
# is the single flakiest part of building rtpengine and isn't needed for a
# lab voice/video call test). Verified against rtpengine's own
# utils/gen-common-flags, which hard-fails the build if any of these (or
# libssl-dev/libmysqlclient-dev, already listed above) are missing. Its
# curl check is just `pkg-config --exists libcurl` -- any flavor satisfies
# it, so this deliberately does NOT list libcurl4-openssl-dev: Ubuntu's
# libcurl4-*-dev packages (gnutls/openssl/nss backends) Conflict with each
# other, and libcurl4-gnutls-dev is already pulled in above for Open5GS.
BUILD_PACKAGES+=(libglib2.0-dev libjson-glib-dev zlib1g-dev libpcre2-dev
  libhiredis-dev gperf libevent-dev libpcap-dev libsystemd-dev
  libspandsp-dev libmosquitto-dev libwebsockets-dev libopus-dev
  libncurses-dev libjwt-dev)

# MySQL, MongoDB prereqs, Redis (pyHSS)
BUILD_PACKAGES+=(mysql-server redis-server)

# jq: used to parse pyHSS's REST API responses when bootstrapping APNs and
# provisioning subscribers
BUILD_PACKAGES+=(jq)

# Install everything in one batch (fast path). If that fails -- most likely
# because one package name doesn't exist under this Ubuntu release/version
# (already happened once with ipsec-tools, since removed) -- fall back to
# checking each name individually so one bad name can't take the rest of
# this down; report exactly what's missing instead of a single opaque error.
if ! apt-get install -y "${BUILD_PACKAGES[@]}"; then
  warn "Batch apt-get install failed -- retrying package by package to isolate the bad name(s)"
  MISSING=()
  for pkg in "${BUILD_PACKAGES[@]}"; do
    apt-cache show "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
  done
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    die "These package names don't exist in apt's index on this VM: ${MISSING[*]} -- find the right name for your Ubuntu release with 'apt-cache search <topic>', edit the BUILD_PACKAGES list near the top of install.sh, and re-run (already-completed steps are safe to repeat)."
  fi
  # All names resolve individually -- the failure was something else
  # (network blip, dpkg lock, disk space). Re-run and let it surface directly.
  apt-get install -y "${BUILD_PACKAGES[@]}" \
    || die "apt-get install failed -- every package name individually resolves, so check the output above for a 'Conflicts:' line between two of them (fix: drop one from the BUILD_PACKAGES list near the top of install.sh), or a network/disk-space/held-dpkg-lock issue"
fi

# --------------------------------------------------------------------------
# 2. MongoDB (Open5GS UDR/PCF backend)
# --------------------------------------------------------------------------
if ! command -v mongod >/dev/null 2>&1; then
  log "Installing MongoDB"
  curl -fsSL https://pgp.mongodb.com/server-8.0.asc | gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-8.0.list
  apt-get update
  apt-get install -y mongodb-org
else
  log "MongoDB already installed"
fi
systemctl enable --now mongod

# --------------------------------------------------------------------------
# 3. MySQL databases for Kamailio (pcscf/icscf/scscf) and pyHSS
# --------------------------------------------------------------------------
log "Provisioning MySQL databases"
systemctl enable --now mysql

mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS pcscf;
CREATE DATABASE IF NOT EXISTS icscf;
CREATE DATABASE IF NOT EXISTS scscf;
CREATE DATABASE IF NOT EXISTS ${PYHSS_DB_NAME};

CREATE USER IF NOT EXISTS 'pcscf'@'localhost' IDENTIFIED BY '${KAM_DB_PASS}';
CREATE USER IF NOT EXISTS 'icscf'@'localhost' IDENTIFIED BY '${KAM_DB_PASS}';
CREATE USER IF NOT EXISTS 'scscf'@'localhost' IDENTIFIED BY '${KAM_DB_PASS}';
CREATE USER IF NOT EXISTS '${PYHSS_DB_USER}'@'localhost' IDENTIFIED BY '${PYHSS_DB_PASS}';

GRANT ALL PRIVILEGES ON pcscf.* TO 'pcscf'@'localhost';
GRANT ALL PRIVILEGES ON icscf.* TO 'icscf'@'localhost';
GRANT ALL PRIVILEGES ON scscf.* TO 'scscf'@'localhost';
GRANT ALL PRIVILEGES ON ${PYHSS_DB_NAME}.* TO '${PYHSS_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# --------------------------------------------------------------------------
# 4. Build & install Open5GS from source
# --------------------------------------------------------------------------
log "Building Open5GS from source"
fetch_source open5gs "$SRC_DIR/open5gs" https://github.com/open5gs/open5gs
pip3 install --quiet pymongo || pip3 install --quiet --break-system-packages pymongo || true

cd "$SRC_DIR/open5gs"
if [[ ! -d build ]]; then
  meson setup build --prefix=/usr --sysconfdir=/etc --localstatedir=/var
else
  meson setup --reconfigure build --prefix=/usr --sysconfdir=/etc --localstatedir=/var
fi
ninja -C build
ninja -C build install
ldconfig

if ! command -v open5gs-dbctl >/dev/null 2>&1; then
  install -m 0755 "$SRC_DIR/open5gs/misc/db/open5gs-dbctl" /usr/bin/open5gs-dbctl
fi

# --------------------------------------------------------------------------
# 5. TUN devices for the internet/ims DNNs + NAT + forwarding
# --------------------------------------------------------------------------
log "Configuring ogstun/ogstun2 and NAT"
install -d /usr/local/sbin
cat > /usr/local/sbin/open5gs-netconf.sh <<'NETCONF'
#!/usr/bin/env bash
set -e
add_tun() {
  local name=$1 v4=$2 v6=$3
  if ! ip link show "$name" >/dev/null 2>&1; then
    ip tuntap add name "$name" mode tun
  fi
  ip addr replace "$v4" dev "$name"
  ip addr replace "$v6" dev "$name" 2>/dev/null || true
  ip link set "$name" mtu 1400
  ip link set "$name" up
}
add_tun ogstun  10.45.0.1/16 cafe::1/48
add_tun ogstun2 10.46.0.1/16 cafe:1::1/48

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

add_nat() {
  local subnet=$1 dev=$2
  iptables -t nat -C POSTROUTING -s "$subnet" ! -o "$dev" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$subnet" ! -o "$dev" -j MASQUERADE
  iptables -C INPUT -i "$dev" -j ACCEPT 2>/dev/null || iptables -I INPUT -i "$dev" -j ACCEPT
}
add_nat 10.45.0.0/16 ogstun
add_nat 10.46.0.0/16 ogstun2
NETCONF
chmod +x /usr/local/sbin/open5gs-netconf.sh

cat > /etc/systemd/system/open5gs-netconf.service <<UNIT
[Unit]
Description=Open5GS TUN device + NAT setup
Before=network-online.target
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/open5gs-netconf.sh

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now open5gs-netconf.service

# --------------------------------------------------------------------------
# 6. Deploy Open5GS config (from configs/open5gs), rewriting the template IP
# --------------------------------------------------------------------------
log "Deploying Open5GS config to /etc/open5gs"
mkdir -p /etc/open5gs
cp -a "$CFG_O5GS/." /etc/open5gs/
rm -f /etc/open5gs/coreconfig.zip
rm -rf /etc/open5gs/backup-*

if [[ "$CORE_IP" != "$TEMPLATE_IP" ]]; then
  grep -rl "$TEMPLATE_IP" /etc/open5gs --include='*.yaml' | xargs -r sed -i "s/${TEMPLATE_IP//./\\.}/${CORE_IP}/g"
fi

# --------------------------------------------------------------------------
# 7. systemd units for the 5G SA network functions (NRF/SCP first, then the rest)
# --------------------------------------------------------------------------
log "Installing Open5GS systemd units"
NFS_FIRST=(nrf scp)
NFS_REST=(amf smf upf ausf udm udr pcf nssf bsf)

install_o5gs_unit() {
  local nf=$1 after=$2
  cat > "/etc/systemd/system/open5gs-${nf}d.service" <<UNIT
[Unit]
Description=Open5GS ${nf}d
After=network.target mongod.service open5gs-netconf.service ${after}
Wants=mongod.service

[Service]
Type=simple
ExecStart=/usr/bin/open5gs-${nf}d -c /etc/open5gs/${nf}.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
}

for nf in "${NFS_FIRST[@]}"; do install_o5gs_unit "$nf" ""; done
for nf in "${NFS_REST[@]}";  do install_o5gs_unit "$nf" "open5gs-nrfd.service open5gs-scpd.service"; done

systemctl daemon-reload
for nf in "${NFS_FIRST[@]}"; do systemctl enable --now "open5gs-${nf}d.service"; done
sleep 2
for nf in "${NFS_REST[@]}";  do systemctl enable --now "open5gs-${nf}d.service"; done

# --------------------------------------------------------------------------
# 8. Build & install Kamailio (mainline) with the IMS module set the uploaded
#    P/I/S-CSCF configs actually load
# --------------------------------------------------------------------------
log "Building Kamailio $KAMAILIO_TAG from source"
fetch_source kamailio "$SRC_DIR/kamailio" https://github.com/kamailio/kamailio "$KAMAILIO_TAG"
cd "$SRC_DIR/kamailio"

# NOTE: rtpping is deliberately NOT in this list -- it doesn't exist in
# Kamailio 6.1.4's src/modules/ at all (removed upstream at some point after
# the uploaded pcscf.cfg was written against an older Kamailio). Its
# loadmodule line in kamailio_pcscf.cfg is guarded by `#!ifdef WITH_RTPPING`,
# which pcscf.cfg leaves disabled (`##!define WITH_RTPPING`), so it was
# never going to be loaded at runtime anyway -- dropping it from the build
# changes nothing behaviorally, it just stops the build from failing on a
# module that can't be compiled.
KAM_MODULES=(kex tm tmx sl rr pv maxfwd textops textopsx siputils sanity ctl
  cfg_rpc xlog auth usrloc registrar jsonrpcs xhttp corex pike nathelper
  htable sqlops uac sdpops path statistics presence pua enum dispatcher
  rtimer debugger siptrace tls websocket db_mysql db_cluster cdp cdp_avp
  ims_dialog ims_usrloc_pcscf ims_ipsec_pcscf ims_registrar_pcscf ims_qos
  ims_icscf ims_usrloc_scscf ims_registrar_scscf ims_auth ims_isc
  ims_charging rtpengine sctp xmlrpc)

# Verify every module actually exists before spending minutes compiling --
# a bad name here (like rtpping was) fails at the very end of `make all`
# after building everything else, which is a much slower way to find out.
KAM_MISSING=()
for mod in "${KAM_MODULES[@]}"; do
  [[ -d "src/modules/$mod" ]] || KAM_MISSING+=("$mod")
done
if [[ ${#KAM_MISSING[@]} -gt 0 ]]; then
  die "These modules don't exist in this Kamailio checkout ($KAMAILIO_TAG): ${KAM_MISSING[*]} -- check 'ls $SRC_DIR/kamailio/src/modules/ | grep -i <topic>' for the current name, fix the KAM_MODULES array near the top of the Kamailio build step in install.sh, and re-run."
fi

export RADCLI=1
make include_modules="${KAM_MODULES[*]}" cfg
make -j"$(nproc)" all
make install
ldconfig

# --------------------------------------------------------------------------
# 9. Load Kamailio DB schemas + the I-CSCF seed data that was missing
# --------------------------------------------------------------------------
log "Loading Kamailio DB schemas"
MYSQL_DIR="$SRC_DIR/kamailio/utils/kamctl/mysql"

mysql -u root pcscf < "$MYSQL_DIR/standard-create.sql"
mysql -u root pcscf < "$MYSQL_DIR/presence-create.sql"
mysql -u root pcscf < "$MYSQL_DIR/ims_usrloc_pcscf-create.sql"
mysql -u root pcscf < "$MYSQL_DIR/ims_dialog-create.sql"

mysql -u root scscf < "$MYSQL_DIR/standard-create.sql"
mysql -u root scscf < "$MYSQL_DIR/presence-create.sql"
mysql -u root scscf < "$MYSQL_DIR/ims_usrloc_scscf-create.sql"
mysql -u root scscf < "$MYSQL_DIR/ims_dialog-create.sql"
mysql -u root scscf < "$MYSQL_DIR/ims_charging-create.sql"

mysql -u root icscf < "$CFG_KAM/icscf/icscf.sql"
mysql -u root icscf < "$CFG_KAM/icscf-seed.sql"

# --------------------------------------------------------------------------
# 10. Deploy Kamailio configs (from configs/kamailio/{pcscf,icscf,scscf}),
#     rewriting the template IP
# --------------------------------------------------------------------------
log "Deploying Kamailio P/I/S-CSCF configs"
for role in pcscf icscf scscf; do
  mkdir -p "/etc/kamailio_${role}"
  cp -a "$CFG_KAM/${role}/." "/etc/kamailio_${role}/"
  mkdir -p "/run/kamailio_${role}"
  if [[ "$CORE_IP" != "$TEMPLATE_IP" ]]; then
    grep -rl "$TEMPLATE_IP" "/etc/kamailio_${role}" --include='*.cfg' --include='*.xml' 2>/dev/null \
      | xargs -r sed -i "s/${TEMPLATE_IP//./\\.}/${CORE_IP}/g"
  fi
done

for role in pcscf icscf scscf; do
  cat > "/etc/systemd/system/kamailio-${role}.service" <<UNIT
[Unit]
Description=Kamailio ${role^^}
After=network.target mysql.service open5gs-netconf.service
Wants=mysql.service

[Service]
Type=simple
WorkingDirectory=/etc/kamailio_${role}
ExecStart=/usr/local/sbin/kamailio -f /etc/kamailio_${role}/kamailio_${role}.cfg -DD -E -P /run/kamailio_${role}/kamailio.pid
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
done

# --------------------------------------------------------------------------
# 11. Build & install rtpengine (media relay) and wire it to the P-CSCF
# --------------------------------------------------------------------------
log "Building rtpengine $RTPENGINE_TAG from source (userspace daemon only)"
fetch_source rtpengine "$SRC_DIR/rtpengine" https://github.com/sipwise/rtpengine "$RTPENGINE_TAG"
cd "$SRC_DIR/rtpengine"
# Plain daemon-only build: skips the dkms kernel module and packaging
# toolchain (the flakiest part of rtpengine across kernels/Ubuntu releases)
# and transcoding support (needs ffmpeg headers, not needed when both call
# legs negotiate the same codec, which is the normal case in this lab).
make -C daemon -j"$(nproc)" with_transcoding=no
install -m 0755 daemon/rtpengine /usr/local/bin/rtpengine

mkdir -p /etc/rtpengine
cat > /etc/rtpengine/rtpengine.conf <<CONF
[rtpengine]
interface = ${CORE_IP}
listen-ng = 127.0.0.1:2223
port-min = 30000
port-max = 40000
log-level = 6
pidfile = /run/rtpengine.pid
foreground = true
# Deliberately generous: these are the only three knobs in rtpengine that can
# tear down an established call on their own (independent of SIP signaling),
# so for multi-hour stability runs they're set well above anything a real
# call -- including a long silent/held/DTX-heavy audio or video stream --
# should ever hit. Defaults are much lower and are not something to trust
# blind for an overnight test.
timeout = 14400
silent-timeout = 14400
final-timeout = 86400
CONF

cat > /etc/systemd/system/rtpengine.service <<UNIT
[Unit]
Description=rtpengine media relay
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rtpengine --config-file=/etc/rtpengine/rtpengine.conf --foreground
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now rtpengine.service

# --------------------------------------------------------------------------
# 12. pyHSS (Cx/Dx HSS) -- fills the gap: no HSS was present in the uploaded
#     bundle, and without one S-CSCF/I-CSCF can never complete a Cx
#     authentication/registration round trip.
# --------------------------------------------------------------------------
log "Installing pyHSS"
fetch_source pyhss "$PYHSS_DIR" https://github.com/herlesupreeth/pyhss
cd "$PYHSS_DIR"
python3 -m venv venv
./venv/bin/pip install --quiet --upgrade pip
./venv/bin/pip install --quiet -r requirements.txt

# Known-good defaults from the repo's shipped config.yaml, edited only where
# this deployment's realm/DB actually differ:
#  - OriginRealm/OriginHost must match what icscf.xml/scscf.xml declare as
#    the Cx peer (Realm="ims.mnc001.mcc001.3gppnetwork.org",
#    Peer FQDN="hss.ims.mnc001.mcc001.3gppnetwork.org") -- the shipped
#    default OriginRealm is the *epc* realm, which is wrong for this role.
#  - MCC/MNC and scscf_pool already match this deployment out of the box.
sed -i \
  -e "s/OriginHost: \"hss01\"/OriginHost: \"hss.${REALM}\"/" \
  -e "s/OriginRealm: \"epc.mnc001.mcc001.3gppnetwork.org\"/OriginRealm: \"${REALM}\"/" \
  -e "s/username: dbeaver/username: ${PYHSS_DB_USER}/" \
  -e "s/password: password/password: ${PYHSS_DB_PASS}/" \
  -e "s/database: hss2/database: ${PYHSS_DB_NAME}/" \
  config.yaml

for svc in diameterService hssService apiService; do
  cat > "/etc/systemd/system/pyhss-${svc}.service" <<UNIT
[Unit]
Description=pyHSS ${svc}
After=network.target mysql.service redis-server.service
Wants=mysql.service redis-server.service

[Service]
Type=simple
WorkingDirectory=${PYHSS_DIR}
ExecStart=${PYHSS_DIR}/venv/bin/python3 ${PYHSS_DIR}/services/${svc}.py
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
done

systemctl daemon-reload
systemctl enable --now redis-server
systemctl enable --now pyhss-diameterService.service pyhss-hssService.service pyhss-apiService.service

# --------------------------------------------------------------------------
# 12b. Bootstrap the two APNs (internet/ims) in pyHSS once. SUBSCRIBER rows
#      have NOT NULL foreign keys to an APN and an AUC record (confirmed
#      from pyHSS's own lib/database.py -- the API does not auto-create
#      these), so provision-subscriber can't create a working subscriber
#      without an APN already existing to point at. Done once here rather
#      than per-subscriber since APNs are shared, not per-subscriber.
# --------------------------------------------------------------------------
log "Bootstrapping pyHSS APN records"
PYHSS_API="http://127.0.0.1:8080"
for i in $(seq 1 30); do
  curl -sf "${PYHSS_API}/apn/" >/dev/null 2>&1 && break
  sleep 1
  [[ $i -eq 30 ]] && warn "pyHSS API never came up on ${PYHSS_API} -- APN bootstrap and provision-subscriber will fail until it does; check 'systemctl status pyhss-apiService'"
done

APN_ENV=/etc/open5gsexperiment-pyhss-apns.env
get_or_create_apn() {
  local name=$1 qci=$2
  local existing
  existing="$(curl -sf "${PYHSS_API}/apn/" 2>/dev/null | jq -r ".[] | select(.apn==\"${name}\") | .apn_id" 2>/dev/null | head -1)"
  if [[ -n "$existing" && "$existing" != "null" ]]; then
    echo "$existing"
    return
  fi
  curl -sf -X PUT "${PYHSS_API}/apn/" -H 'Content-Type: application/json' \
    -d "{\"apn\":\"${name}\",\"apn_ambr_dl\":1000000,\"apn_ambr_ul\":1000000,\"qci\":${qci}}" \
    | jq -r '.apn_id'
}
APN_ID_INTERNET="$(get_or_create_apn internet 9)"
APN_ID_IMS="$(get_or_create_apn ims 5)"
if [[ -z "$APN_ID_INTERNET" || "$APN_ID_INTERNET" == "null" || -z "$APN_ID_IMS" || "$APN_ID_IMS" == "null" ]]; then
  warn "Could not bootstrap APN records in pyHSS (API not reachable or returned unexpected data). provision-subscriber will not be able to create a working subscriber until ${APN_ENV} exists -- retry manually: curl -X PUT ${PYHSS_API}/apn/ ..., or check ${PYHSS_API}/docs/"
else
  cat > "$APN_ENV" <<ENV
APN_ID_INTERNET=${APN_ID_INTERNET}
APN_ID_IMS=${APN_ID_IMS}
ENV
  log "pyHSS APNs ready: internet=apn_id $APN_ID_INTERNET, ims=apn_id $APN_ID_IMS"
fi

# --------------------------------------------------------------------------
# 12a. Log rotation -- a disk filling up from hours of logs is a common,
#      entirely avoidable way for a long test run to take a service down;
#      Open5GS and pyHSS write their own log files and don't rotate them
#      on their own.
# --------------------------------------------------------------------------
log "Configuring log rotation"
cat > /etc/logrotate.d/open5gsexperiment <<'ROTATE'
/var/log/open5gs/*.log /var/log/pyhss_*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
ROTATE

# --------------------------------------------------------------------------
# 13. /etc/hosts entries for the 3GPP-style Diameter peer FQDNs
#
#     Kamailio's cdp module resolves the P-CSCF/I-CSCF/S-CSCF/HSS Diameter
#     peers by FQDN (icscf.xml / scscf.xml / pcscf.xml have no static IP for
#     their peers). Nothing in the uploaded bundle set up DNS or /etc/hosts
#     for these names -- without this, the Cx connections to the HSS can
#     never come up, no matter how correct everything else is.
# --------------------------------------------------------------------------
log "Adding /etc/hosts entries for the IMS realm"
HOSTS_MARK="# added by open5gsexperiment/scripts/install.sh"
sed -i "/${HOSTS_MARK//\//\\/}/d" /etc/hosts
cat >> /etc/hosts <<HOSTS
${CORE_IP} pcscf.${REALM} icscf.${REALM} scscf.${REALM} hss.${REALM} ${HOSTS_MARK}
HOSTS

# --------------------------------------------------------------------------
# 14. Start Kamailio last (needs pyHSS + DNS/hosts + MySQL schemas in place)
# --------------------------------------------------------------------------
log "Starting Kamailio P/I/S-CSCF"
systemctl enable --now kamailio-icscf.service kamailio-scscf.service
sleep 1
systemctl enable --now kamailio-pcscf.service

install -m 0755 "$SCRIPT_DIR/provision-subscriber.sh" /usr/local/bin/provision-subscriber
install -m 0755 "$SCRIPT_DIR/monitor-overnight.sh" /usr/local/bin/monitor-overnight

# --------------------------------------------------------------------------
# 15. Status report
# --------------------------------------------------------------------------
log "Status"
UNITS=(mongod mysql redis-server open5gs-nrfd open5gs-scpd open5gs-amfd open5gs-smfd \
       open5gs-upfd open5gs-ausfd open5gs-udmd open5gs-udrd open5gs-pcfd open5gs-nssfd \
       open5gs-bsfd pyhss-diameterService pyhss-hssService pyhss-apiService \
       kamailio-pcscf kamailio-icscf kamailio-scscf rtpengine)
FAILED=0
for u in "${UNITS[@]}"; do
  st="$(systemctl is-active "$u" 2>/dev/null || true)"
  if [[ "$st" == "active" ]]; then
    printf "  \033[1;32m%-28s active\033[0m\n" "$u"
  else
    printf "  \033[1;31m%-28s %s\033[0m\n" "$u" "${st:-not found}"
    FAILED=1
  fi
done

echo
if [[ $FAILED -eq 0 ]]; then
  echo -e "\033[1;32mAll services are up.\033[0m Add a test subscriber with:"
  echo "  sudo provision-subscriber <imsi> <ki> <opc> [msisdn]"
  echo "e.g. sudo provision-subscriber 001010000000001 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA 0000000001"
  echo
  echo "Before an overnight stability run, start the monitor so any drop can be"
  echo "checked against core/IMS service state at that exact timestamp:"
  echo "  sudo nohup monitor-overnight 15 /var/log/overnight-\$(date +%F).log &"
else
  echo -e "\033[1;31mOne or more services failed to start.\033[0m Check with:"
  echo "  journalctl -u <unit-name> -n 80 --no-pager"
fi
