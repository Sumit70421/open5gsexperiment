#!/usr/bin/env python3
"""
Quick liveness + coherence check for an open5gs + Kamailio-IMS deployment.
Run this ON the baremetal host (or point --open5gs-dir / --kamailio-dir at
wherever the configs actually live). No third-party dependencies.

Checks:
  1. Every open5gs NF's SBI/GTP/NGAP/PFCP port is actually listening.
  2. Kamailio's P-CSCF/I-CSCF/S-CSCF SIP + Diameter ports are listening.
  3. MongoDB is reachable.
  4. Cross-file coherence: does the PLMN the MME advertises match the PLMN
     the AMF/PCF/Kamailio are actually configured and populated for? A
     mismatch here means a real eNB/UE could attach to one core (or neither)
     while your IMS/QoS policy is only provisioned for the other's PLMN --
     exactly the kind of thing that silently kills VoLTE/VoNR registration
     while every individual process looks "up".
"""
import argparse
import glob
import os
import re
import socket
import subprocess
import sys

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def load_yaml(path):
    if not os.path.isfile(path):
        return None
    if HAVE_YAML:
        with open(path) as f:
            try:
                return yaml.safe_load(f)
            except Exception as e:
                print(f"  [!] Failed to parse {path}: {e}")
                return None
    # Minimal fallback: good enough to pull mcc/mnc/tac/policy presence.
    with open(path) as f:
        text = f.read()
    return {"_raw": text}


def get(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def find_plmn(cfg):
    """Best-effort: find the first mcc/mnc pair anywhere in a parsed config."""
    if cfg is None:
        return None
    if "_raw" in cfg:
        m = re.search(r"mcc:\s*(\d+)\s*\n.*?mnc:\s*(\d+)", cfg["_raw"], re.DOTALL)
        return (m.group(1), m.group(2)) if m else None

    def fmt(mcc, mnc):
        # YAML parses unquoted 001/01 as ints, dropping leading zeros -- put
        # them back for display (mcc is always 3 digits, mnc is 2 or 3).
        mcc_s = str(mcc).zfill(3)
        mnc_s = str(mnc)
        mnc_s = mnc_s.zfill(2) if len(mnc_s) <= 2 else mnc_s.zfill(3)
        return (mcc_s, mnc_s)

    def walk(node):
        if isinstance(node, dict):
            if "mcc" in node and "mnc" in node:
                return fmt(node["mcc"], node["mnc"])
            for v in node.values():
                r = walk(v)
                if r:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = walk(v)
                if r:
                    return r
        return None

    return walk(cfg)


def has_active_policy(cfg):
    if cfg is None:
        return False
    if "_raw" in cfg:
        # crude: an uncommented top-level "policy:" line
        return bool(re.search(r"^policy:\s*$", cfg["_raw"], re.MULTILINE))
    return bool(cfg.get("policy"))


def check_tcp(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_udp_listen(host, port):
    """Best-effort UDP 'is anything listening' check via `ss`."""
    try:
        out = subprocess.run(["ss", "-lunp"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return None
    pattern = f"{host}:{port} " if host != "0.0.0.0" else f":{port} "
    return pattern in out or f"*:{port} " in out


def check_sctp_listen(port):
    try:
        out = subprocess.run(["ss", "-lnp", "-A", "sctp"], capture_output=True,
                              text=True, timeout=3).stdout
    except Exception:
        return None
    return f":{port}" in out


def mongo_ping(uri):
    for cmd in (["mongosh", "--quiet", "--eval", "db.runCommand({ping:1}).ok", uri],
                ["mongo", "--quiet", "--eval", "db.runCommand({ping:1}).ok", uri]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "1" in r.stdout:
                return True
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None


NF_PORTS = {
    # name: (yaml file, section path to server list, default port)
    "nrf":  ("nrf.yaml",  ("nrf", "sbi", "server"),  7777),
    "scp":  ("scp.yaml",  ("scp", "sbi", "server"),  7777),
    "ausf": ("ausf.yaml", ("ausf", "sbi", "server"), 7777),
    "udm":  ("udm.yaml",  ("udm", "sbi", "server"),  7777),
    "udr":  ("udr.yaml",  ("udr", "sbi", "server"),  7777),
    "pcf":  ("pcf.yaml",  ("pcf", "sbi", "server"),  7777),
    "amf":  ("amf.yaml",  ("amf", "sbi", "server"),  7777),
    "smf":  ("smf.yaml",  ("smf", "sbi", "server"),  7777),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--open5gs-dir", default="/etc/open5gs")
    ap.add_argument("--kamailio-pcscf-dir", default="/etc/kamailio_pcscf")
    ap.add_argument("--kamailio-icscf-dir", default="/etc/kamailio_icscf")
    ap.add_argument("--kamailio-scscf-dir", default="/etc/kamailio_scscf")
    ap.add_argument("--mongo-uri", default="mongodb://localhost/open5gs")
    args = ap.parse_args()

    if not HAVE_YAML:
        print("[i] PyYAML not installed -- falling back to regex-based scanning.")
        print("    (pip install pyyaml, or apt install python3-yaml, for more accurate checks)")
    print()

    problems = []

    print("== 1. open5gs NF SBI ports ==")
    for name, (fname, path, default_port) in NF_PORTS.items():
        cfg = load_yaml(os.path.join(args.open5gs_dir, fname))
        server = get(cfg, *path, default=[{}]) if cfg else [{}]
        addr = (server[0] or {}).get("address", "127.0.0.1") if isinstance(server, list) and server else "127.0.0.1"
        port = (server[0] or {}).get("port", default_port) if isinstance(server, list) and server else default_port
        up = check_tcp(addr, port)
        status = "UP  " if up else "DOWN"
        print(f"  [{status}] {name:5s} sbi {addr}:{port}")
        if not up:
            problems.append(f"{name} SBI ({addr}:{port}) not reachable")

    print()
    print("== 2. RAN/UP-facing ports ==")
    amf_cfg = load_yaml(os.path.join(args.open5gs_dir, "amf.yaml"))
    amf_ngap = get(amf_cfg, "amf", "ngap", "server", default=[{}])
    amf_ngap_addr = (amf_ngap[0] or {}).get("address", "?") if amf_ngap else "?"
    sctp_up = check_sctp_listen(38412)
    label = "UP  " if sctp_up else ("DOWN" if sctp_up is False else "?   ")
    print(f"  [{label}] amf  ngap sctp {amf_ngap_addr}:38412")
    if sctp_up is False:
        problems.append(f"AMF NGAP (sctp {amf_ngap_addr}:38412) not listening -- a real/simulated gNB cannot attach")

    upf_cfg = load_yaml(os.path.join(args.open5gs_dir, "upf.yaml"))
    upf_gtpu = get(upf_cfg, "upf", "gtpu", "server", default=[])
    for entry in (upf_gtpu or []):
        addr = entry.get("address", "?")
        up = check_udp_listen(addr, 2152)
        label = "UP  " if up else ("DOWN" if up is False else "?   ")
        print(f"  [{label}] upf  gtpu udp {addr}:2152")

    print()
    print("== 3. Kamailio IMS ports ==")
    kamailio_ports = [
        ("p-cscf sip", args.kamailio_pcscf_dir, 5060, check_tcp),
        ("p-cscf rx (diameter)", args.kamailio_pcscf_dir, 3871, check_tcp),
        ("i-cscf sip", args.kamailio_icscf_dir, 4060, check_tcp),
        ("i-cscf cx (diameter)", args.kamailio_icscf_dir, 3869, check_tcp),
        ("s-cscf cx (diameter)", args.kamailio_scscf_dir, 3870, check_tcp),
    ]
    # Best-effort: pull the bind address out of the *.cfg listen= lines
    # (SIP ports) or the *.xml <Acceptor bind="..."/> tags (Diameter ports).
    for label, cfgdir, port, checker in kamailio_ports:
        addr = "127.0.0.1"
        found = False
        for candidate in glob.glob(os.path.join(cfgdir, "*.cfg")):
            try:
                text = open(candidate).read()
            except OSError:
                continue
            m = re.search(rf"listen\s*=\s*(?:udp|tcp):([\d.]+):{port}\b", text)
            if m:
                addr = m.group(1)
                found = True
                break
        if not found:
            for candidate in glob.glob(os.path.join(cfgdir, "*.xml")):
                try:
                    text = open(candidate).read()
                except OSError:
                    continue
                m = re.search(
                    rf'<Acceptor\s+port="{port}"\s+bind="([\d.]+)"', text)
                if m:
                    addr = m.group(1)
                    break
        up = checker(addr, port)
        status = "UP  " if up else "DOWN"
        print(f"  [{status}] {label:22s} {addr}:{port}")
        if not up:
            problems.append(f"{label} ({addr}:{port}) not reachable")

    print()
    print("== 4. MongoDB ==")
    ok = mongo_ping(args.mongo_uri)
    if ok is None:
        print(f"  [?   ] could not check ({args.mongo_uri}) -- no mongosh/mongo client found")
    else:
        print(f"  [{'UP  ' if ok else 'DOWN'}] {args.mongo_uri}")
        if not ok:
            problems.append("MongoDB not reachable -- HSS/UDR/PCRF/PCF have no subscriber data")

    print()
    print("== 5. PLMN / policy coherence ==")
    mme_cfg = load_yaml(os.path.join(args.open5gs_dir, "mme.yaml"))
    mme_plmn = find_plmn(get(mme_cfg, "mme", "gummei", default=mme_cfg))
    amf_plmn = find_plmn(get(amf_cfg, "amf", "plmn_support", default=amf_cfg))
    print(f"  MME (4G/EPC) PLMN : {mme_plmn}")
    print(f"  AMF (5G/SA)  PLMN : {amf_plmn}")
    if mme_plmn and amf_plmn and mme_plmn != amf_plmn:
        print("  [!] MME and AMF are configured for DIFFERENT PLMNs.")
        print("      Only ONE of these is the path your phone can actually use, depending")
        print("      on which RAT/PLMN it camps on. Confirm which one your phone/SIM/gNB")
        print("      is actually using before assuming the other is broken.")
        problems.append("MME PLMN != AMF PLMN (4G and 5G paths are configured for different networks)")

    pcrf_cfg = load_yaml(os.path.join(args.open5gs_dir, "pcrf.yaml"))
    pcf_cfg = load_yaml(os.path.join(args.open5gs_dir, "pcf.yaml"))
    pcrf_active = has_active_policy(pcrf_cfg)
    pcf_active = has_active_policy(pcf_cfg)
    print(f"  PCRF (4G Gx/Rx) policy active : {pcrf_active}")
    print(f"  PCF  (5G Npcf)  policy active : {pcf_active}")
    if not pcrf_active and pcf_active:
        print("  [!] Only the 5G PCF has an active IMS voice/video QoS policy.")
        print("      If your phone attaches over 4G/LTE for VoLTE, PCRF will hand out no")
        print("      QoS policy at all for the 'ims' session (no GBR bearer for voice).")
        problems.append("PCRF has no active policy while PCF does -- 4G VoLTE QoS would be unpoliced")

    print()
    if problems:
        print(f"=== {len(problems)} issue(s) found ===")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    else:
        print("=== All checks passed ===")
        sys.exit(0)


if __name__ == "__main__":
    main()
