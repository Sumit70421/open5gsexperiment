#!/usr/bin/env python3
"""
Standalone SIP REGISTER probe for a Kamailio P-CSCF/I-CSCF/S-CSCF/HSS(Cx) chain.

Purpose: answer "is my IMS core alive?" in a couple of seconds, without a
phone, gNB/eNB, or PDU session. It sends an IMS-AKA-style REGISTER (with the
empty-challenge Authorization header 3GPP TS 24.229 requires so the S-CSCF
can identify the IMPI) straight to the P-CSCF and reports how far it got:

  - No response at all           -> P-CSCF unreachable / not listening / firewalled
  - 100 Trying only, then nothing -> P-CSCF got it but I-CSCF/S-CSCF routing is broken
  - 403/404/5xx                  -> I-CSCF couldn't find/reach an S-CSCF, or S-CSCF
                                     rejected the request outright
  - 401 Unauthorized w/ a Digest challenge -> the WHOLE chain worked: P-CSCF routed
    it, I-CSCF picked an S-CSCF (via its local capability table), and the S-CSCF did
    a successful Cx Multimedia-Auth-Request/Answer against the HSS to fetch an
    authentication vector. This is the strongest possible signal that the IMS core
    itself is healthy -- everything after this point is UE-side credentials.
  - 200 OK (only reachable if --password is given and the challenge algorithm is
    plain MD5, not AKAv1-MD5) -> fully registered.

This script does NOT implement AKA/MILENAGE, so it cannot complete a real IMS-AKA
registration on its own (that requires computing RES from the subscriber's K/OPc).
That's fine for its purpose: reaching the 401 challenge already proves the core
signaling path end-to-end. If your S-CSCF is configured for plain MD5 test auth
instead of AKA, pass --password and it will complete the full REGISTER.

Usage examples:
  # Bare probe against the P-CSCF, IPv4 UDP (matches a typical open5gs+Kamailio lab)
  ./register_test.py --pcscf 172.17.9.48 --domain ims.mnc001.mcc001.3gppnetwork.org \\
      --impi 001010000000001@ims.mnc001.mcc001.3gppnetwork.org

  # Bind the probe to the tun interface UERANSIM created after a PDU session,
  # so the REGISTER looks exactly like it came from the simulated UE:
  ./register_test.py --pcscf 172.17.9.48 --domain ims.mnc001.mcc001.3gppnetwork.org \\
      --impi 001010000000001@ims.mnc001.mcc001.3gppnetwork.org \\
      --local-ip 10.46.0.2

No third-party dependencies -- stdlib only.
"""
import argparse
import random
import re
import socket
import string
import sys
import time
import hashlib


def rand_str(n=10):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def build_register(domain, impi, impu, local_ip, local_port, branch, call_id,
                    cseq, tag, contact_expires, auth_header=None):
    uri = f"sip:{domain}"
    lines = [
        f"REGISTER {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        f"Max-Forwards: 70",
        f"From: <sip:{impi}>;tag={tag}",
        f"To: <{impu}>",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{impi.split('@')[0]}@{local_ip}:{local_port}>;expires={contact_expires}",
        f"Supported: path",
        f"User-Agent: open5gs-volte-stub/register_test.py",
        f"Content-Length: 0",
    ]
    if auth_header:
        lines.append(auth_header)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse_status(data):
    text = data.decode(errors="replace")
    m = re.match(r"SIP/2\.0\s+(\d{3})\s+(.*)", text)
    if not m:
        return None, None, text
    return int(m.group(1)), m.group(2).strip(), text


def parse_www_authenticate(text):
    m = re.search(r"WWW-Authenticate:\s*(.*)", text, re.IGNORECASE)
    if not m:
        return None
    header = m.group(1)
    fields = {}
    for key, quoted, inner in re.findall(r'(\w+)=("([^"]*)"|[^,\s]+)', header):
        fields[key] = inner if quoted.startswith('"') else quoted
    return fields


def md5_digest_response(username, realm, password, method, uri, nonce):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def initial_auth_header(username, realm, uri):
    # Per 3GPP TS 24.229, even the FIRST (unauthenticated) REGISTER in IMS-AKA
    # carries an Authorization header with empty nonce/response -- unlike plain
    # RFC 3261 digest auth, where the first request normally has none at all.
    # Kamailio's S-CSCF (ims_registrar_scscf) reads the "username" out of this
    # header to know which IMPI to fetch a Cx auth vector for; without it, it
    # rejects with 403 "Private identity not found" before ever reaching Cx.
    return (f'Authorization: Digest username="{username}", realm="{realm}", '
            f'nonce="", uri="{uri}", response=""')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcscf", required=True, help="P-CSCF IP (e.g. 172.17.9.48)")
    ap.add_argument("--port", type=int, default=5060, help="P-CSCF SIP port (default 5060)")
    ap.add_argument("--domain", required=True,
                     help="IMS home domain, e.g. ims.mnc001.mcc001.3gppnetwork.org")
    ap.add_argument("--impi", required=True,
                     help="Private user identity, e.g. 001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
    ap.add_argument("--impu", default=None,
                     help="Public user identity (default: sip:<impi-user>@<domain>)")
    ap.add_argument("--local-ip", default=None,
                     help="Local source IP to bind/advertise (e.g. the UE's PDU session "
                          "address from UERANSIM). Defaults to auto-detected outbound IP.")
    ap.add_argument("--local-port", type=int, default=0, help="Local UDP port (0 = OS picks one)")
    ap.add_argument("--password", default=None,
                     help="If the S-CSCF challenge uses plain MD5 (not AKAv1-MD5), complete "
                          "the REGISTER with this password.")
    ap.add_argument("--timeout", type=float, default=4.0, help="Per-request timeout in seconds")
    ap.add_argument("-v", "--verbose", action="store_true", help="Dump raw SIP messages")
    args = ap.parse_args()

    impu = args.impu or f"sip:{args.impi.split('@')[0]}@{args.domain}"
    if not impu.startswith("sip:"):
        impu = f"sip:{impu}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    if args.local_ip:
        sock.bind((args.local_ip, args.local_port))
    else:
        # Bind to whatever local interface the OS would use to reach the P-CSCF,
        # so Contact/Via carry a real routable address instead of 0.0.0.0.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((args.pcscf, args.port))
        auto_ip = probe.getsockname()[0]
        probe.close()
        sock.bind((auto_ip, args.local_port))
    local_ip, local_port = sock.getsockname()

    print(f"[*] Local endpoint : {local_ip}:{local_port}")
    print(f"[*] Target P-CSCF  : {args.pcscf}:{args.port} (UDP)")
    print(f"[*] Domain         : {args.domain}")
    print(f"[*] IMPI / IMPU    : {args.impi} / {impu}")
    print()

    call_id = f"{rand_str(16)}@{local_ip}"
    tag = rand_str(8)
    cseq = 1

    def send_recv(auth_header=None):
        nonlocal cseq
        branch = "z9hG4bK" + rand_str(12)
        msg = build_register(args.domain, args.impi, impu, local_ip, local_port,
                              branch, call_id, cseq, tag, 600, auth_header)
        cseq += 1
        if args.verbose:
            print("---- sending ----")
            print(msg.decode())
        sock.sendto(msg, (args.pcscf, args.port))
        t0 = time.time()
        replies = []
        try:
            while True:
                remaining = args.timeout - (time.time() - t0)
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                data, _ = sock.recvfrom(65535)
                code, reason, text = parse_status(data)
                replies.append((code, reason, text))
                if args.verbose:
                    print("---- received ----")
                    print(text)
                if code is not None and code >= 200:
                    break
        except socket.timeout:
            pass
        return replies

    print("[1/2] Sending initial REGISTER (Authorization header with empty challenge, per IMS-AKA) ...")
    # Per 3GPP TS 24.229, the private user identity is a NAI (RFC 4282) --
    # i.e. the FULL "user@realm" string -- and that's what's stored verbatim
    # in the HSS's private-identity table. Using just the user part here
    # (like a generic SIP digest username) makes the lookup fail even when
    # the subscriber is provisioned correctly.
    initial_header = initial_auth_header(args.impi, args.domain, f"sip:{args.domain}")
    replies = send_recv(initial_header)
    if not replies:
        print("[FAIL] No response at all from the P-CSCF.")
        print("       -> Check the P-CSCF process is running and listening on")
        print(f"          udp:{args.pcscf}:{args.port}, and that nothing (firewall,")
        print("          wrong interface bind) is dropping the packet.")
        sys.exit(2)

    final = replies[-1]
    provisional = [r for r in replies if r[0] is not None and r[0] < 200]
    for code, reason, _ in provisional:
        print(f"       <- {code} {reason} (provisional)")

    code, reason, text = final
    if code is None:
        print("[FAIL] Got a reply that doesn't parse as a SIP status line.")
        sys.exit(2)

    print(f"       <- {code} {reason}")

    if code == 401 or code == 407:
        auth = parse_www_authenticate(text)
        print()
        print("[OK] Received a challenge -- P-CSCF -> I-CSCF -> S-CSCF -> HSS (Cx) chain")
        print("     is up and the S-CSCF successfully pulled an auth vector for this IMPI.")
        if auth:
            print(f"     realm={auth.get('realm')}  algorithm={auth.get('algorithm')}  "
                  f"qop={auth.get('qop')}")
        algorithm = (auth or {}).get("algorithm", "").upper()
        if algorithm.startswith("AKAV1"):
            print()
            print("     Challenge algorithm is AKAv1-MD5, so completing the REGISTER needs")
            print("     real AKA math (K/OPc -> MILENAGE -> RES) which this stub does not")
            print("     implement. That's fine -- you've already proven the core chain works.")
            print("     Use --password only if you reconfigure the S-CSCF for plain MD5 test")
            print("     auth, or use the UERANSIM flow for a real end-to-end attach + REGISTER.")
        elif args.password and auth:
            print()
            print("[2/2] Retrying REGISTER with MD5 digest credentials ...")
            username = args.impi  # full IMPI (NAI), same reasoning as above
            realm = auth.get("realm", args.domain)
            nonce = auth.get("nonce", "")
            uri = f"sip:{args.domain}"
            response = md5_digest_response(username, realm, args.password, "REGISTER", uri, nonce)
            auth_header = (
                f'Authorization: Digest username="{username}", realm="{realm}", '
                f'nonce="{nonce}", uri="{uri}", response="{response}", algorithm=MD5'
            )
            replies2 = send_recv(auth_header)
            if not replies2:
                print("[FAIL] No response to the authenticated REGISTER.")
                sys.exit(2)
            code2, reason2, _ = replies2[-1]
            print(f"       <- {code2} {reason2}")
            if code2 == 200:
                print()
                print("[OK] Fully registered (200 OK). IMS core end-to-end path confirmed.")
            else:
                print()
                print(f"[FAIL] Authenticated REGISTER was rejected ({code2} {reason2}).")
                print("       Check the password / subscriber provisioning against the HSS.")
                sys.exit(1)
        sys.exit(0)

    if code == 200:
        print("[OK] 200 OK on an unauthenticated REGISTER -- unusual (no auth required),")
        print("     but the core chain is clearly working end-to-end.")
        sys.exit(0)

    print()
    print(f"[FAIL] Unexpected final response: {code} {reason}")
    if code in (403, 404):
        print("       -> Likely I-CSCF could not find/route to an S-CSCF for this domain")
        print("          (check icscf.sql s_cscf table), or S-CSCF rejected the IMPU/IMPI")
        print("          outright (not provisioned in the HSS).")
    elif 500 <= code < 600:
        print("       -> Server-side failure downstream of P-CSCF -- check I-CSCF/S-CSCF")
        print("          logs and the Cx Diameter connection between S-CSCF and the HSS")
        print("          (realm/FQDN mismatch is the most common cause).")
    sys.exit(1)


if __name__ == "__main__":
    main()
