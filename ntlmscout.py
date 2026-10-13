#!/usr/bin/env python3
"""
ntlmscout.py  --  Exposed NTLM endpoint information-disclosure enumerator.

Sends an unauthenticated NTLM Type-1 (NEGOTIATE) message across a range of
transports and fully parses the Type-2 (CHALLENGE) the server returns, squeezing
out every field: NetBIOS/DNS host + domain + forest names, OS build -> product,
server clock (time skew), negotiate flags, and every AV_PAIR.

Transports: HTTP(S) (+ endpoint discovery), SMB2/3, MSSQL/TDS, SMTP, IMAP, POP3,
NNTP, LDAP(S), RDP/CredSSP(NLA).

Pure standard library. Python 3.7+.

  Examples:
    python3 ntlmscout.py mail.example.com
    python3 ntlmscout.py https://mail.example.com/ews/
    python3 ntlmscout.py smb://10.0.0.5
    python3 ntlmscout.py -I targets.txt 10.0.0.0/24 --json results.json
    python3 ntlmscout.py --spray -I hosts.txt -u users.txt -p passwords.txt
"""

import argparse
import base64
import binascii
import concurrent.futures
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import traceback
import uuid
from collections import OrderedDict

NTLMSSP_SIG = b"NTLMSSP\x00"
UTC = datetime.timezone.utc

# Runtime toggles, set once from CLI flags in main(): TLS verification (off by
# default -- targets routinely use internal/self-signed certs), debug output,
# and an optional HTTP CONNECT proxy (host, port) that all TCP connects tunnel
# through. SOCKS is not supported (no stdlib SOCKS client).
_VERIFY_TLS = False
_DEBUG = False
_PROXY = None  # (host, port) or None


def _tls_context():
    """Single source of truth for TLS behaviour. Verification off unless
    --verify-tls; when off we're deliberately permissive (legacy TLS versions
    and weak ciphers) so we can still hand-shake with old/hardened LDAPS and the
    like -- we're fingerprinting, not protecting data."""
    ctx = ssl.create_default_context()
    if not _VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            pass
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def _tcp_connect(host, port, timeout):
    """Open a TCP socket, tunnelling through the HTTP CONNECT proxy if one is set."""
    if not _PROXY:
        return socket.create_connection((host, port), timeout=timeout)
    sock = socket.create_connection(_PROXY, timeout=timeout)
    sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                  % (host, port, host, port)).encode())
    sock.settimeout(timeout)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(1)
        if not chunk:
            break
        resp += chunk
        if len(resp) > 8192:
            break
    status_line = resp.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line:
        raise OSError("proxy CONNECT failed: %r" % status_line)
    return sock


def _proxy_url():
    """The proxy as a URL string (for urllib), or None."""
    return "http://%s:%d" % _PROXY if _PROXY else None


# Planning budget.  What exhausts memory is not the address count but the
# post-fan-out *probe* count: one bare host fans out to ~368 probes by default
# (23 ports, 6 of them web x the HTTP path wordlist, plus the internal-address
# disclosure checks), so a /16 projects to ~24M probes.  Planning is streamed in
# batches (see iter_job_batches), so the plan no longer has to fit in memory;
# this budget refuses runs whose result set and runtime would be absurd anyway.
_MAX_JOBS = 500000          # override with --max-jobs (0 = unlimited)


def _as_network(t):
    """Parse a bare CIDR token into an ip_network, or None if it isn't one."""
    if "://" in t or "/" not in t or t.startswith("["):
        return None
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None


def _host_count(t):
    """How many hosts a target token expands to, without enumerating them."""
    net = _as_network(t)
    if net is None:
        return 1
    n = net.num_addresses
    if n <= 2:                                   # /31, /32 and v6 equivalents
        return n
    return n - 1 if net.version == 6 else n - 2  # .hosts() drops network/broadcast


def _expand_targets(raw):
    """Expand any bare CIDR entries (e.g. 10.0.0.0/24, 2001:db8::/120) into host
    IPs.  A generator: a large prefix is never materialized as a list."""
    for t in raw:
        net = _as_network(t)
        if net is None:
            yield t
            continue
        empty = True
        for ip in net.hosts():
            empty = False
            yield str(ip)
        if empty:                                # nets whose .hosts() is empty
            for ip in net:
                yield str(ip)


def _split_host_port(token):
    """Split a target into (host, port|None), handling IPv6 literals.

    Accepts 'host', 'host:port', '[2001:db8::1]', '[2001:db8::1]:445', and a
    bare 'fe80::1' (no port -- unbracketed IPv6 can't carry one)."""
    token = token.strip()
    if token.startswith("["):                      # [ipv6] or [ipv6]:port
        host, _sep, rest = token[1:].partition("]")
        port = int(rest[1:]) if rest[:1] == ":" and rest[1:].isdigit() else None
        return host, port
    if token.count(":") == 1:                       # host:port or ipv4:port
        h, p = token.rsplit(":", 1)
        return (h, int(p)) if p.isdigit() else (token, None)
    return token, None                              # bare host / ipv4 / ipv6


def _url_host(host):
    """Bracket an IPv6 literal for use inside a URL; pass through otherwise."""
    return "[%s]" % host if ":" in host else host


def _dbg(where):
    """When --debug is set, surface the current exception instead of silently swallowing it."""
    if _DEBUG:
        sys.stderr.write("[debug] %s: %s\n" % (where, traceback.format_exc().strip().splitlines()[-1]))


def _secure_open(path, newline=None):
    """Open a file for writing with owner-only perms -- outputs can hold internal
    hostnames/IPs or (in spray) plaintext credentials, so don't leave them world-readable."""
    fh = open(path, "w", newline=newline)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return fh


# ANSI colors (applied only when writing to an interactive terminal).
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def _color(s, code, enable):
    return code + s + C_RESET if enable else s


def _use_color(stream):
    """True if the stream is an interactive terminal (so ANSI codes are safe)."""
    return hasattr(stream, "isatty") and stream.isatty()


BANNER = r"""
          __  __                                __
   ____  / /_/ /___ ___  ______________  __  __/ /_
  / __ \/ __/ / __ `__ \/ ___/ ___/ __ \/ / / / __/
 / / / / /_/ / / / / / (__  ) /__/ /_/ / /_/ / /_
/_/ /_/\__/_/_/ /_/ /_/____/\___/\____/\__,_/\__/
"""


def print_banner(quiet=False):
    if quiet:
        return
    tty = _use_color(sys.stderr)
    sys.stderr.write(_color(BANNER, C_CYAN, tty) + "\n")
    sys.stderr.write(_color("   hunting exposed NTLM", C_BOLD, tty) + "\n")
    sys.stderr.write(_color("   BoydHacks  ·  github.com/BoydHacks", C_DIM, tty) + "\n\n")


# ---------------------------------------------------------------------------
#  Minimal DER (ASN.1) helpers  -- used for SPNEGO / LDAP / CredSSP wrapping
# ---------------------------------------------------------------------------
def der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _read_asn1_len(b, i):
    """Decode a DER/BER length at b[i]; return (length, index_after_length)."""
    n = b[i]; i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(b[i:i + k], "big"), i + k


def der(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def der_int(n):
    if n == 0:
        return der(0x02, b"\x00")
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return der(0x02, out)


def der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    first = 40 * parts[0] + parts[1]
    body = bytes([first])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
            continue
        stack = []
        while p:
            stack.insert(0, p & 0x7F)
            p >>= 7
        for i in range(len(stack) - 1):
            stack[i] |= 0x80
        body += bytes(stack)
    return der(0x06, body)


OID_SPNEGO = "1.3.6.1.5.5.2"
OID_NTLMSSP = "1.3.6.1.4.1.311.2.2.10"


def spnego_neg_token_init(ntlm_token):
    """Wrap a raw NTLMSSP token in a GSSAPI/SPNEGO NegTokenInit (SMB/LDAP/RDP)."""
    mech_types = der(0xA0, der(0x30, der_oid(OID_NTLMSSP)))
    mech_token = der(0xA2, der(0x04, ntlm_token))
    neg_token_init = der(0xA0, der(0x30, mech_types + mech_token))
    inner = der_oid(OID_SPNEGO) + neg_token_init
    return der(0x60, inner)  # [APPLICATION 0]


# ---------------------------------------------------------------------------
#  NTLM Type-1 (NEGOTIATE) builder
# ---------------------------------------------------------------------------
# Battle-tested flag set used by NTLMRecon / Metasploit / nuclei:
# UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXT_SESSION_SEC |
# VERSION | 128 | KEY_EXCH | 56.  Setting VERSION + a stamped version block
# reliably coaxes the server to include its own VERSION in the CHALLENGE.
DEFAULT_TYPE1_FLAGS = 0xE2088207
FLAG_VERSION = 0x02000000


def build_type1(flags=DEFAULT_TYPE1_FLAGS, with_version=None):
    """Build a raw NTLM Type-1 (NEGOTIATE) message to send to the server."""
    if with_version is None:
        with_version = bool(flags & FLAG_VERSION)
    msg = bytearray()
    msg += NTLMSSP_SIG
    msg += struct.pack("<I", 1)          # MessageType = 1
    msg += struct.pack("<I", flags)      # NegotiateFlags
    msg += struct.pack("<HHI", 0, 0, 0)  # DomainName fields (empty)
    msg += struct.pack("<HHI", 0, 0, 0)  # Workstation fields (empty)
    if with_version:
        # ProductMajor.Minor.Build + reserved + NTLMRevision(0x0f).  10.0.19041.
        msg += bytes([10, 0]) + struct.pack("<H", 19041) + b"\x00\x00\x00" + b"\x0f"
    return bytes(msg)


TYPE1_B64 = base64.b64encode(build_type1()).decode()


# ---------------------------------------------------------------------------
#  NTLM Type-2 (CHALLENGE) parser  -- the heart of the tool
# ---------------------------------------------------------------------------
NEGOTIATE_FLAGS = OrderedDict([
    ("NTLMSSP_NEGOTIATE_UNICODE", 0x00000001),
    ("NTLM_NEGOTIATE_OEM", 0x00000002),
    ("NTLMSSP_REQUEST_TARGET", 0x00000004),
    ("NTLMSSP_NEGOTIATE_SIGN", 0x00000010),
    ("NTLMSSP_NEGOTIATE_SEAL", 0x00000020),
    ("NTLMSSP_NEGOTIATE_DATAGRAM", 0x00000040),
    ("NTLMSSP_NEGOTIATE_LM_KEY", 0x00000080),
    ("NTLMSSP_NEGOTIATE_NTLM", 0x00000200),
    ("NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED", 0x00001000),
    ("NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED", 0x00002000),
    ("NTLMSSP_NEGOTIATE_ALWAYS_SIGN", 0x00008000),
    ("NTLMSSP_TARGET_TYPE_DOMAIN", 0x00010000),
    ("NTLMSSP_TARGET_TYPE_SERVER", 0x00020000),
    ("NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY", 0x00080000),
    ("NTLMSSP_NEGOTIATE_IDENTIFY", 0x00100000),
    ("NTLMSSP_REQUEST_NON_NT_SESSION_KEY", 0x00400000),
    ("NTLMSSP_NEGOTIATE_TARGET_INFO", 0x00800000),
    ("NTLMSSP_NEGOTIATE_VERSION", 0x02000000),
    ("NTLMSSP_NEGOTIATE_128", 0x20000000),
    ("NTLMSSP_NEGOTIATE_KEY_EXCH", 0x40000000),
    ("NTLMSSP_NEGOTIATE_56", 0x80000000),
])

AV_IDS = {
    0x0000: "MsvAvEOL",
    0x0001: "MsvAvNbComputerName",
    0x0002: "MsvAvNbDomainName",
    0x0003: "MsvAvDnsComputerName",
    0x0004: "MsvAvDnsDomainName",
    0x0005: "MsvAvDnsTreeName",
    0x0006: "MsvAvFlags",
    0x0007: "MsvAvTimestamp",
    0x0008: "MsvAvSingleHost",
    0x0009: "MsvAvTargetName",
    0x000A: "MsvAvChannelBindings",
}

# build -> (client_name, server_name).  server_name None => client-only build.
BUILD_MAP = {
    2600: ("Windows XP", None),
    3790: ("Windows XP x64", "Windows Server 2003 / 2003 R2"),
    6000: ("Windows Vista", None),
    6001: ("Windows Vista SP1", "Windows Server 2008"),
    6002: ("Windows Vista SP2", "Windows Server 2008 SP2"),
    7600: ("Windows 7", "Windows Server 2008 R2"),
    7601: ("Windows 7 SP1", "Windows Server 2008 R2 SP1"),
    9200: ("Windows 8", "Windows Server 2012"),
    9600: ("Windows 8.1", "Windows Server 2012 R2"),
    10240: ("Windows 10 1507", None),
    10586: ("Windows 10 1511", None),
    14393: ("Windows 10 1607", "Windows Server 2016"),
    15063: ("Windows 10 1703", None),
    16299: ("Windows 10 1709", "Windows Server 1709"),
    17134: ("Windows 10 1803", "Windows Server 1803"),
    17763: ("Windows 10 1809", "Windows Server 2019"),
    18362: ("Windows 10 1903", None),
    18363: ("Windows 10 1909", None),
    19041: ("Windows 10 2004", None),
    19042: ("Windows 10 20H2", None),
    19043: ("Windows 10 21H1", None),
    19044: ("Windows 10 21H2", None),
    19045: ("Windows 10 22H2", None),
    20348: (None, "Windows Server 2022"),
    22000: ("Windows 11 21H2", None),
    22621: ("Windows 11 22H2", None),
    22631: ("Windows 11 23H2", None),
    25398: (None, "Windows Server 23H2"),
    26100: ("Windows 11 24H2", "Windows Server 2025"),
    26200: ("Windows 11 25H2", None),
}


def _u(b):  # decode UTF-16LE-ish
    try:
        return b.decode("utf-16-le")
    except UnicodeDecodeError:
        return b.decode("latin-1", "replace")


def parse_version(vb, target_type=None):
    if len(vb) < 8 or vb[:8] == b"\x00" * 8:
        return None
    major, minor = vb[0], vb[1]
    build = struct.unpack("<H", vb[2:4])[0]
    ntlm_rev = vb[7]
    client, server = BUILD_MAP.get(build, (None, None))
    if client is None and server is None:
        approx = {(5, 1): ("Windows XP", None), (5, 2): (None, "Windows Server 2003"),
                  (6, 0): ("Windows Vista", "Windows Server 2008"),
                  (6, 1): ("Windows 7", "Windows Server 2008 R2"),
                  (6, 2): ("Windows 8", "Windows Server 2012"),
                  (6, 3): ("Windows 8.1", "Windows Server 2012 R2"),
                  (10, 0): ("Windows 10/11", "Windows Server 2016+")}
        client, server = approx.get((major, minor), ("Unknown", None))
    # Disambiguate using the NTLM target type when the build is shared.
    if client and server:
        if target_type == "domain":
            product = server
        elif target_type == "server":
            product = client
        else:
            product = "{} / {}".format(client, server)
    else:
        product = client or server
    return {"major": major, "minor": minor, "build": build,
            "ntlm_revision": ntlm_rev, "product": product,
            "client_candidate": client, "server_candidate": server,
            "string": "{}.{}.{} ({})".format(major, minor, build, product)}


def filetime_to_dt(ft):
    # 100ns ticks since 1601-01-01 UTC
    return datetime.datetime(1601, 1, 1, tzinfo=UTC) + datetime.timedelta(microseconds=ft / 10)


def parse_target_info(ti):
    pairs = OrderedDict()
    raw_pairs = []
    off = 0
    while off + 4 <= len(ti):
        av_id, av_len = struct.unpack("<HH", ti[off:off + 4])
        val = ti[off + 4:off + 4 + av_len]
        off += 4 + av_len
        name = AV_IDS.get(av_id, "AvId_0x%04x" % av_id)
        if av_id == 0x0000:
            break
        if av_id in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0009):
            pairs[name] = _u(val)
        elif av_id == 0x0006:
            fl = struct.unpack("<I", val.ljust(4, b"\x00")[:4])[0]
            meanings = []
            if fl & 0x1: meanings.append("account auth constrained")
            if fl & 0x2: meanings.append("client provides MIC")
            if fl & 0x4: meanings.append("SPN from untrusted source")
            pairs[name] = {"value": fl, "flags": meanings}
        elif av_id == 0x0007:
            ft = struct.unpack("<Q", val.ljust(8, b"\x00")[:8])[0]
            dt = filetime_to_dt(ft)
            pairs[name] = {"filetime": ft, "utc": dt.strftime("%Y-%m-%d %H:%M:%S.%f")}
        elif av_id == 0x0008:  # Single_Host_Data: Size(4) Z4(4) CustomData(8) MachineID(32)
            mid = val[16:48] if len(val) >= 48 else b""
            pairs[name] = ({"machine_id": binascii.hexlify(mid).decode()} if mid
                           else {"raw": binascii.hexlify(val).decode()})
        elif av_id == 0x000A:
            hexed = binascii.hexlify(val).decode()
            pairs[name] = {"hash": hexed,
                           "present": any(b for b in val)}  # non-zero => EPA/CB in play
        else:
            pairs[name] = binascii.hexlify(val).decode()
        raw_pairs.append((name, av_id, binascii.hexlify(val).decode()))
    return pairs, raw_pairs


def parse_challenge(blob):
    """Parse an NTLMSSP CHALLENGE (Type-2). `blob` starts at the NTLMSSP signature."""
    if len(blob) < 48 or not blob.startswith(NTLMSSP_SIG):
        raise ValueError("not an NTLMSSP message")
    msg_type = struct.unpack("<I", blob[8:12])[0]
    if msg_type != 2:
        raise ValueError("not a CHALLENGE message (type=%d)" % msg_type)
    tn_len, tn_max, tn_off = struct.unpack("<HHI", blob[12:20])
    flags = struct.unpack("<I", blob[20:24])[0]
    server_challenge = blob[24:32]
    ti_len, ti_max, ti_off = struct.unpack("<HHI", blob[40:48])
    target_type = None
    if flags & 0x00010000:
        target_type = "domain"
    elif flags & 0x00020000:
        target_type = "server"
    version = parse_version(blob[48:56], target_type) if len(blob) >= 56 else None
    target_name = None
    if tn_len and tn_off + tn_len <= len(blob):
        tn = blob[tn_off:tn_off + tn_len]
        target_name = _u(tn) if flags & 0x1 else tn.decode("latin-1", "replace")
    target_info, raw_pairs = (OrderedDict(), [])
    if ti_len and ti_off + ti_len <= len(blob):
        target_info, raw_pairs = parse_target_info(blob[ti_off:ti_off + ti_len])
    flag_names = [n for n, v in NEGOTIATE_FLAGS.items() if flags & v]
    return {
        "target_name": target_name,
        "target_type": target_type,
        "server_challenge": binascii.hexlify(server_challenge).decode(),
        "negotiate_flags": flags,
        "negotiate_flag_names": flag_names,
        "version": version,
        "target_info": target_info,
        "raw_av_pairs": raw_pairs,
        "raw_blob_b64": base64.b64encode(blob).decode(),
    }


def extract_ntlm_blob(raw):
    """Find the NTLMSSP Type-2 signature inside an arbitrary byte buffer."""
    idx = raw.find(NTLMSSP_SIG)
    if idx == -1:
        return None
    return raw[idx:]


# ---------------------------------------------------------------------------
#  Transport handlers.  Each returns a raw byte buffer containing the Type-2,
#  or None. `extract_ntlm_blob` then locates the NTLMSSP signature.
# ---------------------------------------------------------------------------
def _recv_some(sock, n=8192, timeout=8):
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except socket.timeout:
        return b""


def _read_line(sock, timeout=8):
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


# ---- HTTP / HTTPS ---------------------------------------------------------
import urllib.request
import urllib.error


# Unauthenticated HTTP response headers that leak internal Exchange/IIS
# server names (present even on the 401). X-CalculatedBETarget / X-FEServer /
# X-BEServer / X-DiagInfo carry internal FE/BE mailbox server FQDNs.
_EXCHANGE_NAME_HDRS = ["X-FEServer", "X-CalculatedBETarget", "X-BEServer", "X-DiagInfo"]
_EXCHANGE_INFO_HDRS = ["X-OWA-Version", "X-AspNet-Version", "X-Powered-By", "Server"]


def _http_fetch(url, host_header=None, timeout=10):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "NTLM " + TYPE1_B64)
    req.add_header("User-Agent", "Mozilla/5.0 (ntlmscout)")
    if host_header:
        req.add_header("Host", host_header)
    try:
        if _PROXY:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": _proxy_url(), "https": _proxy_url()}),
                urllib.request.HTTPSHandler(context=_tls_context()))
            resp = opener.open(req, timeout=timeout)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=_tls_context())
        return resp.headers
    except urllib.error.HTTPError as e:
        return e.headers  # 401 lands here, which is what we want
    except Exception:
        _dbg("http %s" % url)
        return None


def _ntlm_from_headers(headers):
    auth_vals = []
    if hasattr(headers, "get_all"):
        auth_vals = headers.get_all("WWW-Authenticate") or []
    if not auth_vals:
        one = headers.get("WWW-Authenticate")
        if one:
            auth_vals = [one]
    for auth in auth_vals:
        m = re.search(r"(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", auth)
        if m:
            try:
                return base64.b64decode(m.group(1))
            except binascii.Error:
                continue
    return None


def http_challenge(url, host_header=None, timeout=10):
    headers = _http_fetch(url, host_header, timeout)
    return _ntlm_from_headers(headers) if headers else None


def http_probe(url, host_header=None, timeout=10):
    """Return (ntlm_blob_or_None, {name_headers}, {info_headers}, responded).

    ``responded`` is False only when the request never got an HTTP response at
    all -- timeout, reset, TLS failure, rate-limit drop. A 401/404/200 without a
    challenge *is* an answer and reports True. That distinction is what lets the
    catch-all guard tell "this path is not protected" apart from "we never found
    out", instead of treating both as proof the host is path-specific."""
    headers = _http_fetch(url, host_header, timeout)
    if headers is None:
        return None, {}, {}, False
    blob = _ntlm_from_headers(headers)
    names = {k: headers.get(k) for k in _EXCHANGE_NAME_HDRS if headers.get(k)}
    info = {k: headers.get(k) for k in _EXCHANGE_INFO_HDRS if headers.get(k)}
    return blob, names, info, True


# ---- Line-based SASL: SMTP / IMAP / POP3 / NNTP ---------------------------
def _connect(host, port, use_tls=False, timeout=8):
    sock = _tcp_connect(host, port, timeout)
    if use_tls:
        sock = _tls_context().wrap_socket(sock, server_hostname=host)
    return sock


def _starttls(sock, host):
    return _tls_context().wrap_socket(sock, server_hostname=host)


def _b64d(data):
    return base64.b64decode(data)


def smtp_challenge(host, port=25, use_tls=False, timeout=8):
    """EHLO (+STARTTLS), then AUTH NTLM; return the raw Type-2 from the 334 reply."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        _recv_some(sock)  # banner
        sock.sendall(b"EHLO ntlmscout\r\n")
        ehlo = _recv_some(sock)
        if not use_tls and b"STARTTLS" in ehlo.upper():
            sock.sendall(b"STARTTLS\r\n")
            _recv_some(sock)
            sock = _starttls(sock, host)
            sock.sendall(b"EHLO ntlmscout\r\n")
            _recv_some(sock)
        # Inline (SASL-IR) first.
        sock.sendall(b"AUTH NTLM " + TYPE1_B64.encode() + b"\r\n")
        resp = _read_line(sock)
        m = re.search(rb"334\s+([A-Za-z0-9+/=]+)", resp)
        if m:
            return _b64d(m.group(1))
        # Two-step fallback.
        if resp.startswith(b"334"):
            sock.sendall(TYPE1_B64.encode() + b"\r\n")
            resp = _read_line(sock)
            m = re.search(rb"334\s+([A-Za-z0-9+/=]+)", resp)
            if m:
                return _b64d(m.group(1))
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    return None


def imap_challenge(host, port=143, use_tls=False, timeout=8):
    """(STARTTLS then) AUTHENTICATE NTLM; return the raw Type-2 from the '+' reply."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        _recv_some(sock)
        if not use_tls:
            sock.sendall(b"a0 STARTTLS\r\n")
            r = _recv_some(sock)
            if b"OK" in r:
                try:
                    sock = _starttls(sock, host)
                except Exception:
                    pass
        sock.sendall(b"a1 AUTHENTICATE NTLM\r\n")
        cont = _read_line(sock)
        if not cont.startswith(b"+"):
            return None
        sock.sendall(TYPE1_B64.encode() + b"\r\n")
        resp = _read_line(sock)
        m = re.search(rb"\+\s+([A-Za-z0-9+/=]+)", resp)
        if m:
            return _b64d(m.group(1))
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    return None


def pop3_challenge(host, port=110, use_tls=False, timeout=8):
    """(STLS then) AUTH NTLM; return the raw Type-2 from the '+' continuation."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        _recv_some(sock)
        if not use_tls:
            sock.sendall(b"STLS\r\n")
            r = _read_line(sock)
            if r.startswith(b"+OK"):
                try:
                    sock = _starttls(sock, host)
                except Exception:
                    pass
        sock.sendall(b"AUTH NTLM\r\n")
        cont = _read_line(sock)
        if not cont.startswith(b"+"):
            return None
        sock.sendall(TYPE1_B64.encode() + b"\r\n")
        resp = _read_line(sock)
        m = re.search(rb"\+\s+([A-Za-z0-9+/=]+)", resp)
        if m:
            return _b64d(m.group(1))
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    return None


def nntp_challenge(host, port=119, use_tls=False, timeout=8):
    """AUTHINFO GENERIC/SASL NTLM; return the raw Type-2 from the 381/383 reply."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        _recv_some(sock)
        # Primary: AUTHINFO GENERIC NTLM (nmap-proven; 381 continuation).
        sock.sendall(b"AUTHINFO GENERIC NTLM\r\n")
        resp = _read_line(sock)
        if resp.startswith(b"381"):
            sock.sendall(TYPE1_B64.encode() + b"\r\n")
            resp = _read_line(sock)
            m = re.search(rb"38[13]\s+([A-Za-z0-9+/=]+)", resp)
            if m:
                return _b64d(m.group(1))
        # Fallback: RFC 4643 SASL (383 continuation, inline IR).
        sock.sendall(b"AUTHINFO SASL NTLM " + TYPE1_B64.encode() + b"\r\n")
        resp = _read_line(sock)
        m = re.search(rb"383\s+([A-Za-z0-9+/=]+)", resp)
        if m:
            return _b64d(m.group(1))
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    return None


# ---- SMB2/3 ---------------------------------------------------------------
def smb_challenge(host, port=445, timeout=8):
    """SMB2 NEGOTIATE + SESSION_SETUP (SPNEGO); return the raw Type-2 challenge."""
    sock = _tcp_connect(host, port, timeout)
    try:
        sock.sendall(_smb2_negotiate_request())
        _smb_recv(sock)
        sock.sendall(_smb2_session_setup_request())
        resp = _smb_recv(sock)
        return extract_ntlm_blob(resp)
    except Exception:
        _dbg("smb %s:%s" % (host, port))
        return None
    finally:
        try: sock.close()
        except Exception: pass


def _smb_recv(sock, timeout=8):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            return b""
        hdr += c
    length = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
    data = b""
    while len(data) < length:
        c = sock.recv(length - len(data))
        if not c:
            break
        data += c
    return data


def _nbss(payload):
    return struct.pack(">I", len(payload)) + payload


def _smb2_header(command, message_id):
    h = bytearray(64)
    h[0:4] = b"\xfeSMB"
    struct.pack_into("<H", h, 4, 64)        # StructureSize
    struct.pack_into("<H", h, 6, 1)         # CreditCharge
    struct.pack_into("<H", h, 12, command)  # Command
    struct.pack_into("<H", h, 14, 31)       # Credits requested
    struct.pack_into("<Q", h, 24, message_id)
    struct.pack_into("<I", h, 32, 0xFEFF)   # ProcessId
    return bytes(h)


def _smb2_negotiate_request():
    hdr = _smb2_header(0x0000, 0)
    body = struct.pack("<HH", 36, 4)          # StructSize, DialectCount (2.0.2..3.0.2)
    body += struct.pack("<H", 0x0001)         # SecurityMode = signing enabled
    body += struct.pack("<H", 0)              # Reserved
    body += struct.pack("<I", 0)              # Capabilities
    body += b"\x00" * 16                      # ClientGuid
    body += struct.pack("<I", 0)              # NegotiateContextOffset
    body += struct.pack("<H", 0)              # NegotiateContextCount
    body += struct.pack("<H", 0)              # Reserved2
    body += struct.pack("<HHHH", 0x0202, 0x0210, 0x0300, 0x0302)  # avoid 3.1.1 preauth
    return _nbss(hdr + body)


def _smb2_session_setup_request():
    hdr = _smb2_header(0x0001, 1)
    token = spnego_neg_token_init(build_type1())
    struct_size = 25
    sec_off = 64 + struct_size - 1            # offset from SMB2 header start
    body = struct.pack("<H", struct_size)     # StructureSize (25)
    body += struct.pack("<B", 0)              # Flags
    body += struct.pack("<B", 1)              # SecurityMode = signing enabled
    body += struct.pack("<I", 1)              # Capabilities = DFS
    body += struct.pack("<I", 0)              # Channel
    body += struct.pack("<H", sec_off)        # SecurityBufferOffset
    body += struct.pack("<H", len(token))     # SecurityBufferLength
    body += struct.pack("<Q", 0)              # PreviousSessionId
    body += token
    return _nbss(hdr + body)


# ---- MSSQL / TDS ----------------------------------------------------------
def mssql_challenge(host, port=1433, timeout=8):
    """TDS PRELOGIN + LOGIN7 with SSPI; return the raw Type-2 from the response."""
    sock = _tcp_connect(host, port, timeout)
    try:
        sock.sendall(_tds_prelogin())
        _tds_recv(sock)
        sock.sendall(_tds_login7_sspi())
        resp = _tds_recv(sock)
        return extract_ntlm_blob(resp)
    except Exception:
        _dbg("mssql %s:%s" % (host, port))
        return None
    finally:
        try: sock.close()
        except Exception: pass


def _tds_packet(ptype, payload):
    # TDS header: Type, Status(EOM=1), Length(BE incl header), SPID, PacketID, Window
    return struct.pack(">BBHHBB", ptype, 1, len(payload) + 8, 0, 1, 0) + payload


def _tds_recv(sock, timeout=8):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 8:
        c = sock.recv(8 - len(hdr))
        if not c:
            return b""
        hdr += c
    length = struct.unpack(">H", hdr[2:4])[0]
    body = b""
    while len(body) < length - 8:
        c = sock.recv(length - 8 - len(body))
        if not c:
            break
        body += c
    return body


def _tds_prelogin():
    # Full option set: VERSION(0), ENCRYPTION(1), INSTOPT(2), THREADID(3), TERM(0xff)
    ver = struct.pack(">I", 0x11000000) + struct.pack(">H", 0)  # v17.0 build0
    enc = b"\x02"          # ENCRYPT_NOT_SUP
    inst = b"\x00"         # empty instance, null-terminated
    thread = struct.pack(">I", 0)
    options = [(0x00, ver), (0x01, enc), (0x02, inst), (0x03, thread)]
    header = b""
    running = 5 * len(options) + 1  # each entry 5 bytes + 1 terminator
    payload = b""
    for token, data in options:
        header += struct.pack(">BHH", token, running, len(data))
        running += len(data)
        payload += data
    header += b"\xff"
    return _tds_packet(0x12, header + payload)


def _tds_login7_sspi():
    sspi = build_type1()
    FIXED = 94  # fixed portion up to and including cbSSPILong
    appname = "ntlmscout".encode("utf-16-le")
    libname = "ntlmscout".encode("utf-16-le")
    data = b""
    offsets = {}

    def add(name, blob):
        nonlocal data
        offsets[name] = (FIXED + len(data), len(blob))
        data += blob

    add("host", b"")
    add("user", b"")
    add("pass", b"")
    add("app", appname)
    add("server", b"")
    add("unused", b"")
    add("lib", libname)
    add("lang", b"")
    add("db", b"")
    sspi_off = FIXED + len(data)
    data += sspi
    total = FIXED + len(data)

    b = b""
    b += struct.pack("<I", total)           # Length
    b += struct.pack("<I", 0x74000004)      # TDSVersion (7.4)
    b += struct.pack("<I", 4096)            # PacketSize
    b += struct.pack("<I", 0x07000000)      # ClientProgVer
    b += struct.pack("<I", 0)               # ClientPID
    b += struct.pack("<I", 0)               # ConnectionID
    b += struct.pack("<B", 0xE0)            # OptionFlags1
    b += struct.pack("<B", 0x80)            # OptionFlags2 = fIntSecurity ON
    b += struct.pack("<B", 0)               # TypeFlags
    b += struct.pack("<B", 0)               # OptionFlags3
    b += struct.pack("<i", 0)               # ClientTimeZone
    b += struct.pack("<I", 0x00000409)      # ClientLCID

    def ol(name, char=True):
        off, ln = offsets[name]
        return struct.pack("<HH", off, ln // 2 if char else ln)

    b += ol("host") + ol("user") + ol("pass") + ol("app") + ol("server")
    b += ol("unused") + ol("lib") + ol("lang") + ol("db")
    b += b"\x00" * 6                        # ClientID (MAC)
    b += struct.pack("<HH", sspi_off, len(sspi))  # ibSSPI / cbSSPI
    b += struct.pack("<HH", 0, 0)           # AtchDBFile
    b += struct.pack("<HH", 0, 0)           # ChangePassword
    b += struct.pack("<I", 0)               # cbSSPILong
    b += data
    return _tds_packet(0x10, b)


# ---- LDAP -----------------------------------------------------------------
def ldap_challenge(host, port=389, use_tls=False, timeout=8):
    """SASL GSS-SPNEGO bind; return the raw Type-2 from serverSaslCreds."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        sock.sendall(_ldap_sasl_bind())
        resp = _recv_until_sig(sock)
        return extract_ntlm_blob(resp)
    except Exception:
        _dbg("ldap %s:%s" % (host, port))
        return None
    finally:
        try: sock.close()
        except Exception: pass


def _recv_until_sig(sock, timeout=8):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
            if NTLMSSP_SIG in buf:
                break
    except socket.timeout:
        pass
    return buf


def _ldap_sasl_bind(mech="GSS-SPNEGO"):
    creds = spnego_neg_token_init(build_type1())
    sasl = der(0xA3, der(0x04, mech.encode()) + der(0x04, creds))  # [3] SaslCredentials
    bind_body = der_int(3) + der(0x04, b"") + sasl                 # version, name, auth
    bind_req = der(0x60, bind_body)                                # [APPLICATION 0]
    msg = der(0x30, der_int(1) + bind_req)                         # LDAPMessage
    return msg


# AD functional-level number -> Windows version (rootDSE *Functionality attrs).
_FUNC_LEVEL = {"0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
               "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016"}

# rootDSE attributes worth pulling anonymously (all unauth-readable on most DCs).
_ROOTDSE_ATTRS = ["defaultNamingContext", "rootDomainNamingContext",
                  "configurationNamingContext", "dnsHostName", "serverName",
                  "domainFunctionality", "forestFunctionality",
                  "domainControllerFunctionality", "ldapServiceName",
                  "supportedSASLMechanisms"]


def _ldap_anon_bind():
    """Anonymous LDAPv3 simple bind (name + empty password)."""
    body = der_int(3) + der(0x04, b"") + der(0x80, b"")     # [0] simple auth, empty
    return der(0x30, der_int(1) + der(0x60, body))


def _ldap_search_rootdse(attrs):
    """SearchRequest for the rootDSE: base='', scope=base, filter (objectClass=*)."""
    body = (der(0x04, b"")                                  # baseObject ''
            + der(0x0A, b"\x00")                            # scope = baseObject(0)
            + der(0x0A, b"\x00")                            # derefAliases = never
            + der_int(0) + der_int(0)                       # size/time limit
            + der(0x01, b"\x00")                            # typesOnly = FALSE
            + der(0x87, b"objectClass")                     # filter: present [7]
            + der(0x30, b"".join(der(0x04, a.encode()) for a in attrs)))
    return der(0x30, der_int(2) + der(0x63, body))          # msgID 2, [APPLICATION 3]


def _ldap_recv(sock, timeout=8):
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < 65536:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    return buf


def _parse_rootdse(data, attrs):
    """Pull each attribute's value(s) out of the searchResEntry (PartialAttribute)."""
    out = OrderedDict()
    for a in attrs:
        name = a.encode()
        i = data.find(b"\x04" + bytes([len(name)]) + name)
        if i < 0:
            continue
        j = i + 2 + len(name)
        if j >= len(data) or data[j] != 0x31:               # expect SET OF values
            continue
        setlen, k = _read_asn1_len(data, j + 1)
        vals, p, end = [], k, k + setlen
        while p < end and p < len(data) and data[p] == 0x04:
            vlen, q = _read_asn1_len(data, p + 1)
            vals.append(data[q:q + vlen].decode("utf-8", "replace"))
            p = q + vlen
        if vals:
            out[a] = vals if len(vals) > 1 else vals[0]
    return out


def ldap_rootdse(host, port, use_tls=False, timeout=8):
    """Anonymous rootDSE read: naming contexts, dnsHostName, functional levels."""
    sock = _connect(host, port, use_tls, timeout)
    try:
        sock.sendall(_ldap_anon_bind())
        _recv_some(sock, timeout=timeout)                   # bindResponse (ignored)
        sock.sendall(_ldap_search_rootdse(_ROOTDSE_ATTRS))
        return _parse_rootdse(_ldap_recv(sock, timeout), _ROOTDSE_ATTRS)
    except Exception:
        _dbg("ldap-rootdse %s:%s" % (host, port))
        return {}
    finally:
        try: sock.close()
        except Exception: pass


# ---- RDP / CredSSP (NLA) --------------------------------------------------
def rdp_challenge(host, port=3389, timeout=8):
    """RDP CredSSP/NLA: X.224 negotiate -> TLS -> TSRequest; return raw Type-2."""
    sock = _tcp_connect(host, port, timeout)
    try:
        sock.sendall(_rdp_x224_cr())
        _rdp_recv_tpkt(sock)
        tls = _tls_context().wrap_socket(sock, server_hostname=host)
        tls.sendall(_credssp_tsrequest(spnego_neg_token_init(build_type1())))
        resp = _recv_until_sig(tls)
        return extract_ntlm_blob(resp)
    except Exception:
        _dbg("rdp %s:%s" % (host, port))
        return None
    finally:
        try: sock.close()
        except Exception: pass


def _rdp_x224_cr():
    neg = struct.pack("<BBHI", 0x01, 0x00, 0x0008, 0x00000003)  # SSL|HYBRID
    x224 = struct.pack(">B", 6 + len(neg)) + b"\xe0" + b"\x00\x00" + b"\x00\x00" + b"\x00" + neg
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(x224)) + x224
    return tpkt


def _rdp_recv_tpkt(sock, timeout=8):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            return b""
        hdr += c
    length = struct.unpack(">H", hdr[2:4])[0]
    body = b""
    while len(body) < length - 4:
        c = sock.recv(length - 4 - len(body))
        if not c:
            break
        body += c
    return body


def _credssp_tsrequest(spnego_token):
    nego_token = der(0xA0, der(0x04, spnego_token))
    nego_data = der(0x30, nego_token)
    nego_tokens = der(0xA1, der(0x30, nego_data))
    version = der(0xA0, der_int(6))
    return der(0x30, version + nego_tokens)


# ---------------------------------------------------------------------------
#  HTTP endpoint discovery wordlist
# ---------------------------------------------------------------------------
# Merged & de-duplicated. Sources: pwnfoo/NTLMRecon, praetorian-inc/NTLMRecon,
# nyxgeek/ntlmscan (paths.dict), nyxgeek/lyncsmash, + Exchange/ADFS/ADCS/
# SharePoint/WinRM paths from MS docs. Directory-style paths are normalised to
# a trailing slash (IIS vdirs 301-redirect a bare path but 401+NTLM the slash).
_HTTP_PATHS_RAW = [
    "/",
    # ---- Exchange (OWA / EWS / EAS / MAPI / RPC / Autodiscover) ----
    "/autodiscover/", "/Autodiscover/Autodiscover.xml",
    "/Autodiscover/AutodiscoverService.svc/root", "/autodiscover/autodiscover.svc",
    "/EWS/", "/EWS/Exchange.asmx", "/EWS/Services.wsdl",
    "/ecp/", "/owa/", "/owa/auth/", "/OAB/", "/mapi/", "/mapi/nspi/",
    "/mapi/emsmdb/", "/Microsoft-Server-ActiveSync/", "/Rpc/", "/rpc/rpcproxy.dll",
    "/RpcWithCert/", "/PowerShell/", "/API/", "/Exchange/", "/Exchweb/",
    "/Public/", "/aspnet_client/",
    # ---- Skype for Business / Lync (lyncsmash + ntlmscan) ----
    "/abs/", "/abs/handler/", "/CertProv/", "/Conf/", "/dialin/", "/GroupExpansion/",
    "/GroupExpansion/service.svc", "/HybridConfig/", "/mcx/", "/mcx/mcxservice.svc",
    "/meet/", "/meeting/", "/PassiveAuth/", "/PersistentChat/", "/PhoneConferencing/",
    "/Reach/sip.svc", "/RequestHandler/", "/RequestHandlerExt/",
    "/Rgs/", "/RgsClients/", "/scheduler/", "/Ucwa/", "/ucwa/v1/applications",
    "/UnifiedMessaging/", "/WebTicket/", "/WebTicket/WebTicketService.svc",
    "/iwa/authenticated.aspx", "/iwa/iwa_test.aspx",
    # ---- AD FS ----
    "/adfs/ls/", "/adfs/ls/wia", "/adfs/ls/idpinitiatedsignon.aspx",
    "/adfs/services/trust/", "/adfs/services/trust/2005/windowstransport",
    "/adfs/services/trust/13/windowstransport",
    "/internal_windows_authentication/",   # praetorian
    # ---- AD Certificate Services ----
    "/CertEnroll/", "/CertSrv/", "/certsrv/mscep/", "/ocsp/",
    # ---- Updates / misc service endpoints ----
    "/AutoUpdate/", "/deviceupdatefiles_ext/", "/deviceupdatefiles_int/",
    "/debug/", "/Etc/", "/reports/", "/sso/", "/remote/", "/wsman",
    "/_windows/default.aspx?ReturnUrl=/",
    # ---- SharePoint / generic IIS ----
    "/_vti_bin/", "/_vti_bin/lists.asmx", "/_layouts/", "/_layouts/15/",
    "/sharepoint/", "/wss/", "/my/", "/sites/", "/search/",
]

_FILE_MARKERS = (".xml", ".svc", ".asmx", ".aspx", ".dll", ".wsdl", ".txt")


def _normalize_paths(paths):
    seen, out = set(), []
    for p in paths:
        # normalise directory-style paths to a trailing slash
        if ("?" not in p and not p.endswith("/")
                and not any(p.lower().endswith(m) for m in _FILE_MARKERS)
                and "." not in p.rsplit("/", 1)[-1]):
            p = p + "/"
        k = p.lower()
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


HTTP_PATHS = _normalize_paths(_HTTP_PATHS_RAW)


# ---------------------------------------------------------------------------
#  Catch-all (path-agnostic) NTLM detection
#
#  A site that enforces NTLM on *every* path -- an IIS site-wide Windows Auth
#  filter, or an ADC / reverse proxy in front of the app -- answers the whole
#  endpoint wordlist with a challenge, so the "discovered" endpoints are just
#  the wordlist enumerating itself. We probe one random, cannot-exist path (a
#  canary); if it also challenges, the host is a site-wide auth gate and its
#  per-path hits are collapsed to a single, honest finding.
# ---------------------------------------------------------------------------
CANARY_MARKER = "/_ntlmscout_canary_"

# More than one canary per endpoint: the guard should not hinge on a single
# request surviving a host that is slow, throttling, or dropping connections
# under the probe load.
CANARY_PROBES = 2

# Fallback for when every canary died. A host that challenges nearly every path
# it actually answered is a site-wide gate whether or not the canary got through.
# The sample floor keeps a two-hit host from collapsing on a 100% ratio.
CATCHALL_MIN_SAMPLE = 10
CATCHALL_HIT_RATIO = 0.9


def canary_path():
    """A random path that cannot correspond to a real application endpoint."""
    return "{}{}/".format(CANARY_MARKER, uuid.uuid4().hex)


def is_canary_result(result):
    """True if this result came from the synthetic canary probe."""
    return CANARY_MARKER in (result.get("url") or "")


# ---------------------------------------------------------------------------
#  Internal-address disclosure modules (passive; no auth / no relay)
#
#  The NTLM CHALLENGE never carries an IP, but two well-known unauthenticated
#  leaks recover the host's internal address(es):
#    1. IIS internal-IP disclosure (CVE-2000-0649 + IIS7 variant): an HTTP/1.0
#       request with NO Host header makes IIS reflect its internal IP in the
#       Location / Content-Location header of a redirect.
#    2. RPC IOXIDResolver::ServerAlive2 (opnum 5) on TCP 135: returns a
#       DUALSTRINGARRAY of every network interface binding -- internal IPv4
#       and IPv6 included -- with no authentication.
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_IPV6_RE = re.compile(r"\b((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})\b")


def _is_internal_addr(a):
    """True if RFC1918/CGNAT/link-local/loopback, False if public, None if not an IP."""
    a = a.split("[")[0].split("%")[0].strip().strip("/")
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", a)
    if m:
        o = [int(x) for x in m.groups()]
        if any(x > 255 for x in o):
            return None
        if o[0] == 10: return True
        if o[0] == 172 and 16 <= o[1] <= 31: return True
        if o[0] == 192 and o[1] == 168: return True
        if o[0] == 169 and o[1] == 254: return True
        if o[0] == 127: return True
        if o[0] == 100 and 64 <= o[1] <= 127: return True
        return False
    al = a.lower()
    if ":" in al:  # IPv6
        if al.startswith(("fe80", "fc", "fd", "::1")):
            return True
        return False
    return None


def _raw_http(host, port, use_tls, method, path, timeout, extra=""):
    """Minimal HTTP/1.0 request with NO Host header; returns raw response bytes."""
    try:
        sock = _connect(host, port, use_tls, timeout)
        sock.sendall(("%s %s HTTP/1.0\r\n%s\r\n" % (method, path, extra)).encode())
        data = b""
        sock.settimeout(timeout)
        while len(data) < 131072:
            c = sock.recv(4096)
            if not c:
                break
            data += c
        try: sock.close()
        except Exception: pass
        return data
    except Exception:
        return b""


def iis_internal_ip(host, port, use_tls, timeout=8):
    """Internal-IP disclosure: CVE-2000-0649 (Host-less redirect) + WebDAV PROPFIND.

    Both send an HTTP/1.0 request with NO Host header so IIS reflects its own
    internal IP in Location/Content-Location (redirect) or in the PROPFIND body
    <href>. Unauthenticated; no creds sent.
    """
    found = OrderedDict()
    target_ip = host

    def harvest(data, where):
        # Redirect headers.
        for m in re.finditer(rb"(?im)^(location|content-location)\s*:\s*(\S+)", data):
            val = m.group(2).decode("latin-1", "replace")
            _add_ips(val, "%s header (%s)" % (m.group(1).decode("latin-1"), where))
        # PROPFIND / body hrefs.
        for m in re.finditer(rb"(?is)<(?:D:)?href>\s*(.*?)\s*</(?:D:)?href>", data):
            _add_ips(m.group(1).decode("latin-1", "replace"), "PROPFIND href (%s)" % where)

    def _add_ips(text, source):
        for ip in _IPV4_RE.findall(text) + _IPV6_RE.findall(text):
            if ip == target_ip:
                continue
            internal = _is_internal_addr(ip)
            if internal is None or ip in found:
                continue
            found[ip] = {"address": ip, "internal": bool(internal), "source": source}

    # 1. Host-less GET on redirect-prone paths.
    for path in ("/", "/owa", "/exchange", "/ews", "/aspnet_client",
                 "/Autodiscover", "/Microsoft-Server-ActiveSync"):
        harvest(_raw_http(host, port, use_tls, "GET", path, timeout), "GET " + path)
    # 2. WebDAV PROPFIND on root (Depth: 0) -- body <href> can echo the internal IP.
    harvest(_raw_http(host, port, use_tls, "PROPFIND", "/", timeout,
                      extra="Depth: 0\r\nContent-Length: 0\r\n"), "PROPFIND /")
    return list(found.values())


# ---- TLS / RDP certificate name disclosure --------------------------------
def parse_cert_der(der):
    """Extract CN + SAN dNSName/iPAddress from a DER X.509 cert (no deps)."""
    cn, dns, ips = None, [], []
    # Common Name: OID 2.5.4.3 = 55 04 03. It appears in BOTH issuer and subject;
    # the subject Name comes after the issuer in the cert, so take the LAST match
    # (otherwise we'd report the CA/issuer CN instead of the server's subject CN).
    cn_hits = list(re.finditer(b"\x06\x03\x55\x04\x03", der))
    if cn_hits:
        j = cn_hits[-1].end()
        if j < len(der) and der[j] in (0x0C, 0x13, 0x16, 0x14):  # UTF8/Printable/IA5/T61
            ln, k = _read_asn1_len(der, j + 1)
            cn = der[k:k + ln].decode("utf-8", "replace")
        # If the subject carried no CN, the only CN OID present is the issuer's
        # (a CA name). Reject anything that isn't hostname-shaped: CA names have
        # spaces, and a bare "*" is meaningless.
        if cn and (" " in cn or cn.strip() == "*"):
            cn = None
    # subjectAltName: OID 2.5.29.17 = 55 1D 11, value in the OCTET STRING that follows.
    m = re.search(b"\x06\x03\x55\x1d\x11", der)
    if m:
        j = m.end()
        if j < len(der) and der[j] == 0x01:      # optional critical BOOLEAN
            j += 3
        if j < len(der) and der[j] == 0x04:      # OCTET STRING wrapper
            _oln, j = _read_asn1_len(der, j + 1)
            if j < len(der) and der[j] == 0x30:  # SEQUENCE OF GeneralName
                seqln, j = _read_asn1_len(der, j + 1)
                end = j + seqln
                while j < end and j < len(der):
                    tag = der[j]; j += 1
                    ln, j = _read_asn1_len(der, j)
                    val = der[j:j + ln]; j += ln
                    if tag == 0x82:              # dNSName (IA5String)
                        dns.append(val.decode("latin-1", "replace"))
                    elif tag == 0x87:            # iPAddress (OCTET STRING)
                        if ln == 4:
                            ips.append(".".join(str(x) for x in val))
                        elif ln == 16:
                            ips.append(":".join("%x" % int.from_bytes(val[k:k + 2], "big")
                                                for k in range(0, 16, 2)))
    return {"cn": cn, "dns_names": dns, "ip_addresses": ips}


def get_cert_der(host, port, timeout=8, rdp=False):
    """Grab the server certificate (DER). For RDP, do the X.224 preamble first."""
    sock = _tcp_connect(host, port, timeout)
    try:
        if rdp:
            sock.sendall(_rdp_x224_cr())
            _rdp_recv_tpkt(sock)
        tls = _tls_context().wrap_socket(sock, server_hostname=host)
        return tls.getpeercert(binary_form=True)
    except Exception:
        _dbg("get_cert_der %s:%s" % (host, port))
        return None
    finally:
        try: sock.close()
        except Exception: pass


def tls_cert_disclosure(host, port, timeout=8, rdp=False):
    """Return (internal_ip_entries, disclosed_name_entries) from the TLS cert."""
    der = get_cert_der(host, port, timeout, rdp)
    if not der:
        return [], []
    info = parse_cert_der(der)
    src = "RDP cert" if rdp else "TLS cert"
    ips, names = [], []
    for ip in info["ip_addresses"]:
        internal = _is_internal_addr(ip)
        ips.append({"address": ip, "internal": bool(internal) if internal is not None else None,
                    "is_ip": True, "source": src + " SAN"})
    seen = set()
    for nm in ([info["cn"]] if info["cn"] else []) + info["dns_names"]:
        if not nm or nm.lower() in seen:
            continue
        seen.add(nm.lower())
        names.append({"name": nm, "source": src + (" CN" if nm == info["cn"] else " SAN")})
    return ips, names


def probe_tlscert(host, port, timeout=10, rdp=False):
    label = "rdpcert" if rdp else "tlscert"
    result = {"target": "{}://{}:{}".format(label, host, port), "protocol": label,
              "host": host, "port": port, "success": False}
    t0 = time.time()
    try:
        ips, names = tls_cert_disclosure(host, port, timeout, rdp)
        if ips or names:
            result["success"] = True
            if ips:
                result["internal_addresses"] = ips
            if names:
                result["disclosed_names"] = names
        else:
            result["error"] = "no cert names recovered"
    except Exception as e:
        result["error"] = "{}: {}".format(type(e).__name__, e)
    result["elapsed_ms"] = int((time.time() - t0) * 1000)
    return result


# ---- RPC IOXIDResolver / ServerAlive2 (TCP 135) ---------------------------
_UUID_IOXID = uuid.UUID("99fcfec4-5260-101b-bbcb-00aa0021347a").bytes_le
_UUID_NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le


def _rpc_common_header(ptype, frag_len, call_id):
    # rpc_vers=5, minor=0, ptype, pfc_flags=0x03 (first|last), NDR LE drep
    return (struct.pack("<BBBB", 5, 0, ptype, 0x03) + b"\x10\x00\x00\x00"
            + struct.pack("<HH", frag_len, 0) + struct.pack("<I", call_id))


def _rpc_bind():
    ctx = struct.pack("<HBB", 0, 1, 0)                       # p_cont_id, n_xfer=1, rsvd
    ctx += _UUID_IOXID + struct.pack("<HH", 0, 0)            # abstract syntax v0.0
    ctx += _UUID_NDR + struct.pack("<HH", 2, 0)              # transfer syntax NDR v2.0
    body = struct.pack("<HHI", 5840, 5840, 0)               # max_xmit, max_recv, assoc
    body += struct.pack("<BBH", 1, 0, 0)                    # n_context_elem=1
    body += ctx
    return _rpc_common_header(11, 16 + len(body), 1) + body  # ptype 11 = bind


def _rpc_request(opnum, stub=b""):
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub   # alloc_hint, cont_id, opnum
    return _rpc_common_header(0, 16 + len(body), 2) + body   # ptype 0 = request


def _rpc_recv(sock, timeout=8):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 16:
        c = sock.recv(16 - len(hdr))
        if not c:
            return b""
        hdr += c
    frag = struct.unpack("<H", hdr[8:10])[0]
    body = b""
    while len(body) < frag - 16:
        c = sock.recv(frag - 16 - len(body))
        if not c:
            break
        body += c
    return hdr + body


def _parse_serveralive2(stub):
    """Extract network-address strings from the DUALSTRINGARRAY in the reply."""
    addrs = []
    try:
        off = 4                                   # skip COMVERSION
        off += 4                                   # skip unique-ptr referent id
        off += 4                                   # skip conformant max_count
        num = struct.unpack("<H", stub[off:off + 2])[0]; off += 2
        secoff = struct.unpack("<H", stub[off:off + 2])[0]; off += 2
        warr = stub[off:off + num * 2]
        sbind = warr[:secoff * 2]
        i = 0
        while i + 2 <= len(sbind):
            tower = struct.unpack("<H", sbind[i:i + 2])[0]
            if tower == 0:
                break
            i += 2
            start = i
            while i + 2 <= len(sbind) and sbind[i:i + 2] != b"\x00\x00":
                i += 2
            s = sbind[start:i].decode("utf-16-le", "replace").strip()
            i += 2
            if s:
                addrs.append(s)
    except Exception:
        pass
    if not addrs:  # fallback: scrape any address-looking token from the stub
        try:
            text = stub.decode("utf-16-le", "replace")
        except Exception:
            text = ""
        addrs = _IPV4_RE.findall(text) + _IPV6_RE.findall(text)
    # de-dup, classify
    out, seen = [], set()
    for a in addrs:
        a = a.strip().strip("\x00")
        if not a or a in seen:
            continue
        seen.add(a)
        internal = _is_internal_addr(a)
        out.append({"address": a, "internal": bool(internal) if internal is not None else None,
                    "is_ip": internal is not None})
    return out


def oxid_resolve(host, port=135, timeout=8):
    """RPC IOXIDResolver::ServerAlive2 (TCP 135): return every interface address."""
    sock = _tcp_connect(host, port, timeout)
    try:
        sock.sendall(_rpc_bind())
        ack = _rpc_recv(sock, timeout)
        if not ack or ack[2] != 12:               # ptype 12 = bind_ack
            return []
        sock.sendall(_rpc_request(5))              # ServerAlive2, no input args
        resp = _rpc_recv(sock, timeout)
        if len(resp) < 24:
            return []
        return _parse_serveralive2(resp[24:])
    except Exception:
        _dbg("oxid %s:%s" % (host, port))
        return []
    finally:
        try: sock.close()
        except Exception: pass


def probe_iisip(host, port, url, timeout=10):
    use_tls = (url or "").startswith("https") or port in (443, 8443, 5986)
    p = port or (443 if use_tls else 80)
    result = {"target": "iis-ip://{}:{}".format(host, p), "protocol": "iisip",
              "host": host, "port": p, "success": False}
    t0 = time.time()
    try:
        addrs = iis_internal_ip(host, p, use_tls, timeout)
        if addrs:
            result["success"] = True
            result["internal_addresses"] = addrs
        else:
            result["error"] = "no internal IP disclosed"
    except Exception as e:
        result["error"] = "{}: {}".format(type(e).__name__, e)
    result["elapsed_ms"] = int((time.time() - t0) * 1000)
    return result


def probe_oxid(host, port=135, timeout=10):
    result = {"target": "oxid://{}:{}".format(host, port), "protocol": "oxid",
              "host": host, "port": port, "success": False}
    t0 = time.time()
    try:
        addrs = oxid_resolve(host, port, timeout)
        if addrs:
            result["success"] = True
            ips = [a for a in addrs if a.get("is_ip")]
            names = [{"name": a["address"], "source": "OXID ServerAlive2"}
                     for a in addrs if not a.get("is_ip")]
            if ips:
                result["internal_addresses"] = ips
            if names:
                result["disclosed_names"] = names
        else:
            result["error"] = "no bindings returned"
    except Exception as e:
        result["error"] = "{}: {}".format(type(e).__name__, e)
    result["elapsed_ms"] = int((time.time() - t0) * 1000)
    return result


# ---------------------------------------------------------------------------
#  Protocol dispatch + result assembly
# ---------------------------------------------------------------------------
PORT_PROTOCOL = {
    80: "http", 443: "https", 8080: "http", 8443: "https",
    445: "smb", 139: "smb", 1433: "mssql", 25: "smtp", 587: "smtp",
    465: "smtps", 143: "imap", 993: "imaps", 110: "pop3", 995: "pop3s",
    119: "nntp", 563: "nntps", 389: "ldap", 636: "ldaps",
    3268: "ldap", 3269: "ldaps",   # Global Catalog (DC-only) -> confirms DC role
    3389: "rdp", 5985: "http", 5986: "https",
}


def _tls_first(handler, host, port, timeout):
    """Try implicit TLS; if the port is really plaintext+STARTTLS (common on a
    misconfigured 465/993/995), fall back to the plaintext STARTTLS path."""
    try:
        blob = handler(host, port, True, timeout)
    except Exception:
        blob = None
    if blob is None:
        try:
            blob = handler(host, port, False, timeout)
        except Exception:
            _dbg("mail %s:%s" % (host, port))
            blob = None
    return blob


def run_protocol(proto, host, port=None, url=None, host_header=None, timeout=10):
    """Dispatch to the right transport handler and return its raw response bytes."""
    if proto in ("http", "https"):
        if not url:
            scheme = "https" if proto == "https" else "http"
            p = port or (443 if proto == "https" else 80)
            url = "{}://{}:{}/".format(scheme, _url_host(host), p)
        return http_challenge(url, host_header, timeout)
    if proto == "smb":
        return smb_challenge(host, port or 445, timeout)
    if proto == "mssql":
        return mssql_challenge(host, port or 1433, timeout)
    if proto == "smtp":
        return smtp_challenge(host, port or 25, False, timeout)
    if proto == "smtps":
        return _tls_first(smtp_challenge, host, port or 465, timeout)
    if proto == "imap":
        return imap_challenge(host, port or 143, False, timeout)
    if proto == "imaps":
        return _tls_first(imap_challenge, host, port or 993, timeout)
    if proto == "pop3":
        return pop3_challenge(host, port or 110, False, timeout)
    if proto == "pop3s":
        return _tls_first(pop3_challenge, host, port or 995, timeout)
    if proto == "nntp":
        return nntp_challenge(host, port or 119, False, timeout)
    if proto == "nntps":
        return nntp_challenge(host, port or 563, True, timeout)
    if proto == "ldap":
        return ldap_challenge(host, port or 389, False, timeout)
    if proto == "ldaps":
        return ldap_challenge(host, port or 636, True, timeout)
    if proto == "rdp":
        return rdp_challenge(host, port or 3389, timeout)
    raise ValueError("unknown protocol: %s" % proto)


def probe(proto, host, port=None, url=None, host_header=None, timeout=10):
    """Run one probe: elicit + decode the NTLM challenge (or an internal-disclosure
    check) and return a result dict with fingerprint / posture / addresses."""
    if proto == "oxid":
        return probe_oxid(host, port or 135, timeout)
    if proto == "iisip":
        return probe_iisip(host, port, url, timeout)
    if proto == "tlscert":
        return probe_tlscert(host, port or 443, timeout, rdp=False)
    if proto == "rdpcert":
        return probe_tlscert(host, port or 3389, timeout, rdp=True)
    result = {"target": url or "{}:{}".format(host, port or ""), "protocol": proto,
              "host": host, "port": port, "url": url, "success": False}
    if proto in ("http", "https"):
        # Overwritten once the fetch returns; staying False means the probe
        # never reached the server, which the catch-all guard treats as "no
        # evidence" rather than as evidence of path-specific auth.
        result["responded"] = False
    t0 = time.time()
    try:
        exch_names, exch_info = {}, {}
        if proto in ("http", "https"):
            if not url:
                p = port or (443 if proto == "https" else 80)
                url = "{}://{}:{}/".format(proto, _url_host(host), p)
            raw, exch_names, exch_info, responded = http_probe(url, host_header, timeout)
            result["responded"] = responded
        else:
            raw = run_protocol(proto, host, port, url, host_header, timeout)
        if not raw:
            result["error"] = "no NTLM challenge returned"
        else:
            blob = raw if raw.startswith(NTLMSSP_SIG) else extract_ntlm_blob(raw)
            if not blob:
                result["error"] = "NTLMSSP signature not found in response"
            else:
                parsed = parse_challenge(blob)
                result["success"] = True
                result["ntlm"] = parsed
                result["fingerprint"] = build_fingerprint(parsed)
                result["security_posture"] = assess_posture(parsed)
                ts = parsed["target_info"].get("MsvAvTimestamp")
                if ts:
                    server_dt = filetime_to_dt(ts["filetime"])
                    skew = (server_dt - datetime.datetime.now(UTC)).total_seconds()
                    result["fingerprint"]["server_time_utc"] = ts["utc"]
                    result["fingerprint"]["time_skew_seconds"] = round(skew, 1)
        # Exchange/IIS diagnostic headers leak internal FE/BE server names
        # unauthenticated (present even on the 401). Capture regardless of NTLM.
        if exch_names:
            result.setdefault("disclosed_names", [])
            for hdr, val in exch_names.items():
                for nm in re.split(r"[;,]", val):
                    nm = nm.strip()
                    if nm:
                        result["disclosed_names"].append({"name": nm, "source": hdr + " header"})
            result["success"] = True  # an unauth disclosure still counts as a hit
        if exch_info:
            result["http_info"] = exch_info
        # LDAP also answers an anonymous rootDSE read (unauth) -- naming contexts,
        # dnsHostName, functional levels. Also confirms the Domain Controller role.
        if proto in ("ldap", "ldaps"):
            rd = ldap_rootdse(host, port or (636 if proto == "ldaps" else 389),
                              proto == "ldaps", timeout)
            if rd:
                result["rootdse"] = rd
                result["success"] = True
    except Exception as e:
        result["error"] = "{}: {}".format(type(e).__name__, e)
    result["elapsed_ms"] = int((time.time() - t0) * 1000)
    return result


def build_fingerprint(parsed):
    """Flatten a parsed challenge into the tidy host fingerprint used for reporting."""
    ti = parsed.get("target_info", {})
    fp = OrderedDict()
    fp["target_realm"] = parsed.get("target_name")
    fp["target_realm_type"] = parsed.get("target_type")
    fp["netbios_computer"] = ti.get("MsvAvNbComputerName")
    fp["netbios_domain"] = ti.get("MsvAvNbDomainName")
    fp["dns_computer"] = ti.get("MsvAvDnsComputerName")
    fp["dns_domain"] = ti.get("MsvAvDnsDomainName")
    fp["dns_forest"] = ti.get("MsvAvDnsTreeName")
    if parsed.get("version"):
        fp["os"] = parsed["version"]["product"]
        fp["os_build"] = "{}.{}.{}".format(parsed["version"]["major"],
                                           parsed["version"]["minor"],
                                           parsed["version"]["build"])
    mid = ti.get("MsvAvSingleHost")
    if isinstance(mid, dict) and mid.get("machine_id"):
        fp["machine_id"] = mid["machine_id"]
    fp["spn"] = ti.get("MsvAvTargetName")
    return fp


def _has_flag(flags, name):
    """True if the named NEGOTIATE_FLAGS bit is set (single source of truth)."""
    return bool(flags & NEGOTIATE_FLAGS[name])


def assess_posture(parsed):
    """Passive security-posture observations derived from the challenge."""
    flags = parsed.get("negotiate_flags", 0)
    ti = parsed.get("target_info", {})
    p = OrderedDict()
    # Signing
    p["signing_offered"] = (_has_flag(flags, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN")
                            or _has_flag(flags, "NTLMSSP_NEGOTIATE_SIGN"))
    # EPA / channel binding presence
    cb = ti.get("MsvAvChannelBindings")
    p["channel_binding_present"] = bool(cb and isinstance(cb, dict) and cb.get("present"))
    # Weak crypto offered
    weak = []
    if _has_flag(flags, "NTLMSSP_NEGOTIATE_LM_KEY"):
        weak.append("LM_KEY")
    if (_has_flag(flags, "NTLMSSP_NEGOTIATE_NTLM")
            and not _has_flag(flags, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY")):
        weak.append("NTLMv1 (no ExtendedSessionSecurity)")
    p["weak_crypto_offered"] = weak
    # Domain membership + a NAME-BASED DC hint only.
    #
    # IMPORTANT: TargetType=DOMAIN and "forest root == DNS domain" only prove
    # the host is a domain-joined member of the forest-root domain -- every
    # member server trips them, so they are NOT used to assert DC. The only
    # name-based signal that is genuinely DC-like is the host naming itself
    # after the domain (server FQDN == domain DNS name, or NetBIOS host ==
    # NetBIOS domain). Authoritative DC calls require a DC service (LDAP/GC/
    # Kerberos) and are resolved at the host level in resolve_host_roles().
    nb_c = ti.get("MsvAvNbComputerName")
    nb_d = ti.get("MsvAvNbDomainName")
    dns_c = ti.get("MsvAvDnsComputerName")
    dns_d = ti.get("MsvAvDnsDomainName")
    p["domain_joined"] = bool(parsed.get("target_type") == "domain" or dns_d or nb_d)
    hints = []
    if dns_c and dns_d and dns_c.lower() == dns_d.lower():
        hints.append("server FQDN == domain DNS name")
    if nb_c and nb_d and nb_c.lower() == nb_d.lower():
        hints.append("NetBIOS host == NetBIOS domain")
    p["dc_name_hint"] = hints
    return p


# Protocols that only a Domain Controller answers (confirms the DC role).
_DC_PROTOCOLS = {"ldap", "ldaps"}


def resolve_host_roles(results):
    """Host-level role: DC requires a DC *service*; otherwise domain member.

    Returns {host: {"role","confidence","reasons"}}.
      - "Domain Controller" / confirmed : an LDAP/GC/Kerberos service answered.
      - "Domain Controller" / heuristic : NTLM name strongly implies a DC.
      - "Domain member"      / confirmed : domain-joined, no DC service seen.
      - "Unknown"                        : not enough data.
    """
    by_host = OrderedDict()
    for r in results:
        by_host.setdefault(r["host"], []).append(r)
    roles = {}
    for host, rs in by_host.items():
        succ = [r for r in rs if r.get("success")]
        ntlm = [r for r in succ if r.get("ntlm")]
        # Strong evidence: an actual LDAP/GC service answered -- either an NTLM bind
        # or an anonymous rootDSE read. (Not a tlscert grab that merely used 636.)
        svc = [r for r in succ if r.get("protocol") in _DC_PROTOCOLS
               and (r.get("ntlm") or r.get("rootdse"))]
        gc = [r for r in svc if r.get("port") in (3268, 3269)]
        domain_joined = any(r.get("security_posture", {}).get("domain_joined") for r in ntlm)
        if svc:
            proto_names = sorted({(r.get("protocol") or str(r.get("port"))) for r in svc})
            label = "Global Catalog/LDAP" if gc else "LDAP"
            roles[host] = {"role": "Domain Controller", "confidence": "confirmed",
                           "reasons": ["{} service responding ({})".format(label, ", ".join(proto_names))]}
            continue
        # Name-based heuristic (rare, but a real DC signal).
        hints = []
        for r in ntlm:
            hints = r.get("security_posture", {}).get("dc_name_hint") or []
            if hints:
                break
        if hints:
            roles[host] = {"role": "Domain Controller", "confidence": "heuristic",
                           "reasons": hints + ["confirm via LDAP/389, GC/3268, or Kerberos/88"]}
        elif domain_joined:
            roles[host] = {"role": "Domain member", "confidence": "confirmed",
                           "reasons": ["domain-joined; no DC service observed "
                                       "(LDAP/GC/Kerberos not seen -- try --auto)"]}
        else:
            roles[host] = {"role": "Unknown", "confidence": "", "reasons": []}
    return roles


# ---------------------------------------------------------------------------
#  Target planning
# ---------------------------------------------------------------------------
def _discover_on(args):
    """HTTP path-wordlist discovery is ON by default; --no-discover turns it off."""
    return not getattr(args, "no_discover", False)


def _iter_raw_targets(args):
    """Yield raw target tokens from the command line and -I file, lazily."""
    for t in args.targets:
        yield t
    if args.input_list:
        with open(args.input_list) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line


# Canonical TLS port per protocol, for the cert-disclosure jobs below.
_TLS_DEFAULT_PORT = {"https": 443, "ldaps": 636, "imaps": 993, "pop3s": 995,
                     "smtps": 465, "nntps": 563}


def _internal_disclosure_jobs(jobs):
    """Internal-address disclosure jobs for one host's probe list (on by default):
         * iisip   : one per unique http(s) endpoint (Host-header + PROPFIND)
         * tlscert : one per unique TLS endpoint (cert CN/SAN names + IPs)
         * rdpcert : one per unique RDP endpoint (CredSSP cert CN)
         * oxid    : one per unique host (RPC ServerAlive2 / 135)"""
    http_seen, tls_seen, host_seen, extra = set(), set(), set(), []
    for (proto, host, port, url) in jobs:
        if proto in ("http", "https"):
            p = port or (443 if proto == "https" else 80)
            if ("iisip", host, p) not in http_seen:
                http_seen.add(("iisip", host, p))
                extra.append(("iisip", host, p, "{}://{}:{}".format(proto, _url_host(host), p)))
        if proto in _TLS_DEFAULT_PORT:
            p = port or _TLS_DEFAULT_PORT[proto]
            if (host, p) not in tls_seen:
                tls_seen.add((host, p))
                extra.append(("tlscert", host, p, None))
        elif proto == "rdp":
            p = port or 3389
            if (host, p) not in tls_seen:
                tls_seen.add((host, p))
                extra.append(("rdpcert", host, p, None))
    for (proto, host, port, url) in jobs:
        if host not in host_seen:
            host_seen.add(host)
            extra.append(("oxid", host, 135, None))
    return extra


def _canary_jobs(jobs):
    """One canary per HTTP(S) endpoint in this host's probe list: a random path
    that cannot exist.  If it returns an NTLM challenge the host challenges
    every path, which is what collapse_catchall_endpoints() keys off.  WinRM is
    a single-path service, so the wordlist -- and the canary -- don't apply."""
    canary_seen, extra = set(), []
    for (proto, host, port, url) in jobs:
        if proto not in ("http", "https") or not url:
            continue
        if _job_port(proto, port) in _WINRM_PORTS:
            continue
        key = (proto, host, _job_port(proto, port))
        if key in canary_seen:
            continue
        canary_seen.add(key)
        scheme, rest = url.split("://", 1)
        origin = "{}://{}".format(scheme, rest.split("/", 1)[0])
        for _ in range(CANARY_PROBES):
            extra.append((proto, host, port, origin + canary_path()))
    return extra


def _plan_token(t, args):
    """Every (proto, host, port, url) probe for a single target token, including
    that host's internal-disclosure jobs.  This is the unit the planner streams."""
    discover = _discover_on(args)
    jobs = []
    if "://" in t:
        scheme = t.split("://", 1)[0].lower()
        rest = t.split("://", 1)[1]
        hostport = rest.split("/", 1)[0]
        host, port = _split_host_port(hostport)
        path_part = rest[len(hostport):]           # includes leading '/', if any
        has_path = path_part not in ("", "/")
        if scheme in ("http", "https"):
            # A URL targeting the site root fans out over the path wordlist;
            # a specific path (e.g. /ews/) is a single, deliberate probe.
            if discover and not has_path:
                for p in HTTP_PATHS:
                    jobs.append((scheme, host, port,
                                 "{}://{}{}".format(scheme, hostport, p)))
            else:
                jobs.append((scheme, host, port, t))
        elif scheme == "smb":
            jobs.append(("smb", host, port or 445, None))
        elif scheme == "mssql":
            jobs.append(("mssql", host, port or 1433, None))
        elif scheme in ("smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
                        "nntp", "nntps", "ldap", "ldaps", "rdp"):
            jobs.append((scheme, host, port, None))
        else:
            jobs.append((scheme, host, port, t))
    else:
        host, port = _split_host_port(t)
        if port:
            # A specific host:port -> probe just that service.
            _add_host(jobs, PORT_PROTOCOL.get(port, "http"), host, port, args)
        else:
            # Bare host -> full sweep of every known NTLM port/protocol.
            for p, proto in sorted(PORT_PROTOCOL.items()):
                _add_host(jobs, proto, host, p, args)
    if discover:
        jobs += _canary_jobs(jobs)
    if not getattr(args, "no_internal_ip", False):
        jobs += _internal_disclosure_jobs(jobs)
    return jobs


def _unique_raw_targets(args):
    """Raw target tokens with repeats dropped.  Deduping happens *before* CIDR
    expansion on purpose: expanding a prefix already yields each address once,
    so the set stays bounded by the size of the target list rather than growing
    with the size of the range."""
    seen = set()
    for t in _iter_raw_targets(args):
        if t not in seen:
            seen.add(t)
            yield t


def iter_job_groups(args):
    """Stream the plan one target at a time, so no scan has to hold its whole
    job list in memory."""
    for t in _expand_targets(_unique_raw_targets(args)):
        group = _plan_token(t, args)
        if group:
            yield group


_PLAN_BATCH = 20000     # probes planned, port-checked and submitted at a time


def iter_job_batches(args, size=_PLAN_BATCH):
    """Stream the plan in batches of roughly `size` probes, never splitting one
    target's jobs across batches -- prune_closed_ports() dedupes within a batch,
    so keeping a host whole keeps it to one connect per host:port."""
    batch = []
    for group in iter_job_groups(args):
        batch.extend(group)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def plan_targets(args):
    """The whole plan as a single list.  Materializes every probe -- callers
    scanning more than a handful of hosts should use iter_job_batches()."""
    jobs = []
    for group in iter_job_groups(args):
        jobs.extend(group)
    return jobs


# --- Planning budget -------------------------------------------------------
# The plan is streamed, so its size no longer has to fit in memory, but a run
# that would issue tens of millions of probes is still almost always a mistake.
# The budget counts *probes*, not addresses, because the per-host fan-out swings
# ~16x with --no-discover / --no-internal-ip and grows every time a path is added
# to HTTP_PATHS.  Fan-out is measured, not hardcoded, so it can't drift.
_FANOUT_CACHE = {}


def _fanout(token, args):
    """Probes a token of this shape generates, measured by planning a dummy."""
    key = (token, _discover_on(args), bool(getattr(args, "no_internal_ip", False)))
    if key not in _FANOUT_CACHE:
        _FANOUT_CACHE[key] = len(_plan_token(token, args))
    return _FANOUT_CACHE[key]


def _shape_of(t):
    """A dummy token with the same fan-out as `t` -- one per distinct shape, so
    the measurement is cached across a target list of any length."""
    net = _as_network(t)
    if net is not None:
        return "0.0.0.0"                       # CIDR -> bare hosts
    if "://" in t:
        scheme, rest = t.split("://", 1)
        hostport = rest.split("/", 1)[0]
        path = rest[len(hostport):]
        return "%s://0.0.0.0%s" % (scheme.lower(), "/" if path in ("", "/") else "/x")
    _host, port = _split_host_port(t)
    return "0.0.0.0:%d" % port if port else "0.0.0.0"


def project_plan(args, max_jobs=None, per_target=None):
    """Count hosts and projected probes *before* planning anything.

    Returns (hosts, probes), or (None, None) after explaining the refusal when
    the projection exceeds the budget.  `per_target` overrides the measured
    fan-out (spray resolves one endpoint per target, so it passes 1)."""
    if max_jobs is None:
        max_jobs = getattr(args, "max_jobs", _MAX_JOBS)
    hosts = probes = 0
    for t in _unique_raw_targets(args):
        n = _host_count(t)
        hosts += n
        probes += n * (per_target if per_target is not None
                       else _fanout(_shape_of(t), args))
    if max_jobs and probes > max_jobs:
        sys.stderr.write(
            "[!] refusing to plan {:,} probe(s) across {:,} host(s) -- the budget "
            "is {:,}.\n".format(probes, hosts, max_jobs))
        if per_target is None:
            sys.stderr.write("[!] that is {:,} probe(s) per host at these flags. "
                             "Options:\n".format(probes // max(hosts, 1)))
            sys.stderr.write("[!]   --no-discover      skip the HTTP path wordlist "
                             "(~9x fewer probes)\n")
            sys.stderr.write("[!]   --no-internal-ip   skip the cert / OXID / IIS "
                             "disclosure probes\n")
        else:
            sys.stderr.write("[!] spray resolves one endpoint per target. Options:\n")
        sys.stderr.write("[!]   --max-jobs N       raise the budget deliberately "
                         "(0 = unlimited)\n")
        sys.stderr.write("[!]   or split the range into smaller prefixes\n")
        return None, None
    return hosts, probes


class _DefaultScope(object):
    """Stand-in args for measuring the default per-host fan-out, for --help."""
    no_discover = False
    no_internal_ip = False


def _bare_host_probes():
    """How many probes one bare host costs with default flags."""
    return _fanout("0.0.0.0", _DefaultScope())


_WINRM_PORTS = {5985, 5986}


def _add_host(jobs, proto, host, port, args):
    if proto in ("http", "https") and port in _WINRM_PORTS:
        # WinRM isn't a web app -- the OWA wordlist is pure noise here; a single
        # /wsman probe is enough to catch its NTLM/Negotiate offer.
        jobs.append((proto, host, port, "{}://{}:{}/wsman".format(proto, _url_host(host), port)))
    elif proto in ("http", "https") and _discover_on(args):
        for pth in HTTP_PATHS:
            jobs.append((proto, host, port,
                         "{}://{}:{}{}".format(proto, _url_host(host), port, pth)))
    else:
        url = None
        if proto in ("http", "https"):
            url = "{}://{}:{}/".format(proto, _url_host(host), port)
        jobs.append((proto, host, port, url))


# Canonical default port per protocol, for resolving jobs whose port is unset.
_DEFAULT_PORT = {
    "http": 80, "https": 443, "smb": 445, "mssql": 1433,
    "smtp": 25, "smtps": 465, "imap": 143, "imaps": 993,
    "pop3": 110, "pop3s": 995, "nntp": 119, "nntps": 563,
    "ldap": 389, "ldaps": 636, "rdp": 3389,
    "iisip": 443, "tlscert": 443, "rdpcert": 3389, "oxid": 135,
}


def _job_port(proto, port):
    return port or _DEFAULT_PORT.get(proto)


def prune_closed_ports(jobs, timeout, threads):
    """Drop every job whose TCP port isn't open. One fast connect per unique
    host:port -- a closed port can't yield an NTLM challenge, so skipping it
    avoids the per-probe timeout that dominates scan time on filtered hosts.
    Returns (live_jobs, closed_port_count). Skipped when a proxy is set."""
    if _PROXY:
        return jobs, 0
    unique = {(host, _job_port(proto, port))
              for (proto, host, port, url) in jobs if _job_port(proto, port)}
    connect_timeout = min(timeout, 3.0)

    def _open(hp):
        try:
            socket.create_connection(hp, timeout=connect_timeout).close()
            return hp
        except Exception:
            return None

    open_ports = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_open, unique):
            if r:
                open_ports.add(r)
    live = [j for j in jobs if (j[1], _job_port(j[0], j[2])) in open_ports]
    return live, len(unique) - len(open_ports)


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
FP_ORDER = [("Realm", "target_realm"), ("Realm type", "target_realm_type"),
            ("NetBIOS host", "netbios_computer"), ("NetBIOS domain", "netbios_domain"),
            ("DNS host", "dns_computer"), ("DNS domain", "dns_domain"),
            ("DNS forest", "dns_forest"), ("OS", "os"), ("OS build", "os_build"),
            ("SPN", "spn"), ("Machine ID", "machine_id"),
            ("Server time (UTC)", "server_time_utc"), ("Time skew (s)", "time_skew_seconds")]

CSV_COLUMNS = ["target", "protocol", "host", "port", "success",
               "target_realm", "target_realm_type", "netbios_computer",
               "netbios_domain", "dns_computer", "dns_domain", "dns_forest",
               "os", "os_build", "machine_id", "server_time_utc",
               "time_skew_seconds", "domain_role", "role_confidence", "signing",
               "channel_binding", "weak_crypto", "internal_addresses",
               "disclosed_names", "elapsed_ms", "error"]


def _addr_str(addrs):
    parts = []
    for a in addrs:
        s = a["address"] if isinstance(a, dict) else a
        if isinstance(a, dict) and a.get("internal"):
            s += " (internal)"
        parts.append(s)
    return ", ".join(parts)


def host_line(r):
    """Concise one-liner printed the first time a host is confirmed (default view)."""
    fp = r.get("fingerprint", {})
    bits = []
    if fp.get("netbios_domain") and fp.get("netbios_computer"):
        bits.append("{}\\{}".format(fp["netbios_domain"], fp["netbios_computer"]))
    if fp.get("dns_computer"):
        bits.append(fp["dns_computer"])
    if fp.get("os"):
        bits.append(fp["os"])
    for a in r.get("internal_addresses", []):
        if isinstance(a, dict) and a.get("internal"):
            bits.append("internal: " + a["address"])
            break
    return "[+] {}  {}".format(r["host"], "  ".join(bits))


def fmt_text(result):
    if not result.get("success"):
        return "[-] {:<40} {:<6} -> {}".format(
            result["target"], result["protocol"], result.get("error", "failed"))
    if result.get("internal_addresses") or (result.get("disclosed_names") and not result.get("ntlm")):
        bits = []
        if result.get("internal_addresses"):
            bits.append("addrs: " + _addr_str(result["internal_addresses"]))
        if result.get("disclosed_names"):
            bits.append("names: " + ", ".join(x["name"] for x in result["disclosed_names"]))
        return "[+] {} ({}) {}".format(result["target"], result["protocol"], " | ".join(bits))
    fp = result["fingerprint"]
    lines = ["[+] {} ({})".format(result["target"], result["protocol"])]
    for label, key in FP_ORDER:
        if fp.get(key) is not None:
            lines.append("      {:<18}: {}".format(label, fp[key]))
    sp = result.get("security_posture", {})
    if sp:
        obs = []
        obs.append("signing " + ("offered" if sp.get("signing_offered") else "not offered"))
        obs.append("channel-binding " + ("present" if sp.get("channel_binding_present") else "absent"))
        if sp.get("weak_crypto_offered"):
            obs.append("WEAK: " + ", ".join(sp["weak_crypto_offered"]))
        lines.append("      {:<18}: {}".format("Posture", " | ".join(obs)))
    return "\n".join(lines)


def _fp_score(r):
    return len([v for v in r.get("fingerprint", {}).values() if v not in (None, "")])


def _endpoint_key(r):
    """(protocol, host, port) identity for an endpoint, with defaults resolved."""
    return (r.get("protocol"), r.get("host"), _job_port(r.get("protocol"), r.get("port")))


def _url_path(url):
    """Path portion of a URL ('/' when there is none)."""
    rest = url.split("://", 1)[-1]
    return rest[rest.find("/"):] if "/" in rest else "/"


def _catchall_representative(rs):
    """The single endpoint to keep for a catch-all host: the site root when
    present, otherwise the richest fingerprint, otherwise the first."""
    for r in rs:
        if _url_path(r.get("url") or "") == "/":
            return r
    return max(rs, key=_fp_score)


def _canary_verdict(canaries):
    """What this endpoint's canary probes actually proved.

    ``catchall`` -- a canary was challenged on a path that cannot exist.
    ``specific`` -- a canary reached the server and was not challenged, so auth
                    really is per-path.
    ``unknown``  -- every canary failed to reach the server, so the guard learned
                    nothing. Treating that as ``specific`` is what made a single
                    timed-out request silently re-expose the whole wordlist.
    """
    reached = False
    for r in canaries:
        if r.get("ntlm"):
            return "catchall"
        if r.get("responded", True):
            reached = True
    return "specific" if reached else "unknown"


def collapse_catchall_endpoints(results):
    """Collapse site-wide (path-agnostic) NTLM auth to one endpoint per host.

    A canary probe that returns an NTLM challenge proves the host challenges
    every path, so its wordlist hits are false positives. When every canary for
    an endpoint failed to reach the server the verdict is ``unknown``, and the
    hit ratio over the paths that *did* answer decides instead -- otherwise one
    dropped request silently re-exposes the whole wordlist as findings.

    The canary results are dropped; for each affected (protocol, host, port)
    group one representative keeps its challenge (tagged ``catchall``, plus
    ``catchall_inferred`` when the ratio decided it) while the rest stay in the
    list for their disclosed names / addresses but no longer count as endpoints.

    Mutates ``results`` in place and returns the filtered list.
    """
    canaries, answered, hits = {}, {}, {}
    out, groups = [], OrderedDict()
    for r in results:
        key = _endpoint_key(r)
        if is_canary_result(r):
            canaries.setdefault(key, []).append(r)
            continue                   # synthetic path -- never an endpoint
        out.append(r)
        if r.get("protocol") not in ("http", "https"):
            continue
        if r.get("responded", True):
            answered[key] = answered.get(key, 0) + 1
            if r.get("ntlm"):
                hits[key] = hits.get(key, 0) + 1
        if r.get("ntlm"):
            groups.setdefault(key, []).append(r)

    for key, rs in groups.items():
        verdict = _canary_verdict(canaries.get(key, []))
        inferred = False
        if verdict == "unknown":
            # No canary survived. Fall back on the shape of the wordlist run
            # itself, which costs no extra request and cannot time out.
            n = answered.get(key, 0)
            if n >= CATCHALL_MIN_SAMPLE and hits.get(key, 0) >= n * CATCHALL_HIT_RATIO:
                verdict, inferred = "catchall", True
        if verdict != "catchall":
            continue
        rep = _catchall_representative(rs)
        for r in rs:
            r["catchall"] = True
            if inferred:
                r["catchall_inferred"] = True
            if r is rep:
                r["catchall_collapsed"] = len(rs)
            else:
                r["ntlm"] = None
    return out


def print_host_summaries(results, roles=None, out=sys.stdout, full=False):
    """Per-host summary block.

    full=False (default screen): show endpoint COUNT only.
    full=True  (log file / -v):  enumerate every disclosing endpoint.
    """
    roles = roles or {}
    use_color = _use_color(out)
    hosts = OrderedDict()
    for r in results:
        if r.get("success"):
            hosts.setdefault(r["host"], []).append(r)
    if not hosts:
        return
    for host, rs in hosts.items():
        rep = max(rs, key=_fp_score)
        fp = rep.get("fingerprint", {})
        has_internal = any(r.get("internal_addresses") for r in rs)
        # On the default (non-full) screen, skip hosts whose only finding is a
        # disclosed name (no NTLM fingerprint, no internal address).
        if not full and not fp and not has_internal:
            continue
        ident = fp.get("dns_computer") or fp.get("netbios_computer") or host
        out.write("\n" + "=" * 72 + "\n")
        out.write("  HOST: {}   ({})\n".format(host, ident))
        out.write("-" * 72 + "\n")
        # Addresses -- highest-value findings, shown first. External is the
        # scanned public IP; internal is whatever a disclosure leaked.
        internal = OrderedDict()  # addr -> source
        for r in rs:
            for a in r.get("internal_addresses", []):
                addr = a["address"] if isinstance(a, dict) else a
                src = (a.get("source") if isinstance(a, dict) else None) or r.get("protocol")
                internal.setdefault(addr, src)
        out.write("  {:<18}: {}\n".format("External address", host))
        if internal:
            if full:
                shown = ", ".join("{} ({})".format(a, s) for a, s in internal.items())
            else:
                shown = ", ".join(internal.keys())
            out.write("  {:<18}: {}\n".format("Internal address", shown))
        for label, key in FP_ORDER:
            if fp.get(key) is not None:
                out.write("  {:<18}: {}\n".format(label, fp[key]))
        # Domain role (member vs DC), from host-level evidence. Screen shows the
        # bare label; the reasoning moves to the full log / -v.
        role = roles.get(host)
        if role and role.get("role") and role["role"] != "Unknown":
            if role["role"] == "Domain Controller":
                q = "confirmed" if role.get("confidence") == "confirmed" else "likely"
                val = "Domain Controller ({})".format(q)
            else:
                val = role["role"]  # "Domain member"
            if full and role.get("reasons"):
                val += " -- " + "; ".join(role["reasons"])
            out.write("  {:<18}: {}\n".format("Role", val))
        sp = rep.get("security_posture", {})
        if sp.get("weak_crypto_offered"):
            out.write("  {:<18}: {}\n".format("Weak crypto", ", ".join(sp["weak_crypto_offered"])))
        # rootDSE (anonymous LDAP read) -- naming contexts + AD functional levels.
        rd = next((r.get("rootdse") for r in rs if r.get("rootdse")), None)
        if rd:
            if rd.get("dnsHostName"):
                out.write("  {:<18}: {}\n".format("LDAP dnsHostName", rd["dnsHostName"]))
            if rd.get("defaultNamingContext"):
                out.write("  {:<18}: {}\n".format("Naming context", rd["defaultNamingContext"]))
            dl = _FUNC_LEVEL.get(str(rd.get("domainFunctionality", "")))
            fl = _FUNC_LEVEL.get(str(rd.get("forestFunctionality", "")))
            if dl or fl:
                out.write("  {:<18}: domain {}  /  forest {}\n".format(
                    "Functional level", dl or "?", fl or "?"))
        # Disclosed names (TLS/RDP cert CN+SAN, Exchange FE/BE headers, OXID).
        # Low-signal, so only rendered in the full log / -v, not the default screen.
        if full:
            names = OrderedDict()
            for r in rs:
                for a in r.get("disclosed_names", []):
                    nm = a["name"] if isinstance(a, dict) else a
                    ssrc = a.get("source") if isinstance(a, dict) else None
                    names.setdefault(nm, ssrc or r.get("protocol"))
            if names:
                out.write("  {:<18}: {}\n".format("Disclosed names", len(names)))
                for nm, ssrc in names.items():
                    out.write("      - {} [{}]\n".format(nm, ssrc))
        # NTLM-disclosing endpoints only (exclude probe-only rows).
        _PROBE_ONLY = ("iisip", "oxid", "tlscert", "rdpcert")
        eps = []
        for r in sorted(rs, key=lambda x: (x["protocol"], x.get("url") or "")):
            if r.get("protocol") in _PROBE_ONLY or not r.get("ntlm"):
                continue
            eps.append(r.get("url") or "{}://{}:{}".format(r["protocol"], r["host"], r.get("port") or ""))
        if eps:
            row = "  {}: {}".format("NTLM endpoints identified", len(eps))
            out.write(_color(row, C_RED, use_color) + "\n")
            for e in eps:
                out.write("      - {}\n".format(e))
            if any(r.get("catchall") for r in rs):
                n = max((r.get("catchall_collapsed") or 0)
                        for r in rs if r.get("catchall"))
                # Say which signal decided it: a canary that came back, or the
                # hit ratio standing in because none of them did.
                basis = ("inferred from hit ratio, canary unreachable"
                         if any(r.get("catchall_inferred") for r in rs)
                         else "canary confirmed")
                out.write(_color(
                    "      (site-wide NTLM auth -- path-agnostic; {} wordlist "
                    "path(s) collapsed; {})".format(n, basis),
                    C_YELLOW, use_color) + "\n")
    out.write("=" * 72 + "\n")


def write_csv(results, path, roles=None):
    import csv
    roles = roles or {}
    with _secure_open(path, newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in results:
            fp = r.get("fingerprint", {}) or {}
            sp = r.get("security_posture", {}) or {}
            role = roles.get(r.get("host"), {})
            row = {"target": r.get("target"), "protocol": r.get("protocol"),
                   "host": r.get("host"), "port": r.get("port"),
                   "success": r.get("success"), "elapsed_ms": r.get("elapsed_ms"),
                   "error": r.get("error", ""),
                   "domain_role": role.get("role"),
                   "role_confidence": role.get("confidence"),
                   "signing": sp.get("signing_offered"),
                   "channel_binding": sp.get("channel_binding_present"),
                   "weak_crypto": ";".join(sp.get("weak_crypto_offered", [])),
                   "internal_addresses": ";".join(
                       (a["address"] if isinstance(a, dict) else a)
                       for a in r.get("internal_addresses", [])),
                   "disclosed_names": ";".join(
                       (a["name"] if isinstance(a, dict) else a)
                       for a in r.get("disclosed_names", []))}
            row.update({k: fp.get(k) for k in (
                "target_realm", "target_realm_type", "netbios_computer",
                "netbios_domain", "dns_computer", "dns_domain", "dns_forest",
                "os", "os_build", "machine_id", "server_time_utc",
                "time_skew_seconds")})
            w.writerow(row)


def write_hosts_file(results, path, roles=None):
    """NetExec-style hosts file: 'FQDN shortname' (+ bare domain for DCs)."""
    roles = roles or {}
    lines, seen = [], set()
    for r in results:
        if not r.get("success") or not r.get("fingerprint"):
            continue
        fp = r["fingerprint"]
        ip = r["host"]
        fqdn = fp.get("dns_computer")
        short = fp.get("netbios_computer")
        names = []
        if fqdn:
            names.append(fqdn)
        if short and (not fqdn or short.lower() != fqdn.split(".")[0].lower()):
            names.append(short)
        if roles.get(ip, {}).get("role") == "Domain Controller" and fp.get("dns_domain"):
            names.append(fp["dns_domain"])
        if names:
            key = (ip, tuple(n.lower() for n in names))
            if key not in seen:
                seen.add(key)
                lines.append("{}\t{}".format(ip, " ".join(names)))
    with _secure_open(path) as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)


# ===========================================================================
#  SPRAY MODE  (opt-in, --spray)
#
#  Separate from recon. Sends real credentials (NTLM Type-3 or HTTP Basic) to
#  the single most effective auth endpoint on each target. Password-spray
#  ordering (one password across all users, then wait) is enforced so each
#  account sees at most one attempt per round -- the safe pattern that avoids
#  tripping account lockout. NEVER relays or cracks; just validates creds.
# ===========================================================================

# Ranked HTTP endpoints for credential validation. Top entries give a clean
# 200/401 oracle and lean on legacy auth (MailSniper / SprayingToolkit lineage).
SPRAY_PATHS = [
    "/EWS/Exchange.asmx", "/Microsoft-Server-ActiveSync/",
    "/Autodiscover/Autodiscover.xml", "/mapi/emsmdb/", "/rpc/", "/OAB/", "/owa/",
]


# ---- MD4 (OpenSSL 3 dropped it from the default provider, so implement it) --
def _md4(msg):
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = h

        def F(x, y, z): return (x & y) | (~x & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z
        for i in (0, 4, 8, 12):
            a = lrot(a + F(b, c, d) + X[i], 3); d = lrot(d + F(a, b, c) + X[i + 1], 7)
            c = lrot(c + F(d, a, b) + X[i + 2], 11); b = lrot(b + F(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + G(b, c, d) + X[i] + 0x5A827999, 3)
            d = lrot(d + G(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + G(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + G(c, d, a) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + H(b, c, d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + H(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + H(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + H(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
        h = [(h[0] + a) & 0xFFFFFFFF, (h[1] + b) & 0xFFFFFFFF,
             (h[2] + c) & 0xFFFFFFFF, (h[3] + d) & 0xFFFFFFFF]
    return struct.pack("<4I", *h)


def _ntowfv2(password, user, domain):
    nt = _md4(password.encode("utf-16-le"))
    return hmac.new(nt, (user.upper() + domain).encode("utf-16-le"), hashlib.md5).digest()


def _ntlmv2_response(nt_v2, server_challenge, target_info):
    ts = struct.pack("<Q", (int(time.time()) + 11644473600) * 10000000)
    cc = os.urandom(8)
    blob = (b"\x01\x01\x00\x00\x00\x00\x00\x00" + ts + cc + b"\x00\x00\x00\x00"
            + target_info + b"\x00\x00\x00\x00")
    proof = hmac.new(nt_v2, server_challenge + blob, hashlib.md5).digest()
    return proof + blob


def _build_type3(domain, user, nt_resp, workstation=""):
    flags = 0x00088205  # UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXT_SESSION_SEC
    lm = b"\x00" * 24
    dom = domain.encode("utf-16-le"); usr = user.encode("utf-16-le")
    wks = workstation.encode("utf-16-le"); skey = b""
    base = 64
    payload = b""
    fields = b""
    off = base
    for data in (lm, nt_resp, dom, usr, wks, skey):
        fields += struct.pack("<HHI", len(data), len(data), off)
        payload += data
        off += len(data)
    hdr = NTLMSSP_SIG + struct.pack("<I", 3) + fields + struct.pack("<I", flags)
    return hdr + payload


def _http_conn(host, port, use_tls, timeout):
    if _PROXY:
        ph, pp = _PROXY
        conn = (http.client.HTTPSConnection(ph, pp, timeout=timeout, context=_tls_context())
                if use_tls else http.client.HTTPConnection(ph, pp, timeout=timeout))
        conn.set_tunnel(host, port)
        return conn
    if use_tls:
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=_tls_context())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def spray_ntlm(host, port, use_tls, path, domain, user, password, timeout=10):
    """Full NTLM Type-1/2/3 over one keep-alive connection. Returns HTTP status or None."""
    conn = _http_conn(host, port, use_tls, timeout)
    ua = "Mozilla/5.0 (ntlmscout)"
    try:
        t1 = base64.b64encode(build_type1()).decode()
        conn.request("GET", path, headers={"Authorization": "NTLM " + t1,
                                            "User-Agent": ua, "Connection": "keep-alive"})
        r1 = conn.getresponse(); r1.read()
        m = re.search(r"NTLM ([A-Za-z0-9+/=]+)", r1.getheader("WWW-Authenticate", "") or "")
        if not m:
            return None  # NTLM not offered here
        t2 = base64.b64decode(m.group(1))
        server_challenge = t2[24:32]
        ti_len, _tmax, ti_off = struct.unpack("<HHI", t2[40:48])
        target_info = t2[ti_off:ti_off + ti_len]
        nt_v2 = _ntowfv2(password, user, domain)
        nt_resp = _ntlmv2_response(nt_v2, server_challenge, target_info)
        t3 = base64.b64encode(_build_type3(domain, user, nt_resp)).decode()
        conn.request("GET", path, headers={"Authorization": "NTLM " + t3,
                                            "User-Agent": ua, "Connection": "keep-alive"})
        r2 = conn.getresponse(); r2.read()
        return r2.status
    except Exception:
        _dbg("spray_ntlm %s %s" % (host, path))
        return None
    finally:
        try: conn.close()
        except Exception: pass


def spray_basic(host, port, use_tls, path, user, password, timeout=10):
    conn = _http_conn(host, port, use_tls, timeout)
    try:
        cred = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        conn.request("GET", path, headers={"Authorization": "Basic " + cred,
                                           "User-Agent": "Mozilla/5.0 (ntlmscout)"})
        r = conn.getresponse(); r.read()
        return r.status
    except Exception:
        _dbg("spray_basic %s %s" % (host, path))
        return None
    finally:
        try: conn.close()
        except Exception: pass


def _spray_target_parts(t):
    """(host, port, use_tls, path) from a bare host or URL (IPv6-aware)."""
    if "://" in t:
        scheme = t.split("://", 1)[0].lower()
        rest = t.split("://", 1)[1].split("/", 1)[0]
        host, port = _split_host_port(rest)
        port = port or (443 if scheme == "https" else 80)
        path = t.split("://", 1)[1][len(rest):] or None
        return host, port, scheme == "https", path
    host, port = _split_host_port(t)
    port = port or 443
    return host, port, port != 80, None


def _learn_ntlm_domain(host, port, use_tls, path, timeout):
    """Send a Type-1 and read the NetBIOS domain out of the Type-2 challenge."""
    conn = _http_conn(host, port, use_tls, timeout)
    try:
        t1 = base64.b64encode(build_type1()).decode()
        conn.request("GET", path, headers={"Authorization": "NTLM " + t1, "User-Agent": "Mozilla/5.0"})
        r = conn.getresponse(); r.read()
        m = re.search(r"NTLM ([A-Za-z0-9+/=]+)", r.getheader("WWW-Authenticate", "") or "")
        if m:
            blob = base64.b64decode(m.group(1))
            if blob.startswith(NTLMSSP_SIG):
                return parse_challenge(blob)["target_info"].get("MsvAvNbDomainName")
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass
    return None


def pick_spray_endpoint(host, port, use_tls, auth, timeout, forced_path=None):
    """Return (path, domain) for the first endpoint offering the needed scheme.

    Probes with NO Authorization header and reads the 401's WWW-Authenticate
    list -- the reliable way to enumerate accepted schemes. For NTLM spraying we
    accept either 'NTLM' or 'Negotiate' (SPNEGO carries NTLM); for basic, 'Basic'.
    """
    wanted = ("basic",) if auth == "basic" else ("ntlm", "negotiate")
    paths = [forced_path] if forced_path else SPRAY_PATHS
    for path in paths:
        conn = _http_conn(host, port, use_tls, timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})  # unauthenticated
            r = conn.getresponse(); r.read()
            auths = " ".join(v for (k, v) in r.getheaders()
                             if k.lower() == "www-authenticate").lower()
        except Exception:
            continue
        finally:
            try: conn.close()
            except Exception: pass
        if any(w in auths for w in wanted):
            domain = None
            if auth != "basic":
                domain = _learn_ntlm_domain(host, port, use_tls, path, timeout)
            return path, domain
    return (forced_path, None) if forced_path else (None, None)


def _identity(user, domain):
    """Resolve how to present a username. Returns (send_domain, send_user, display).

    - UPN / email (has '@')  -> sent alone, NO NetBIOS domain (domain="").
    - pre-qualified DOMAIN\\user -> split and respected as given.
    - bare sAMAccountName -> qualified with the learned/`--domain` NetBIOS domain.
    """
    if "@" in user:
        return "", user, user
    if "\\" in user:
        d, u = user.split("\\", 1)
        return d, u, user
    if domain:
        return domain, user, "%s\\%s" % (domain, user)
    return "", user, user


def _load_list(values):
    """Expand a list of user/password args: each item is a literal or a file path."""
    out = []
    for v in values or []:
        if os.path.isfile(v):
            with open(v, "r", errors="ignore") as fh:
                out += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        else:
            out.append(v)
    # de-dupe, preserve order
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq


def run_spray(args):
    """Spray mode: resolve the best endpoint per target, then password-spray
    (one password across all users per round) and report valid/invalid/inconclusive."""
    users = _load_list(args.user)
    passwords = _load_list(args.password)
    if not users or not passwords:
        sys.stderr.write("[!] spray mode requires users (-u) and passwords (-p)\n")
        return 2
    # Spray resolves exactly one endpoint per target, so the budget counts one
    # probe per host rather than the recon fan-out.
    n_targets, _ = project_plan(args, per_target=1)
    if n_targets is None:
        return 2
    if not n_targets:
        sys.stderr.write("[!] no targets given\n")
        return 2

    # Resolve one spray endpoint per target.  Targets are expanded lazily so a
    # large prefix is never held as a list.
    sys.stderr.write("[*] Resolving spray endpoints across %d target(s)...\n" % n_targets)
    endpoints = []  # (host, port, use_tls, path, domain)
    for t in _expand_targets(_iter_raw_targets(args)):
        host, port, use_tls, path = _spray_target_parts(t)
        ep, dom = pick_spray_endpoint(host, port, use_tls, args.auth, args.timeout,
                                      forced_path=path or args.spray_path)
        if not ep:
            sys.stderr.write("[-] %s: no %s-capable endpoint found; skipping\n"
                             % (host, args.auth.upper()))
            continue
        domain = args.domain or dom or ""
        endpoints.append((host, port, use_tls, ep, domain))
        sys.stderr.write("[+] %s -> spray %s via %s%s\n"
                         % (host, args.auth.upper(), ep,
                            "  (domain %s)" % domain if domain else ""))
    if not endpoints:
        sys.stderr.write("[!] No sprayable endpoints resolved; nothing to do.\n")
        return 1

    rounds = len(passwords)
    sys.stderr.write(
        "\n[!] SPRAY: %d user(s) x %d password(s) = %d round(s), <=1 attempt/account/round.\n"
        "    auth=%s  delay=%ss between rounds  jitter=%ss  threads=%d\n"
        "    Password-spray ordering keeps each account to one try per round to\n"
        "    avoid lockout -- confirm the target's lockout policy first.\n\n"
        % (len(users), len(passwords), rounds, args.auth, args.delay, args.jitter, args.threads))

    def classify(st):
        if st in (200, 301, 302):
            return "valid"
        if st == 403:
            return "valid"          # authenticated, access restricted -- creds are good
        if st in (401, 407):
            return "invalid"
        return "error"              # None / 400 / 5xx -> could NOT reliably test

    found = {}          # (host, user) -> password  (stop retrying once valid)
    attempts = []       # every attempt, for the audit trail / --json
    tally = {"valid": 0, "invalid": 0, "error": 0}
    sc = _use_color(sys.stdout)   # colorize per-attempt lines only on a real terminal

    def attempt(host, port, use_tls, path, domain, user, password):
        if args.jitter:
            time.sleep(random.uniform(0, args.jitter))
        send_dom, send_user, _disp = _identity(user, domain)
        if args.auth == "basic":
            st = spray_basic(host, port, use_tls, path, _disp, password, args.timeout)
        else:
            st = spray_ntlm(host, port, use_tls, path, send_dom, send_user, password, args.timeout)
        return st

    for pi, password in enumerate(passwords):
        if pi > 0 and args.delay:
            sys.stderr.write("[*] round %d/%d done; waiting %ss before next password...\n"
                             % (pi, rounds, args.delay))
            time.sleep(args.delay)
        round_tally = {"valid": 0, "invalid": 0, "error": 0}
        jobs = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for (host, port, use_tls, path, domain) in endpoints:
                for user in users:
                    if (host, user) in found:
                        continue
                    jobs.append((ex.submit(attempt, host, port, use_tls, path, domain, user, password),
                                 host, path, domain, user, password))
            for fut, host, path, domain, user, password in jobs:
                st = fut.result()
                verdict = classify(st)
                tally[verdict] += 1
                round_tally[verdict] += 1
                who = _identity(user, domain)[2]
                rec = {"host": host, "endpoint": path, "domain": domain, "user": user,
                       "password": password, "status": st, "result": verdict}
                attempts.append(rec)
                if verdict == "valid":
                    found[(host, user)] = password
                    print(_color("[VALID]   ", C_GREEN, sc)
                          + "%s  %s : %s   (HTTP %s, %s)" % (host, who, password, st, path))
                elif args.verbose and verdict == "invalid":
                    print(_color("[invalid] ", C_RED, sc)
                          + "%s  %s : %s   (HTTP %s)" % (host, who, password, st))
                elif args.verbose and verdict == "error":
                    print(_color("[error]   ", C_YELLOW, sc)
                          + "%s  %s : %s   (no clean response - not tested)" % (host, who, password))
        sys.stderr.write("[*] round %d/%d (password %r): valid=%d invalid=%d inconclusive=%d\n"
                         % (pi + 1, rounds, password, round_tally["valid"],
                            round_tally["invalid"], round_tally["error"]))

    # ---- Verdict summary the consultant can trust -------------------------
    sys.stderr.write("\n" + "=" * 64 + "\n")
    sys.stderr.write("  SPRAY RESULTS\n")
    sys.stderr.write("-" * 64 + "\n")
    sys.stderr.write("  attempts made     : %d\n" % len(attempts))
    sys.stderr.write("  VALID credentials : %d\n" % tally["valid"])
    sys.stderr.write("  invalid (rejected): %d\n" % tally["invalid"])
    sys.stderr.write("  inconclusive/error: %d   (endpoint gave no clean 200/401 oracle)\n"
                     % tally["error"])
    dom_of = {e[0]: e[4] for e in endpoints}
    if tally["valid"]:
        sys.stderr.write("\n  Valid credentials found:\n")
        for (h, u), pw in found.items():
            who = "%s\\%s" % (dom_of.get(h) or h, u) if dom_of.get(h) else u
            sys.stderr.write("    %s  %s : %s\n" % (h, who, pw))
    elif tally["invalid"] and not tally["error"]:
        sys.stderr.write("\n  No valid credentials -- every account cleanly rejected (tested OK).\n")
    elif tally["error"] and not tally["invalid"]:
        sys.stderr.write("\n  INCONCLUSIVE -- no endpoint returned a clean 200/401 oracle, so\n"
                         "  these creds were NOT actually validated. Try --auth basic, a\n"
                         "  different --spray-path, or check the endpoint manually.\n")
    else:
        sys.stderr.write("\n  No valid credentials found (%d rejected, %d inconclusive).\n"
                         % (tally["invalid"], tally["error"]))
    sys.stderr.write("=" * 64 + "\n")

    if args.output:
        with _secure_open(args.output) as fh:
            for (h, u), pw in found.items():
                fh.write("%s\t%s\t%s\n" % (h, u, pw))
        sys.stderr.write("[*] %d valid credential(s) written to %s\n" % (len(found), args.output))
    if args.json:
        with _secure_open(args.json) as fh:
            json.dump({"summary": tally, "valid": [
                {"host": h, "user": u, "password": pw} for (h, u), pw in found.items()],
                "attempts": attempts}, fh, indent=2)
        sys.stderr.write("[*] Full attempt log written to %s\n" % args.json)
    return 0


def build_arg_parser():
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Enumerate information disclosed by exposed NTLM endpoints "
                    "(CHALLENGE/Type-2 parsing). Protocols: http https smb mssql "
                    "smtp smtps imap imaps pop3 pop3s nntp nntps ldap ldaps rdp",
        epilog="examples:\n"
               "  ntlmscout.py 1.1.1.1                          scan a single IP\n"
               "  ntlmscout.py mail.example.com                 scan a host\n"
               "  ntlmscout.py 10.0.0.0/24                      scan a CIDR range\n"
               "  ntlmscout.py -I targets.txt                   scan a list of targets\n")
    ap.add_argument("targets", nargs="*",
                    help="hosts or URLs (e.g. https://h/ews/, smb://10.0.0.5, host:445)")
    ap.add_argument("-I", "--input-list", metavar="FILE",
                    help="file with one target per line")

    scope = ap.add_argument_group("recon scope (default: full sweep of all ports)")
    scope.add_argument("--no-discover", action="store_true",
                       help="skip the HTTP path wordlist; probe site roots only "
                            "(~9x fewer probes per host)")
    scope.add_argument("--no-internal-ip", action="store_true",
                       help="skip internal-disclosure checks (IIS Host-header/PROPFIND, "
                            "TLS+RDP cert names, Exchange FE/BE headers, RPC OXID/135) "
                            "(~2x fewer probes per host)")
    scope.add_argument("--max-jobs", type=int, default=_MAX_JOBS, metavar="N",
                       help="refuse to start if the plan exceeds N probes "
                            "(default %d; 0 = unlimited). A bare host costs %d "
                            "probes at default flags, so a /24 is ~%d and a /16 "
                            "is ~%d -- check this before scanning a large prefix."
                            % (_MAX_JOBS, _bare_host_probes(),
                               254 * _bare_host_probes(), 65534 * _bare_host_probes()))

    spray = ap.add_argument_group("spray mode")
    spray.add_argument("--spray", action="store_true",
                       help="AUTHENTICATION SPRAY mode: send real creds to the best "
                            "endpoint. Requires -u and -p.")
    spray.add_argument("-u", "--user", action="append", metavar="USER|FILE",
                       help="username, or path to a userlist file (repeatable)")
    spray.add_argument("-p", "--password", action="append", metavar="PASS|FILE",
                       help="password, or path to a password-list file (repeatable)")
    spray.add_argument("--domain", help="AD domain to qualify usernames "
                                        "(auto-learned from NTLM if omitted)")
    spray.add_argument("--auth", choices=("ntlm", "basic"), default="ntlm",
                       help="spray auth method (default ntlm)")
    spray.add_argument("--spray-path", help="force a specific endpoint path to spray")
    spray.add_argument("--delay", type=float, default=0.0,
                       help="seconds to wait between password rounds (lockout safety)")
    spray.add_argument("--jitter", type=float, default=0.0,
                       help="random 0..N seconds added per attempt")

    out = ap.add_argument_group("output")
    out.add_argument("-o", "--output", "--log", dest="output",
                     help="write detailed per-host log (every disclosing endpoint) to file")
    out.add_argument("--json", help="write full JSON results to file")
    out.add_argument("--ndjson", help="write newline-delimited JSON (one object per line)")
    out.add_argument("--csv", help="write results as CSV (one row per probe)")
    out.add_argument("--generate-hosts-file", dest="hosts_file",
                     help="write a NetExec-style hosts file from discovered names")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="print the full fingerprint block for every hit as it lands")
    out.add_argument("--no-summary", action="store_true",
                     help="skip the grouped per-host summary at the end")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress per-probe stderr")

    behavior = ap.add_argument_group("behavior")
    behavior.add_argument("-t", "--threads", type=int, default=20,
                          help="concurrency (default 20)")
    behavior.add_argument("--timeout", type=float, default=10,
                          help="per-probe timeout seconds")
    behavior.add_argument("--proxy", metavar="HOST:PORT",
                          help="tunnel all connections through an HTTP CONNECT proxy "
                               "(e.g. 127.0.0.1:8080; SOCKS not supported)")
    behavior.add_argument("--verify-tls", action="store_true",
                          help="verify TLS certificates (off by default for self-signed)")
    behavior.add_argument("--debug", action="store_true",
                          help="surface swallowed exceptions for troubleshooting")
    return ap


def run_recon(args):
    """Default mode: full sweep of every NTLM-capable port on each target
    (HTTP/S + wordlist, SMB, all mail, LDAP/GC, MSSQL, RDP, NNTP) plus the
    internal-disclosure modules; decode every challenge and report.
    --no-discover trims the HTTP wordlist; --no-internal-ip drops cert/OXID/IIS."""
    hosts, projected = project_plan(args)
    if hosts is None:
        return 2
    if not hosts:
        sys.stderr.write("[!] no targets to scan\n")
        return 2
    # Config line first, so the user sees activity before the (silent) port check.
    if not args.quiet:
        sys.stderr.write("[*] recon  ·  %d host(s)  ·  ~%d probe(s)  ·  %d threads  ·  "
                         "%gs timeout  ·  proxy %s\n"
                         % (hosts, projected, args.threads, args.timeout,
                            "on" if _PROXY else "off"))

    # The plan is streamed in batches rather than built up front, so peak memory
    # tracks concurrency instead of target count.  Look one batch ahead: when the
    # whole scan fits in a single batch (the common case) the exact totals are
    # known and progress reports them as before.
    batches = iter_job_batches(args)
    first = next(batches, None)
    if first is None:
        sys.stderr.write("[!] no probes planned for the given target(s)\n")
        return 2
    second = next(batches, None)
    single = second is None
    # Held in a list so each batch is released as soon as it is handed over.
    head = [first] if single else [first, second]
    del first, second

    def _stream():
        while head:
            yield head.pop(0)
        for b in batches:
            yield b

    # Live in-place progress on an interactive terminal (not when piped/quiet/-v).
    show_progress = (not args.quiet) and (not args.verbose) and _use_color(sys.stderr)

    def _clear_progress():
        if show_progress:
            sys.stderr.write("\r\033[K"); sys.stderr.flush()

    results = []
    announced = set()
    done = planned = total = closed_total = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for batch_no, batch in enumerate(_stream()):
            planned += len(batch)
            # Skip everything on closed ports (one fast connect per host:port) --
            # avoids the per-probe timeouts that dominate scan time on filtered
            # hosts.  A batch holds whole hosts, so this still dedupes per host.
            if not args.quiet and batch_no == 0:
                if single:
                    ports = len({(j[1], _job_port(j[0], j[2])) for j in batch})
                    sys.stderr.write("[*] checking %d host:port(s) for open services ...\n"
                                     % ports)
                else:
                    sys.stderr.write("[*] planning in batches of %d probe(s); checking "
                                     "ports as each batch is reached ...\n" % _PLAN_BATCH)
            live, closed = prune_closed_ports(batch, args.timeout, args.threads)
            closed_total += closed
            total += len(live)
            del batch
            if not args.quiet and batch_no == 0:
                if single and closed_total:
                    sys.stderr.write("[*] %d closed port(s) skipped  ·  %d/%d probes live\n"
                                     % (closed_total, total, planned))
                sys.stderr.write("[*] scouting exposed NTLM, please stand by ...\n")
            futs = {ex.submit(probe, proto, host, port, url, None, args.timeout): (proto, host)
                    for (proto, host, port, url) in live}
            del live
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                results.append(r)
                done += 1
                if args.quiet:
                    continue
                if args.verbose and not is_canary_result(r):
                    # Full live detail: every endpoint / probe (the synthetic
                    # canary path is internal plumbing, not a finding).
                    if r.get("success"):
                        print(fmt_text(r)); print()
                    else:
                        print(fmt_text(r))
                elif (r.get("success") and r["host"] not in announced
                      and (r.get("fingerprint") or r.get("internal_addresses"))):
                    # Default: one concise line the first time a host is confirmed
                    # (name-only cert hits don't warrant a live line).
                    announced.add(r["host"])
                    _clear_progress()
                    print(host_line(r)); sys.stdout.flush()
                if show_progress:
                    sys.stderr.write("\r\033[K[*] scouting... %d/%s probes  |  %d misconfigured host(s) found"
                                     % (done, total if single else "%d+" % total,
                                        len(announced)))
                    sys.stderr.flush()
            futs.clear()
        _clear_progress()
    if not args.quiet and not single and closed_total:
        sys.stderr.write("[*] %d closed port(s) skipped  ·  %d/%d probes live\n"
                         % (closed_total, total, planned))

    # Fold site-wide NTLM auth (path-agnostic) down to one finding per host so
    # the wordlist doesn't masquerade as dozens of distinct endpoints.
    results = collapse_catchall_endpoints(results)
    roles = resolve_host_roles(results)
    # "Exposed NTLM" = endpoints that actually returned an NTLM challenge (not
    # cert names / internal IPs / headers leaked via an adjacent check).
    ntlm_endpoints = sum(1 for r in results if r.get("ntlm"))
    ntlm_hosts = {r["host"] for r in results if r.get("ntlm")}
    if not args.quiet:
        if not args.no_summary:
            # Screen block: counts only (full endpoint list goes to -o / -v).
            print_host_summaries(results, roles, sys.stdout, full=args.verbose)
        color = _use_color(sys.stdout)
        if ntlm_endpoints:
            print(_color("[+] %d exposed NTLM endpoint(s) on %d of %d host(s)."
                         % (ntlm_endpoints, len(ntlm_hosts), hosts), C_GREEN, color))
        else:
            print(_color("[-] No exposed NTLM endpoints found across %d host(s)."
                         % hosts, C_YELLOW, color))

    if args.json:
        with _secure_open(args.json) as fh:
            json.dump({"results": results, "roles": roles}, fh, indent=2, default=str)
        sys.stderr.write("[*] JSON written to %s\n" % args.json)
    if args.ndjson:
        with _secure_open(args.ndjson) as fh:
            for r in results:
                fh.write(json.dumps(r, default=str) + "\n")
        sys.stderr.write("[*] NDJSON written to %s\n" % args.ndjson)
    if args.csv:
        write_csv(results, args.csv, roles)
        sys.stderr.write("[*] CSV written to %s\n" % args.csv)
    if args.hosts_file:
        n = write_hosts_file(results, args.hosts_file, roles)
        sys.stderr.write("[*] Hosts file (%d entries) written to %s\n" % (n, args.hosts_file))
    if args.output:
        # Detailed log: full per-host block with every disclosing endpoint.
        with _secure_open(args.output) as fh:
            print_host_summaries(results, roles, fh, full=True)
        sys.stderr.write("[*] Detailed log written to %s\n" % args.output)
    return 0


def main():
    global _VERIFY_TLS, _DEBUG, _PROXY
    ap = build_arg_parser()
    args = ap.parse_args()
    _VERIFY_TLS = args.verify_tls
    _DEBUG = args.debug
    if args.proxy:
        p = args.proxy.split("://", 1)[-1].rstrip("/")
        _PROXY = (p.rsplit(":", 1)[0], int(p.rsplit(":", 1)[1]))

    print_banner(args.quiet)

    if not args.targets and not args.input_list:
        sys.stderr.write(ap.format_usage())
        sys.stderr.write("[!] no targets given -- try: ntlmscout.py 1.1.1.1"
                         "  (see -h for full help)\n")
        sys.exit(2)

    # Catch the common slip of passing a target file as a positional arg.
    for t in args.targets:
        if os.path.isfile(t):
            sys.stderr.write("[!] '%s' looks like a file -- did you mean:  -I %s\n" % (t, t))
            sys.exit(2)

    sys.exit(run_spray(args) if args.spray else run_recon(args))


if __name__ == "__main__":
    main()
