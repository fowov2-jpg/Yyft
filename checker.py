#!/usr/bin/env python3
"""Bounded read-only checks of allowlisted public VPN subscriptions.

Nothing from the feeds is executed as code. Outbound server addresses are pinned
on the runner to a single public IP after DNS resolution (no DNS rebinding).
The published output never includes the original share URL or credentials.
"""
from __future__ import annotations
import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler, Request

# Stable IDs mirror ConfigSources.kt. All source URLs are fixed in this code.
SOURCES = {
    "avia": ["https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/ru_configs.txt", "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt"],
    "nikita": ["https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt", "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt"],
    "3inker": ["https://raw.githubusercontent.com/3inker/v2ray-subscription/main/subs/all_not_ru.txt", "https://raw.githubusercontent.com/3inker/v2ray-subscription/main/subs/all_ru.txt"],
    "radikal": ["https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt"],
    "morpheus": ["https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt", "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt"],
    "hamed": ["https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/top100.txt"],
    "barry": ["https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"],
    "solispirit": ["https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt"],
    "ebrasha": ["https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt"],
    "mohammad": ["https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/Tested.txt"],
    # Newly verified public GitHub sources. Their update cadence is not proof of local reachability.
    "telega_ru": ["https://raw.githubusercontent.com/TelegaVPN/free-vpn-keys/main/sub/base64/for-russia.txt",
                  "https://raw.githubusercontent.com/TelegaVPN/free-vpn-keys/main/sub/base64/all.txt"],
    "au1rxx": ["https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/protocol/vless/v2ray-base64-0001.txt"],

}
# The legacy Android PublicRankingFeed rejects an entire feed if ANY source_id
# is absent from ConfigSources.all (notably cloud-only telega_ru). Keep the
# metadata ranking compatible with already-installed APKs. This restriction
# does not affect candidates.json, where the extra public source is explicitly
# allowlisted by PublicCandidateSourcePolicy.
ANDROID_RANKING_SOURCE_IDS = frozenset({
    "avia", "nikita", "3inker", "radikal", "morpheus", "hamed",
    "barry", "solispirit", "ebrasha", "mohammad", "au1rxx",
})
assert ANDROID_RANKING_SOURCE_IDS <= SOURCES.keys()
MAX_PER_RUN = 24
MAX_RESULTS = 180
MAX_PUBLIC_CANDIDATES = 24
MAX_PUBLIC_CANDIDATES_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_FEED_BYTES = 256 * 1024
MAX_SOURCE_LINKS = 600
MAX_WORKERS = 2
MAX_RESTART_CHECKS = 3  # Extra real Xray launches, bounded per hour
MAX_RECHECKS = 6  # Re-probe successful public routes; total initial Xray checks remains 24
RESULT_TTL = timedelta(hours=8)
PUBLICATION_TTL = timedelta(hours=6)
ALLOWED_SCHEMES = {"vless", "vmess", "trojan", "ss"}
CREDENTIAL_METHODS = {"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
LINK_RE = re.compile(r"(?i)(?:vless|vmess|trojan|ss)://[^\s<>\"']+")

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect blocked")

OPENER = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

def fetch_fixed_https(url, limit):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"raw.githubusercontent.com", "github.com"}:
        raise ValueError("not an allowlisted source host")
    with OPENER.open(Request(url, headers={"User-Agent": "SecureConnect-Public-Checker/1"}), timeout=7) as resp:
        if resp.status != 200:
            raise ValueError("non-200 source")
        data = resp.read(limit + 1)
        if len(data) > limit:
            raise ValueError("oversized source")
        return data

def fingerprint(raw):
    if not isinstance(raw, str):
        raise TypeError("expected URI")
    return hashlib.sha256(raw.strip().split("#", 1)[0].encode("utf-8")).hexdigest()

def b64decode(raw):
    try:
        if not raw or len(raw) > 2 * MAX_SOURCE_BYTES:
            return None
        return base64.b64decode(raw.replace("-", "+").replace("_", "/") + "=" * ((-len(raw)) % 4), validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        return None

def extract_links(data):
    text = data.decode("utf-8", errors="replace")
    gathered = []
    def collect(content):
        for line in content[:MAX_SOURCE_BYTES].splitlines():
            trimmed = line.strip()
            matches = list(LINK_RE.finditer(trimmed))
            if len(matches) == 1 and matches[0].start() == 0 and "#" in matches[0].group():
                # Preserve Unicode/whitespace display labels; fingerprint strips them.
                gathered.append(trimmed.rstrip(",;"))
            else:
                gathered.extend(m.group().rstrip(",;") for m in matches)
            if len(gathered) >= MAX_SOURCE_LINKS:
                break
    collect(text)
    if len(gathered) < MAX_SOURCE_LINKS:
        stripped = "".join(line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
        decoded = b64decode(stripped)
        if decoded:
            collect(decoded)
    if len(gathered) < MAX_SOURCE_LINKS:
        for line in text.splitlines()[:80]:
            if "://" not in line and len(line.strip()) > 24:
                decoded = b64decode(line.strip())
                if decoded:
                    collect(decoded)
    return list(dict.fromkeys(gathered))[:MAX_SOURCE_LINKS]

def public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

def pin_address(host, port, resolver=socket.getaddrinfo):
    """Resolve ONCE, disallow local ranges, pin outbound to a checked address.

    Check every returned A/AAAA; no DNS name is passed to Xray. Use SNI from
    the original host while the dial IP is fixed. Reject Unicode/control hosts.
    """
    host = host.strip("[]").rstrip(".")
    if not host or len(host) > 253 or any(ord(c) < 33 or ord(c) > 126 for c in host):
        raise ValueError("invalid host")
    if public_ip(host):
        return host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("nonpublic IP")
    labels = host.lower().split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("invalid DNS name")
    if host.endswith((".local", ".localhost", ".internal", ".test", ".lan", ".home.arpa")):
        raise ValueError("internal DNS")
    addresses = {i[4][0] for i in resolver(host, port, type=socket.SOCK_STREAM)}
    if not addresses or not all(public_ip(ip) for ip in addresses):
        raise ValueError("private/unresolved DNS")
    # Stable choice avoids race between a check and the outbound connection.
    return sorted(addresses)[0]

def hostport(authority):
    parsed = urlsplit("tcp://" + authority)
    if parsed.username or parsed.password or not parsed.hostname or not parsed.port or parsed.path:
        raise ValueError("bad endpoint")
    return parsed.hostname, parsed.port

def query_params(query):
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items() if v}

def outbound_from_uri(raw, resolver=socket.getaddrinfo):
    """Return an allowlisted Xray outbound; decline exotic/custom transports."""
    if not isinstance(raw, str) or len(raw) > 8192 or any(ord(c) < 32 for c in raw):
        raise ValueError("invalid link")
    link = raw.strip().split("#", 1)[0]
    scheme = link.split("://", 1)[0].lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError("unsupported protocol")
    if scheme == "vmess":
        payload = b64decode(link.split("://", 1)[1]); cfg = json.loads(payload or "null")
        if not isinstance(cfg, dict):
            raise ValueError("invalid VMess")
        host = str(cfg.get("add", "")); port = int(cfg.get("port", 0))
        user = str(cfg.get("id", ""))
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", user):
            raise ValueError("invalid UUID")
        security = "tls" if cfg.get("tls") == "tls" else "none"
        q = {"type": cfg.get("net", "tcp"), "sni": cfg.get("sni"), "host": cfg.get("host"), "path": cfg.get("path")}
    else:
        p = urlsplit(link)
        host, port = p.hostname, p.port
        if scheme == "ss" and (not host or not port):
            decoded = b64decode(link[5:].split("?", 1)[0])
            if not decoded or "@" not in decoded:
                raise ValueError("bad fully encoded SS")
            host, port = hostport(decoded.rsplit("@", 1)[1])
        q = query_params(p.query)
        user = unquote(p.username or "")
        security = q.get("security", "tls" if scheme == "trojan" else "none")
    if not isinstance(host, str) or not (1 <= port <= 65535):
        raise ValueError("bad port")
    if scheme == "vless" and security not in ("tls", "reality"):
        raise ValueError("plaintext VLESS rejected")
    if scheme == "trojan" and security != "tls":
        raise ValueError("plaintext Trojan rejected")
    ip = pin_address(host, port, resolver)
    if scheme == "ss":
        auth = link[5:].split("?", 1)[0]
        if "plugin=" in link.lower():
            raise ValueError("SS plugin unsupported")
        if "@" in auth:
            userinfo = auth.rsplit("@", 1)[0]
        else:
            decoded = b64decode(auth)
            if not decoded or "@" not in decoded:
                raise ValueError("invalid SS")
            userinfo = decoded.rsplit("@", 1)[0]
        cred = unquote(userinfo) if ":" in userinfo else b64decode(userinfo)
        if not cred or ":" not in cred:
            raise ValueError("invalid SS credentials")
        method, password = cred.split(":", 1)
        if method.lower() not in CREDENTIAL_METHODS or not password:
            raise ValueError("weak SS cipher")
        return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [{"address": ip, "port": port, "method": method.lower(), "password": password}]}}
    if not user or len(user) > 1024:
        raise ValueError("missing user")
    if scheme == "vless" and not re.fullmatch(r"[0-9a-fA-F-]{36}", user):
        raise ValueError("bad UUID")
    net = str(q.get("type", "tcp") or "tcp").lower()
    net = "tcp" if net in ("tcp", "raw") else net
    if net not in ("tcp", "ws", "grpc"):
        raise ValueError("unsupported transport")
    stream = {"network": net, "security": security}
    if net == "ws":
        stream["wsSettings"] = {"path": str(q.get("path", "/") or "/")[:256], "headers": {"Host": str(q.get("host") or host)[:253]}}
    if net == "grpc":
        stream["grpcSettings"] = {"serviceName": str(q.get("serviceName", ""))[:160]}
    if security == "tls":
        stream["tlsSettings"] = {"serverName": str(q.get("sni") or q.get("host") or host)[:253], "fingerprint": str(q.get("fp") or "chrome")[:20]}
    elif security == "reality" and scheme == "vless":
        if not q.get("pbk"):
            raise ValueError("missing REALITY key")
        stream["realitySettings"] = {"serverName": str(q.get("sni") or host)[:253], "fingerprint": str(q.get("fp") or "chrome")[:20], "publicKey": str(q["pbk"])[:100], "shortId": str(q.get("sid", ""))[:64], "spiderX": str(q.get("spx", ""))[:256]}
    elif security != "none":
        raise ValueError("invalid security")
    if scheme == "vless":
        u = {"id": user, "encryption": q.get("encryption", "none"), "level": 0}
        if q.get("flow"):
            u["flow"] = q["flow"]
        settings = {"vnext": [{"address": ip, "port": port, "users": [u]}]}
    elif scheme == "vmess":
        settings = {"vnext": [{"address": ip, "port": port, "users": [{"id": user, "alterId": int(cfg.get("aid", 0)), "security": str(cfg.get("scy", "auto") or "auto")[:32]}]}]}
    else:
        settings = {"servers": [{"address": ip, "port": port, "password": user}]}
    return {"tag": "proxy", "protocol": scheme, "settings": settings, "streamSettings": stream}

def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size-len(result))
        if not part:
            raise OSError("socket closed")
        result.extend(part)
    return bytes(result)

def probe_https(port, hostname, path, timeout=5):
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if exact(sock, 2) != b"\x05\x00":
            raise OSError("bad SOCKS handshake")
        h = hostname.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + (443).to_bytes(2, "big"))
        reply = exact(sock, 4)
        if reply[1] != 0:
            raise OSError("SOCKS dial failed")
        typ = reply[3]
        exact(sock, 4 if typ == 1 else 16 if typ == 4 else exact(sock, 1)[0] if typ == 3 else 0)
        exact(sock, 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
            tls.settimeout(timeout)
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nUser-Agent: SecureConnect-Checker/1\r\n\r\n".encode())
            status = tls.recv(256).split(b"\r\n", 1)[0]
        if not status.startswith(b"HTTP/"):
            raise OSError("invalid HTTPS response")
        return int(status.split()[1]), int((time.monotonic()-started)*1000)

def probe_https_body(port, hostname="www.google.com", path="/robots.txt",
                     timeout=6, minimum=512, limit=8192):
    """Verify an actual HTTPS RESPONSE BODY via SOCKS5 + certificate-checked TLS.

    Only fixed public endpoints; download is capped. No carrier claim or speed
    estimate is made from this short request.
    """
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS auth failed")
        h = hostname.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + (443).to_bytes(2, "big"))
        ans = exact(sock, 4)
        if len(ans) != 4 or ans[1] != 0 or ans[3] not in (1, 3, 4):
            raise OSError("SOCKS dial failed")
        if ans[3] == 1:
            exact(sock, 4)
        elif ans[3] == 4:
            exact(sock, 16)
        else:
            exact(sock, exact(sock, 1)[0])
        exact(sock, 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
            tls.settimeout(timeout)
            tls.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + hostname +
                         "\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
                         "User-Agent: SecureConnect-Checker/1\r\n\r\n").encode("ascii"))
            data = bytearray()
            while len(data) < limit:
                part = tls.recv(min(2048, limit-len(data)))
                if not part:
                    break
                data.extend(part)
                if b"\r\n\r\n" in data:
                    head, body = bytes(data).split(b"\r\n\r\n", 1)
                    if len(head) > 4096:
                        raise OSError("oversize headers")
                    status = head.split(b"\r\n", 1)[0].split()
                    if len(status) < 2 or not status[0].startswith(b"HTTP/") or status[1] != b"200":
                        raise OSError("HTTP body endpoint failed")
                    if len(body) >= minimum:
                        return len(body), int((time.monotonic()-started)*1000)
    raise OSError("incomplete HTTPS response body")


def probe_https_upload(port, timeout=7):
    """Verify a bounded outbound POST by checking the remote HTTPS echo.

    Requires a real TLS-valid POST response containing every transmitted byte;
    no credentials or user data is sent. This is NOT a throughput measurement.
    An unavailable public diagnostic endpoint does not invalidate basic VPN.
    """
    hostname, path = "postman-echo.com", "/post"
    payload = b"SC-UPLOAD-PROBE-V1-" + b"x" * 1024
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS auth failed")
        name = hostname.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        reply = exact(sock, 4)
        if len(reply) != 4 or reply[1] != 0 or reply[3] not in (1, 3, 4):
            raise OSError("SOCKS upload dial failed")
        if reply[3] == 1:
            exact(sock, 4)
        elif reply[3] == 4:
            exact(sock, 16)
        else:
            exact(sock, exact(sock, 1)[0])
        exact(sock, 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
            tls.settimeout(timeout)
            header = (f"POST {path} HTTP/1.1\r\nHost: {hostname}\r\n"
                      "Content-Type: text/plain\r\nAccept-Encoding: identity\r\n"
                      f"Content-Length: {len(payload)}\r\nConnection: close\r\n"
                      "User-Agent: SecureConnect-Checker/1\r\n\r\n").encode("ascii")
            tls.sendall(header + payload)
            response = bytearray()
            while len(response) < 16384:
                part = tls.recv(min(2048, 16384 - len(response)))
                if not part:
                    break
                response.extend(part)
                if b"\r\n\r\n" in response:
                    header_bytes, body = bytes(response).split(b"\r\n\r\n", 1)
                    status = header_bytes.split(b"\r\n", 1)[0].split()
                    if len(status) < 2 or not status[0].startswith(b"HTTP/") or status[1] != b"200":
                        raise OSError("unexpected upload endpoint status")
                    if payload in body:
                        return len(payload), int((time.monotonic()-started)*1000)
    raise OSError("remote server did not echo full uploaded payload")


def reserve_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def test_candidate(item, xray, check_payload=False, check_upload=False):
    result = {"fingerprint": item["fingerprint"], "source_id": item["source_id"], "https_ok": False, "youtube_page_ok": False, "https_latency_ms": None}
    try:
        outbound = outbound_from_uri(item["raw"])
        port = reserve_port()
        config = {"log": {"loglevel": "none"}, "inbounds": [{"tag": "test", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}], "outbounds": [outbound]}
        with tempfile.TemporaryDirectory(prefix="sc-probe-") as temp:
            cfg_path = Path(temp) / "config.json"
            cfg_path.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(cfg_path, 0o600)
            proc = subprocess.Popen([xray, "run", "-c", str(cfg_path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(25):
                    if proc.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.15):
                            break
                    except OSError:
                        time.sleep(.1)
                if proc.poll() is None:
                    status, ms = probe_https(port, "www.gstatic.com", "/generate_204")
                    if status == 204:
                        result.update(https_ok=True, https_latency_ms=ms)
                        if check_payload:
                            result.update(payload_ok=False, download_bytes=0, download_ms=None)
                            try:
                                n, duration = probe_https_body(port)
                                result.update(payload_ok=True, download_bytes=n, download_ms=duration)
                            except (OSError, ValueError, ssl.SSLError):
                                pass
                        if check_upload:
                            result.update(upload_ok=False, upload_bytes=0, upload_ms=None)
                            try:
                                n, upload_duration = probe_https_upload(port)
                                result.update(upload_ok=True, upload_bytes=n, upload_ms=upload_duration)
                            except (OSError, ValueError, ssl.SSLError):
                                pass
                        try:
                            yt, _ = probe_https(port, "www.youtube.com", "/")
                            result["youtube_page_ok"] = yt in (200, 301, 302, 303, 307, 308)
                        except (OSError, ValueError, ssl.SSLError):
                            pass
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait(timeout=2)
    except (OSError, ValueError, KeyError, TypeError, ssl.SSLError, subprocess.SubprocessError):
        pass
    return result

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def parse_iso(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("non UTC timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt

def accepted_previous(raw, now):
    """Reuse *real* checked_at only and never mint new life for old records."""
    if not isinstance(raw, dict) or raw.get("schema") != 1 or not isinstance(raw.get("results"), list):
        return []
    results = []
    for r in raw["results"][:MAX_RESULTS]:
        if not isinstance(r, dict) or not r.get("https_ok") is True or not isinstance(r.get("youtube_page_ok"), bool):
            continue
        if not isinstance(r.get("fingerprint"), str) or not FINGERPRINT_RE.fullmatch(r["fingerprint"]):
            continue
        if r.get("source_id") not in SOURCES or type(r.get("https_latency_ms")) != int:
            continue
        try:
            checked = parse_iso(r["checked_at"])
        except (ValueError, KeyError):
            continue
        if timedelta(0) <= now - checked < RESULT_TTL:
            results.append(r)
    return results

def pack_feed(checked, previous, now):
    good = {r["fingerprint"]: r for r in accepted_previous(previous, now)}
    for r in checked:
        fp = r["fingerprint"]
        if r["https_ok"]:
            good[fp] = {**r, "checked_at": iso(now)}
        else:
            good.pop(fp, None)  # known failure invalidates prior success
    # Legacy Android parser is fail-closed for unknown IDs: one cloud-only
    # telega_ru entry previously invalidated ALL 85 otherwise valid results.
    # Preserve every verified item's original checked_at; never mint liveness.
    compatible = (r for r in good.values()
                  if r["source_id"] in ANDROID_RANKING_SOURCE_IDS)
    results = sorted(compatible, key=lambda r: (not r["youtube_page_ok"], r["https_latency_ms"], r["source_id"]))[:MAX_RESULTS]
    obj = {"schema": 1, "generated_at": iso(now), "valid_until": iso(now+PUBLICATION_TTL), "checker": "xray-github-actions", "results": results}
    output = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(output) > MAX_FEED_BYTES:
        raise ValueError("feed exceeded 256 KiB")
    return output

def pack_public_candidates(checked, sampled, now, previous=None, restart_results=None,
                           download_results=None, upload_results=None):
    """Publish public, freshly Xray-verified URIs using Android's existing schema.

    Previous candidates survive only their original short TTL. Successfully
    restarted Xray routes lead the list; failed restarts revoke eligibility.
    No mobile-operator whitelist or domain-fronting claim is made.
    """
    by_hash = {r["fingerprint"]: r for r in sampled}
    ok = sorted((r for r in checked if r["https_ok"] is True),
                key=lambda r: (not r["youtube_page_ok"], r["https_latency_ms"] or 30000))
    entries = []
    for result in ok:
        origin = by_hash.get(result["fingerprint"])
        if not origin or origin["source_id"] not in SOURCES:
            continue
        uri = origin["raw"].strip().split("#", 1)[0]
        if len(uri.encode("utf-8")) > 4096 or uri.split("://", 1)[0].lower() not in ALLOWED_SCHEMES:
            continue
        if fingerprint(uri) != result["fingerprint"]:
            continue
        entries.append({
            "fingerprint": result["fingerprint"],
            "source_id": origin["source_id"],
            "uri": uri,
            "https_latency_ms": result["https_latency_ms"],
            "youtube_page_ok": result["youtube_page_ok"],
            "checked_at": iso(now),
        })
        if len(entries) >= MAX_PUBLIC_CANDIDATES:
            break
    # Rolling two-hour pool; never extend the original checked_at.
    failed = {r["fingerprint"] for r in checked if r.get("https_ok") is not True}
    known = {r["fingerprint"] for r in entries}
    if isinstance(previous, dict) and previous.get("schema") == 1 and previous.get("checker") == "xray-github-actions":
        old = previous.get("candidates", [])
        if isinstance(old, list):
            for item in old[:MAX_PUBLIC_CANDIDATES]:
                if not isinstance(item, dict) or set(item) != {"fingerprint", "source_id", "uri", "https_latency_ms", "youtube_page_ok", "checked_at"}:
                    continue
                fp, uri = item["fingerprint"], item["uri"]
                if not isinstance(fp, str) or not FINGERPRINT_RE.fullmatch(fp) or fp in failed or fp in known:
                    continue
                if not isinstance(uri, str) or not 20 <= len(uri.encode("utf-8")) <= 4096 or "#" in uri or fingerprint(uri) != fp:
                    continue
                if uri.split("://", 1)[0].lower() not in ALLOWED_SCHEMES or item["source_id"] not in SOURCES:
                    continue
                if type(item["youtube_page_ok"]) is not bool or type(item["https_latency_ms"]) is not int or not 1 <= item["https_latency_ms"] <= 30000:
                    continue
                try:
                    checked_at = parse_iso(item["checked_at"])
                except (ValueError, TypeError):
                    continue
                if not timedelta(0) <= now - checked_at < timedelta(hours=2):
                    continue
                entries.append(item)
                known.add(fp)
    confirmed = {r["fingerprint"] for r in (restart_results or [])
                 if r.get("restart_ok") is True}
    downloaded = {r["fingerprint"] for r in (download_results or [])
                  if r.get("payload_ok") is True}
    uploaded = {r["fingerprint"] for r in (upload_results or [])
                if r.get("upload_ok") is True}
    both_directions = confirmed & downloaded & uploaded
    # Only a real, independently restarted Xray connection plus confirmed
    # download AND upload earns top priority. This is not carrier throughput.
    entries.sort(key=lambda r: (
        r["fingerprint"] not in both_directions,
        r["fingerprint"] not in confirmed,
        not r["youtube_page_ok"], r["https_latency_ms"], r["source_id"]))
    entries = entries[:MAX_PUBLIC_CANDIDATES]
    payload = json.dumps({"schema": 1, "checker": "xray-github-actions",
        "generated_at": iso(now), "valid_until": iso(now + timedelta(hours=2)),
        "candidates": entries}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_PUBLIC_CANDIDATES_BYTES:
        raise ValueError("candidate feed exceeds 128 KiB")
    return payload


def load_previous(url, now):
    if not url:
        return {}
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or not p.hostname.endswith(".github.io") or not p.path.endswith(("/feed.json", "/candidates.json")):
        return {}
    try:
        with OPENER.open(Request(url, headers={"User-Agent": "SecureConnect-Checker/1"}), timeout=6) as resp:
            if resp.status != 200:
                return {}
            raw = resp.read(MAX_FEED_BYTES + 1)
        return json.loads(raw) if len(raw) <= MAX_FEED_BYTES else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

def pick_balanced(collected, run_number, max_items=MAX_PER_RUN):
    """Round-robin sources with changed deterministic offsets each run."""
    pools = {}
    for sid, entries in collected.items():
        distinct = list(dict.fromkeys(entries))
        if distinct:
            offset = (run_number * 31) % len(distinct)
            pools[sid] = distinct[offset:] + distinct[:offset]
    output = []
    seen = set()
    while len(output) < max_items and any(pools.values()):
        changed = False
        for sid in list(pools):
            while pools[sid]:
                raw = pools[sid].pop(0)
                fp = fingerprint(raw)
                if fp not in seen:
                    seen.add(fp)
                    output.append({"source_id": sid, "fingerprint": fp, "raw": raw})
                    changed = True
                    break
            if len(output) >= max_items:
                break
        if not changed:
            break
    return output

def select_probe_batch(collected, run_number, previous_candidates, now):
    """Spend up to six of 24 slots re-testing previously working public routes.

    Only carry forward publicly published, previously Xray-checked URIs with
    valid fingerprints, allowlisted source IDs and unexpired timestamps.
    Every reused URI is actually rechecked this run before being published.
    Never assume Github's network matches a mobile carrier.
    """
    prior = []
    if (isinstance(previous_candidates, dict) and
            previous_candidates.get("schema") == 1 and
            previous_candidates.get("checker") == "xray-github-actions" and
            isinstance(previous_candidates.get("candidates"), list)):
        seen = set()
        for item in previous_candidates["candidates"][:MAX_PUBLIC_CANDIDATES]:
            if not isinstance(item, dict) or set(item) != {
                    "fingerprint", "source_id", "uri", "https_latency_ms",
                    "youtube_page_ok", "checked_at"}:
                continue
            fp, uri, sid = item["fingerprint"], item["uri"], item["source_id"]
            if (not isinstance(fp, str) or not FINGERPRINT_RE.fullmatch(fp) or
                    not isinstance(uri, str) or not 20 <= len(uri.encode("utf-8")) <= 4096 or
                    "#" in uri or fingerprint(uri) != fp or fp in seen or sid not in SOURCES or
                    uri.split("://", 1)[0].lower() not in ALLOWED_SCHEMES or
                    type(item["https_latency_ms"]) is not int or
                    not 1 <= item["https_latency_ms"] <= 30000 or
                    type(item["youtube_page_ok"]) is not bool):
                continue
            try:
                checked_at = parse_iso(item["checked_at"])
            except (KeyError, ValueError, TypeError):
                continue
            if not timedelta(0) <= now - checked_at < timedelta(hours=2):
                continue
            seen.add(fp)
            prior.append(item)
    prior.sort(key=lambda c: (not c["youtube_page_ok"], c["https_latency_ms"], c["source_id"]))
    diverse = []
    used_sources = set()
    for c in prior:
        if c["source_id"] not in used_sources:
            diverse.append(c)
            used_sources.add(c["source_id"])
            if len(diverse) == MAX_RECHECKS:
                break
    for c in prior:
        if len(diverse) >= MAX_RECHECKS:
            break
        if c not in diverse:
            diverse.append(c)
    selected = [{"fingerprint": c["fingerprint"], "source_id": c["source_id"],
                 "raw": c["uri"]} for c in diverse]
    checked_fps = {r["fingerprint"] for r in selected}
    # Rotation continues for the remaining budget; a repeated link uses only
    # one probe, even if it appears in multiple subscriptions.
    for fresh in pick_balanced(collected, run_number, MAX_PER_RUN + MAX_RECHECKS):
        if len(selected) >= MAX_PER_RUN:
            break
        if fresh["fingerprint"] not in checked_fps:
            selected.append(fresh)
            checked_fps.add(fresh["fingerprint"])
    return selected


def apply_restart_quality(checked, restarts):
    """A failed second independent Xray launch vetoes publishing that route.

    Does not falsify latency or renew checked_at. The failure also revokes
    a matching previous positive feed entry in the normal merge function.
    """
    failed = {r["fingerprint"] for r in restarts
              if isinstance(r, dict) and r.get("restart_ok") is False}
    return [
        {**r, "https_ok": False, "youtube_page_ok": False,
         "https_latency_ms": None} if r["fingerprint"] in failed else r
        for r in checked
    ]


def check_xray_restarts(checked, sampled, xray, now, probe=None, payload_records=None, upload_records=None):
    """Re-launch Xray for up to 3 previously passing routes, across sources.

    Each test_candidate invocation starts and stops a NEW Xray process with
    an independent SOCKS/HTTPS session. This measures runner-side restart
    resilience, NOT Android TUN failover or local-network reachability.
    No VPN credentials or raw URIs are written to the result.
    """
    if probe is None:
        probe = lambda item, binary: test_candidate(item, binary, check_payload=True, check_upload=True)
    originals = {r["fingerprint"]: r for r in sampled}
    ordered = sorted(
        (r for r in checked if r.get("https_ok") is True and r.get("fingerprint") in originals),
        key=lambda r: (r.get("https_latency_ms") if type(r.get("https_latency_ms")) is int else 30000, r["source_id"]),
    )
    chosen = []
    used_sources = set()
    for result in ordered:
        source_id = originals[result["fingerprint"]]["source_id"]
        if source_id in used_sources:
            continue
        chosen.append(originals[result["fingerprint"]])
        used_sources.add(source_id)
        if len(chosen) >= MAX_RESTART_CHECKS:
            break
    records = []
    for item in chosen:
        try:
            retry = probe(item, xray)
            ok = retry.get("https_ok") is True and type(retry.get("https_latency_ms")) is int and retry["https_latency_ms"] >= 0
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            retry, ok = {}, False
        records.append({
            "fingerprint": item["fingerprint"],
            "source_id": item["source_id"],
            "restart_ok": ok,
            "restart_https_latency_ms": retry.get("https_latency_ms") if ok else None,
            "checked_at": iso(now),
        })
        if payload_records is not None:
            n, delay_ms = retry.get("download_bytes", 0), retry.get("download_ms")
            good = (ok and retry.get("payload_ok") is True and type(n) is int
                    and 512 <= n <= 8192 and type(delay_ms) is int and delay_ms >= 0)
            payload_records.append({
                "fingerprint": item["fingerprint"], "source_id": item["source_id"],
                "payload_ok": bool(good), "download_bytes": n if good else 0,
                "download_ms": delay_ms if good else None, "checked_at": iso(now)
            })
        if upload_records is not None:
            uploaded, upl_ms = retry.get("upload_bytes", 0), retry.get("upload_ms")
            verified = (ok and retry.get("upload_ok") is True and
                        type(uploaded) is int and uploaded == 1043 and
                        type(upl_ms) is int and upl_ms >= 0)
            upload_records.append({
                "fingerprint": item["fingerprint"], "source_id": item["source_id"],
                "upload_ok": bool(verified), "upload_bytes": uploaded if verified else 0,
                "upload_ms": upl_ms if verified else None, "checked_at": iso(now)
            })
    return records


def pack_xray_restarts(records, now):
    """Independent diagnostic feed; immutable existing Android feed schemas."""
    clean = []
    for row in records[:MAX_RESTART_CHECKS]:
        if not isinstance(row, dict) or set(row) != {
            "fingerprint", "source_id", "restart_ok", "restart_https_latency_ms", "checked_at"
        }:
            raise ValueError("invalid Xray restart result shape")
        if not isinstance(row["fingerprint"], str) or not FINGERPRINT_RE.fullmatch(row["fingerprint"]):
            raise ValueError("invalid fingerprint")
        if row["source_id"] not in SOURCES or type(row["restart_ok"]) is not bool:
            raise ValueError("invalid restart status")
        if row["restart_ok"] and (type(row["restart_https_latency_ms"]) is not int or row["restart_https_latency_ms"] < 0):
            raise ValueError("invalid successful latency")
        if not row["restart_ok"] and row["restart_https_latency_ms"] is not None:
            raise ValueError("invalid failed latency")
        if row["checked_at"] != iso(now):
            raise ValueError("invalid restart checked_at")
        clean.append(row)
    payload = json.dumps({
        "schema": 1, "checker": "xray-github-actions",
        "kind": "xray_process_restart", "android_tun_tested": False,
        "generated_at": iso(now), "valid_until": iso(now + timedelta(hours=2)),
        "results": clean
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > 8192:
        raise ValueError("oversize Xray restart diagnostics")
    return payload


def pack_payload_probes(records, now):
    """Separate and strictly validated diagnostic; unchanged Android feed."""
    if len(records) > MAX_RESTART_CHECKS:
        raise ValueError("too many payload tests")
    for row in records:
        if not isinstance(row, dict) or set(row) != {
                "fingerprint", "source_id", "payload_ok",
                "download_bytes", "download_ms", "checked_at"}:
            raise ValueError("unexpected payload fields")
        if not isinstance(row["fingerprint"], str) or not FINGERPRINT_RE.fullmatch(row["fingerprint"]):
            raise ValueError("invalid payload fingerprint")
        if row["source_id"] not in SOURCES or type(row["payload_ok"]) is not bool:
            raise ValueError("invalid payload source")
        n, ms = row["download_bytes"], row["download_ms"]
        if type(n) is not int or (ms is not None and type(ms) is not int):
            raise ValueError("invalid payload value types")
        if row["payload_ok"]:
            if n < 512 or n > 8192 or ms is None or ms < 0:
                raise ValueError("invalid successful payload")
        elif n != 0 or ms is not None:
            raise ValueError("failure cannot claim transferred bytes")
        if row["checked_at"] != iso(now):
            raise ValueError("payload time mismatch")
    output = json.dumps({
        "schema": 1, "checker": "xray-github-actions",
        "kind": "xray_https_download", "android_tun_tested": False,
        "megafon_tested": False, "upload_speed_tested": False,
        "generated_at": iso(now), "valid_until": iso(now+timedelta(hours=2)),
        "results": records
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(output) > 8192:
        raise ValueError("payload report exceeded limit")
    return output


def pack_upload_probes(records, now):
    """Independent, bounded upload diagnostic. Never claims mobile-carrier tests."""
    if len(records) > MAX_RESTART_CHECKS:
        raise ValueError("too many upload probes")
    for r in records:
        if not isinstance(r, dict) or set(r) != {
            "fingerprint", "source_id", "upload_ok", "upload_bytes",
            "upload_ms", "checked_at"
        }:
            raise ValueError("unexpected upload fields")
        if not isinstance(r["fingerprint"], str) or not FINGERPRINT_RE.fullmatch(r["fingerprint"]):
            raise ValueError("bad upload fingerprint")
        if r["source_id"] not in SOURCES or type(r["upload_ok"]) is not bool:
            raise ValueError("bad upload source")
        size, latency = r["upload_bytes"], r["upload_ms"]
        if type(size) is not int or (latency is not None and type(latency) is not int):
            raise ValueError("bad upload number")
        if r["upload_ok"]:
            if size != 1043 or latency is None or latency < 0:
                raise ValueError("upload result not verified")
        elif size != 0 or latency is not None:
            raise ValueError("failed upload claims bytes")
        if r["checked_at"] != iso(now):
            raise ValueError("upload checked_at does not match run")
    output = json.dumps({
        "schema": 1, "checker": "xray-github-actions", "kind": "xray_https_upload",
        "android_tun_tested": False, "megafon_tested": False,
        "upload_speed_tested": False,
        "generated_at": iso(now), "valid_until": iso(now+timedelta(hours=2)),
        "results": records
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(output) > 8192:
        raise ValueError("upload report exceeds limit")
    return output


def main():
    now = datetime.now(timezone.utc)
    run_number = int(os.environ.get("GITHUB_RUN_NUMBER", "1"))
    collected = {}
    for sid, urls in SOURCES.items():
        links = []
        for url in urls[:2]:
            try:
                links.extend(extract_links(fetch_fixed_https(url, MAX_SOURCE_BYTES)))
            except (OSError, ValueError):
                continue
        collected[sid] = links[:MAX_SOURCE_LINKS]
        print(f"source {sid}: {len(collected[sid])} candidates")  # never log raw URLs
    previous_candidates = load_previous(os.environ.get("PREVIOUS_CANDIDATES_URL", ""), now)
    sampled = select_probe_batch(collected, run_number, previous_candidates, now)
    checked = []
    xray = os.environ.get("XRAY_BIN", "./xray")
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(test_candidate, item, xray) for item in sampled]
        for fut in concurrent.futures.as_completed(futures):
            checked.append(fut.result())
    # A second independent Xray launch gates the selected top routes BEFORE
    # public output. One failed restart invalidates an earlier positive result.
    download_reports = []
    upload_reports = []
    restart_results = check_xray_restarts(
        checked, sampled, xray, now,
        payload_records=download_reports, upload_records=upload_reports)
    checked = apply_restart_quality(checked, restart_results)
    previous = load_previous(os.environ.get("PREVIOUS_FEED_URL", ""), now)
    packed = pack_feed(checked, previous, now)
    output_dir = Path(os.environ.get("OUTPUT_DIR", "site"))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "feed.json").write_bytes(packed)
    (output_dir / "candidates.json").write_bytes(
        pack_public_candidates(checked, sampled, now, previous_candidates,
                               restart_results, download_reports, upload_reports))
    (output_dir / "restarts.json").write_bytes(pack_xray_restarts(restart_results, now))
    (output_dir / "payload.json").write_bytes(pack_payload_probes(download_reports, now))
    (output_dir / "upload.json").write_bytes(pack_upload_probes(upload_reports, now))
    print(f"upload_probes={len(upload_reports)} upload_ok={sum(row['upload_ok'] for row in upload_reports)}")
    print(f"payload_probes={len(download_reports)} payload_ok={sum(row['payload_ok'] for row in download_reports)}")
    print(f"xray_restart_checks={len(restart_results)} restart_success={sum(r['restart_ok'] for r in restart_results)}")

    (output_dir / ".nojekyll").write_text("", encoding="utf-8")
    print(f"sampled={len(sampled)} tested={len(checked)} passing={sum(r['https_ok'] for r in checked)} bytes={len(packed)} elapsed_s={int(time.monotonic()-start)}")

if __name__ == "__main__":
    main()
