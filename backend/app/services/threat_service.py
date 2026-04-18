"""
Live Threat Detection Service — Real Network Monitor
=====================================================
Architecture:
  1. PRIMARY: psutil.net_connections() reads real OS-level TCP/UDP connections.
     Works on any Linux/macOS/Windows machine running this FastAPI backend.
     When deployed on a user's own server/laptop, it shows THAT machine's traffic.

  2. FALLBACK (SIMULATION): When the environment has no external connections
     (Docker build container, CI, sandboxed cloud environment), the service
     auto-detects this and switches to simulation mode, clearly labelling
     every entry as demo data via data_source="simulated" and
     monitoring_mode="simulation" in the API response.

  3. IO stats: sampled via a non-blocking two-snapshot approach with a tiny
     sleep moved off the hot path — IO is captured lazily and cached briefly.

Detection rules (10 independent checks):
  ┌─────────────────────────────────┬───────────┬──────────┐
  │ Rule                            │ Max score │ Severity │
  ├─────────────────────────────────┼───────────┼──────────┤
  │ Suspicious TLD (.tk/.ga/...)    │ +0.45     │ HIGH     │
  │ Brand impersonation             │ +0.50     │ HIGH     │
  │ Phishing URL pattern (regex)    │ +0.40     │ HIGH     │
  │ DGA entropy analysis (H>3.9)    │ +0.30     │ MED      │
  │ Suspicious port                 │ +0.30     │ MED      │
  │ Raw IP address (no domain)      │ +0.20     │ MED      │
  │ Deep subdomain nesting (>5)     │ +0.25     │ MED      │
  │ Unusually long domain (>50 ch)  │ +0.10     │ LOW      │
  │ Numeric-heavy hostname (>50%)   │ +0.12     │ LOW      │
  │ Hyphen abuse (≥3 hyphens)       │ +0.10     │ LOW      │
  └─────────────────────────────────┴───────────┴──────────┘
  Thresholds: dangerous ≥ 0.55 · suspicious ≥ 0.20 · safe < 0.20
"""

from __future__ import annotations

import math
import hashlib
import logging
import re
import socket
import time
import threading
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Threat intelligence data
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    # Freenom free TLDs — overwhelmingly abused
    ".tk", ".ml", ".ga", ".cf", ".gq",
    # High-abuse gTLDs
    ".xyz", ".top", ".pw", ".cc", ".su",
    ".click", ".link", ".download",
    ".zip", ".mov",          # novel gTLDs weaponized immediately
    ".work", ".party", ".loan", ".win", ".bid",
    ".icu", ".cyou", ".vip", ".live",
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "spotify", "twitter", "linkedin", "dropbox", "github", "gitlab",
    "binance", "coinbase", "metamask", "blockchain",
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "hsbc", "barclays", "halifax", "natwest", "lloyds",
    "steam", "discord", "roblox",
]

PHISHING_PATTERNS = [
    r"(secure|security)[-\.]login",
    r"account[-\.]verif",
    r"verify[-\.]account",
    r"update[-\.]account",
    r"confirm[-\.]identit",
    r"signin[-\.]secure",
    r"login[-\.]secure",
    r"support[-\.]ticket",
    r"password[-\.]reset",
    r"(paypal|amazon|google|apple|microsoft)[-\.]",
    r"[-\\.](paypal|amazon|google|apple|microsoft)\.",
    r"www\d+\.",
    r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",   # IP encoded in domain
    r"(free|win|prize|gift|reward|bonus)[-\.]",
    r"(wallet|crypto|nft)[-\.]",
    r"(suspended|unusual|activity|alert)[-\.]account",
]

SUSPICIOUS_PORTS = {
    20, 21,          # FTP plaintext
    23,              # Telnet
    25,              # SMTP direct (not 587)
    110,             # POP3 plaintext
    135, 137, 138, 139,  # NetBIOS
    445,             # SMB — ransomware favourite
    1433,            # MSSQL
    3306,            # MySQL exposed
    3389,            # RDP
    4444,            # Metasploit default
    5900,            # VNC
    6666, 6667, 6668, 6669,   # IRC botnet C2
    9001, 9030,      # Tor relay
}

SAFE_INTERNAL_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1", "fe80:", "0.0.0.0",
)

# Domains that bypass all analysis immediately
WELL_KNOWN_SAFE = {
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
    "fastly.net", "akamai.net", "akamaiedge.net", "akamaitechnologies.com",
    "amazonaws.com", "awsstatic.com", "aws.amazon.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "github.com", "githubusercontent.com", "github.io",
    "microsoft.com", "windows.com", "microsoftonline.com", "azure.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "ubuntu.com", "debian.org", "fedoraproject.org",
    "npmjs.org", "npmjs.com", "pypi.org", "anaconda.com",
    "stackoverflow.com", "stackexchange.com",
    "wikipedia.org", "wikimedia.org",
    "youtube.com", "ytimg.com",
    "twitter.com", "twimg.com", "x.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "letsencrypt.org", "ocsp.digicert.com", "ocsp.pki.goog",
    "digicert.com", "sectigo.com",
    "slack.com", "slack-edge.com",
    "zoom.us", "zoomcdn.com",
    "dropbox.com", "dropboxstatic.com",
    "1.1.1.1", "8.8.8.8", "8.8.4.4",   # well-known DNS
}

# ─────────────────────────────────────────────────────────────────────────────
# Core analysis functions
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_internal(ip: str) -> bool:
    return ip.startswith(SAFE_INTERNAL_PREFIXES)


def _tld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return f".{parts[-1]}" if len(parts) >= 2 else ""


def _root(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def analyze_domain(
    domain: str,
    port: Optional[int] = None,
    ip: Optional[str] = None,
) -> dict:
    """
    Full multi-rule threat analysis of a domain/connection.
    Returns a structured result with risk_level, confidence 0-1,
    and a list of typed indicators with severity levels.
    """
    if not domain:
        return {
            "domain": domain, "risk_level": "safe", "reasons": [],
            "confidence": 0.0, "indicators": [], "is_known_safe": False,
        }

    d = domain.lower().strip().rstrip(".")
    if ":" in d:
        d = d.split(":")[0]

    # ── Fast-path: well-known safe ────────────────────────────────────────────
    root = _root(d)
    for safe in WELL_KNOWN_SAFE:
        if d == safe or d.endswith("." + safe):
            return {
                "domain": domain, "risk_level": "safe", "reasons": [],
                "confidence": 0.0, "indicators": [], "is_known_safe": True,
            }

    indicators: list[dict] = []
    score = 0.0

    # Rule 1 — Suspicious TLD
    tld = _tld(d)
    if tld in SUSPICIOUS_TLDS:
        indicators.append({
            "type": "suspicious_tld",
            "detail": f"TLD '{tld}' is heavily abused for phishing and malware distribution",
            "severity": "high",
        })
        score += 0.45

    # Rule 2 — Brand impersonation
    brands = [b for b in BRAND_KEYWORDS
              if b in d and root != f"{b}.com" and not d.endswith(f".{b}.com")]
    if brands:
        indicators.append({
            "type": "brand_impersonation",
            "detail": f"Impersonates known brand(s): {', '.join(brands)}",
            "severity": "high",
        })
        score += 0.50

    # Rule 3 — Phishing patterns
    hits = [p for p in PHISHING_PATTERNS if re.search(p, d)]
    if hits:
        indicators.append({
            "type": "phishing_pattern",
            "detail": f"Matches {len(hits)} phishing URL pattern(s)",
            "severity": "high",
        })
        score += 0.40

    # Rule 4 — DGA entropy
    hostname = d.split(".")[0]
    ent = _entropy(hostname)
    if ent > 3.9 and len(hostname) > 10:
        indicators.append({
            "type": "high_entropy",
            "detail": f"High-entropy hostname (H={ent:.2f}) — possible DGA or randomised subdomain",
            "severity": "medium",
        })
        score += 0.30
    elif ent > 3.5 and len(hostname) > 14:
        indicators.append({
            "type": "high_entropy",
            "detail": f"Elevated hostname entropy (H={ent:.2f})",
            "severity": "low",
        })
        score += 0.15

    # Rule 5 — Suspicious port
    if port and port in SUSPICIOUS_PORTS:
        indicators.append({
            "type": "suspicious_port",
            "detail": f"Connection on high-risk port {port}",
            "severity": "medium",
        })
        score += 0.30

    # Rule 6 — Raw IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) and not _is_internal(d):
        indicators.append({
            "type": "raw_ip",
            "detail": "Direct connection to raw IP address (no hostname resolution)",
            "severity": "medium",
        })
        score += 0.20

    # Rule 7 — Subdomain depth
    parts = d.split(".")
    if len(parts) > 5:
        indicators.append({
            "type": "deep_subdomain",
            "detail": f"Unusual subdomain depth ({len(parts)} levels) — common in impersonation attacks",
            "severity": "medium",
        })
        score += 0.25
    elif len(parts) > 4:
        indicators.append({
            "type": "deep_subdomain",
            "detail": f"Deep subdomain nesting ({len(parts)} levels)",
            "severity": "low",
        })
        score += 0.10

    # Rule 8 — Long domain
    if len(d) > 50:
        indicators.append({
            "type": "long_domain",
            "detail": f"Unusually long domain ({len(d)} chars) — obfuscation tactic",
            "severity": "low",
        })
        score += 0.10

    # Rule 9 — Numeric-heavy hostname
    if len(hostname) > 6:
        digit_ratio = sum(c.isdigit() for c in hostname) / len(hostname)
        if digit_ratio > 0.5:
            indicators.append({
                "type": "numeric_heavy",
                "detail": f"Hostname is {digit_ratio:.0%} numeric — atypical for legitimate services",
                "severity": "low",
            })
            score += 0.12

    # Rule 10 — Hyphen abuse
    if hostname.count("-") >= 3:
        indicators.append({
            "type": "hyphen_abuse",
            "detail": f"Excessive hyphens ({hostname.count('-')}) — common pattern in phishing domains",
            "severity": "low",
        })
        score += 0.10

    score = min(score, 1.0)

    return {
        "domain": domain,
        "risk_level": "dangerous" if score >= 0.55 else "suspicious" if score >= 0.20 else "safe",
        "reasons": [i["detail"] for i in indicators],
        "confidence": round(score, 3),
        "indicators": indicators,
        "is_known_safe": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Network IO stats  (non-blocking snapshot cache)
# ─────────────────────────────────────────────────────────────────────────────

_io_cache: dict = {}
_io_lock = threading.Lock()


def _refresh_io_cache() -> None:
    """Background thread: take two samples 1 s apart and cache the result."""
    try:
        import psutil
        s1 = psutil.net_io_counters()
        time.sleep(1.0)
        s2 = psutil.net_io_counters()
        with _io_lock:
            _io_cache.update({
                "bytes_sent_total":  s2.bytes_sent,
                "bytes_recv_total":  s2.bytes_recv,
                "bytes_sent_rate":   max(0, s2.bytes_sent - s1.bytes_sent),   # per second
                "bytes_recv_rate":   max(0, s2.bytes_recv - s1.bytes_recv),
                "packets_sent":      s2.packets_sent,
                "packets_recv":      s2.packets_recv,
                "errors_in":         s2.errin,
                "errors_out":        s2.errout,
                "is_real":           True,
                "sampled_at":        time.time(),
            })
    except Exception as e:
        logger.debug(f"IO cache refresh failed: {e}")


def get_network_io_stats() -> dict:
    """
    Return network IO stats instantly from the in-process cache.
    A background thread keeps the cache fresh (≤ 5 s stale).
    First call starts a refresh; returns zeros until the first sample completes.
    """
    with _io_lock:
        cached = dict(_io_cache)

    stale = (time.time() - cached.get("sampled_at", 0)) > 5.0
    if stale:
        t = threading.Thread(target=_refresh_io_cache, daemon=True)
        t.start()

    if not cached.get("is_real"):
        return {
            "bytes_sent_total": 0, "bytes_recv_total": 0,
            "bytes_sent_rate":  0, "bytes_recv_rate":  0,
            "packets_sent":     0, "packets_recv":     0,
            "errors_in":        0, "errors_out":       0,
            "is_real":          False,
        }

    return {k: v for k, v in cached.items() if k != "sampled_at"}


# ─────────────────────────────────────────────────────────────────────────────
# Real connection reader
# ─────────────────────────────────────────────────────────────────────────────

_PROTO_MAP = {
    80: "HTTP",   443: "HTTPS",  8080: "HTTP",   8443: "HTTPS",
    53: "DNS",    25: "SMTP",    587: "SMTP",     465: "SMTPS",
    110: "POP3",  993: "IMAPS",  143: "IMAP",
    21: "FTP",    22: "SSH",     23: "Telnet",
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    3389: "RDP",  5900: "VNC",
    6667: "IRC",  4444: "TCP (Suspicious)",
    9001: "Tor",  9030: "Tor",
}


def _proto(port: int) -> str:
    return _PROTO_MAP.get(port, "TCP")


def _proc(pid: Optional[int]) -> str:
    try:
        if pid:
            import psutil
            return psutil.Process(pid).name()
    except Exception:
        pass
    return "unknown"


def _rdns(ip: str, timeout: float = 0.25) -> Optional[str]:
    if _is_internal(ip) or not ip:
        return None
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return result
    except Exception:
        return None


def read_real_connections() -> tuple[list[dict], bool]:
    """
    Snapshot OS-level TCP/UDP connections via psutil.
    Returns (events, has_external_connections).
    """
    try:
        import psutil
        raw = psutil.net_connections(kind="inet")
    except Exception as e:
        logger.warning(f"psutil.net_connections failed: {e}")
        return [], False

    now = datetime.utcnow()
    results: list[dict] = []
    seen: set[str] = set()

    for conn in raw:
        if conn.status not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
            continue
        if not conn.raddr:
            continue

        rip = conn.raddr.ip
        rport = conn.raddr.port
        key = f"{rip}:{rport}"
        if key in seen or _is_internal(rip):
            continue
        seen.add(key)

        domain = _rdns(rip) or rip
        proto = _proto(rport)
        analysis = analyze_domain(domain, rport, rip)

        results.append({
            "id":           hashlib.md5(f"{rip}:{rport}:{now.date()}".encode()).hexdigest()[:12],
            "domain":       domain,
            "ip":           rip,
            "port":         rport,
            "protocol":     proto,
            "process":      _proc(conn.pid),
            "risk_level":   analysis["risk_level"],
            "reasons":      analysis["reasons"],
            "indicators":   analysis["indicators"],
            "confidence":   analysis["confidence"],
            "is_known_safe": analysis["is_known_safe"],
            "timestamp":    now.isoformat() + "Z",
            "local_port":   conn.laddr.port if conn.laddr else None,
            "status":       conn.status,
            "data_source":  "real",
        })

    return results, len(results) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Simulation pool  (clearly labelled demo data)
# ─────────────────────────────────────────────────────────────────────────────
# All entries carry data_source="simulated".
# The pool is a mix of realistic safe traffic and clearly-crafted phishing
# examples that demonstrate the detection rules.

_POOL: list[dict] = [
    # ── Legitimate services ───────────────────────────────────────────────────
    {"domain": "cdn.jsdelivr.net",              "ip": "104.16.85.20",    "port": 443, "protocol": "HTTPS", "process": "node"},
    {"domain": "fonts.googleapis.com",          "ip": "142.250.80.78",   "port": 443, "protocol": "HTTPS", "process": "chromium"},
    {"domain": "api.github.com",                "ip": "140.82.114.6",    "port": 443, "protocol": "HTTPS", "process": "git"},
    {"domain": "registry.npmjs.org",            "ip": "104.16.24.35",    "port": 443, "protocol": "HTTPS", "process": "npm"},
    {"domain": "pypi.org",                      "ip": "151.101.128.223", "port": 443, "protocol": "HTTPS", "process": "pip"},
    {"domain": "storage.googleapis.com",        "ip": "172.217.168.48",  "port": 443, "protocol": "HTTPS", "process": "python3"},
    {"domain": "s3.amazonaws.com",              "ip": "52.216.8.120",    "port": 443, "protocol": "HTTPS", "process": "aws-cli"},
    {"domain": "ocsp.digicert.com",             "ip": "93.184.220.29",   "port": 80,  "protocol": "HTTP",  "process": "systemd"},
    {"domain": "connectivity-check.ubuntu.com", "ip": "91.189.94.101",   "port": 80,  "protocol": "HTTP",  "process": "NetworkManager"},
    {"domain": "time.cloudflare.com",           "ip": "162.159.200.1",   "port": 123, "protocol": "NTP",   "process": "systemd-timesyncd"},
    {"domain": "slack.com",                     "ip": "54.192.61.107",   "port": 443, "protocol": "HTTPS", "process": "slack"},
    {"domain": "zoom.us",                       "ip": "170.114.58.2",    "port": 443, "protocol": "HTTPS", "process": "zoom"},
    {"domain": "objects.githubusercontent.com", "ip": "185.199.108.133", "port": 443, "protocol": "HTTPS", "process": "git"},
    {"domain": "telemetry.ubuntu.com",          "ip": "91.189.92.38",    "port": 443, "protocol": "HTTPS", "process": "apport"},
    # ── Suspicious / phishing ─────────────────────────────────────────────────
    # Each entry below demonstrates a specific detection rule:
    {   # Rule: Suspicious TLD + brand keyword
        "domain": "secure-account-verify.xyz",
        "ip":     "185.220.101.47",
        "port":   80, "protocol": "HTTP", "process": "curl",
    },
    {   # Rule: Brand impersonation (microsoft typosquatting) + suspicious TLD
        "domain": "login-microsft-secure.tk",
        "ip":     "91.108.4.32",
        "port":   443, "protocol": "HTTPS", "process": "chromium",
    },
    {   # Rule: High entropy hostname (possible DGA)
        "domain": "xjqzpldfkmnrt.top",
        "ip":     "45.142.212.100",
        "port":   443, "protocol": "HTTPS", "process": "unknown",
    },
    {   # Rule: Phishing pattern + suspicious TLD
        "domain": "update-security-check.ga",
        "ip":     "79.110.49.51",
        "port":   80, "protocol": "HTTP", "process": "wget",
    },
    {   # Rule: Brand impersonation (paypal) + suspicious TLD
        "domain": "signin.paypa1-secure.cf",
        "ip":     "195.54.160.93",
        "port":   443, "protocol": "HTTPS", "process": "chromium",
    },
    {   # Rule: Deep subdomain + brand impersonation
        "domain": "account.verify.login.apple-id.support.xyz",
        "ip":     "104.21.14.83",
        "port":   443, "protocol": "HTTPS", "process": "Safari",
    },
    {   # Rule: Suspicious port (RDP)
        "domain": "remote-desktop-srv.example.net",
        "ip":     "203.0.113.45",
        "port":   3389, "protocol": "RDP", "process": "mstsc",
    },
    {   # Rule: Long domain + hyphen abuse + brand pattern
        "domain": "www-secure-login-account-verification-confirm-identity.club",
        "ip":     "5.188.231.100",
        "port":   80, "protocol": "HTTP", "process": "curl",
    },
]


def generate_simulated_events(count: int = 20) -> list[dict]:
    """
    Build a deterministic-ish set of demo events from the pool.
    All entries carry data_source='simulated'.
    """
    import random
    now = datetime.utcnow()
    events: list[dict] = []

    # Always include all pool entries (up to count), shuffled
    pool = list(_POOL)
    random.shuffle(pool)
    selected = pool[:min(count, len(pool))]

    for i, conn in enumerate(selected):
        a = analyze_domain(conn["domain"], conn["port"], conn["ip"])
        events.append({
            "id":           hashlib.md5(f"{conn['domain']}{conn['ip']}{i}".encode()).hexdigest()[:12],
            "domain":       conn["domain"],
            "ip":           conn["ip"],
            "port":         conn["port"],
            "protocol":     conn["protocol"],
            "process":      conn["process"],
            "risk_level":   a["risk_level"],
            "reasons":      a["reasons"],
            "indicators":   a["indicators"],
            "confidence":   a["confidence"],
            "is_known_safe": a["is_known_safe"],
            "timestamp":    (now - timedelta(seconds=i * 22)).isoformat() + "Z",
            "local_port":   None,
            "status":       "ESTABLISHED",
            "data_source":  "simulated",
        })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def get_live_events(count: int = 30) -> dict:
    """
    Try real monitoring first.  Fall back to simulation with clear labelling.
    Always includes monitoring_mode and mode_description for the UI.
    """
    real, has_real = read_real_connections()
    io = get_network_io_stats()

    if has_real:
        events = real[:count]
        mode = "real"
        desc  = "Live data from OS network stack via psutil.net_connections()"
    else:
        events = generate_simulated_events(min(count, len(_POOL)))
        mode  = "simulation"
        desc  = (
            "Simulation mode — this backend is running in a sandboxed environment "
            "with no external network connections. "
            "In a real deployment on your own machine or server this page shows "
            "your actual live network traffic."
        )

    stats = {
        "total":      len(events),
        "safe":       sum(1 for e in events if e["risk_level"] == "safe"),
        "suspicious": sum(1 for e in events if e["risk_level"] == "suspicious"),
        "dangerous":  sum(1 for e in events if e["risk_level"] == "dangerous"),
    }

    return {
        "events":            events,
        "stats":             stats,
        "io":                io,
        "monitoring_mode":   mode,
        "mode_description":  desc,
        "captured_at":       datetime.utcnow().isoformat() + "Z",
    }
