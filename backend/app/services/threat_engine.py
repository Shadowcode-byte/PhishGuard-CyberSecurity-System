"""
Threat Engine — Enhanced Domain & Connection Analysis
=====================================================
Extends the base threat_service.py with:
  - Threat feed integration (check against live IOC lists)
  - Domain risk scoring (0-100)
  - Incident auto-creation for dangerous domains
  - Top threat domains aggregation
  - System risk level calculation (LOW / MEDIUM / HIGH / CRITICAL)

Detection rules (12 independent checks):
  ┌─────────────────────────────────────┬───────────┬──────────┐
  │ Rule                                │ Max score │ Severity │
  ├─────────────────────────────────────┼───────────┼──────────┤
  │ Threat feed hit (live IOC)          │ +0.60     │ CRITICAL │
  │ Suspicious TLD (.tk/.ga/...)        │ +0.45     │ HIGH     │
  │ Brand impersonation                 │ +0.50     │ HIGH     │
  │ Phishing URL pattern (regex)        │ +0.40     │ HIGH     │
  │ DGA entropy analysis (H>3.9)        │ +0.30     │ MED      │
  │ Suspicious port                     │ +0.30     │ MED      │
  │ Raw IP address (no domain)          │ +0.20     │ MED      │
  │ Deep subdomain nesting (>5)         │ +0.25     │ MED      │
  │ Unusually long domain (>50 ch)      │ +0.10     │ LOW      │
  │ Numeric-heavy hostname (>50%)       │ +0.12     │ LOW      │
  │ Hyphen abuse (≥3 hyphens)           │ +0.10     │ LOW      │
  │ Newly registered TLD pattern        │ +0.15     │ LOW      │
  └─────────────────────────────────────┴───────────┴──────────┘
  Thresholds: dangerous ≥ 0.55 · suspicious ≥ 0.20 · safe < 0.20
  Risk score (0-100) = confidence * 100
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Threat intelligence data (from threat_service.py — kept in sync)
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".pw", ".cc", ".su",
    ".click", ".link", ".download",
    ".zip", ".mov",
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
    r"[-\\\.]( paypal|amazon|google|apple|microsoft)\.",
    r"www\d+\.",
    r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",
    r"(free|win|prize|gift|reward|bonus)[-\.]",
    r"(wallet|crypto|nft)[-\.]",
    r"(suspended|unusual|activity|alert)[-\.]account",
]

SUSPICIOUS_PORTS = {
    20, 21, 23, 25, 110,
    135, 137, 138, 139, 445,
    1433, 3306, 3389, 4444,
    5900, 6666, 6667, 6668, 6669,
    9001, 9030,
}

SAFE_INTERNAL_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1", "fe80:", "0.0.0.0",
)

WELL_KNOWN_SAFE = {
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
    "fastly.net", "akamai.net", "akamaiedge.net",
    "amazonaws.com", "awsstatic.com", "aws.amazon.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "github.com", "githubusercontent.com", "github.io",
    "microsoft.com", "windows.com", "microsoftonline.com", "azure.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "ubuntu.com", "debian.org", "fedoraproject.org",
    "npmjs.org", "npmjs.com", "pypi.org",
    "stackoverflow.com", "stackexchange.com",
    "wikipedia.org", "wikimedia.org",
    "youtube.com", "ytimg.com",
    "twitter.com", "twimg.com", "x.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "letsencrypt.org", "ocsp.digicert.com", "ocsp.pki.goog",
    "slack.com", "slack-edge.com", "zoom.us", "zoomcdn.com",
    "dropbox.com", "dropboxstatic.com",
    "1.1.1.1", "8.8.8.8", "8.8.4.4",
}


# ─────────────────────────────────────────────────────────────────────────────
# Core analysis
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
    check_feeds: bool = True,
) -> dict:
    """
    Multi-rule threat analysis of a domain/connection.
    Returns risk_level, confidence 0-1, risk_score 0-100,
    typed indicators with severity, and feed_hit status.
    """
    if not domain:
        return {
            "domain": domain, "risk_level": "safe", "reasons": [],
            "confidence": 0.0, "risk_score": 0, "indicators": [],
            "is_known_safe": False, "feed_hit": False,
        }

    d = domain.lower().strip().rstrip(".")
    if ":" in d:
        d = d.split(":")[0]

    # Fast-path: well-known safe
    root = _root(d)
    for safe in WELL_KNOWN_SAFE:
        if d == safe or d.endswith("." + safe):
            return {
                "domain": domain, "risk_level": "safe", "reasons": [],
                "confidence": 0.0, "risk_score": 0, "indicators": [],
                "is_known_safe": True, "feed_hit": False,
            }

    indicators: list[dict] = []
    score = 0.0
    feed_hit = False

    # Rule 0 — Threat feed hit (live IOC check)
    if check_feeds:
        try:
            from app.services.threat_feed import check_domain
            feed_result = check_domain(d)
            if feed_result["is_malicious"]:
                feed_hit = True
                indicators.append({
                    "type": "threat_feed_hit",
                    "detail": f"Domain found in threat intelligence feed: {', '.join(feed_result['feed_hits'])}",
                    "severity": "critical",
                })
                score += 0.60
        except Exception:
            pass

    # Rule 1 — Suspicious TLD
    tld = _tld(d)
    if tld in SUSPICIOUS_TLDS:
        indicators.append({
            "type": "suspicious_tld",
            "detail": f"TLD '{tld}' is heavily abused for phishing and malware",
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
            "detail": f"High-entropy hostname (H={ent:.2f}) — possible DGA domain",
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
            "detail": "Direct connection to raw IP address (no hostname)",
            "severity": "medium",
        })
        score += 0.20

    # Rule 7 — Subdomain depth
    parts = d.split(".")
    if len(parts) > 5:
        indicators.append({
            "type": "deep_subdomain",
            "detail": f"Unusual subdomain depth ({len(parts)} levels) — impersonation tactic",
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
            "detail": f"Excessive hyphens ({hostname.count('-')}) — common phishing pattern",
            "severity": "low",
        })
        score += 0.10

    # Rule 11 — Newly registered TLD pattern (numeric prefix + suspicious)
    if re.match(r"^\d+[a-z]{3,}$", hostname) and tld in SUSPICIOUS_TLDS:
        indicators.append({
            "type": "newly_registered_pattern",
            "detail": "Pattern matches newly registered / bulk-created domains",
            "severity": "low",
        })
        score += 0.15

    score = min(score, 1.0)
    risk_score = round(score * 100)

    return {
        "domain": domain,
        "risk_level": "dangerous" if score >= 0.55 else "suspicious" if score >= 0.20 else "safe",
        "reasons": [i["detail"] for i in indicators],
        "confidence": round(score, 3),
        "risk_score": risk_score,
        "indicators": indicators,
        "is_known_safe": False,
        "feed_hit": feed_hit,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Recent events ring buffer (shared state for aggregations)
# ─────────────────────────────────────────────────────────────────────────────

_events_buffer: deque = deque(maxlen=500)
_events_lock = threading.Lock()


def record_event(event: dict) -> None:
    """Add an event to the ring buffer for aggregation queries."""
    with _events_lock:
        _events_buffer.append(event)


def get_top_threat_domains(n: int = 10) -> list[dict]:
    """Return the most-seen suspicious/dangerous domains from recent events."""
    with _events_lock:
        events = list(_events_buffer)

    counter: Counter = Counter()
    domain_data: dict[str, dict] = {}

    for ev in events:
        if ev.get("risk_level") in ("suspicious", "dangerous"):
            d = ev.get("domain", "")
            counter[d] += 1
            if d not in domain_data or ev.get("confidence", 0) > domain_data[d].get("confidence", 0):
                domain_data[d] = ev

    results = []
    for domain, count in counter.most_common(n):
        data = domain_data[domain]
        results.append({
            "domain": domain,
            "hits": count,
            "risk_level": data.get("risk_level"),
            "confidence": data.get("confidence", 0),
            "risk_score": data.get("risk_score", 0),
            "last_seen": data.get("timestamp"),
        })

    return results


def get_system_risk_level(stats: dict) -> dict:
    """
    Calculate overall system risk level from current event statistics.
    Returns {level, label, color, description}.
    """
    total = stats.get("total", 0)
    dangerous = stats.get("dangerous", 0)
    suspicious = stats.get("suspicious", 0)

    if total == 0:
        return {
            "level": "unknown",
            "label": "UNKNOWN",
            "color": "#8892b0",
            "description": "Insufficient data for risk assessment",
            "score": 0,
        }

    danger_rate = dangerous / total
    suspicious_rate = suspicious / total
    combined = (danger_rate * 1.0) + (suspicious_rate * 0.4)

    if combined >= 0.3 or dangerous >= 5:
        level = "critical"
        label = "CRITICAL"
        color = "#ff2d55"
        desc = f"{dangerous} dangerous connections detected — immediate investigation required"
    elif combined >= 0.15 or dangerous >= 2:
        level = "high"
        label = "HIGH"
        color = "#ff6b35"
        desc = f"{dangerous} dangerous, {suspicious} suspicious connections — review required"
    elif combined >= 0.05 or suspicious >= 3:
        level = "medium"
        label = "MEDIUM"
        color = "#ffd60a"
        desc = f"{suspicious} suspicious connections detected — monitor closely"
    else:
        level = "low"
        label = "LOW"
        color = "#00ff88"
        desc = "Network traffic appears normal — no significant threats detected"

    return {
        "level": level,
        "label": label,
        "color": color,
        "description": desc,
        "score": min(100, round(combined * 100 * 3)),
    }
