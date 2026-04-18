"""
VirusTotal Threat Intelligence Service — PhishGuard
=====================================================
Queries the VirusTotal v3 public API for domain reputation data and folds the
result into the URL scanning pipeline as an additional detection layer.

Free-tier constraints (strictly enforced)
------------------------------------------
  4 requests / minute   →  minimum 15 s between any two API calls
  500 requests / day    →  daily counter tracked in-process

Both limits are enforced conservatively so this service can never cause a
429 response regardless of how many concurrent scan requests arrive.

Caching (24-hour TTL)
---------------------
Every domain that receives a successful VT response is stored in
_VT_CACHE keyed by the normalised root domain. Subsequent lookups for the
same domain — even from different scan requests — return the cached result
immediately without touching the API. This is the primary mechanism that
keeps daily usage well within the 500-request budget.

Cache entry shape (domain):
    {
        "domain":       str,
        "malicious":    int,
        "suspicious":   int,
        "harmless":     int,
        "total":        int,
        "reputation":   int,
        "categories":   list[str],
        "verdict":      str,          # "malicious"|"suspicious"|"clean"|"unknown"
        "confidence":   float,
        "cached_at":    float,
        "source":       str,          # "virustotal"
    }

Cache entry shape (file hash):
    {
        "sha256":       str,
        "malicious":    int,
        "suspicious":   int,
        "total":        int,
        "verdict":      str,          # "malicious"|"suspicious"|"clean"|"unknown"
        "confidence":   float,
        "cached_at":    float,
        "source":       str,          # "virustotal_file"
    }

Rate limiting (token-bucket–style via a simple timestamp gate)
--------------------------------------------------------------
_VT_LAST_CALL_TIME tracks the epoch of the most recent outbound VT request.
Before every call, we compute the elapsed time since that request. If less
than VT_RATE_LIMIT_SECONDS (15 s) has passed, the call is skipped and the
function returns None — the pipeline continues with the layers it already has.

A threading.Lock (_VT_RATE_LOCK) ensures the check-and-update of
_VT_LAST_CALL_TIME is atomic, preventing two concurrent scan requests from
both passing the gate at the same moment.

The daily counter (_VT_DAILY_CALLS) is reset when the calendar date changes
(compared against _VT_DAILY_DATE). Once _VT_DAILY_CALLS reaches
VT_DAILY_BUDGET the service stops calling the API for the rest of the day.

Conditional triggering
----------------------
check_domain() only calls the API when the upstream detection layers have
already raised a flag:
  - ML phishing probability  ≥ VT_ML_THRESHOLD      (0.35)
  - rule engine score        ≥ VT_RULE_THRESHOLD     (0.30)
  - label is PHISHING or SUSPICIOUS

check_file_hash() always queries when a sha256 is provided, subject only to
the shared rate/budget gate and the 24-hour cache.

Fixes applied (vs previous version):
  [FIX-8] check_file_hash() added — queries /files/{hash} endpoint so that
          known malware uploaded as a file is caught by VT even when its
          hosting domain is clean.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import date
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration constants
# ─────────────────────────────────────────────────────────────────────────────

VT_API_BASE = "https://www.virustotal.com/api/v3"

# Minimum seconds between successive API calls (enforces 4 req/min limit)
VT_RATE_LIMIT_SECONDS: float = 15.0

# Maximum calls per calendar day (free-tier hard cap is 500)
VT_DAILY_BUDGET: int = 480          # 480 < 500 — 20-call safety margin

# HTTP timeout for VT requests
VT_HTTP_TIMEOUT: float = 10.0

# How long a cached result stays valid (seconds). 24 h = one call per domain/day.
VT_CACHE_TTL: float = 86_400.0      # 24 hours

# Minimum ML probability that triggers a VT domain lookup
VT_ML_THRESHOLD: float = 0.35

# Minimum rule-engine score that triggers a VT domain lookup
VT_RULE_THRESHOLD: float = 0.30

# Malicious-engine ratio thresholds
VT_MALICIOUS_RATIO_HIGH: float = 0.10   # ≥10% of engines flagged malicious
VT_MALICIOUS_RATIO_MED:  float = 0.03   # ≥ 3% — suspicious but not definitive


# ─────────────────────────────────────────────────────────────────────────────
# In-memory cache  (process lifetime)
# Keys: normalised domain strings  OR  "file:<sha256>"
# ─────────────────────────────────────────────────────────────────────────────

_VT_CACHE: dict[str, dict] = {}
_VT_CACHE_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limit state  (all mutations must hold _VT_RATE_LOCK)
# ─────────────────────────────────────────────────────────────────────────────

_VT_LAST_CALL_TIME: float = 0.0
_VT_DAILY_CALLS:    int   = 0
_VT_DAILY_DATE:     date  = date.min
_VT_RATE_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _vt_available() -> bool:
    """Return True only when a VirusTotal API key is configured."""
    return bool(getattr(settings, "VIRUSTOTAL_API_KEY", None))


import tldextract

def _normalise_domain(raw: str) -> str:
    """
    Extract and normalise the registered root domain using the Public Suffix List.
    Correctly handles complex TLDs like .gov.in, .co.uk, etc.
    """
    raw = raw.strip().lower()

    import re
    if re.match(r"(?<!\d)(\d{1,3}\.){3}\d{1,3}(?!\d)", raw):
        match = re.search(r"(\d{1,3}\.){3}\d{1,3}", raw)
        return match.group(0) if match else raw

    ext = tldextract.extract(raw)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"

    return raw


def _cache_get(key: str) -> Optional[dict]:
    """Return a cached entry if it exists and has not expired; else None."""
    with _VT_CACHE_LOCK:
        entry = _VT_CACHE.get(key)
    if entry is None:
        return None
    age = time.time() - entry.get("cached_at", 0.0)
    if age > VT_CACHE_TTL:
        with _VT_CACHE_LOCK:
            _VT_CACHE.pop(key, None)
        return None
    return entry


def _cache_set(key: str, result: dict) -> None:
    """Store a result in the cache with the current timestamp."""
    result["cached_at"] = time.time()
    with _VT_CACHE_LOCK:
        _VT_CACHE[key] = result


def _acquire_rate_slot() -> bool:
    """
    Atomically check both the per-minute and per-day limits, then mark a
    call slot as consumed.

    Returns True if the caller may proceed with an API call.
    Returns False if the call must be skipped (rate-limited or budget exhausted).
    """
    global _VT_LAST_CALL_TIME, _VT_DAILY_CALLS, _VT_DAILY_DATE

    now   = time.time()
    today = date.today()

    with _VT_RATE_LOCK:
        if today != _VT_DAILY_DATE:
            _VT_DAILY_CALLS = 0
            _VT_DAILY_DATE  = today
            logger.debug("VirusTotal daily counter reset for %s", today.isoformat())

        if _VT_DAILY_CALLS >= VT_DAILY_BUDGET:
            logger.warning(
                "VirusTotal daily budget exhausted (%d/%d calls) — "
                "skipping request until midnight.",
                _VT_DAILY_CALLS, VT_DAILY_BUDGET,
            )
            return False

        elapsed = now - _VT_LAST_CALL_TIME
        if elapsed < VT_RATE_LIMIT_SECONDS:
            logger.debug(
                "VirusTotal rate limit: %.1f s since last call (min %.1f s) — skipping.",
                elapsed, VT_RATE_LIMIT_SECONDS,
            )
            return False

        # Slot acquired — update state
        _VT_LAST_CALL_TIME = now
        _VT_DAILY_CALLS   += 1
        return True


def _parse_vt_response(domain: str, data: dict) -> dict:
    """Parse a VirusTotal v3 /domains/{domain} JSON response into a normalised dict."""
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        reputation = attrs.get("reputation", 0)
        categories = list(attrs.get("categories", {}).values())

        mal_ratio = malicious / total if total else 0.0

        if malicious >= 3 or mal_ratio >= VT_MALICIOUS_RATIO_HIGH:
            verdict    = "malicious"
            confidence = min(0.9, 0.5 + mal_ratio * 2)
        elif malicious >= 1 or mal_ratio >= VT_MALICIOUS_RATIO_MED:
            verdict    = "suspicious"
            confidence = min(0.6, 0.3 + mal_ratio * 3)
        elif reputation < -5:
            verdict    = "suspicious"
            confidence = 0.25
        else:
            verdict    = "clean"
            confidence = 0.0

        return {
            "domain":     domain,
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "total":      total,
            "reputation": reputation,
            "categories": categories,
            "verdict":    verdict,
            "confidence": round(confidence, 4),
            "source":     "virustotal",
        }

    except Exception as exc:
        logger.warning("VirusTotal response parse error for '%s': %s", domain, exc)
        return _unknown_result(domain)


def _unknown_result(domain: str) -> dict:
    """Safe fallback result when VT is unavailable or parsing fails."""
    return {
        "domain":     domain,
        "malicious":  0,
        "suspicious": 0,
        "harmless":   0,
        "total":      0,
        "reputation": 0,
        "categories": [],
        "verdict":    "unknown",
        "confidence": 0.0,
        "source":     "virustotal",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API — domain reputation
# ─────────────────────────────────────────────────────────────────────────────

async def check_domain(
    domain: str,
    ml_probability: float = 0.0,
    rule_score: float = 0.0,
    label: str = "SAFE",
) -> Optional[dict]:
    """
    Query VirusTotal for the reputation of *domain*.

    Returns a result dict when VT was consulted (cache or fresh call).
    Returns None when key absent, below triggering thresholds, rate-limited,
    or the API call fails.
    """
    if not _vt_available():
        logger.debug("VIRUSTOTAL_API_KEY not configured — skipping VT check")
        return None

    is_suspicious = (
        label in ("PHISHING", "SUSPICIOUS")
        or ml_probability >= VT_ML_THRESHOLD
        or rule_score     >= VT_RULE_THRESHOLD
    )
    if not is_suspicious:
        logger.debug(
            "VirusTotal skipped for '%s' — below thresholds "
            "(label=%s, ml=%.3f, rule=%.3f).",
            domain, label, ml_probability, rule_score,
        )
        return None

    normalised = _normalise_domain(domain)
    if not normalised:
        return None

    cached = _cache_get(normalised)
    if cached is not None:
        age_min = round((time.time() - cached["cached_at"]) / 60, 1)
        logger.info(
            "VirusTotal cache hit for '%s' "
            "(verdict=%s, malicious=%d, cached %.1f min ago).",
            normalised, cached["verdict"], cached["malicious"], age_min,
        )
        return cached

    if not _acquire_rate_slot():
        return None

    url     = f"{VT_API_BASE}/domains/{normalised}"
    headers = {
        "x-apikey":   settings.VIRUSTOTAL_API_KEY,
        "Accept":     "application/json",
        "User-Agent": "PhishGuard/2.0 threat-intel",
    }

    logger.info("VirusTotal domain check performed for '%s'.", normalised)

    try:
        async with httpx.AsyncClient(timeout=VT_HTTP_TIMEOUT) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 404:
            logger.info("VirusTotal: domain '%s' not found in database (404).", normalised)
            result = _unknown_result(normalised)
            _cache_set(normalised, result)
            return result

        if response.status_code == 429:
            logger.warning(
                "VirusTotal rate limit hit (429) for '%s' — skipping.", normalised,
            )
            return None

        response.raise_for_status()

        result = _parse_vt_response(normalised, response.json())
        _cache_set(normalised, result)

        logger.info(
            "VirusTotal result for '%s': verdict=%s, malicious=%d/%d, reputation=%d.",
            normalised, result["verdict"], result["malicious"],
            result["total"], result["reputation"],
        )
        return result

    except httpx.TimeoutException:
        logger.warning(
            "VirusTotal request timed out after %.1f s for '%s'.",
            VT_HTTP_TIMEOUT, normalised,
        )
        return None

    except httpx.HTTPStatusError as exc:
        logger.warning(
            "VirusTotal HTTP error %s for '%s': %s — skipping.",
            exc.response.status_code, normalised, exc.response.text[:120],
        )
        return None

    except Exception as exc:
        logger.warning("VirusTotal unexpected error for '%s': %s — skipping.", normalised, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API — file hash lookup  [FIX-8]
# ─────────────────────────────────────────────────────────────────────────────

async def check_file_hash(sha256: str) -> Optional[dict]:
    """
    Query VirusTotal v3 /files/{sha256} for a file reputation report.

    [FIX-8] Previously, VT was only consulted for domain names extracted from
    URLs inside the file. A file containing known malware hosted behind a clean
    domain was never caught by VT. This endpoint checks the file itself.

    Returns a result dict on cache hit or successful API call.
    Returns None when:
      - VIRUSTOTAL_API_KEY not configured
      - hash not found in VT database (404) — treated as unknown, not clean
      - rate-limited or daily budget exhausted
      - API call fails for any reason

    Cache key: "file:<sha256>"  (separate namespace from domain cache)
    """
    if not _vt_available():
        return None

    if not sha256 or len(sha256) != 64:
        logger.debug("check_file_hash: invalid sha256 '%s' — skipping", sha256)
        return None

    cache_key = f"file:{sha256}"
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.info(
            "VirusTotal file cache hit for sha256 %s... (verdict=%s)",
            sha256[:12], cached["verdict"],
        )
        return cached

    if not _acquire_rate_slot():
        return None

    url     = f"{VT_API_BASE}/files/{sha256}"
    headers = {
        "x-apikey":   settings.VIRUSTOTAL_API_KEY,
        "Accept":     "application/json",
        "User-Agent": "PhishGuard/2.0 threat-intel",
    }

    logger.info("VirusTotal file hash check for sha256 %s...", sha256[:12])

    try:
        async with httpx.AsyncClient(timeout=VT_HTTP_TIMEOUT) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 404:
            # File not in VT database — unknown, not confirmed clean.
            # Cache the unknown result so we don't waste budget re-checking
            # every time the same file is uploaded.
            logger.info("VirusTotal: file sha256 %s... not in database (404).", sha256[:12])
            result = {
                "sha256":     sha256,
                "malicious":  0,
                "suspicious": 0,
                "total":      0,
                "verdict":    "unknown",
                "confidence": 0.0,
                "source":     "virustotal_file",
            }
            _cache_set(cache_key, result)
            return result

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit hit (429) on file hash check — skipping.")
            return None

        response.raise_for_status()

        data  = response.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        mal_ratio = malicious / total if total else 0.0

        # Verdict thresholds for files are tighter than for domains because
        # a file hash match is a direct indicator, not a reputation proxy.
        if malicious >= 3 or mal_ratio >= 0.05:
            verdict    = "malicious"
            confidence = round(min(0.95, 0.6 + mal_ratio * 2), 4)
        elif (malicious + suspicious) >= 2:
            verdict    = "suspicious"
            confidence = round(min(0.65, 0.35 + mal_ratio * 3), 4)
        else:
            verdict    = "clean"
            confidence = 0.0

        result = {
            "sha256":     sha256,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "verdict":    verdict,
            "confidence": confidence,
            "source":     "virustotal_file",
        }
        _cache_set(cache_key, result)

        logger.info(
            "VirusTotal file result for sha256 %s...: verdict=%s, malicious=%d/%d.",
            sha256[:12], verdict, malicious, total,
        )
        return result

    except httpx.TimeoutException:
        logger.warning(
            "VirusTotal file hash request timed out after %.1f s for sha256 %s...",
            VT_HTTP_TIMEOUT, sha256[:12],
        )
        return None

    except httpx.HTTPStatusError as exc:
        logger.warning(
            "VirusTotal HTTP error %s on file hash check for sha256 %s...: %s",
            exc.response.status_code, sha256[:12], exc.response.text[:120],
        )
        return None

    except Exception as exc:
        logger.warning(
            "VirusTotal unexpected error on file hash check for sha256 %s...: %s",
            sha256[:12], exc,
        )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Observability
# ─────────────────────────────────────────────────────────────────────────────

def get_cache_stats() -> dict:
    """
    Return current cache and rate-limit statistics.
    Used by the admin/health endpoints for observability.
    """
    global _VT_DAILY_CALLS, _VT_DAILY_DATE, _VT_LAST_CALL_TIME

    with _VT_RATE_LOCK:
        daily_calls   = _VT_DAILY_CALLS
        daily_date    = _VT_DAILY_DATE.isoformat()
        last_call_age = round(time.time() - _VT_LAST_CALL_TIME, 1) if _VT_LAST_CALL_TIME else None

    with _VT_CACHE_LOCK:
        cache_size = len(_VT_CACHE)
        now = time.time()
        live_entries      = sum(1 for e in _VT_CACHE.values() if (now - e.get("cached_at", 0)) <= VT_CACHE_TTL)
        domain_entries    = sum(1 for k in _VT_CACHE if not k.startswith("file:"))
        file_hash_entries = sum(1 for k in _VT_CACHE if k.startswith("file:"))

    return {
        "available":           _vt_available(),
        "cache_total_entries": cache_size,
        "cache_live_entries":  live_entries,
        "cache_domain_entries": domain_entries,
        "cache_file_entries":  file_hash_entries,
        "cache_ttl_hours":     VT_CACHE_TTL / 3600,
        "daily_calls_used":    daily_calls,
        "daily_budget":        VT_DAILY_BUDGET,
        "daily_date":          daily_date,
        "rate_limit_seconds":  VT_RATE_LIMIT_SECONDS,
        "last_call_age_s":     last_call_age,
        "next_slot_in_s":      max(0.0, round(VT_RATE_LIMIT_SECONDS - (time.time() - (_VT_LAST_CALL_TIME or 0)), 1)),
    }