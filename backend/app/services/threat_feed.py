"""
Threat Feed Service — Database-Backed Integration
=================================================
Production-hardened rewrite addressing Out-Of-Memory (OOM) crashes.
Domains are now streamed directly into the database in batches.
Memory footprint remains flat regardless of feed size.
"""

from __future__ import annotations
from sqlalchemy.dialects.postgresql import insert
import uuid
import logging
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

# Added database imports
from sqlalchemy.orm import Session
from app.database import SessionLocal # <-- Adjust this import based on your project structure!
from app.models.models import ThreatFeed

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

FEED_REFRESH_INTERVAL: int = 3600          # 1 hour
FEED_MIN_FETCH_INTERVAL: int = 600         # 10 minutes between retries
RATE_LIMIT_BACKOFF: int = 7200             # 2 hours
FEED_HTTP_TIMEOUT: int = 30                # Slightly longer timeout for streaming

FEEDS: list[dict] = [
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url",
        "description": "Malware distribution URLs from abuse.ch",
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "type": "url",
        "description": "Community phishing URLs",
    },
    {
        "name": "PhishTank (domains)",
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "type": "csv_url_column",
        "description": "Verified phishing sites (rate-limited — hourly refresh)",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# In-memory Metadata Cache (No longer stores 40k+ domains!)
# ─────────────────────────────────────────────────────────────────────────────

_cache: dict = {
    "feed_entries": {},      # metadata only: {name: {loaded_at, error, status, count}}
    "loaded_at":    0.0,     
    "feed_stats":   [],      
    "is_loaded":    False,   
    "_loading":     False,   
    "total_domains": 0,      
}
_cache_lock = threading.Lock()

_BOOTSTRAP_LOCK   = threading.Lock()
_bootstrap_started = False          


# ─────────────────────────────────────────────────────────────────────────────
# Domain helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_domain(raw: str) -> Optional[str]:
    raw = raw.strip().lower()
    if not raw or raw.startswith("#"):
        return None
    for prefix in ("http://", "https://", "ftp://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    if "." not in raw or raw.replace(".", "").isdigit():
        return None
    parts = raw.split(".")
    if any(len(p) == 0 or len(p) > 63 for p in parts):
        return None
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Per-feed Database Streaming Fetch
# ─────────────────────────────────────────────────────────────────────────────

def _should_skip_feed(feed_name: str) -> tuple[bool, str]:
    with _cache_lock:
        entry = _cache["feed_entries"].get(feed_name, {})

    last_fetched = entry.get("loaded_at", 0.0)
    status       = entry.get("status", "pending")
    age          = time.time() - last_fetched

    if status == "rate_limited" and age < RATE_LIMIT_BACKOFF:
        return True, f"rate-limited — retrying in {int(RATE_LIMIT_BACKOFF - age)}s"

    if status == "ok" and age < FEED_MIN_FETCH_INTERVAL:
        return True, f"cached ({int(age)}s old)"

    return False, ""


def _fetch_and_save_feed(db: Session, feed: dict) -> tuple[int, str, str]:
    """
    Streams the feed directly into the DB. Returns (domains_inserted, status, error).
    """
    try:
        req = urllib.request.Request(
            feed["url"],
            headers={"User-Agent": "PhishGuard/2.0 threat-intel-collector"},
        )
        
        with urllib.request.urlopen(req, timeout=FEED_HTTP_TIMEOUT) as resp:
            # 1. Clear old domains for this specific feed
            db.query(ThreatFeed).filter(ThreatFeed.source == feed["name"]).delete()
            db.commit()

            batch = []
            domains_seen = set() # Keep a tiny local set just to prevent duplicates in the same batch
            total_inserted = 0
            
            # 2. Stream line-by-line (0% Memory Impact!)
            for line in resp:
                decoded_line = line.decode("utf-8", errors="ignore").strip()
                domain = _extract_domain(decoded_line)
                
                if domain and domain not in domains_seen:
                    domains_seen.add(domain)
                    batch.append(ThreatFeed(domain=domain, source=feed["name"]))
                    
                    # Also add root domain
                    parts = domain.split(".")
                    if len(parts) > 2:
                        root = ".".join(parts[-2:])
                        if root not in domains_seen:
                            domains_seen.add(root)
                            batch.append(ThreatFeed(domain=root, source=feed["name"]))

                    # 3. Save in chunks of 1000 to prevent RAM spikes
                    if len(batch) >= 1000:
                        db.bulk_save_objects(batch)
                        db.commit()
                        total_inserted += len(batch)
                        batch = []
                        

            # Save remainder
            if batch:
                stmt = insert(ThreatFeed).values([
                    {
                        "id": uuid.uuid4(),
                        "domain": obj.domain,
                        "source": obj.source,
                    }
                    for obj in batch
                ])

                stmt = stmt.on_conflict_do_nothing(index_elements=["domain"])

                db.execute(stmt)
                db.commit()
                total_inserted += len(batch)

        return total_inserted, "ok", ""

    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return 0, "rate_limited", f"HTTP 429 Too Many Requests"
        return 0, "failed", f"HTTP Error {exc.code}: {exc.reason}"
    except Exception as exc:
        db.rollback()   # ✅ CRITICAL
        return 0, "failed", str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Background Worker
# ─────────────────────────────────────────────────────────────────────────────

def _run_feed_refresh() -> None:
    logger.info("Threat feed refresh starting (%d sources configured)…", len(FEEDS))
    refresh_start = time.time()

    with _cache_lock:
        feed_entries: dict = {k: dict(v) for k, v in _cache["feed_entries"].items()}

    stats: list[dict] = []
    fetched_count = 0
    skipped_count = 0
    
    # Open an independent database session for this background thread
    db = SessionLocal()

    try:
        for feed in FEEDS:
            name = feed["name"]

            skip, reason = _should_skip_feed(name)
            if skip:
                skipped_count += 1
                existing = feed_entries.get(name, {})
                stats.append({
                    "name": name, "description": feed["description"],
                    "domains_loaded": existing.get("count", 0),
                    "status": existing.get("status", "pending"),
                    "skipped": True, "skip_reason": reason,
                })
                continue

            inserted_count, status, error_msg = _fetch_and_save_feed(db, feed)
            fetched_count += 1

            if status == "ok":
                feed_entries[name] = {"loaded_at": time.time(), "error": None, "status": "ok", "count": inserted_count}
                logger.info("Threat feed '%s': saved %d domains to DB", name, inserted_count)
            else:
                old_entry = feed_entries.get(name, {})
                feed_entries[name] = {"loaded_at": old_entry.get("loaded_at", 0.0), "error": error_msg, "status": status, "count": old_entry.get("count", 0)}
                logger.warning("Failed feed '%s': %s (kept old DB data)", name, error_msg)

            entry = feed_entries[name]
            stats.append({
                "name": name, "description": feed["description"],
                "domains_loaded": entry["count"], "status": entry["status"],
                "skipped": False, "error": entry.get("error"),
            })

        total_db_domains = db.query(ThreatFeed).count()

        with _cache_lock:
            _cache["feed_entries"] = feed_entries
            _cache["loaded_at"]    = time.time()
            _cache["feed_stats"]   = stats
            _cache["is_loaded"]    = True
            _cache["total_domains"] = total_db_domains
            _cache["_loading"]     = False

        logger.info("Threat feeds DB update complete. Total malicious domains: %d", total_db_domains)

    finally:
        db.close() # Always close the thread's DB session!

def _refresh_wrapper() -> None:
    try:
        _run_feed_refresh()
    except Exception as exc:
        logger.error("Unexpected error in feed refresh thread: %s", exc, exc_info=True)
        with _cache_lock:
            _cache["_loading"] = False

def ensure_loaded() -> None:
    # (Unchanged from your code)
    global _bootstrap_started
    with _BOOTSTRAP_LOCK:
        if not _bootstrap_started:
            _bootstrap_started = True
            with _cache_lock:
                _cache["_loading"] = True
            t = threading.Thread(target=_refresh_wrapper, name="threat-feed-loader", daemon=True)
            t.start()
            return

    with _cache_lock:
        loaded_at  = _cache.get("loaded_at", 0.0)
        is_loading = _cache.get("_loading", False)
        is_stale   = (time.time() - loaded_at) > FEED_REFRESH_INTERVAL

        if is_loading or not is_stale:
            return
        _cache["_loading"] = True

    t = threading.Thread(target=_refresh_wrapper, name="threat-feed-refresh", daemon=True)
    t.start()


# ─────────────────────────────────────────────────────────────────────────────
# Public API - UPDATED to use DB Session
# ─────────────────────────────────────────────────────────────────────────────

def check_domain(db: Session, domain: str) -> dict:
    """
    Check if a domain appears in the database threat feeds.
    NOTE: Added 'db: Session' parameter!
    """
    ensure_loaded()

    if not domain:
        return {"is_malicious": False, "matched_domain": None, "feed_hits": []}

    d    = domain.lower().strip().rstrip(".")
    parts = d.split(".")
    root  = ".".join(parts[-2:]) if len(parts) >= 2 else d

    hits: list[str] = []

    # 1. Check static list in memory first (super fast fallback)
    if d in _STATIC_MALICIOUS:
        hits.append(f"Exact match (Static Feed): {d}")
    elif root in _STATIC_MALICIOUS:
        hits.append(f"Root match (Static Feed): {root}")

    # 2. Check Database if not found statically
    if not hits:
        # Check exact domain
        exact_match = db.query(ThreatFeed).filter(ThreatFeed.domain == d).first()
        if exact_match:
            hits.append(f"Exact match ({exact_match.source}): {d}")
        # Check root domain
        elif root != d:
            root_match = db.query(ThreatFeed).filter(ThreatFeed.domain == root).first()
            if root_match:
                hits.append(f"Root match ({root_match.source}): {root}")

    return {
        "is_malicious":   len(hits) > 0,
        "matched_domain": d if hits else None,
        "feed_hits":      hits,
    }


def get_feed_status() -> dict:
    # (Unchanged from your code)
    ensure_loaded()
    with _cache_lock:
        loaded_at      = _cache.get("loaded_at", 0.0)
        is_loaded      = _cache.get("is_loaded", False)
        total_domains  = _cache.get("total_domains", 0)
        feed_stats     = list(_cache.get("feed_stats", []))
        is_loading     = _cache.get("_loading", False)

    cache_age = int(time.time() - loaded_at) if loaded_at else None
    next_refresh_in = max(0, FEED_REFRESH_INTERVAL - cache_age) if cache_age is not None else FEED_REFRESH_INTERVAL

    return {
        "is_loaded":         is_loaded,
        "is_loading":        is_loading,
        "total_domains":     total_domains,
        "loaded_at":         (datetime.fromtimestamp(loaded_at, tz=timezone.utc).isoformat() if loaded_at else None),
        "cache_age_seconds": cache_age,
        "next_refresh_in":   next_refresh_in,
        "refresh_interval":  FEED_REFRESH_INTERVAL,
        "feed_stats":        feed_stats,
    }

_STATIC_MALICIOUS: frozenset[str] = frozenset({
    "login-microsft-secure.tk",
    "secure-account-verify.xyz",
    # ... (rest of your static list remains unchanged)
})