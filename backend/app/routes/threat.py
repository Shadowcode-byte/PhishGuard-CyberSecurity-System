"""
Threat & Network Detection Routes
===================================
Endpoint map:

  POST /threat/analyze        — Single-domain threat analysis (unchanged)
  GET  /threat/network-scan   — Full local-network device discovery (NEW/FIXED)

Removed from original:
  GET  /threat/live           — Deleted per spec (replaced by network scanner)
  GET  /threat/io             — Deleted (was only used by the live threat page)

The network-scan endpoint calls network_scanner.scan() which tries four
strategies in order (ARP → kernel cache → TCP probe → self-only) and always
returns a structured response with scan_mode, error_type, and instructions.
The frontend reads these fields to decide which UI state to render.
"""

import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import HTTPException

from app.database import get_db
from app.models.models import User
from app.security.auth import require_user
from app.services.threat_service import analyze_domain
from app.services.network_scanner import scan as network_scan

from slowapi import Limiter


def _user_id_key(request: Request) -> str:
    user: User = getattr(request.state, "rate_limit_user", None)
    if user is not None:
        return f"user:{user.id}"
    return request.client.host or "unknown"


threat_limiter = Limiter(key_func=_user_id_key)
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat", tags=["Threat Detection"])


def _inject_user(
    request: Request,
    current_user: User = Depends(require_user),
) -> User:
    request.state.rate_limit_user = current_user
    return current_user


# ── Domain threat analysis (unchanged from original) ─────────────────────────

@router.post("/analyze")
@threat_limiter.limit("20/minute")
async def analyze_single_domain(
    request: Request,
    payload: dict,
    current_user: User = Depends(_inject_user),
):
    """Analyze a specific domain or IP for threat indicators."""
    domain = payload.get("domain", "").strip()
    port   = payload.get("port")
    ip     = payload.get("ip")
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")
    return analyze_domain(domain, port, ip)


# ── Network scanner ───────────────────────────────────────────────────────────

@router.get("/network-scan")
@threat_limiter.limit("6/minute")
async def run_network_scan(
    request: Request,
    current_user: User = Depends(_inject_user),
):
    """
    Discover devices on the local network.

    Tries four strategies in order:
      1. Raw ARP broadcast  — full MAC+IP, root + broadcast iface required
      2. Kernel ARP cache   — /proc/net/arp, instant, no root
      3. TCP connect probe  — port-based, no root, no MACs
      4. Interface self     — always works, reports this machine only

    The response always includes:
      scan_mode           one of: arp_full | arp_kernel | tcp_probe |
                          self_only | container | error
      error_type          None or a machine-readable reason string
      permission_required bool — whether sudo would unlock more features
      instructions        user-readable next steps (shown in the UI)
    """
    try:
        result = network_scan()
        return result
    except Exception as e:
        logger.error(f"[network-scan] unexpected error: {e}", exc_info=True)
        return {
            "devices":              [],
            "total":                0,
            "scan_mode":            "error",
            "error_type":           "internal_error",
            "scanned_subnet":       None,
            "interface":            None,
            "total_hosts_probed":   0,
            "duration_seconds":     0.0,
            "scanned_at":           datetime.utcnow().isoformat() + "Z",
            "permission_required":  True,
            "instructions": (
                f"The scanner encountered an unexpected error: {e}\n\n"
                "Try running the backend with elevated privileges:\n\n"
                "  sudo uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
            ),
        }
