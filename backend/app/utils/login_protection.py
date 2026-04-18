"""
Login Rate Limiting & Account Lockout
======================================
Provides two independent protections against brute-force attacks:

1. Per-IP rate limiting  — enforced via slowapi on the /auth/login endpoint
   (5 attempts / minute per IP, returns 429).

2. Per-account lockout   — in-process counter, resets after LOCKOUT_WINDOW_SECONDS.
   After MAX_FAILURES consecutive failures the account is locked for
   LOCKOUT_DURATION_SECONDS.  Uses a module-level dict so it works without
   Redis (suitable for single-process deployments like Railway).

   Structure:
     _attempts: { email_lower -> {"count": int, "locked_until": float | None, "first_attempt": float} }

Both mechanisms are independent.  An attacker who rotates IPs is still blocked
by the account lockout.  An attacker who probes many accounts is blocked by
per-IP rate limiting.
"""

import time
import threading
import logging
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
MAX_FAILURES          = 5     # failures before lockout
LOCKOUT_DURATION      = 600   # 10 minutes in seconds
ATTEMPT_WINDOW        = 300   # reset counter if no failures in 5 minutes

# ── State ─────────────────────────────────────────────────────────────────────
_attempts: dict[str, dict] = {}
_lock = threading.Lock()


def _key(email: str) -> str:
    return email.strip().lower()


def check_lockout(email: str) -> None:
    """
    Raise HTTP 429 if the account is currently locked out.
    Call this BEFORE verifying credentials.
    """
    k = _key(email)
    with _lock:
        state = _attempts.get(k)
        if state is None:
            return

        locked_until = state.get("locked_until")
        if locked_until and time.monotonic() < locked_until:
            remaining = int(locked_until - time.monotonic())
            logger.warning(f"Login blocked — account locked: {k} ({remaining}s remaining)")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked due to repeated failures. "
                       f"Try again in {remaining} seconds.",
                headers={"Retry-After": str(remaining)},
            )
        elif locked_until and time.monotonic() >= locked_until:
            # Lockout expired — clear state
            del _attempts[k]


def record_failure(email: str, ip: str) -> None:
    """
    Increment the failure counter for this email.
    Lock the account if MAX_FAILURES is reached.
    Call this AFTER a failed credential check.
    """
    k = _key(email)
    now = time.monotonic()

    with _lock:
        state = _attempts.setdefault(k, {"count": 0, "locked_until": None, "first_attempt": now})

        # Reset counter if last failure was long ago (outside the window)
        if now - state["first_attempt"] > ATTEMPT_WINDOW:
            state["count"] = 0
            state["first_attempt"] = now
            state["locked_until"] = None

        state["count"] += 1
        logger.warning(
            f"Failed login attempt #{state['count']} for {k} from {ip}"
        )

        if state["count"] >= MAX_FAILURES:
            state["locked_until"] = now + LOCKOUT_DURATION
            logger.warning(
                f"Account locked: {k} after {state['count']} failures (10 min lockout)"
            )


def record_success(email: str) -> None:
    """
    Clear failure state on successful login.
    Call this AFTER successful credential verification.
    """
    k = _key(email)
    with _lock:
        _attempts.pop(k, None)


def get_failure_count(email: str) -> int:
    """Return current failure count (for logging/debugging)."""
    k = _key(email)
    with _lock:
        return _attempts.get(k, {}).get("count", 0)
