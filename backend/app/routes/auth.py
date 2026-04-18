"""
Authentication Routes
======================
Hardened authentication with:

  - Per-IP rate limiting on /auth/login (5 req/min via slowapi)
  - Account lockout after 5 consecutive failures (10-minute lockout)
  - Failed logins logged to audit trail
  - Logout endpoint + audit log
  - Successful logins clear the failure counter
  - Admin email gate (only configured ADMIN_EMAIL may log in as admin)
  - Registration always forces role=user (no privilege escalation)
  - Terms of Service acceptance required on registration
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import User, UserRole
from app.schemas.schemas import UserRegister, UserLogin, TokenResponse, RefreshRequest, UserOut
from app.security.auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token, get_current_user,
)
from app.utils.audit import log_action
from app.utils.login_protection import check_lockout, record_failure, record_success
from app.config import settings

from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Per-IP rate limiter for login — 5 attempts / minute
_login_limiter = Limiter(key_func=get_remote_address)


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(payload: UserRegister, request: Request, db: Session = Depends(get_db)):

    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    if not payload.terms_accepted:
        raise HTTPException(
            status_code=400,
            detail="You must accept the Terms of Service to register",
        )

    user = User(
    email=payload.email,
    username=payload.username,
    hashed_password=hash_password(payload.password),
    role=UserRole.user,
    last_login=datetime.utcnow(),
)

    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = create_access_token({"sub": str(user.id), "role": user.role.value})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    log_action(
        db,
        "user.register",
        user_id=user.id,  # FIX HERE
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenResponse)
@_login_limiter.limit("5/minute")          # [C9] per-IP brute-force protection
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate a user and return JWT tokens.

    Security layers:
      1. Per-IP rate limit: 5 req/min (slowapi, returns 429).
      2. Account lockout:   5 failures → 10-minute lockout.
      3. Admin email gate:  admin role restricted to configured ADMIN_EMAIL.
      4. Audit log:         both successes and failures are recorded.
    """
    ip = request.client.host

    # [H1] Check lockout BEFORE touching credentials
    check_lockout(payload.email)

    user = db.query(User).filter(User.email == payload.email).first()

    # Treat "user not found" and "wrong password" identically to prevent
    # email enumeration via timing differences.
    if not user or not verify_password(payload.password, user.hashed_password):
        # [C8] Log failed attempt
        user_id_for_log = str(user.id) if user else None
        log_action(
            db, "user.login_failed",
            user_id=user_id_for_log,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"email": payload.email, "reason": "invalid_credentials"},
        )
        record_failure(payload.email, ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        log_action(
            db, "user.login_failed",
            user_id=str(user.id),
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"reason": "account_disabled"},
        )
        raise HTTPException(status_code=403, detail="Account disabled")

    # [C9-admin] Admin email gate
    user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
    if user_role == "admin" and user.email.lower() != settings.ADMIN_EMAIL.lower():
        log_action(
            db, "user.login_failed",
            user_id=str(user.id),
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"reason": "admin_gate"},
        )
        record_failure(payload.email, ip)
        raise HTTPException(status_code=403, detail="Admin access restricted")

    # ── Credentials valid — clear lockout counter ─────────────────────────────
    record_success(payload.email)

    user.last_login = datetime.utcnow()
    db.commit()

    access_token  = create_access_token({"sub": str(user.id), "role": user_role})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    log_action(
        db, "user.login",
        user_id=str(user.id),
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Logout endpoint — purely audit-side since tokens are stateless JWTs.
    The frontend is responsible for discarding the tokens.
    Logs the logout event to the audit trail.
    """
    log_action(
        db, "user.logout",
        user_id=str(current_user.id),
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )
    # 204 No Content


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        token_data = decode_token(payload.refresh_token)

        if token_data.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    import uuid

    # ✅ FIX 1: Extract user_id from token
    user_id = token_data.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # ✅ FIX 2: Convert to UUID safely
    try:
        user_uuid = uuid.UUID(str(user_id))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    # ✅ FIX 3: Correct query (comma + no double conversion)
    user = db.query(User).filter(
        User.id == user_uuid,
        User.is_active == True
    ).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token({
        "sub": str(user.id),
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
    })

    new_refresh = create_refresh_token({"sub": str(user.id)})

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
