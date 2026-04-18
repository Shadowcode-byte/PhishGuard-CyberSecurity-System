"""
Admin Routes — Enhanced
========================
Full user management + audit logging with:
  - Create / delete users
  - Enable / disable accounts
  - Change roles
  - Reset passwords
  - Search/filter users
  - Enriched audit logs with username resolution
  - Full audit trail for all admin actions
"""

import json
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_
from app.database import get_db
from app.models.models import User, Scan, AuditLog, UserRole
from app.schemas.schemas import (
    AdminStats, AdminUserList, UserOut, RoleUpdate,
    AdminCreateUser, AdminResetPassword,
)
from app.security.auth import require_admin, hash_password
from app.utils.audit import log_action

router = APIRouter(prefix="/admin", tags=["Admin"])


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=AdminStats)
def get_stats(
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    today_start = datetime.combine(datetime.utcnow().date(), datetime.min.time())

    total_users      = db.query(func.count(User.id)).scalar()
    total_scans      = db.query(func.count(Scan.id)).scalar()
    scans_today      = db.query(func.count(Scan.id)).filter(Scan.created_at >= today_start).scalar()
    phishing_detected = db.query(func.count(Scan.id)).filter(Scan.label == "PHISHING").scalar()
    fraud_detected   = db.query(func.count(Scan.id)).filter(Scan.label == "FRAUD").scalar()
    safe_scans       = db.query(func.count(Scan.id)).filter(Scan.label == "SAFE").scalar()
    url_scans        = db.query(func.count(Scan.id)).filter(Scan.scan_type == "url").scalar()
    message_scans    = db.query(func.count(Scan.id)).filter(Scan.scan_type == "message").scalar()
    file_scans       = db.query(func.count(Scan.id)).filter(Scan.scan_type == "file").scalar()

    return AdminStats(
        total_users=total_users,
        total_scans=total_scans,
        scans_today=scans_today,
        phishing_detected=phishing_detected,
        fraud_detected=fraud_detected,
        safe_scans=safe_scans,
        url_scans=url_scans,
        message_scans=message_scans,
        file_scans=file_scans,
    )


# ── User Management ───────────────────────────────────────────────────────────

@router.get("/users", response_model=AdminUserList)
def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: str = Query(None),
    role: str = Query(None),
    is_active: bool = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """List users with optional search, role and status filters."""
    query = db.query(User)

    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(User.username.ilike(term), User.email.ilike(term))
        )
    if role:
        try:
            query = query.filter(User.role == UserRole(role))
        except ValueError:
            pass
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    total = query.count()
    users = (
        query.order_by(desc(User.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return AdminUserList(items=users, total=total)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    request: Request,
    payload: "AdminCreateUser",
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Admin creates a new user account."""
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    try:
        role = UserRole(payload.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")

    new_user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=role,
        is_active=True,
        is_verified=True,
        terms_accepted=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_action(
        db, "admin.user_create",
        user_id=str(current_admin.id),
        resource="user", resource_id=str(new_user.id),
        ip_address=request.client.host,
        details={"username": new_user.username, "email": new_user.email, "role": role.value},
    )
    return new_user


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete a user account. Admins cannot delete themselves."""
    if user_id == str(current_admin.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    log_action(
        db, "admin.user_delete",
        user_id=str(current_admin.id),
        resource="user", resource_id=user_id,
        ip_address=request.client.host,
        details={"username": user.username, "email": user.email},
    )

    db.delete(user)
    db.commit()


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: str,
    request: Request,
    payload: RoleUpdate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role.value if hasattr(user.role, "value") else str(user.role)
    user.role = UserRole(payload.role)
    db.commit()
    db.refresh(user)

    log_action(
        db, "admin.role_change",
        user_id=str(current_admin.id),
        resource="user", resource_id=user_id,
        ip_address=request.client.host,
        details={"username": user.username, "old_role": old_role, "new_role": payload.role},
    )
    return user


@router.patch("/users/{user_id}/toggle")
def toggle_user_active(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    if user_id == str(current_admin.id):
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = not user.is_active
    db.commit()

    log_action(
        db, "admin.user_disable" if not user.is_active else "admin.user_enable",
        user_id=str(current_admin.id),
        resource="user", resource_id=user_id,
        ip_address=request.client.host,
        details={"username": user.username, "is_active": user.is_active},
    )
    return {"is_active": user.is_active}


@router.post("/users/{user_id}/reset-password", status_code=200)
def reset_user_password(
    user_id: str,
    request: Request,
    payload: "AdminResetPassword",
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Admin resets a user's password."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user.hashed_password = hash_password(payload.new_password)
    db.commit()

    log_action(
        db, "admin.password_reset",
        user_id=str(current_admin.id),
        resource="user", resource_id=user_id,
        ip_address=request.client.host,
        details={"username": user.username},
    )
    return {"message": f"Password reset for {user.username}"}


# ── Audit Logs ────────────────────────────────────────────────────────────────

@router.get("/logs")
def get_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    search: str = Query(None),
    action_filter: str = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """
    Paginated audit logs with optional action filter and search.
    Returns enriched entries with username where available.
    """
    query = db.query(AuditLog)

    if action_filter and action_filter != "all":
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AuditLog.action.ilike(term),
                AuditLog.ip_address.ilike(term),
                AuditLog.details.ilike(term),
            )
        )

    total = query.count()
    logs = (
        query.order_by(desc(AuditLog.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    # Build user_id → username lookup for this page
    user_ids = list({str(log.user_id) for log in logs if log.user_id})
    user_map: dict[str, str] = {}
    if user_ids:
        users = db.query(User.id, User.username).filter(
            User.id.in_([uuid.UUID(uid) for uid in user_ids])
        ).all()
        user_map = {str(u.id): u.username for u in users}

    return {
        "items": [
            {
                "id": str(log.id),
                "user_id": str(log.user_id) if log.user_id else None,
                "username": user_map.get(str(log.user_id), "—") if log.user_id else "—",
                "action": log.action,
                "resource": log.resource,
                "resource_id": log.resource_id,
                "ip_address": log.ip_address,
                "details": json.loads(log.details) if log.details else None,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ── Scans ─────────────────────────────────────────────────────────────────────

@router.get("/scans")
def get_all_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    label: str = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(Scan)
    if label:
        query = query.filter(Scan.label == label.upper())

    total = query.count()
    scans = query.order_by(desc(Scan.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "items": [
            {
                "id": str(s.id),
                "user_id": str(s.user_id),
                "scan_type": s.scan_type,
                "input_data": s.input_data[:200],
                "label": s.label,
                "confidence": s.confidence,
                "created_at": s.created_at.isoformat(),
            }
            for s in scans
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    }
