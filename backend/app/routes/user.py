import json
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models.models import User, Scan
from app.schemas.schemas import ScanHistoryResponse, ScanHistoryItem, UserOut, UserUpdate
from app.security.auth import require_user

router = APIRouter(prefix="/user", tags=["User"])


@router.get("/history", response_model=ScanHistoryResponse)
def get_history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_type: str = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user),
):
    """Get paginated scan history for the current user."""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)

    total = query.count()
    scans = (
        query.order_by(desc(Scan.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    items = [
        ScanHistoryItem(
            id=s.id,
            scan_type=s.scan_type,
            input_data=s.input_data[:100] + "..." if len(s.input_data) > 100 else s.input_data,
            label=s.label,
            confidence=s.confidence,
            created_at=s.created_at,
        )
        for s in scans
    ]

    return ScanHistoryResponse(items=items, total=total, page=page, per_page=per_page)


@router.get("/profile", response_model=UserOut)
def get_profile(current_user: User = Depends(require_user)):
    return current_user


@router.get("/stats")
def get_user_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user),
):
    """Get aggregated scan statistics for the current user."""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    
    total = len(scans)
    phishing = sum(1 for s in scans if s.label in ("PHISHING", "FRAUD"))
    suspicious = sum(1 for s in scans if s.label == "SUSPICIOUS")
    safe = sum(1 for s in scans if s.label == "SAFE")
    url_scans = sum(1 for s in scans if s.scan_type == "url")
    message_scans = sum(1 for s in scans if s.scan_type == "message")
    file_scans = sum(1 for s in scans if s.scan_type == "file")

    return {
        "total_scans": total,
        "threats_detected": phishing,
        "suspicious": suspicious,
        "safe": safe,
        "url_scans": url_scans,
        "message_scans": message_scans,
        "file_scans": file_scans,
        "threat_rate": round(phishing / total * 100, 1) if total > 0 else 0.0,
    }
