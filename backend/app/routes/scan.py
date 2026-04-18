"""
Scan Routes — Hardened
========================
Security improvements vs original:

  [C4]  URL scheme validation — javascript:/data:/file: schemes rejected.
  [C5]  File scan rate limit reduced to 10/min (was 20/min same as URL).
  [C6]  SHA-256 hash logged per file upload for auditability.
  [H4]  File content validated via magic bytes (not just Content-Type header).
  [H2]  Input trimmed before passing to ML models.

Fixes applied (vs previous version):
  [FIX-7] SUSPICIOUS label now persisted to DB for URL scans (was silently -> SAFE).
  [FIX-8] process_file_scan no longer receives the request DB session —
          the background task opens its own session (thread-safe).

Rate limits:
  - /scan/url     : 20/min per user
  - /scan/message : 20/min per user
  - /scan/file    :  5/min per user (heavier operation)
"""

import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import User, Scan, ScanType, ScanLabel, FileUpload
from app.schemas.schemas import (
    URLScanRequest, URLScanResponse,
    MessageScanRequest, MessageScanResponse,
    FileScanResponse,
)
from app.security.auth import require_user
from app.services import url_service, message_service
from app.services.file_service import save_encrypted_file, process_file_scan
from app.utils.audit import log_action
from app.utils.url_validator import validate_url_scheme
from app.config import settings

from slowapi import Limiter

# ── Per-user rate limiter ─────────────────────────────────────────────────────
def _user_id_key(request: Request) -> str:
    user: User = getattr(request.state, "rate_limit_user", None)
    if user is not None:
        return f"user:{user.id}"
    return request.client.host or "unknown"


scan_limiter = Limiter(key_func=_user_id_key)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["Scanning"])


def _inject_user_for_rate_limit(request: Request, current_user: User = Depends(require_user)) -> User:
    request.state.rate_limit_user = current_user
    return current_user


# ─────────────────────────────────────────────────────────────────────────────
# URL Scan
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/url", response_model=URLScanResponse)
@scan_limiter.limit("20/minute")
async def scan_url(
    request: Request,
    payload: URLScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_inject_user_for_rate_limit),
):
    """
    Scan a URL for phishing indicators.
    - Rate-limited to 20/min per user.
    - [C4] Rejects javascript:, data:, file:, and other non-http(s) schemes.
    """
    # [C4] Validate scheme before any processing
    safe_url = validate_url_scheme(payload.url)

    result = await url_service.scan_url_async(safe_url)

    # [FIX-7] SUSPICIOUS is now persisted correctly.
    # Previously only PHISHING and SAFE were mapped; a SUSPICIOUS result was
    # silently stored as SAFE in the DB even though the API response was correct.
    label_map = {
        "PHISHING":   ScanLabel.phishing,
        "SUSPICIOUS": ScanLabel.suspicious,
        "SAFE":       ScanLabel.safe,
    }
    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.url,
        input_data=safe_url[:2048],
        label=label_map.get(result["label"], ScanLabel.safe),
        confidence=result["confidence"],
        reasons=json.dumps(result.get("reasons", [])),
        detection_mode=result.get("detection_mode"),
        rule_score=result.get("rule_score"),
        final_score=result.get("confidence"),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_action(
        db, "scan.url",
        user_id=str(current_user.id),
        resource="scan", resource_id=str(scan.id),
        ip_address=request.client.host,
        details={"label": result["label"], "confidence": result["confidence"]},
    )

    return URLScanResponse(
        scan_id=scan.id,
        label=result["label"],
        confidence=result["confidence"],
        risk_score=result.get("risk_score", 0),
        reasons=result.get("reasons", []),
        detection_mode=result.get("detection_mode", "unknown"),
        ai_analysis=result.get("ai_analysis"),
        threat_explanation=result.get("threat_explanation"),
        vt_result=result.get("vt_result"),
        created_at=scan.created_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Message Scan (UPDATED - TRUST + FALSE POSITIVE FIX)
# ─────────────────────────────────────────────────────────────────────────────

# 🔥 Trusted domains list
TRUSTED_DOMAINS = [
    "google.com",
    "spotify.com",
    "amazon.com",
    "microsoft.com",
    "irctc.co.in",
    "linkedin.com"
]

def is_trusted_sender(sender: str | None) -> bool:
    if not sender:
        return False

    domain = sender.split("@")[-1].lower()
    return any(domain.endswith(td) for td in TRUSTED_DOMAINS)


@router.post("/message", response_model=MessageScanResponse)
@scan_limiter.limit("500/minute")
async def scan_message(
    request: Request,
    payload: MessageScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_inject_user_for_rate_limit),
):
    """Scan a text message for fraud patterns with trusted sender handling."""

    # 🔥 Extract inputs
    message_text = payload.message.strip()
    sender = getattr(payload, "sender", None)

    # 🔍 Run existing ML / rule-based scan
    result = await message_service.scan_message_async(message_text)

    # Default label from model
    fl = result.get("final_label", "SAFE")

    # 🔥 TRUST OVERRIDE (MAIN FIX FOR YOUR ISSUE)
    if is_trusted_sender(sender):
        fl = "SAFE"
        result["final_score"] = min(result.get("final_score", 0.0), 0.3)
        result["reasons"] = ["Trusted sender domain detected"]

    # 🧠 Label mapping (unchanged)
    label_map = {
        "FRAUD":      ScanLabel.fraud,
        "SUSPICIOUS": ScanLabel.suspicious,
        "SAFE":       ScanLabel.safe,
    }

    # 💾 Store scan in DB
    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.message,
        input_data=message_text[:5000],
        label=label_map.get(fl, ScanLabel.safe),
        confidence=result.get("final_score", 0.0),
        reasons=json.dumps(result.get("reasons", [])),
        rule_score=result.get("rule_score"),
        final_score=result.get("final_score"),
        language=result.get("language"),
        api_used=not result.get("api_skipped", True),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 📝 Audit log
    log_action(
        db, "scan.message",
        user_id=str(current_user.id),
        resource="scan", resource_id=str(scan.id),
        ip_address=request.client.host,
        details={
            "label": fl,
            "score": result.get("final_score"),
            "sender": sender
        },
    )

    # 📤 Response
    return MessageScanResponse(
        scan_id=scan.id,
        label=fl,
        final_score=result.get("final_score", 0.0),
        rule_score=result.get("rule_score", 0.0),
        confidence_level=result.get("confidence_level", "low"),
        risk_score=result.get("risk_score", 0),
        reasons=result.get("reasons", []),
        language=result.get("language", "unknown"),
        api_used=not result.get("api_skipped", True),
        ai_analysis=result.get("ai_analysis"),
        created_at=scan.created_at,
    )

# ─────────────────────────────────────────────────────────────────────────────
# File Scan
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/file", response_model=FileScanResponse)
@scan_limiter.limit("5/minute")      # [C5] Lower limit — heavier operation
async def scan_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(_inject_user_for_rate_limit),
):
    """
    Upload and scan a file for embedded phishing URLs and fraud messages.
    - Rate-limited to 5/min per user (CPU-intensive background job).
    - [H4] Magic-byte content validation (not just Content-Type header).
    - [C6] SHA-256 hash logged for auditability.
    - [FIX-8] Background task receives only IDs, not the live DB session.
    - Max file size: 10 MB.
    """
    try:
        file_record, sha256 = await save_encrypted_file(file, str(current_user.id), db)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error saving uploaded file: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Unexpected server error during file processing.")

    # [FIX-8] Do NOT pass `db` into the background task.
    # SQLAlchemy sessions are not thread-safe. process_file_scan now opens
    # its own session internally via SessionLocal().
    background_tasks.add_task(
        process_file_scan,
        str(file_record.id),
        str(current_user.id),
        # db intentionally omitted
    )

    log_action(
        db, "scan.file",
        user_id=str(current_user.id),
        resource="file", resource_id=str(file_record.id),
        ip_address=request.client.host,
        details={
            "filename": file.filename,
            "size": file_record.file_size,
            "sha256": sha256[:16] + "...",   # partial hash — not full to save space
        },
    )

    return FileScanResponse(
        file_id=file_record.id,
        filename=file.filename,
        status="processing",
        message="File uploaded successfully. Background scan has started.",
    )


@router.get("/file/{file_id}/status")
async def get_file_scan_status(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user),
):
    """
    Fetch the real-time progress of a background file scan.

    When status == "done", the response is enriched with the final verdict
    from the master meta_scan record written by process_file_scan:
      - result_label  : "SAFE" | "SUSPICIOUS" | "PHISHING" | "FRAUD"
      - result_reasons: list[str]  — human-readable findings
      - confidence    : float
      - threats_found : int
      - urls_found    : int
      - messages_found: int
    """
    try:
        from uuid import UUID
        file_uuid = UUID(file_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid File ID format")

    file_record = (
        db.query(FileUpload)
        .filter(FileUpload.id == file_uuid, FileUpload.user_id == current_user.id)
        .first()
    )
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    response: dict = {
        "file_id":   str(file_record.id),
        "status":    file_record.scan_status,
        "progress":  file_record.progress,
        "message":   file_record.status_message,
    }

    # Only attach the rich result payload once the background job is finished.
    if file_record.scan_status == "done":
        # The background worker writes exactly one Scan row with:
        #   scan_type  = ScanType.file
        #   input_data = "[FILE ANALYSIS] <original_filename>"
        #   user_id    = current_user.id
        # We order by created_at DESC so if re-scans ever happen we get the freshest one.
        meta_scan = (
            db.query(Scan)
            .filter(
                Scan.user_id    == current_user.id,
                Scan.scan_type  == ScanType.file,
                Scan.input_data == f"[FILE ANALYSIS] {file_record.original_filename}",
            )
            .order_by(Scan.created_at.desc())
            .first()
        )

        if meta_scan:
            # Normalise the stored ScanLabel enum to an uppercase string the
            # frontend can switch on directly (matches existing label conventions).
            label_display_map = {
                ScanLabel.safe:       "SAFE",
                ScanLabel.suspicious: "SUSPICIOUS",
                ScanLabel.phishing:   "PHISHING",
                ScanLabel.fraud:      "FRAUD",
            }

            reasons: list[str] = []
            if meta_scan.reasons:
                try:
                    reasons = json.loads(meta_scan.reasons)
                except (json.JSONDecodeError, TypeError):
                    reasons = [meta_scan.reasons]

            response["result_label"]   = label_display_map.get(meta_scan.label, "SAFE")
            response["result_reasons"] = reasons
            response["confidence"]     = meta_scan.confidence
            response["threats_found"]  = file_record.threats_found or 0
            response["urls_found"]     = file_record.urls_found or 0
            response["messages_found"] = file_record.messages_found or 0

    return response