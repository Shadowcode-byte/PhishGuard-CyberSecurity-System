"""
File Upload & Scanning Service — Enhanced
==========================================
Improvements:
  - Deep content analysis for PDF, DOCX, XLSX, ZIP, TXT, HTML
  - Suspicious extension detection
  - Macro-enabled document detection
  - Embedded URL extraction
  - Suspicious keyword scanning
  - Base64 payload detection
  - Known malicious pattern matching
  - Classification: Safe / Suspicious / Potentially Dangerous

Fixes applied (vs previous version):
  [FIX-1] meta_scan now uses ScanType.file (was ScanType.url)
  [FIX-2] URL label mapping includes SUSPICIOUS (was silently -> SAFE)
  [FIX-3] Confidence derived from AI result / risk-calibrated, not hardcoded
  [FIX-4] Entropy check skipped for inherently high-entropy formats
  [FIX-5] Keyword list split into HIGH / MEDIUM tiers; thresholds raised
  [FIX-6] /URI finding only raised when count > 10 (not every hyperlinked PDF)
  [FIX-7] process_file_scan opens its own DB session (thread-safe)
  [FIX-8] VT file-hash check integrated via virustotal_service.check_file_hash
  [FIX-9] URL/message scan loops moved BEFORE AI call and meta_scan insertion.
          Previously the master Scan record was written before embedded URLs and
          messages were checked, so threats_found > 0 could coexist with a SAFE
          label and 99% confidence on the meta row.  Now risk_level and findings
          are fully updated by the loops before label/confidence are calculated.
  [FIX-10] Embedded URL/message threats now escalate file-level risk_level and
           append a human-readable finding to combined_findings so the cause of
           escalation is visible in the UI.
"""

import os
import re
import uuid
import logging
import json
import math
import zipfile
import io
from datetime import datetime
from pathlib import Path
from uuid import UUID
from fastapi import UploadFile, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.models import FileUpload, Scan, ScanType, ScanLabel
from app.utils.encryption import encrypt_file, decrypt_file
from app.utils.file_validator import validate_file_content, ALLOWED_MIME_TYPES
from app.services import url_service, message_service, ai_service
from app.services import virustotal_service as _vt

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = settings.MAX_FILE_SIZE_MB * 1024 * 1024

# ── Suspicious patterns ───────────────────────────────────────────────────────

# [FIX-5] Split into HIGH and MEDIUM tiers to reduce false positives.
# Generic words like "password", "token", "bank", "login" removed entirely —
# they appear in countless legitimate documents.

HIGH_RISK_KEYWORDS = {
    "credit card", "cvv", "ssn", "social security",
    "wire transfer", "western union", "moneygram",
    "bitcoin", "crypto", "inheritance", "lottery", "winner", "prize",
}

MEDIUM_RISK_KEYWORDS = {
    "verify your account", "suspended", "verify now", "confirm your",
    "click here", "urgent", "paypal",
}

DANGEROUS_EXTENSIONS_IN_ZIP = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".scr", ".com", ".pif", ".reg", ".lnk", ".sh",
}

SUSPICIOUS_HTML_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"unescape\s*\(",
    r"window\.location\s*=",
    r"<iframe[^>]*src",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"onload\s*=",
    r"onerror\s*=",
]

# [FIX-4] File types that are inherently high-entropy — skip entropy check for these.
HIGH_ENTROPY_FORMATS = {".zip", ".docx", ".xlsx", ".jpg", ".jpeg", ".png", ".pdf", ".enc"}

# Regex for URLs
URL_RE = re.compile(r"https?://[^\s\">'<,;)}\\\]]+", re.IGNORECASE)

# Base64 payload detection (long base64 strings > 200 chars)
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
def _extract_clean_messages(text: str, max_messages: int = 50) -> list[str]:
    """Extracts natural language sentences, filtering out base64, hex, and code."""
    messages = []
    raw_lines = re.split(r"[\n.!?]", text)

    for line in raw_lines:
        line = line.strip()
        
        # Rule 1: Reasonable length for a sentence
        if len(line) < 20 or len(line) > 500:
            continue
            
        # Rule 2: Must contain multiple words (spaces check)
        if line.count(" ") < 3:
            continue
            
        # Rule 3: Must be mostly alphabetical characters (filters base64/hex/hashes)
        alpha_count = sum(c.isalpha() for c in line)
        if len(line) > 0 and (alpha_count / len(line)) < 0.65:
            continue
        
        # Rule 4: Exclude lines with excessive structural characters (filters JSON/Code/XML/PowerShell)
        special_chars = sum(c in "{}[];<>=\"\\$#" for c in line)
        if special_chars > 3:
            continue
            
        messages.append(line)
        if len(messages) >= max_messages:
            break
            
    return messages
def is_valid_message(text: str) -> bool:
    if len(text) < 25:
        return False
    if len(text.split()) < 5:
        return False
    if re.match(r"^[0-9\s\W]+$", text):
        return False
    if "code:" in text.lower():
        return False
    return True


def _entropy(data: bytes) -> float:
    """Shannon entropy of byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return ent



def _analyze_content(content: bytes, filename: str) -> dict:
    """
    Deep content analysis. Returns a dict with:
      - urls: list[str]
      - messages: list[str]
      - findings: list[str]  (human-readable threat findings)
      - risk_level: "safe" | "suspicious" | "dangerous"
    """
    findings = []
    urls = []
    messages = []
    ext = Path(filename).suffix.lower()

    text = ""

    # ── PDF extraction ──────────────────────────────────────────────────────
    if content[:4] == b"%PDF" or ext == ".pdf":
        try:
            text = content.decode("latin-1", errors="ignore")
            # Check for JavaScript in PDF
            if "/JavaScript" in text or "/JS " in text:
                findings.append("PDF contains embedded JavaScript — high risk")
            if "/Launch" in text:
                findings.append("PDF contains /Launch action — can execute files")
            if "/OpenAction" in text:
                findings.append("PDF has auto-open action")
            if "/EmbeddedFile" in text:
                findings.append("PDF contains embedded file(s)")
            # [FIX-6] Only flag /URI when count is anomalously high.
            # Every hyperlinked PDF contains /URI; >10 indicates a link-farm doc.
            uri_count = text.count("/URI")
            if uri_count > 10:
                findings.append(f"PDF contains {uri_count} URI objects — unusually high link density")
            # Decode any hex-encoded strings for URL extraction
            hex_decoded = re.sub(
                r"<([0-9a-fA-F]+)>",
                lambda m: bytes.fromhex(m.group(1)).decode("latin-1", errors="ignore"),
                text,
            )
            text = text + " " + hex_decoded
        except Exception as e:
            logger.debug(f"PDF parse error: {e}")

    # ── ZIP / DOCX / XLSX extraction ────────────────────────────────────────
    elif content[:4] == b"PK\x03\x04" or ext in (".zip", ".docx", ".xlsx"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
            names = zf.namelist()

            # Check for dangerous extensions inside ZIP
            for name in names:
                inner_ext = Path(name).suffix.lower()
                if inner_ext in DANGEROUS_EXTENSIONS_IN_ZIP:
                    findings.append(f"ZIP contains executable: {name}")

            # Check for macro files in DOCX/XLSX
            macro_files = [n for n in names if "vbaProject" in n or n.endswith(".bin")]
            if macro_files:
                findings.append(f"Document contains macros (VBA): {', '.join(macro_files)}")

            # Extract text from XML content files
            text_parts = []
            for name in names:
                if name.endswith(".xml") or name.endswith(".rels"):
                    try:
                        raw = zf.read(name).decode("utf-8", errors="ignore")
                        # Strip XML tags for text analysis
                        stripped = re.sub(r"<[^>]+>", " ", raw)
                        text_parts.append(stripped)
                    except Exception:
                        pass
            text = " ".join(text_parts)
        except zipfile.BadZipFile:
            findings.append("File claims to be ZIP/DOCX/XLSX but has invalid ZIP structure")
        except Exception as e:
            logger.debug(f"ZIP/Office parse error: {e}")

    # ── HTML analysis ────────────────────────────────────────────────────────
    elif ext in (".html", ".htm") or b"<html" in content[:100].lower():
        text = content.decode("utf-8", errors="ignore")
        for pattern in SUSPICIOUS_HTML_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(f"Suspicious HTML pattern: {pattern}")

    # ── Plain text / CSV / JSON ──────────────────────────────────────────────
    else:
        text = content.decode("utf-8", errors="ignore")

    # ── Universal checks on extracted text ──────────────────────────────────

    # URL extraction
    urls = list(set(URL_RE.findall(text)))

    # Sentence extraction
    # URL extraction
    urls = list(set(URL_RE.findall(text)))

    # Clean Sentence extraction (Replaced old noisy logic)
    messages = _extract_clean_messages(text)

    # [FIX-5] Tiered keyword scan — reduces false positives on legitimate docs.
    text_lower = text.lower()
    high_hits   = [kw for kw in HIGH_RISK_KEYWORDS   if kw in text_lower]
    medium_hits = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in text_lower]

    if high_hits:
        findings.append(f"High-risk keywords found: {', '.join(high_hits)}")
    elif len(medium_hits) >= 3:
        findings.append(f"Multiple phishing-pattern keywords: {', '.join(medium_hits[:5])}")

    # Base64 payload detection
    b64_matches = BASE64_RE.findall(text)
    if len(b64_matches) > 2:
        findings.append(f"Multiple large base64-encoded payloads detected ({len(b64_matches)} found)")
    elif b64_matches:
        findings.append("Base64-encoded payload detected in content")

    # [FIX-4] High entropy detection — skip inherently compressed/encrypted formats.
    if ext not in HIGH_ENTROPY_FORMATS:
        sample = content[:4096]
        ent = _entropy(sample)
        if ent > 7.2:
            findings.append(f"High entropy content ({ent:.2f}/8.0) — possible encryption/obfuscation")

    # Determine risk level
    dangerous_keywords = ["contains executable", "contains macros", "JavaScript", "/Launch", "BadZipFile"]
    if any(any(dk in f for dk in dangerous_keywords) for f in findings):
        risk_level = "dangerous"
    elif findings:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return {
        "urls": urls,
        "messages": messages,
        "findings": findings,
        "risk_level": risk_level,
    }


async def save_encrypted_file(
    file: UploadFile,
    user_id: str,
    db: Session,
) -> tuple[FileUpload, str]:
    """
    Validate, encrypt, and store uploaded file.
    Returns (FileUpload DB record, sha256_hex).
    """
    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {settings.MAX_FILE_SIZE_MB}MB",
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    sha256, detected_type = validate_file_content(
        content=content,
        declared_mime=file.content_type or "application/octet-stream",
        filename=file.filename or "unknown",
    )

    encrypted_data, iv_hex = encrypt_file(content)

    upload_dir = Path(settings.UPLOAD_DIR)
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        logger.error(
            "Cannot create upload directory '%s': %s. "
            "Set UPLOAD_DIR to a writable path in your .env file.",
            upload_dir, exc,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                f"Server misconfiguration: upload directory '{upload_dir}' "
                "is not writable. Contact your administrator."
            ),
        )

    stored_filename = f"{uuid.uuid4()}.enc"
    stored_path = upload_dir / stored_filename

    try:
        with open(stored_path, "wb") as f:
            f.write(encrypted_data)
    except OSError as exc:
        logger.error("Failed to write encrypted file to '%s': %s", stored_path, exc)
        raise HTTPException(
            status_code=500,
            detail="Server error: could not store uploaded file.",
        )

    record = FileUpload(
        user_id=UUID(user_id),
        original_filename=file.filename or "unknown",
        stored_filename=stored_filename,
        file_size=len(content),
        mime_type=file.content_type or "application/octet-stream",
        encryption_iv=iv_hex,
        scan_status="pending",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return record, sha256


def process_file_scan(file_id: str, user_id: str) -> None:
    """
    Background task: decrypt file, deep-analyze, scan URLs and messages.
    """
    db: Session = SessionLocal()
    user_uuid = UUID(user_id)

    try:
        file_record = db.query(FileUpload).filter(FileUpload.id == UUID(file_id)).first()
        if not file_record:
            return

        # --- Helper function to update progress ---
        def update_progress(p: int, msg: str):
            file_record.progress = p
            file_record.status_message = msg
            db.commit()

        file_record.scan_status = "processing"
        update_progress(5, "Decrypting AES-256 file...")

        stored_path = Path(settings.UPLOAD_DIR) / file_record.stored_filename
        with open(stored_path, "rb") as f:
            encrypted = f.read()
        content = decrypt_file(encrypted, file_record.encryption_iv)

        update_progress(10, "Checking file hash against VirusTotal...")
        import hashlib
        sha256 = hashlib.sha256(content).hexdigest()

        vt_file_result = None
        try:
            import asyncio
            vt_file_result = asyncio.run(_vt.check_file_hash(sha256))
        except Exception as vt_exc:
            logger.warning("VT file hash check skipped: %s", vt_exc)

        update_progress(25, "Deep content extraction & analysis...")
        analysis = _analyze_content(content, file_record.original_filename)
        urls      = analysis["urls"]
        messages  = analysis["messages"]
        findings  = analysis["findings"]
        risk_level = analysis["risk_level"]

        if vt_file_result and vt_file_result.get("verdict") == "malicious":
            risk_level = "dangerous"
            findings.insert(0, (
                f"VirusTotal: file hash flagged malicious by "
                f"{vt_file_result['malicious']} engine(s)"
            ))

        # [FIX-9] threats counter, URL loop, and message loop moved UP — before
        # the AI call and meta_scan insertion.  Previously these loops ran after
        # meta_scan was already committed, so:
        #   • threats found inside embedded URLs/messages never raised risk_level
        #   • meta_scan.label could be SAFE while threats_found > 0
        #   • meta_scan.confidence was calibrated without embedded-threat data
        # Now the master record is written last, inheriting the full picture.

        threats = 0

        # ── Scan embedded URLs ───────────────────────────────────────────────
        total_urls = len(urls[:100])
        url_label_map = {"PHISHING": ScanLabel.phishing, "SUSPICIOUS": ScanLabel.suspicious}

        for i, url in enumerate(urls[:100]):
            update_progress(
                30 + int((i / max(total_urls, 1)) * 20),
                f"Scanning embedded URL {i+1} of {total_urls}...",
            )
            try:
                result = url_service.scan_url(url)
                l = url_label_map.get(result["label"], ScanLabel.safe)
                if l in (ScanLabel.phishing, ScanLabel.suspicious):
                    threats += 1
                    # Escalate overall file risk level so meta_scan inherits it
                    if l == ScanLabel.phishing:
                        risk_level = "dangerous"
                        findings.append(f"Embedded URL flagged as malicious: {url[:200]}")
                    elif risk_level == "safe":
                        risk_level = "suspicious"
                        findings.append(f"Embedded URL flagged as suspicious: {url[:200]}")
                db.add(Scan(
                    user_id=user_uuid, scan_type=ScanType.url, input_data=url[:2048],
                    label=l, confidence=result.get("confidence", 0.0),
                    reasons=json.dumps(result.get("reasons", [])),
                    detection_mode=result.get("detection_mode"),
                ))
            except Exception:
                pass

        # ── Scan extracted messages ──────────────────────────────────────────
        total_msgs = len(messages)
        msg_label_map = {"FRAUD": ScanLabel.fraud, "SUSPICIOUS": ScanLabel.suspicious, "SAFE": ScanLabel.safe}

        for i, msg in enumerate(messages):
            update_progress(
                50 + int((i / max(total_msgs, 1)) * 20),
                f"Analyzing extracted message {i+1} of {total_msgs}...",
            )
            try:
                result = message_service.scan_message(msg)
                l = msg_label_map.get(result.get("final_label", "SAFE"), ScanLabel.safe)
                if l in (ScanLabel.fraud, ScanLabel.suspicious):
                    threats += 1
                    # Escalate overall file risk level so meta_scan inherits it
                    if l == ScanLabel.fraud and risk_level == "safe":
                        risk_level = "suspicious"
                        findings.append(f"Extracted message flagged as fraudulent: {msg[:120]}...")
                    elif l == ScanLabel.suspicious and risk_level == "safe":
                        risk_level = "suspicious"
                        findings.append(f"Extracted message flagged as suspicious: {msg[:120]}...")
                db.add(Scan(
                    user_id=user_uuid, scan_type=ScanType.message, input_data=msg[:5000],
                    label=l, confidence=result.get("final_score", 0.0),
                    reasons=json.dumps(result.get("reasons", [])),
                    rule_score=result.get("rule_score"),
                    final_score=result.get("final_score"),
                    language=result.get("language"),
                ))
            except Exception:
                pass

        # ── AI analysis — now has full threat picture from URL/message scans ─
        update_progress(72, "Running AI threat analysis on contents...")
        ai_file_result = None
        try:
            if findings or risk_level in ("suspicious", "dangerous"):
                context_parts = [f"Filename: {file_record.original_filename}"]
                if findings:
                    context_parts.append("Findings:\n" + "\n".join(f"- {f}" for f in findings))
                if messages:
                    sample = " ".join(messages[:5])[:1500]
                    context_parts.append(f"Extracted text sample:\n{sample}")
                ai_context = "\n\n".join(context_parts)
                ai_file_result = ai_service.explain_threat_sync(ai_context)
        except Exception as ai_exc:
            logger.warning("Gemini file analysis skipped: %s", ai_exc)

        # ── Write master meta_scan — label/confidence now reflect everything ─
        ai_conf = float(ai_file_result["confidence"]) if ai_file_result and isinstance(ai_file_result.get("confidence"), (int, float)) else None
        meta_confidence = round(min(ai_conf, 1.0), 4) if ai_conf is not None else (0.85 if risk_level == "dangerous" else 0.55 if risk_level == "suspicious" else 0.99)
        label = ScanLabel.phishing if risk_level == "dangerous" else ScanLabel.suspicious if risk_level == "suspicious" else ScanLabel.safe

        # Count the file-level label itself as a threat if non-safe
        if label in (ScanLabel.phishing, ScanLabel.suspicious):
            threats += 1

        combined_findings = list(findings)
        if not combined_findings and label == ScanLabel.safe:
            combined_findings.append("File is clean: No suspicious content, macros, or dangerous URLs detected.")
        if ai_file_result:
            combined_findings.append(f"[AI] {ai_file_result.get('summary', '')} (threat_level={ai_file_result.get('threat_level', 'unknown')})")

        meta_scan = Scan(
            user_id=user_uuid, scan_type=ScanType.file,
            input_data=f"[FILE ANALYSIS] {file_record.original_filename}",
            label=label, confidence=meta_confidence,
            reasons=json.dumps(combined_findings),
            detection_mode="file_deep_analysis+ai" if ai_file_result else "file_deep_analysis",
        )
        db.add(meta_scan)

        # Finish up
        update_progress(100, "Scan complete.")
        file_record.urls_found = len(urls)
        file_record.messages_found = len(messages)
        file_record.threats_found = threats
        file_record.scan_status = "done"
        file_record.scanned_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        logger.error(f"File scan failed for {file_id}: {e}")
        try:
            file_record = db.query(FileUpload).filter(FileUpload.id == UUID(file_id)).first()
            if file_record:
                file_record.scan_status = "error"
                file_record.status_message = "Scan failed due to an internal error."
                db.commit()
        except Exception:
            pass
    finally:
        db.close()