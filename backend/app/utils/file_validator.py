"""
File Upload Validator — Enhanced
==================================
Two-layer validation + broad file type support.

Supported types:
  - text/plain (.txt), text/html (.html), application/pdf (.pdf)
  - .docx, .xlsx (OOXML), .zip, .csv, .json, .eml, .xml
"""

import hashlib
import logging
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# ── Allowed MIME types ────────────────────────────────────────────────────────
ALLOWED_MIME_TYPES = frozenset({
    "text/plain",
    "text/html",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
    "message/rfc822",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",  # fallback for browsers sending docx/xlsx
})

# ── Magic bytes map ────────────────────────────────────────────────────────────
# (magic_bytes, description, allowed)
_MAGIC_BLOCKS: list[tuple[bytes, str, bool]] = [
    # Executables — always rejected
    (b"MZ",                   "PE executable (EXE/DLL)",           False),
    (b"\x7fELF",              "ELF executable",                     False),
    (b"\xca\xfe\xba\xbe",    "Mach-O executable",                  False),
    (b"\xfe\xed\xfa\xce",    "Mach-O executable",                  False),
    (b"\xfe\xed\xfa\xcf",    "Mach-O 64-bit executable",           False),
    (b"#!/",                  "Shell script",                       False),
    (b"#!",                   "Script file",                        False),
    (b"%!PS",                 "PostScript",                         False),
    # Dangerous archives
    (b"\x1f\x8b",            "Gzip archive",                       False),
    (b"BZh",                  "Bzip2 archive",                      False),
    (b"\xfd7zXZ\x00",        "XZ archive",                         False),
    (b"Rar!",                 "RAR archive",                        False),
    (b"7z\xbc\xaf",          "7-Zip archive",                      False),
    # Legacy OLE2 Office (.doc/.xls with macro risk) — reject
    (b"\xd0\xcf\x11\xe0",   "MS Office legacy OLE2 (macro risk)", False),
    # Allowed: PDF
    (b"%PDF",                 "PDF document",                       True),
    # Allowed: ZIP / OOXML (.docx and .xlsx are ZIP internally)
    (b"PK\x03\x04",          "ZIP/OOXML (DOCX/XLSX/ZIP)",          True),
    (b"PK\x05\x06",          "ZIP archive (empty)",                True),
    # Allowed: UTF-8 BOM text
    (b"\xef\xbb\xbf",        "UTF-8 BOM text",                     True),
]

KNOWN_MALICIOUS_HASHES: frozenset[str] = frozenset()


def compute_sha256(content: bytes) -> str:
    """Return lowercase hex SHA-256 digest of file content."""
    return hashlib.sha256(content).hexdigest()


def validate_file_content(
    content: bytes,
    declared_mime: str,
    filename: str,
) -> tuple[str, str]:
    """
    Validate file content via MIME type and magic bytes.

    Returns:
        Tuple of (sha256_hex, detected_type_description)

    Raises:
        HTTPException(400) if file type is disallowed.
    """
    # Normalise: strip charset and boundary params
    base_mime = declared_mime.split(";")[0].strip().lower()

    if base_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"File type '{base_mime}' is not permitted. "
                "Allowed formats: PDF, DOCX, XLSX, ZIP, TXT, HTML, CSV, JSON, EML."
            ),
        )

    # Magic bytes check
    header = content[:16]
    for magic, description, allowed in _MAGIC_BLOCKS:
        if header.startswith(magic):
            if not allowed:
                logger.warning(f"Rejected '{filename}' — magic bytes: {description}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File content rejected: detected {description}.",
                )
            break

    sha256 = compute_sha256(content)
    if sha256 in KNOWN_MALICIOUS_HASHES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File matches a known malicious signature.",
        )

    detected = "text/unknown"
    for magic, description, _ in _MAGIC_BLOCKS:
        if header.startswith(magic):
            detected = description
            break

    logger.info(f"File '{filename}' passed validation — SHA-256: {sha256[:12]}...")
    return sha256, detected
