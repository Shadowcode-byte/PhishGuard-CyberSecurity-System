"""
URL Scheme Validator
====================
Rejects dangerous URI schemes before any scanning occurs.

Allowed:  http, https
Rejected: javascript, data, file, ftp, vbscript, blob, about, and anything else

Also validates:
- URL is not empty / whitespace
- URL does not start with encoded variants of dangerous schemes
  (e.g. %6Aavascript: or java\x00script:)
"""

import re
import urllib.parse
import logging
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# Allowed schemes
ALLOWED_SCHEMES = {"http", "https"}

# Suspicious scheme patterns (match after url-decoding and removing whitespace/nulls)
_DANGEROUS_SCHEME_RE = re.compile(
    r"^[\s\x00-\x1f\x7f]*"       # strip leading control chars / whitespace
    r"(javascript|vbscript|data|file|blob|about|ftp|ftps|sftp|chrome|moz-extension)"
    r"[\s\x00-\x1f\x7f]*:",       # colon (possibly with whitespace/nulls injected)
    re.IGNORECASE,
)


def validate_url_scheme(url: str) -> str:
    """
    Validate that a URL uses an allowed scheme.
    Returns the cleaned URL string or raises HTTP 400.

    Args:
        url: The raw URL string from user input.

    Returns:
        The stripped URL string.

    Raises:
        HTTPException(400): If the scheme is not allowed.
    """
    if not url or not url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty.",
        )

    cleaned = url.strip()

    # Check for dangerous schemes (before and after URL-decoding)
    for candidate in [cleaned, urllib.parse.unquote(cleaned)]:
        if _DANGEROUS_SCHEME_RE.match(candidate):
            logger.warning(f"Rejected dangerous URL scheme: {cleaned[:80]}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL scheme not permitted. Only http:// and https:// URLs are accepted.",
            )

    # Parse and validate scheme
    try:
        parsed = urllib.parse.urlparse(cleaned)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format.",
        )

    scheme = parsed.scheme.lower()
    if not scheme:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must include a scheme (http:// or https://).",
        )

    if scheme not in ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL scheme '{scheme}' is not allowed. Use http or https.",
        )

    return cleaned
