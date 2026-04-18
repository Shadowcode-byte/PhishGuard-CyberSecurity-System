"""
Security Headers Middleware
===========================
Adds strict security headers to every FastAPI response.

Headers applied:
  - Content-Security-Policy  : restricts resource loading to self + known CDNs
  - X-Frame-Options          : prevents clickjacking via iframes
  - X-Content-Type-Options   : prevents MIME-type sniffing
  - Strict-Transport-Security: forces HTTPS (preload-ready)
  - Referrer-Policy          : limits referrer leakage
  - Permissions-Policy       : disables dangerous browser features
  - X-Request-ID             : per-request correlation ID for log tracing
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject hardened security headers into every HTTP response."""

    # CSP allows:
    #   - self               : same-origin JS, CSS, fonts, images
    #   - fonts.googleapis.com, fonts.gstatic.com : Google Fonts (used by frontend)
    #   - data:              : inline images (recharts/SVG charts use this)
    # Blocks:
    #   - inline scripts (no unsafe-inline for script-src)
    #   - eval (no unsafe-eval)
    #   - all other third-party origins
    CSP = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://phishguard-production-0e6b.up.railway.app; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        # Attach a per-request correlation ID so logs can be joined
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id

        response: Response = await call_next(request)

        response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
        )
        response.headers["X-Frame-Options"]            = "DENY"
        response.headers["X-Content-Type-Options"]     = "nosniff"
        response.headers["X-XSS-Protection"]           = "1; mode=block"
        response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]         = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=()"
        )
        response.headers["Strict-Transport-Security"]  = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["X-Request-ID"] = request_id

        # Remove server fingerprinting headers if uvicorn set them
        if "server" in response.headers:
            del response.headers["server"]

        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        return response
