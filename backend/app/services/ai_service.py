"""
AI Threat Analysis Service — PhishGuard
=========================================
Provides two AI-powered analysis functions layered on top of the existing
rule-based + ML pipeline:

  analyze_text_fast(text)   — Groq / llama3-70b-8192
      Fast text classification for SMS messages, phishing emails, and
      social-engineering language detection.

  explain_threat(context)   — Gemini / gemini-1.5-flash
      Deep reasoning and human-readable explanations for suspicious domains,
      phishing messages, and extracted file content.

Design principles
-----------------
- Keys are read exclusively from app.config.settings — never hardcoded.
- If a key is missing or the API call fails, analysis is silently skipped
  and the caller receives None so rule-based + ML results are returned as-is.
- Every call enforces AI_TIMEOUT_SECONDS and MAX_OUTPUT_TOKENS to protect
  against runaway responses that would slow scans or exhaust free-tier quotas.
- All errors are caught and logged; they never propagate to callers.
"""


import json
import logging
import asyncio
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── Model identifiers ─────────────────────────────────────────────────────────
GROQ_MODEL   = "llama-3.3-70b-versatile"
GEMINI_MODEL = getattr(settings, "GEMINI_MODEL", "gemini-2.0-flash")

# ── Global safety limits (applied to every AI request) ───────────────────────
# MAX_OUTPUT_TOKENS caps the response size for both Groq and Gemini.
# Keeping this at 200 is intentional: our structured JSON responses
# (risk/confidence/reasons or summary/threat_level/explanation) fit
# comfortably within 200 tokens, while preventing the model from producing
# verbose prose that would slow responses and consume free-tier quota.
MAX_OUTPUT_TOKENS: int = 200

# AI_TIMEOUT_SECONDS is the wall-clock deadline for every outbound AI call.
# Applied to the httpx.AsyncClient for HTTP and to ThreadPoolExecutor.submit
# in the sync wrappers so background tasks are never left hanging.
AI_TIMEOUT_SECONDS: float = 10.0

# ── API endpoints ─────────────────────────────────────────────────────────────
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _groq_available() -> bool:
    """Return True only when a Groq key is configured."""
    return bool(getattr(settings, "GROQ_API_KEY", None))


def _gemini_available() -> bool:
    """Return True only when a Gemini key is configured."""
    return bool(getattr(settings, "GEMINI_API_KEY", None))


def _parse_json_response(raw: str) -> Optional[dict]:
    """
    Safely parse a JSON string that may be wrapped in markdown fences.
    Returns None on any parse failure.
    """
    # Strip optional ```json ... ``` fences
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first and last fence lines
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Groq — fast text classification
# ─────────────────────────────────────────────────────────────────────────────

_GROQ_SYSTEM_PROMPT = """You are an expert cybersecurity analyst specialising in phishing,
fraud, and social-engineering detection. Analyse the supplied text and return ONLY a
JSON object — no markdown, no extra text — with exactly these fields:

  "risk"       : "high" | "medium" | "low"
  "confidence" : float between 0.0 and 1.0
  "reasons"    : array of 1–5 short strings, each describing one threat indicator

Risk guidelines:
  high   — clear phishing / fraud intent (credential harvesting, OTP demands,
            account-threat language, prize scams, malicious links, impersonation)
  medium — suspicious but ambiguous (urgency without clear malicious intent,
            unusual sender patterns, brand mention without obvious credential request)
  low    — no threat indicators detected

Examples of reasons: "Credential harvesting language", "Urgency manipulation",
"Suspicious link indicators", "Brand impersonation", "OTP/PIN request".

Return ONLY the JSON object."""


async def analyze_text_fast(text: str) -> Optional[dict]:
    """
    Use Groq (llama3-70b-8192) for fast phishing / social-engineering
    classification of a text message or email body.

    Returns:
        {
            "risk":       "high" | "medium" | "low",
            "confidence": float,
            "reasons":    list[str]
        }
        or None if Groq is unavailable or the call fails.
    """
    if not _groq_available():
        logger.debug("Groq API key not configured — skipping fast AI analysis")
        return None

    # Truncate to keep within context limits and reduce latency
    truncated = text[:3000] if len(text) > 3000 else text

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": _GROQ_SYSTEM_PROMPT},
            {"role": "user",   "content": f"Text to analyse:\n\n{truncated}"},
        ],
        "temperature": 0.2,
        "max_tokens":  MAX_OUTPUT_TOKENS,
    }

    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=AI_TIMEOUT_SECONDS) as client:
            response = await client.post(GROQ_URL, json=payload, headers=headers)
            response.raise_for_status()

        data        = response.json()
        raw_content = data["choices"][0]["message"]["content"]
        parsed      = _parse_json_response(raw_content)

        if parsed is None:
            logger.warning("Groq returned non-JSON response: %s", raw_content[:200])
            return None

        # Normalise and validate
        risk       = str(parsed.get("risk", "low")).lower()
        confidence = float(parsed.get("confidence", 0.5))
        reasons    = parsed.get("reasons", [])

        if risk not in ("high", "medium", "low"):
            risk = "low"
        confidence = max(0.0, min(1.0, confidence))
        if not isinstance(reasons, list):
            reasons = [str(reasons)]

        return {
            "risk":       risk,
            "confidence": round(confidence, 4),
            "reasons":    reasons[:5],   # cap at 5 entries
        }

    except httpx.TimeoutException:
        logger.warning("Groq API timed out after %.1f s", AI_TIMEOUT_SECONDS)
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning("Groq API HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
        return None
    except Exception as exc:
        logger.warning("Groq API unexpected error: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Gemini — deep threat explanation
# ─────────────────────────────────────────────────────────────────────────────

_GEMINI_SYSTEM_PROMPT = """You are a senior threat-intelligence analyst. Your task is to
examine the provided context (which may be a domain name, a phishing message, or text
extracted from a suspicious file) and produce a structured threat assessment.

Return ONLY a JSON object — no markdown, no extra text — with exactly these fields:

  "summary"      : one concise sentence (≤ 20 words) describing the threat
  "threat_level" : "high" | "medium" | "low" | "safe"
  "explanation"  : 2–4 sentences of detailed reasoning covering what makes this
                   context suspicious, what attack vector it represents, and any
                   impersonation or social-engineering techniques observed

Threat level guidelines:
  high   — strong evidence of phishing, credential harvesting, malware distribution,
            or domain impersonation of a well-known brand
  medium — circumstantially suspicious; warrants caution but not definitive
  low    — minor indicators; probably benign but worth noting
  safe   — no meaningful threat signals

Return ONLY the JSON object."""


async def explain_threat(context: str) -> Optional[dict]:
    """
    Use Gemini (gemini-1.5-flash) for deep reasoning and human-readable
    explanation of a suspicious domain, message, or file content excerpt.
    Includes 3 retries with exponential backoff to handle 429 rate limits.
    """
    if not _gemini_available():
        logger.debug("Gemini API key not configured — skipping deep threat explanation")
        return None

    # Keep context short
    truncated = context[:4000] if len(context) > 4000 else context
    full_prompt = f"{_GEMINI_SYSTEM_PROMPT}\n\nContext to analyse:\n\n{truncated}"

    payload = {
        "contents": [{"parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "temperature":     0.2,
            "maxOutputTokens": MAX_OUTPUT_TOKENS,
        },
    }

    url = f"{GEMINI_URL}?key={settings.GEMINI_API_KEY}"
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=AI_TIMEOUT_SECONDS) as client:
                response = await client.post(url, json=payload)
                
                # Handle rate limits explicitly before raising for general status
                if response.status_code == 429:
                    logger.warning("Gemini rate limited (429) on attempt %d/%d", attempt, max_retries)
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return None

                response.raise_for_status()

            data = response.json()
            raw_content = (
                data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
            )

            if not raw_content:
                logger.warning("Gemini returned empty content")
                return None

            parsed = _parse_json_response(raw_content)

            if parsed is None:
                logger.warning("Gemini returned non-JSON response: %s", raw_content[:200])
                return None

            summary      = str(parsed.get("summary", "")).strip()
            threat_level = str(parsed.get("threat_level", "low")).lower()
            explanation  = str(parsed.get("explanation", "")).strip()

            if threat_level not in ("high", "medium", "low", "safe"):
                threat_level = "low"

            return {
                "summary":      summary,
                "threat_level": threat_level,
                "explanation":  explanation,
            }

        except Exception as exc:
            logger.warning("Gemini API error on attempt %d: %s", attempt, exc)
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
            else:
                return None