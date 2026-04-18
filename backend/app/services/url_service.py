"""
URL Phishing Detection Service
================================
Detection pipeline (in order):

  Layer 1 + 2 — RandomForest ML model + rule-based overlay
                (url_detector_core.predict_url)

  Layer 3     — VirusTotal domain reputation
                Called only when ML/rule layers already flag the URL as
                suspicious or phishing.  Skipped on clearly-safe URLs to
                protect the free-tier daily budget (500 req/day).
                Rate-limited to 4 req/min (15 s minimum gap) with 24-hour
                in-memory caching per root domain.

  Layer 4     — Gemini AI deep threat explanation
                Called only for PHISHING or SUSPICIOUS results; adds a
                human-readable summary and threat-level explanation.

  Final       — Weighted confidence merge and risk_score (0-100 int)

All external layers (VT, Gemini) are fully optional: if their keys are absent
or the calls fail, the pipeline returns the ML+rule result unchanged.
"""

import logging
import asyncio
from typing import Optional
from urllib.parse import urlparse

from app.services import url_detector_core as _core
from app.services import ai_service
from app.services import virustotal_service as _vt

logger = logging.getLogger(__name__)

# Module-level model reference
_initialized = False


def initialize() -> None:
    """Load or train the RandomForest model.  Call once at startup."""
    global _initialized
    if _initialized:
        return
    try:
        model = _core.load_or_train_model()
        _core.set_model(model)
        _initialized = True
        logger.info("✅ URL detection model initialized")
    except Exception as e:
        logger.error("❌ URL model init failed: %s", e)
        _initialized = False
        raise


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    """Return the hostname/domain portion of a URL for context strings."""
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        return parsed.netloc or url
    except Exception:
        return url


def _build_risk_score_int(confidence: float) -> int:
    return int(round(confidence * 100))


# ── Score merging ─────────────────────────────────────────────────────────────

# Confidence boosts applied when external layers confirm a threat.
# Values are additive and capped at 1.0; they never reduce an existing score.
_VT_VERDICT_BOOST   = {"malicious": 0.20, "suspicious": 0.08, "clean": 0.0, "unknown": 0.0}
_AI_THREAT_BOOST    = {"high": 0.15, "medium": 0.05, "low": 0.0, "safe": 0.0}


def _apply_vt_boost(threat_score: float, vt_result: Optional[dict]) -> float:
    """
    Adjust threat score based on VirusTotal verdict.
    Boosts score for malicious/suspicious, and REDUCES score for clean verdicts
    to save legitimate URLs from overzealous ML flagging.
    """
    if vt_result is None:
        return threat_score
        
    verdict = vt_result.get("verdict", "unknown")
    vt_conf = float(vt_result.get("confidence", 0.0))
    
    if verdict == "clean":
        # Drastically drop the threat score if VT confirms it is a clean domain
        return round(max(0.0, threat_score - 0.40), 4)

    base_boost  = _VT_VERDICT_BOOST.get(verdict, 0.0)
    actual_boost = base_boost * (0.5 + vt_conf * 0.5)
    return round(min(threat_score + actual_boost, 1.0), 4)


def _reclassify(threat_score: float, current_label: str) -> str:
    """
    Re-derive the label from the merged threat score.
    Allows VT 'clean' verdicts to safely downgrade false positive labels.
    """
    if threat_score >= 0.65:
        return "PHISHING"
    if threat_score >= 0.35:
        return "SUSPICIOUS"
    
    return "SAFE"


def _apply_ai_boost(confidence: float, ai_result: Optional[dict]) -> float:
    """
    Slightly boost confidence when Gemini confirms a high threat level.
    Capped at 1.0 and never reduces an existing score.
    """
    if ai_result is None:
        return confidence
    boost = _AI_THREAT_BOOST.get(ai_result.get("threat_level", "low"), 0.0)
    return round(min(confidence + boost, 1.0), 4)



# ── Async pipeline ────────────────────────────────────────────────────────────

async def scan_url_async(url: str) -> dict:
    """
    Full async detection pipeline.  Called directly from the FastAPI route.
    """
    if not _initialized or getattr(_core, "_model", None) is None:
        initialize()

    # ── Layer 1 + 2: ML model + rule-based overlay ────────────────────────
    try:
        result = _core.predict_url(url.strip())
    except RuntimeError as e:
        logger.error("URL scan failed (model not loaded): %s", e)
        result = {
            "label":          "SAFE",
            "confidence":     0.0,
            "risk_tier":      "LOW",
            "ml_probability": 0.0,
            "rule_score":     0.0,
            "reasons":        ["Model not available — scan inconclusive"],
            "detection_mode": "error",
        }
    except Exception as e:
        logger.error("Unexpected URL scan error: %s", e)
        raise

    current_label       = result.get("label", "SAFE")
    original_confidence = result.get("confidence", 0.0)
    ml_prob             = result.get("ml_probability", 0.0)
    rule_score          = result.get("rule_score", 0.0)

    # ── BUG FIX: Convert label confidence to an internal threat score ──
    # predict_url returns label confidence (e.g., 0.99 for SAFE).
    # We need a unified risk score (0.0 to 1.0 where 1.0 is max threat) 
    # for VT/AI boosts and reclassification.
    if current_label == "SAFE":
        current_threat_score = max(0.0, 1.0 - original_confidence)
    else:
        current_threat_score = original_confidence

    # ── Layer 3: VirusTotal domain reputation ─────────────────────────────
    vt_result: Optional[dict] = None
    try:
        domain = _extract_domain(url)
        vt_result = await _vt.check_domain(
            domain         = domain,
            ml_probability = ml_prob,
            rule_score     = rule_score,
            label          = current_label,
        )
    except Exception as exc:
        logger.warning("VirusTotal layer skipped due to unexpected error: %s", exc)

    # Apply VT boost using the normalized threat score
    after_vt_threat = _apply_vt_boost(current_threat_score, vt_result)

    # If VT pushed us over the PHISHING threshold, append a reason
    if vt_result and vt_result.get("verdict") in ("malicious", "suspicious"):
        vt_reason = (
            f"VirusTotal: {vt_result['malicious']} engine(s) flagged malicious, "
            f"{vt_result['suspicious']} suspicious out of {vt_result['total']} total"
        )
        if vt_reason not in result.get("reasons", []):
            result.setdefault("reasons", []).append(vt_reason)

    # Re-classify label after VT boost
    current_label = _reclassify(after_vt_threat, current_label)

    # ── Layer 4: Gemini AI deep threat explanation ────────────────────────
    ai_result: Optional[dict] = None
    
    # Calculate safe probability based on the ML phishing probability
    ml_safe_prob = 1.0 - ml_prob
    
    # Bypass AI entirely if the ML model is highly confident in either direction
    if ml_safe_prob >= 0.95 or ml_prob >= 0.95:
        logger.info("Skipping AI analysis — ML confidence high")
    elif current_label in ("PHISHING", "SUSPICIOUS"):
        vt_summary = ""
        if vt_result and vt_result.get("verdict") != "unknown":
            vt_summary = (
                f"\nVirusTotal verdict: {vt_result['verdict']} "
                f"({vt_result['malicious']} malicious, "
                f"{vt_result['suspicious']} suspicious / {vt_result['total']} engines)"
            )
        domain_context = (
            f"Domain: {_extract_domain(url)}\n"
            f"Full URL: {url}\n"
            f"Detection reasons: {', '.join(result.get('reasons', []))}"
            f"{vt_summary}"
        )
        try:
            ai_result = await ai_service.explain_threat(domain_context)
        except Exception as exc:
            logger.warning("Gemini threat explanation skipped: %s", exc)

    # ── Final merge ───────────────────────────────────────────────────────
    final_threat = _apply_ai_boost(after_vt_threat, ai_result)
    final_label  = _reclassify(final_threat, current_label)

    # Convert the internal threat score back to label confidence for the frontend
    if final_label == "SAFE":
        final_confidence = max(0.0, 1.0 - final_threat)
    else:
        final_confidence = final_threat

    result["label"]              = final_label
    result["confidence"]         = round(final_confidence, 4)
    result["risk_score"]         = _build_risk_score_int(final_threat)
    result["vt_result"]          = vt_result
    result["vt_used"]            = vt_result is not None
    result["threat_explanation"] = ai_result
    result["ai_analysis"]        = ai_result
    result["ai_used"]            = ai_result is not None

    return result


def scan_url(url: str) -> dict:
    """
    Safe sync wrapper for async scan_url_async.
    Works in background threads (FastAPI).
    """
    import asyncio

    try:
        return asyncio.run(scan_url_async(url))

    except RuntimeError as e:
        # If already inside an event loop (rare case)
        logger.warning(f"Event loop already running: {e}")

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, scan_url_async(url))
            return future.result(timeout=30)

    except Exception as exc:
        logger.warning(
            "scan_url async failed, falling back to core: %s", exc
        )
        try:
            result = _core.predict_url(url.strip())

            current_label = result.get("label", "SAFE")
            conf = result.get("confidence", 0.0)

            threat_score = conf if current_label != "SAFE" else max(0.0, 1.0 - conf)

            result["risk_score"] = _build_risk_score_int(threat_score)
            result["vt_result"] = None
            result["vt_used"] = False
            result["ai_analysis"] = None
            result["ai_used"] = False

            return result

        except Exception as e:
            logger.error("URL scan fallback failed: %s", e)
            return {
                "label": "SAFE",
                "confidence": 0.0,
                "risk_score": 0,
                "reasons": ["Scan failed"],
                "vt_result": None,
                "ai_analysis": None,
                "ai_used": False,
            }