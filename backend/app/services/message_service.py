"""
SMS / Message Fraud Detection Service
======================================
Detection pipeline (in order):
  1. Rule engine       — pattern-based scoring (sms_detector_core)
  2. ML model          — OpenAI fallback when rules are weak (sms_detector_core)
  3. Groq AI           — fast LLM classification via analyze_text_fast()
  4. Final risk score  — weighted combination of all layers

AI analysis runs *after* the existing rule/ML pipeline and enriches the result
with an `ai_analysis` block.  If Groq is unavailable or fails the original
result is returned unchanged — existing functionality is never broken.
"""

import logging
import asyncio
from typing import Optional

from app.services import sms_detector_core as _core
from app.services import ai_service

logger = logging.getLogger(__name__)


# ── Scoring helpers ───────────────────────────────────────────────────────────

_RISK_TO_SCORE = {"high": 0.85, "medium": 0.55, "low": 0.15}


def _merge_ai_score(base_score: float, ai_result: Optional[dict]) -> float:
    """
    Blend the AI risk score into the existing final_score.

    Weighting:
      - Rule/ML pipeline: 70 %
      - Groq AI:          30 %

    The AI is treated as a secondary signal — it can raise the score but
    only modestly, preventing false positives when rules are clean.
    """
    if ai_result is None:
        return base_score

    ai_score = _RISK_TO_SCORE.get(ai_result.get("risk", "low"), 0.15)
    ai_conf  = float(ai_result.get("confidence", 0.5))

    blended = (base_score * 0.70) + (ai_score * ai_conf * 0.30)
    return round(min(blended, 1.0), 4)


def _build_risk_score_int(final_score: float) -> int:
    """Convert 0-1 float score to 0-100 integer for API consumers."""
    return int(round(final_score * 100))


# ── Main public function ──────────────────────────────────────────────────────

async def scan_message_async(text: str) -> dict:
    """Async version of scan_message. Preferred when called from an async route."""
    
    # Default fallback result in case the core rule/OpenAI engine fails
    result = {
        "original_message": text,
        "language":         "unknown",
        "rule_score":       0.0,
        "reasons":          [],
        "final_score":      0.0,
        "final_label":      "SAFE",
        "confidence_level": "low",
        "api_skipped":      True,
    }

    try:
        # Layer 1 + 2: Rule engine + optional OpenAI
        core_result = _core.detect(text.strip())
        result.update(core_result)
    except Exception as e:
        logger.warning(f"Message scan core/OpenAI error, relying on Groq fallback: {e}")
        result["reasons"].append("Core scanner bypassed due to failure.")

    # Layer 3: Groq fast AI analysis
    ai_result: Optional[dict] = None
    try:
        ai_result = await ai_service.analyze_text_fast(text.strip())
    except Exception as exc:
        logger.warning("Groq AI analysis skipped due to error: %s", exc)

    # Layer 4: Merge scores
    base_score     = result.get("final_score", 0.0)
    
    # If the core failed but Groq succeeded, let Groq be the absolute source of truth
    if base_score == 0.0 and ai_result:
        merged_score = _RISK_TO_SCORE.get(ai_result.get("risk", "low"), 0.15)
    else:
        merged_score = _merge_ai_score(base_score, ai_result)
        
    risk_score_int = _build_risk_score_int(merged_score)

    # Re-classify label
    if merged_score >= 0.70: # Standardized FRAUD threshold
        final_label = "FRAUD"
    elif merged_score >= 0.40: # Standardized SUSPICIOUS threshold
        final_label = "SUSPICIOUS"
    else:
        final_label = "SAFE"

    result["final_score"]  = merged_score
    result["final_label"]  = final_label
    result["risk_score"]   = risk_score_int
    result["ai_analysis"]  = ai_result
    result["ai_used"]      = ai_result is not None

    return result

def scan_message(text: str) -> dict:
    """
    Synchronous entry point — wraps scan_message_async.
    Safe to call from FastAPI background tasks (which run in separate threads).
    """
    try:
        # asyncio.run() creates a fresh event loop for this background thread
        return asyncio.run(scan_message_async(text))
    except RuntimeError as e:
        # Fallback: If this is accidentally called from a thread that ALREADY has a loop
        logger.warning(f"Event loop already running, using ThreadPoolExecutor: {e}")
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, scan_message_async(text))
            return future.result(timeout=20)
    except Exception as exc:
        logger.warning("scan_message async dispatch failed, falling back to sync core: %s", exc)
        try:
            result = _core.detect(text.strip())
            result["risk_score"]  = _build_risk_score_int(result.get("final_score", 0.0))
            result["ai_analysis"] = None
            result["ai_used"]     = False
            return result
        except Exception as core_exc:
            logger.error("Message scan fallback error: %s", core_exc)
            return {
                "original_message": text,
                "language":         "unknown",
                "rule_score":       0.0,
                "reasons":          [f"Scan error: {core_exc}"],
                "final_score":      0.0,
                "final_label":      "SAFE",
                "risk_score":       0,
                "ai_analysis":      None,
                "ai_used":          False,
                "api_skipped":      True,
            }