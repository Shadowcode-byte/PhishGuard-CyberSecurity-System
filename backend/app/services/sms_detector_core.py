#!/usr/bin/env python3
"""
Phishing / Fraud SMS & Message Detector — v2.0 (Improved)
============================================================
Changes from v1.x:
  1. Stronger rule set:
     - Added fake brand impersonation patterns (SBI, HDFC, PayPal, etc.)
     - Added suspicious file type lures (.exe, .apk download scams)
     - Added credential keyword patterns (username, password, credentials)
     - Added gift card / voucher scam patterns
     - Added remote access / screen share scams
     - Added refund/tax/insurance claim scams
  2. Improved scoring system:
     - Diminishing-returns soft cap is tuned more precisely
     - High-confidence single-rule hits (>= 0.85) immediately classify FRAUD
     - Combined ML + rule score improved via weighted combination
  3. Improved hybrid decision:
     final_score = max(rule_score, api_score * 0.9)
     Plus a "rule_override" path: if any single rule has weight >= 0.85 → FRAUD
     regardless of final_score (catches OTP/CVV demands absolutely)
  4. Cleaner output: reasons no longer show raw score suffix by default
     (shown only in debug mode)
"""

import os
import re
import sys
import json
import math
import argparse
import unicodedata
from typing import Optional

# ── Optional dependencies ────────────────────────────────────────────────────
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_AVAILABLE = True
except ImportError:
    TRANSLATOR_AVAILABLE = False

# ── Thresholds ────────────────────────────────────────────────────────────────
FRAUD_THRESHOLD      = 0.55   # lowered slightly — catch more phishing
SUSPICIOUS_THRESHOLD = 0.28
DEBUG_MODE = False

F = re.I

# ── Rule Definitions ──────────────────────────────────────────────────────────
# Format: (compiled_regex, score, human_readable_reason, is_hard_trigger)
# is_hard_trigger=True → single match immediately forces FRAUD classification
# regardless of overall score (used for CVV, OTP, credential demands)
# ─────────────────────────────────────────────────────────────────────────────

RULES = [

    # ════════ 1. OTP / One-Time Password ════════

    (re.compile(
        r"(give|send|share|provide|tell|bata|bhejo|batao|dedo|chahiye|bhejiye|bataiye|dijiye|de do)\b.{0,40}\botp\b"
        r"|\botp\b.{0,40}(give|send|share|provide|bhejo|batao)",
        F), 0.92, "Requesting OTP from victim", True),

    (re.compile(r"\botp\b", F), 0.40, "OTP keyword present", False),

    (re.compile(
        r"\bone[\s\-]?time[\s\-]?(pass(word)?|code|pin)\b"
        r"|\bverification[\s\-]?(code|number|pin)\b",
        F), 0.72, "One-time / verification code requested", False),

    # ════════ 2. Bank / Account Details ════════

    (re.compile(
        r"(give|send|share|provide|tell|submit|enter|type|fill).{0,40}"
        r"(bank\s*(detail|account|info|number|data)|account\s*(number|detail|info|no))",
        F), 0.87, "Requesting bank/account details", True),

    (re.compile(r"\bbank\s*(detail|info|account\s*number|data)\b", F), 0.65,
     "Bank detail keywords present", False),

    (re.compile(r"\b(ifsc|sort[\s\-]?code|routing[\s\-]?number)\b", F), 0.65,
     "Bank routing/IFSC code requested", False),

    # ════════ 3. Card Details ════════

    (re.compile(r"\b(credit|debit)\s*card\b.{0,50}(number|detail|info|cvv|pin|expir)", F), 0.82,
     "Credit/debit card details requested", True),

    (re.compile(r"\b(cvv|cvc2?|card\s*verification\s*(value|code))\b", F), 0.92,
     "CVV/CVC security code requested", True),

    (re.compile(r"\b(expir(y|ation|ation\s*date)|valid\s*(thru|through|till|upto))\b", F), 0.55,
     "Card expiry date mentioned", False),

    # ════════ 4. UPI / PIN / Password ════════

    (re.compile(r"\bupi\s*(pin|id|handle|address|vpa)\b", F), 0.82,
     "UPI PIN/ID requested", True),

    (re.compile(
        r"(give|send|share|provide|tell|bata|batao|bhejo|dedo)\b.{0,40}"
        r"\b(pin|mpin|m\s*pin|password|passcode|secret\s*(code|number))\b",
        F), 0.92, "Requesting PIN / password / mPIN from victim", True),

    (re.compile(r"\b(mpin|m[\s\-]?pin)\b", F), 0.45, "mPIN keyword present", False),

    # ════════ 5. Credential / Login keywords ════════ [NEW]

    (re.compile(
        r"(share|send|provide|give|enter|submit).{0,40}"
        r"\b(username|login\s*id|user\s*id|credentials?|login\s*detail)\b",
        F), 0.80, "Requesting login credentials from victim", True),

    (re.compile(
        r"\b(your\s*)?(credentials?|login\s*detail|username\s*and\s*password)\b",
        F), 0.55, "Credential keywords present", False),

    # ════════ 6. Threats — Account Blocking ════════

    (re.compile(
        r"(i\s*(will|am\s*going\s*to|shall|would)|we\s*(will|shall|are\s*going\s*to))"
        r".{0,30}(block|suspend|deactivat|clos|freez|terminat).{0,20}(account|card|service)",
        F), 0.87, "Direct threat to block/suspend account", False),

    (re.compile(
        r"(account|card|service|number).{0,30}"
        r"(will\s*(be|get)|is\s*(being|getting)|has\s*been|shall\s*be|gets?)\s*"
        r"(block(ed)?|suspend(ed)?|deactivat(ed)?|clos(ed)?|freez(en)?|terminat(ed)?)",
        F), 0.87, "Threat of account blocking/suspension/closure", False),

    (re.compile(
        r"\b(block(ed)?|suspend(ed)?|deactivat(ed)?|freez(en)?)\b.{0,30}\b(account|card|number|service)\b"
        r"|\b(account|card|number|service)\b.{0,30}\b(block(ed)?|suspend(ed)?|deactivat(ed)?|freez(en)?)\b",
        F), 0.75, "Account block/suspension language", False),

    # ════════ 7. Threats — Legal / Authority ════════

    (re.compile(
        r"\b(legal\s*action|file\s*(a\s*)?(case|complaint|fir)|police\s*complaint"
        r"|court\s*notice|arrested?|warrant|prosecution|cybercrime)\b",
        F), 0.87, "Threat of legal action / police / court", False),

    # ════════ 8. Urgency / Pressure ════════

    (re.compile(
        r"\b(act\s*now|immediately|right\s*now|do\s*it\s*now|within\s*\d+\s*(hours?|minutes?|mins?|hrs?)"
        r"|last\s*(chance|opportunity)|final\s*(notice|warning|chance)"
        r"|expire[sd]?\s*(today|tonight|now|soon|in\s*\d+)"
        r"|limited\s*time|before\s*it\s*(is\s*)?too\s*late)\b",
        F), 0.50, "Urgency / time-pressure language", False),

    (re.compile(
        r"\b(or\s*(else|i\s*will|we\s*will|your\s*account)|otherwise\b.{0,40}"
        r"(block|suspend|action|police|arrest))",
        F), 0.68, "Conditional threat ('or else / otherwise')", False),

    # ════════ 9. KYC / Verification ════════

    (re.compile(
        r"\b(kyc|know\s*your\s*customer).{0,30}"
        r"(pending|incomplete|update|verify|expire|required|mandatory)\b"
        r"|(update|complete|verify|submit).{0,30}\bkyc\b",
        F), 0.72, "KYC verification request", False),

    # ════════ 10. Prize / Lottery Scams ════════

    (re.compile(
        r"\b(you\s*(have\s*)?(won|win|are\s*the\s*winner)"
        r"|congratulations.{0,30}(won|prize|reward|winner|selected)"
        r"|selected\s*as\s*(the\s*)?(lucky\s*)?(winner|recipient))\b",
        F), 0.92, "Prize/lottery winner scam language", False),

    (re.compile(
        r"\b(claim\s*(your\s*)?(prize|reward|cash|money|winnings|gift|offer)"
        r"|free\s*(cash|money|gift|reward|iphone|laptop|recharge)\b"
        r"|prize\s*(money|amount|of\s*rs\.?))\b",
        F), 0.87, "Claim prize / free reward language", False),

    (re.compile(r"\b(lucky\s*draw|jackpot|lottery|sweepstakes|raffle)\b", F), 0.82,
     "Lottery / lucky draw scam", False),

    # ════════ 11. Gift Card / Voucher Scams ════════ [NEW]

    (re.compile(
        r"\b(gift\s*card|itunes\s*card|google\s*play\s*card|amazon\s*gift\s*card"
        r"|steam\s*card|voucher\s*code)\b.{0,60}(send|share|buy|purchase|provide|give)",
        F), 0.87, "Gift card / voucher payment scam", False),

    (re.compile(
        r"(send|buy|purchase|provide)\b.{0,40}\b(gift\s*card|voucher|prepaid\s*card)\b",
        F), 0.82, "Request to buy/send gift cards", False),

    # ════════ 12. Phishing Links ════════

    (re.compile(
        r"\b(click\s*(here|the\s*link|on\s*the\s*link|below|this)"
        r"|tap\s*(here|the\s*link|below)"
        r"|open\s*the\s*link|visit\s*(this|the)\s*(link|url|site|website|page))\b",
        F), 0.45, "Click/tap link instruction", False),

    (re.compile(
        r"https?://(?!(?:www\.)?"
        r"(?:google|microsoft|apple|amazon|facebook|instagram|youtube|linkedin|twitter|sbi|hdfc|icici|paytm)\."
        r")[^\s]{8,}",
        F), 0.55, "Suspicious / unrecognised URL in message", False),

    # ════════ 13. Fake Brand Impersonation ════════ [NEW]

    (re.compile(
        r"\b(sbi|state\s*bank(\s*of\s*india)?|hdfc(\s*bank)?|icici(\s*bank)?"
        r"|axis\s*bank|kotak(\s*mahindra)?|paytm|phonepe|googlepay|g[\s\-]?pay"
        r"|amazon|flipkart|ebay|paypal|microsoft|apple\s*support|google\s*support)\b"
        r".{0,60}"
        r"\b(account|verify|update|otp|pin|block|suspend|kyc|credential|login|security)\b",
        F), 0.77, "Fake brand impersonation + credential/security topic", False),

    # ════════ 14. Remote Access / Tech Support Scams ════════ [NEW]

    (re.compile(
        r"\b(remote\s*(access|control|desktop)|anydesk|teamviewer|quicksupport"
        r"|screen\s*share|take\s*control\s*of\s*your\s*(computer|phone|device)"
        r"|install\s*(this\s*)?(app|software|program|tool))\b",
        F), 0.82, "Remote access / tech support scam indicators", False),

    # ════════ 15. Suspicious File Type Lures ════════ [NEW]

    (re.compile(
        r"\b(download|install|open|run|execute)\b.{0,40}"
        r"\.(exe|apk|bat|cmd|scr|vbs|js|ps1|dmg|pkg|msi)\b",
        F), 0.82, "Suspicious executable file download lure", False),

    # ════════ 16. Refund / Tax / Insurance Claim Scams ════════ [NEW]

    (re.compile(
        r"\b(refund|tax\s*(refund|credit|return)|income\s*tax"
        r"|insurance\s*(claim|refund|payout)"
        r"|government\s*(grant|payment|benefit|scheme)"
        r"|stimulus\s*(check|payment))\b"
        r".{0,60}"
        r"\b(click|link|verify|account|bank|details?|otp|pin|deposit|transfer|claim)\b",
        F), 0.77, "Refund / tax / government grant scam", False),

    # ════════ 17. Verify / Update Account ════════

    (re.compile(
        r"\b(verify|confirm|validate).{0,30}"
        r"\b(your\s*)?(account|identity|details?|information|card|number|profile)\b",
        F), 0.60, "Account/identity verification request", False),

    (re.compile(
        r"\b(update|re\s*?enter|re\s*?submit|fill\s*(in|out)?).{0,30}"
        r"\b(your\s*)?(detail|info|card|payment|bank|personal|account)\b",
        F), 0.55, "Request to update/re-enter personal details", False),

    # ════════ 18. Personal Identifiers ════════

    (re.compile(r"\b(aadhaar|aadhar|adhar)\b", F), 0.65, "Aadhaar number mentioned", False),
    (re.compile(r"\bpan\s*(card|number|no\.?)\b", F), 0.60, "PAN card number requested", False),
    (re.compile(r"\bpassport\s*(number|no\.?|detail)\b", F), 0.55, "Passport number requested", False),
    (re.compile(r"\b(date\s*of\s*birth|d\.?o\.?b\.?|mother\s*'?s?\s*(maiden\s*name|name))\b", F), 0.50,
     "Sensitive personal identifier (DOB / mother's name) requested", False),

    # ════════ 19. Hindi / Hinglish ════════

    (re.compile(r"\b(khata|bank\s*khata|khata\s*(number|no))\b", F), 0.60,
     "Hindi: Bank account (khata) mentioned", False),

    (re.compile(
        r"\b(band\s*ho\s*(jayega|jaayega|jaega)"
        r"|block\s*ho\s*(jayega|jaayega|jaega)"
        r"|band\s*kar\s*(denge|diya\s*jayega|diya\s*jaayega)"
        r"|suspend\s*ho\s*(jayega|jaayega))\b",
        F), 0.87, "Hindi: Threat of account closure/block", False),

    (re.compile(
        r"\b(paise|paisa)\b.{0,30}"
        r"\b(transfer|bhejo|bheje|mile\s*ge|milenge|jeet|mila)\b",
        F), 0.72, "Hindi: Money transfer / prize mentioned", False),

    (re.compile(r"\b(inam|inaam|jeeta|jeet\s*liya|lucky\s*draw)\b", F), 0.77,
     "Hindi: Prize / lottery (inam/jeeta)", False),

    (re.compile(
        r"\b(abhi|turant|jaldi|fatafat)\b.{0,30}"
        r"\b(karo|karen|kijiye|dijiye|bhejo|batao|dedo)\b",
        F), 0.50, "Hinglish: Urgency — act immediately", False),

    (re.compile(
        r"\b(apna|apni|aapka|aapki|aap\s*ka|apke)\b.{0,30}"
        r"\b(otp|pin|mpin|password|card|khata|account)\b",
        F), 0.87, "Hinglish: Requesting your OTP/PIN/account", True),

    (re.compile(
        r"\b(verify|verification)\b.{0,30}\b(karein|karo|kijiye|karna\s*hai)\b",
        F), 0.55, "Hinglish: Verify (Hindi imperative)", False),

    (re.compile(
        r"\bwarna\b.{0,50}"
        r"\b(block|band|action|police|arrest|suspend|legal|court)\b",
        F), 0.87, "Hinglish: 'warna' (otherwise) + threat", False),

]

# ── Language Detection ─────────────────────────────────────────────────────────
HINDI_UNICODE_RANGE = re.compile(r'[\u0900-\u097F]')
URDU_UNICODE_RANGE  = re.compile(r'[\u0600-\u06FF]')
HINGLISH_MARKERS    = re.compile(
    r'\b(karo|karna|hai|hain|nahi|nhi|bhai|yaar|abhi|turant|jaldi|batao|bhejo|dijiye|milega|milenge|aapka|apna|khata|paise|paisa|inam|band)\b',
    re.I
)

def detect_language(text: str) -> str:
    if HINDI_UNICODE_RANGE.search(text): return "hindi"
    if URDU_UNICODE_RANGE.search(text):  return "urdu"
    if HINGLISH_MARKERS.search(text):    return "hinglish"
    return "english"


def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return re.sub(r'\s+', ' ', text).strip()


def translate_to_english(text: str, language: str) -> str:
    if language == "english":
        return text
    if not TRANSLATOR_AVAILABLE:
        return text
    try:
        src_map = {"hindi": "hi", "urdu": "ur", "hinglish": "hi"}
        src = src_map.get(language, "auto")
        return GoogleTranslator(source=src, target="en").translate(text)
    except Exception:
        return text


# ── Rule Engine ────────────────────────────────────────────────────────────────
def check_rules(text: str) -> dict:
    """
    Apply all rules. Returns rule_score, reasons, matched_count, hard_trigger.
    hard_trigger=True means at least one rule with is_hard_trigger fired.
    """
    reasons       = []
    raw_scores    = []
    hard_trigger  = False

    for pattern, score, reason, is_hard in RULES:
        if pattern.search(text):
            reasons.append(reason if not DEBUG_MODE else f"{reason} (+{score:.2f})")
            raw_scores.append(score)
            if is_hard:
                hard_trigger = True

    cumulative = sum(raw_scores)
    rule_score = round(1.0 - math.exp(-cumulative), 4) if cumulative > 0 else 0.0
    rule_score = min(rule_score, 1.0)

    return {
        "rule_score":    rule_score,
        "reasons":       reasons,
        "matched_count": len(reasons),
        "hard_trigger":  hard_trigger,
        "max_single":    max(raw_scores) if raw_scores else 0.0,
    }


# ── OpenAI Integration (unchanged) ────────────────────────────────────────────
def call_openai_api(text: str) -> dict:
    if not OPENAI_AVAILABLE:
        return {"label": "Unknown", "confidence": 0.0, "explanation": "OpenAI not installed.", "error": "openai missing"}

    # 1. Look for the OpenRouter key instead
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return {"label": "Unknown", "confidence": 0.0, "explanation": "No API key.", "error": "OPENROUTER_API_KEY not set"}

    system_prompt = (
        "You are a fraud and phishing detection expert. "
        "Analyze the following message and classify it.\n\n"
        "Respond ONLY with valid JSON (no markdown) with exactly:\n"
        '  "label": "Fraud" | "Suspicious" | "Safe"\n'
        '  "confidence": float 0-1\n'
        '  "explanation": one-sentence reason\n\n'
        "Fraud indicators: OTP/PIN/CVV/password requests, account threats, prize scams, "
        "fake verification, urgency to panic victim, gift card demands, remote access requests.\n"
        "Safe: normal greetings, everyday questions, legitimate business communication."
    )

    try:
        # 2. Redirect the client to OpenRouter
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )
        response = client.chat.completions.create(
            model="nvidia/nemotron-3-super-120b-a12b:free", # 3. Insert the model string from your screenshot
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": f"Message:\n\n{text}"},
            ],
            temperature=0.0,
            max_tokens=200,
            response_format={"type": "json_object"},
        )
        data        = json.loads(response.choices[0].message.content.strip())
        label       = data.get("label", "Unknown").capitalize()
        if label not in ("Fraud", "Suspicious", "Safe"):
            label = "Unknown"
        confidence  = float(data.get("confidence", 0.5))
        explanation = data.get("explanation", "")
        return {"label": label, "confidence": round(confidence, 4), "explanation": explanation, "error": None}
    except Exception as e:
        return {"label": "Unknown", "confidence": 0.0, "explanation": "API call failed.", "error": str(e)}
# ── Hybrid Scoring ─────────────────────────────────────────────────────────────
def combine_scores(rule_result: dict, api_result: Optional[dict]) -> dict:
    """
    Improved hybrid decision logic:
      1. If hard_trigger fired → immediate FRAUD (high-confidence credential demands)
      2. If rule_score >= 0.45 → skip API, use rule_score
      3. Otherwise: final_score = max(rule_score, api_confidence * 0.9)
    """
    rule_score    = rule_result["rule_score"]
    hard_trigger  = rule_result.get("hard_trigger", False)
    api_skipped   = (api_result is None)

    api_label       = api_result["label"]       if api_result else "N/A"
    api_confidence  = api_result["confidence"]  if api_result else 0.0
    api_explanation = api_result["explanation"] if api_result else ""
    api_error       = api_result["error"]       if api_result else None

    # Hard trigger: OTP/CVV/credential demand → always FRAUD
    if hard_trigger:
        final_score = max(rule_score, 0.85)
        final_label = "FRAUD"
        confidence_level = "High"
        return {
            "final_score": round(final_score, 4),
            "final_label": final_label,
            "confidence_level": confidence_level,
            "api_label": api_label, "api_confidence": api_confidence,
            "api_explanation": api_explanation, "api_error": api_error,
            "api_skipped": True,
        }

    if api_skipped:
        final_score = rule_score
    else:
        # Weighted combination — rule engine slightly more trusted for specific patterns
        final_score = max(rule_score, api_confidence * 0.9)

    final_score = round(final_score, 4)

    if final_score >= FRAUD_THRESHOLD:
        final_label = "FRAUD"
    elif final_score >= SUSPICIOUS_THRESHOLD:
        final_label = "SUSPICIOUS"
    else:
        final_label = "SAFE"

    confidence_level = "High" if final_score >= 0.75 else ("Medium" if final_score >= 0.45 else "Low")

    return {
        "final_score":      final_score,
        "final_label":      final_label,
        "confidence_level": confidence_level,
        "api_label":        api_label,
        "api_confidence":   api_confidence,
        "api_explanation":  api_explanation,
        "api_error":        api_error,
        "api_skipped":      api_skipped,
    }


# ── Main Detection Pipeline ────────────────────────────────────────────────────
def detect(raw_text: str) -> dict:
    text     = clean_text(raw_text)
    language = detect_language(text)
    translated_text = translate_to_english(text, language)

    rule_orig       = check_rules(text)
    rule_translated = check_rules(translated_text) if translated_text != text else rule_orig

    # Merge rule results — union of reasons, max score, OR of hard triggers
    combined_reasons    = list(dict.fromkeys(rule_orig["reasons"] + rule_translated["reasons"]))
    combined_score      = max(rule_orig["rule_score"], rule_translated["rule_score"])
    combined_hard       = rule_orig["hard_trigger"] or rule_translated["hard_trigger"]
    combined_max_single = max(rule_orig.get("max_single", 0), rule_translated.get("max_single", 0))

    rule_result = {
        "rule_score":    combined_score,
        "reasons":       combined_reasons,
        "matched_count": len(combined_reasons),
        "hard_trigger":  combined_hard,
        "max_single":    combined_max_single,
    }

    # API only called when rules are weak and no hard trigger
    api_result = None
    if combined_score < 0.45 and not combined_hard:
        api_result = call_openai_api(translated_text)

    combined = combine_scores(rule_result, api_result)

    return {
        "original_message": raw_text,
        "language":         language,
        "rule_score":       rule_result["rule_score"],
        "reasons":          rule_result["reasons"],
        **combined,
    }


# ── Output Formatter ───────────────────────────────────────────────────────────
_C = {
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m", "gray": "\033[90m",
}

def _colour(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(_C.get(c, "") for c in codes) + text + _C["reset"]


def print_result(result: dict) -> None:
    label  = result["final_label"]
    fscore = result["final_score"]
    clevel = result["confidence_level"]
    color  = {"FRAUD": ("red", "bold"), "SUSPICIOUS": ("yellow", "bold"), "SAFE": ("green", "bold")}.get(label, ("cyan",))

    print()
    print(_colour("═" * 62, "bold"))
    print(_colour("  PHISHING / FRAUD DETECTION  (v2.0)", "bold", "cyan"))
    print(_colour("═" * 62, "bold"))
    print(f"  {'Message':<18}: {result['original_message'][:80]}")
    print(f"  {'Language':<18}: {result['language'].capitalize()}")
    print(f"  {'Rule Score':<18}: {result['rule_score']:.4f}")
    if not result["api_skipped"]:
        print(f"  {'API Label':<18}: {result['api_label']} (conf={result['api_confidence']:.4f})")
        if result["api_explanation"]:
            print(f"  {'API Reason':<18}: {result['api_explanation']}")
    else:
        print(f"  {'API':<18}: {_colour('Skipped', 'gray')}")
    print()
    print(f"  {'Final Score':<18}: {fscore:.4f}")
    print(f"  {'Classification':<18}: {_colour(label, *color)}")
    print(f"  {'Confidence':<18}: {clevel}")
    if result["reasons"]:
        print()
        print(_colour("  Detection Reasons:", "bold"))
        for r in result["reasons"]:
            print(f"    • {r}")
    print(_colour("═" * 62, "bold"))
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────
TEST_CASES = [
    ("hi", "SAFE"),
    ("Your order has been shipped. Track it at amazon.com", "SAFE"),
    ("give me your bank details or i will block your account", "FRAUD"),
    ("send me your otp", "FRAUD"),
    ("Congratulations! You have won Rs 5,00,000. Click here to claim.", "FRAUD"),
    ("Your KYC is pending. Update your Aadhaar and CVV immediately.", "FRAUD"),
    ("Please send me your username and password to proceed.", "FRAUD"),
    ("Buy a $200 Google Play gift card and share the code with me.", "FRAUD"),
    ("Download and install this tool: setup.exe for your refund.", "FRAUD"),
    ("Aapka apna otp dijiye warna account band ho jayega.", "FRAUD"),
]

def run_tests():
    print(_colour("\n  ── TEST SUITE ──\n", "bold", "cyan"))
    passed = failed = 0
    for msg, expected in TEST_CASES:
        r = detect(msg)
        ok = r["final_label"] == expected
        icon = "✓" if ok else "✗"
        col  = "green" if ok else "red"
        print(_colour(f"  {icon} [{expected:<12}] {msg[:60]}", col))
        if ok: passed += 1
        else:   failed += 1
    print(_colour(f"\n  {passed}/{len(TEST_CASES)} passed\n", "bold"))

def main():
    global DEBUG_MODE
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--test",  action="store_true")
    args = parser.parse_args()
    DEBUG_MODE = args.debug

    if args.test:
        run_tests()
    else:
        print(_colour("\n  Phishing & Fraud Detector v2.0 — type 'quit' to exit\n", "cyan", "bold"))
        while True:
            try:
                user_input = input(_colour("  Message: ", "bold")).strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not user_input: continue
            if user_input.lower() in ("quit", "exit", "q"): break
            print_result(detect(user_input))

if __name__ == "__main__":
    main()
