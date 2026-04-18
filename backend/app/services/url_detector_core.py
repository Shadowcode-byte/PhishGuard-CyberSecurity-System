"""
URL Phishing Detector — v3.0 (Improved)
=========================================
Improvements over v2.x:
  1. Extended feature set (23 features vs 9):
     - Domain entropy calculation
     - Suspicious TLD detection
     - Subdomain count
     - URL shortener detection
     - Suspicious query param detection
     - Special char ratios
     - Brand impersonation keywords
     - Path depth
     - Digit ratio in domain
     - Double slash in path
  2. RandomForest with tuned hyperparameters (n_estimators=200, max_depth=20)
  3. Improved hybrid scoring: ML probability + rule trigger count combined
  4. More granular risk tiers: SAFE / SUSPICIOUS / PHISHING
  5. Deletion of stale model.pkl forced when feature count changes
"""
from app.services.threat_intel import is_known_phishing, is_legitimate_domain
import math
import requests
import whois
from datetime import datetime
import pandas as pd
import re
import os
import pickle
import logging
import hashlib

from urllib.parse import urlparse, parse_qs
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

logger = logging.getLogger(__name__)
def _extract_features_worker(url: str):
    import os
    os.environ["PHISHGUARD_TRAINING"] = "1"
    try:
        return extract_features_with_reasons(url)[0]
    except Exception:
        return None

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

# ── Constants ──────────────────────────────────────────────────────────────────
FEATURE_COUNT = 30   # bump this when adding features to force retraining
TRAINING_MODE = False
# Known URL shorteners
# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "shorte.st", "bc.vc", "clk.sh", "0rz.tw", "youtu.be"
}

# Suspicious TLDs commonly abused in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".click", ".link", ".online", ".site", ".website", ".space", ".fun",
    ".loan", ".win", ".download", ".accountant", ".review", ".country",
    ".stream", ".gdn", ".bid", ".trade", ".cricket", ".science",
}

# Brand impersonation keywords
BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "dropbox", "linkedin", "twitter", "ebay",
    "wellsfargo", "chase", "bankofamerica", "citibank", "barclays",
    "sbi", "hdfc", "icici", "kotak", "paytm", "phonepe", "gpay",
    "whatsapp", "telegram", "yahoo", "outlook", "office365",
]

# Suspicious query parameter names
SUSPICIOUS_PARAMS = {
    "redirect", "redir", "url", "next", "goto", "dest", "destination",
    "return", "returnurl", "returnto", "target", "forward", "link",
    "ref", "referer", "checkout", "payment",
}

# Sensitive path keywords
SENSITIVE_PATH_WORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "validation",
    "account", "update", "confirm", "secure", "security",
    "bank", "password", "passwd", "credential", "auth",
    "wallet", "payment", "checkout", "billing",
]


# Brands targeted by typosquatting (Levenshtein-distance check)
TYPOSQUATTING_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "facebook",
    "apple", "instagram", "linkedin", "netflix", "dropbox",
    "twitter", "whatsapp",
]


def _levenshtein(a: str, b: str) -> int:
    """Compute edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — high entropy = random-looking domain."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())
import tldextract

def get_apex_domain(hostname: str):
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def extract_features_with_reasons(url: str):
    """
    Extract 23 numerical features + human-readable rule reasons from a URL.
    Returns: (features: list[float], reasons: list[str])
    """
    features = []
    reasons  = []
    url_lower = url.lower().strip()

    try:
        parsed = urlparse(url_lower if url_lower.startswith("http") else "http://" + url_lower)
        domain   = parsed.netloc or ""
        path     = parsed.path or ""
        query    = parsed.query or ""
        if not domain and path:
            domain = path.split("/")[0]

        # Use parsed.hostname: handles IPv6 brackets, automatically strips port,
        # and lowercases — much safer than manual domain.split(":")[0]
        hostname = (parsed.hostname or domain.split(":")[0]).strip().lower()

        # remove trailing dot (FQDN artefact)
        if hostname.endswith("."):
            hostname = hostname[:-1]

        # remove leading www.
        if hostname.startswith("www."):
            hostname = hostname[4:]
    except Exception:
        parsed = None
        domain = hostname = path = query = ""
    

    domain_age_days = 0

    if TRAINING_MODE or os.environ.get("PHISHGUARD_TRAINING") == "1":
        domain_age_days = 365
    else:
        try:
            w = whois.whois(hostname)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, str):
                creation_date = datetime.fromisoformat(creation_date)

            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
            else:
                domain_age_days = 9999

        except Exception:
            domain_age_days = 9999
    #*!0 Domain age
    features.append(domain_age_days)

    if domain_age_days < 30:
        reasons.append(f"Domain registered recently ({domain_age_days} days old)")
    # Threat intelligence check
    if TRAINING_MODE:
        is_threat = False
    else:
        is_threat = is_known_phishing(url)

    features.append(1 if is_threat else 0)

    if is_threat:
        reasons.append("URL found in phishing threat intelligence feed")

    # ── 1. URL total length ────────────────────────────────────────────────────
    url_len = len(url)
    features.append(url_len)
    if url_len > 75:
        reasons.append(f"URL is unusually long ({url_len} chars)")

    # ── 2. Dot count ──────────────────────────────────────────────────────────
    dot_count = url.count(".")
    features.append(dot_count)
    if dot_count > 4:
        reasons.append(f"Excessive dot count ({dot_count}) — subdomain abuse pattern")

    # ── 3. Hyphen count ───────────────────────────────────────────────────────
    hyphen_count = hostname.count("-")
    features.append(hyphen_count)
    if hyphen_count > 2:
        reasons.append(f"Many hyphens ({hyphen_count}) in domain — brand-spoofing indicator")

    # ── 4. Slash count ────────────────────────────────────────────────────────
    slash_count = url.count("/")
    features.append(slash_count)

    # ── 5. @ symbol ───────────────────────────────────────────────────────────
    has_at = "@" in url
    features.append(1 if has_at else 0)
    if has_at:
        reasons.append("Contains '@' — hides real destination after @")

    # ── 6. IP address as hostname ─────────────────────────────────────────────
    has_ip = bool(re.search(r"(?<!\d)(\d{1,3}\.){3}\d{1,3}(?!\d)", hostname))
    features.append(1 if has_ip else 0)
    if has_ip:
        reasons.append("Uses raw IP address instead of a domain name")

    # ── 7. HTTPS ──────────────────────────────────────────────────────────────
    is_https = url_lower.startswith("https")
    features.append(1 if is_https else 0)
    if not is_https:
        reasons.append("Not using HTTPS — unencrypted connection")

    # ── 8. Suspicious words in URL ────────────────────────────────────────────
    found_sensitive = [w for w in SENSITIVE_PATH_WORDS if w in url_lower]
    features.append(len(found_sensitive))
    if found_sensitive:
        reasons.append(f"Sensitive keywords in URL: {', '.join(found_sensitive[:4])}")

    # ── 9. Long URL flag (binary) ─────────────────────────────────────────────
    features.append(1 if url_len > 75 else 0)

    # ── 10. Subdomain count ───────────────────────────────────────────────────
    parts = hostname.split(".")
    apex_domain = get_apex_domain(hostname)
    subdomain_count = max(0, len(parts) - 2)
    features.append(subdomain_count)
    if subdomain_count > 2:
        reasons.append(f"Excessive subdomains ({subdomain_count}) — common in phishing URLs")

    # ── 11. Domain entropy ────────────────────────────────────────────────────
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    apex_name = apex.split(".")[0]
    entropy = round(_shannon_entropy(apex_name), 4)
    features.append(entropy)
    if entropy > 3.8:
        reasons.append(f"High domain entropy ({entropy:.2f}) — likely randomly generated domain")

    # ── 12. Suspicious TLD ────────────────────────────────────────────────────
    tld = "." + parts[-1] if parts else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    features.append(1 if is_suspicious_tld else 0)
    if is_suspicious_tld:
        reasons.append(f"Suspicious TLD '{tld}' — frequently abused in phishing campaigns")

    # ── 13. URL shortener ─────────────────────────────────────────────────────
    # Use apex_domain for shortener detection so subdomains of shorteners are caught
    # (e.g. "go.bit.ly" → apex "bit.ly" matches).  endswith(tuple) was wrong because
    # it also matched unrelated domains that merely ended with the same character sequence.
    is_shortener = apex_domain in URL_SHORTENERS
    features.append(1 if is_shortener else 0)
    if is_shortener:
        reasons.append("URL shortener detected — masks true destination")

    # ── 14. Brand keyword impersonation ───────────────────────────────────────
    found_brands = [b for b in BRAND_KEYWORDS if b in url_lower]
    brand_not_in_apex = found_brands and not any(b in apex for b in found_brands)
    features.append(1 if brand_not_in_apex else 0)
    if brand_not_in_apex:
        reasons.append(f"Brand keyword(s) '{', '.join(found_brands[:2])}' in path/subdomain — impersonation attempt")

    # ── 15. Digit ratio in domain ─────────────────────────────────────────────
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    features.append(round(digit_ratio, 4))
    if digit_ratio > 0.3:
        reasons.append(f"High digit ratio ({digit_ratio:.0%}) in domain — auto-generated domain pattern")

    # ── 16. Special char ratio in URL ─────────────────────────────────────────
    special_chars = sum(1 for c in url if c in "%=&?#~_;,")
    special_ratio = special_chars / max(len(url), 1)
    features.append(round(special_ratio, 4))
    if special_ratio > 0.15:
        reasons.append(f"High special-character ratio ({special_ratio:.0%}) — encoded/obfuscated URL")

    # ── 17. Suspicious query parameters ──────────────────────────────────────
    try:
        qparams = set(parse_qs(query).keys())
        has_suspicious_params = bool(qparams & SUSPICIOUS_PARAMS)
    except Exception:
        has_suspicious_params = False
    features.append(1 if has_suspicious_params else 0)
    if has_suspicious_params:
        reasons.append("Suspicious redirect/forwarding query parameters detected")

    # ── 18. Path depth ────────────────────────────────────────────────────────
    path_depth = len([p for p in path.split("/") if p])
    features.append(path_depth)

    # ── 19. Double slash in path (//url= tricks) ─────────────────────────────
    has_double_slash = "//" in path
    features.append(1 if has_double_slash else 0)
    if has_double_slash:
        reasons.append("Double slash in path — open redirect indicator")

    # ── 20. Punycode / IDN homograph ─────────────────────────────────────────
    has_punycode = "xn--" in hostname
    features.append(1 if has_punycode else 0)
    if has_punycode:
        reasons.append("Punycode (IDN homograph) detected — visually spoofs trusted domain")

    # ── 21. Port in URL ───────────────────────────────────────────────────────
    has_non_std_port = bool(re.search(r":\d{2,5}", domain)) and not domain.endswith(":80") and not domain.endswith(":443")
    features.append(1 if has_non_std_port else 0)
    if has_non_std_port:
        reasons.append("Non-standard port in URL — atypical for legitimate sites")

    # ── 22. Embedded URL/redirect in path ─────────────────────────────────────
    # Only flag explicit redirect parameters (url=, http://, https://) — not any
    # path segment that happens to contain the substring "http" (e.g. /httpbin/).
    has_url_in_path = "url=" in url_lower or re.search(r"https?://", path) is not None
    features.append(1 if has_url_in_path else 0)
    if has_url_in_path:
        reasons.append("Embedded URL/redirect in path — redirect-chain phishing pattern")

    # ── 23. TLD in path (e.g. .com appearing mid-path) ───────────────────────
    tld_in_path = bool(re.search(r"\.(com|net|org|info|co|io)/", path))
    features.append(1 if tld_in_path else 0)
    if tld_in_path:
        reasons.append("TLD token appearing mid-path — domain-confusion technique")
    #*new features
    # ── 24. Redirect count ─────────────────────────────────────
    

    redirects = 0
    if TRAINING_MODE:
        redirects = 0

    if TRAINING_MODE or os.environ.get("PHISHGUARD_TRAINING") == "1":
        redirects = 0
    else:
        try:
            r = requests.head(url, allow_redirects=True, timeout=3)
            redirects = len(r.history)
        except:
            redirects = 0

    features.append(redirects)

    if redirects > 2:
        reasons.append(f"Multiple redirects detected ({redirects})")


    # ── 25. Suspicious keyword density ─────────────────────────
    suspicious_keywords = ["login","verify","secure","account","update","bank","signin"]

    keyword_hits = sum(1 for k in suspicious_keywords if k in url_lower)

    features.append(keyword_hits)

    if keyword_hits > 1:
        reasons.append(f"Multiple phishing keywords detected ({keyword_hits})")


    # ── 26. URL randomness score ───────────────────────────────
    url_entropy = _shannon_entropy(apex_name)

    features.append(round(url_entropy, 4))

    if url_entropy > 4.2:
        reasons.append("Highly random URL structure — algorithmically generated link")

    # ── 27. Typosquatting detection ────────────────────────────────────────────
    # Compare the apex domain name (without TLD) against known brand keywords
    # using Levenshtein distance. Flag if edit distance <= 2 but it is NOT
    # the real brand domain (prevents false-positive on e.g. paypal.com itself).
    apex_name_for_typo = apex_name
    typosquatting_flag = 0
    for brand in TYPOSQUATTING_BRANDS:
        dist = _levenshtein(apex_name_for_typo, brand)
        if dist <= 2 and brand not in apex:
            typosquatting_flag = 1
            reasons.append(
                f"Domain appears to imitate trusted brand '{brand}' (typosquatting)"
            )
            break   # one flag is enough
    features.append(typosquatting_flag)

    if TRAINING_MODE or os.environ.get("PHISHGUARD_TRAINING") == "1":
        is_legit = False
    else:
        # Hardcode major safe shorteners in case threat_intel.py misses them
        SAFE_SHORTENERS = {"youtu.be", "t.co", "aka.ms", "1drv.ms", "g.co"}
        is_legit = is_legitimate_domain(hostname) or hostname in SAFE_SHORTENERS

    features.append(1 if is_legit else 0)

    # NOTE: is_legit is intentionally NOT added to reasons.
    # It is a safety signal used by predict_url() to gate classification,
    # not a threat indicator. Adding it to reasons inflated rule_score
    # and caused legitimate top-1M domains to be falsely escalated to PHISHING.
    

    assert len(features) == FEATURE_COUNT, f"Feature count mismatch: got {len(features)}, expected {FEATURE_COUNT}"
    return features, reasons


# ── Dataset Loading & Training ─────────────────────────────────────────────────
def _load_and_train() -> RandomForestClassifier:

    logger.info("🔧 Training improved URL detection model (v3.0) from datasets…")

    dataset_path = os.path.join(DATA_DIR, "combined_dataset.csv")

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Training dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)

    logger.info(f"   Loaded combined dataset: {len(df)} rows")

    df = df.drop_duplicates(subset=["url"]).dropna()

    df["url"] = df["url"].astype(str).str.strip().str.lower()

    phish = df[df.label == 1]
    safe  = df[df.label == 0]

    if len(phish) == 0 or len(safe) == 0:
        raise ValueError("Dataset must contain both phishing and safe URLs")

    safe = safe.sample(len(phish), random_state=42)

    df = pd.concat([phish, safe]).sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(f"   Balanced dataset: {len(df)} rows ({len(phish)} each class)")


    logger.info("   Extracting features in parallel…")

    from multiprocessing import Pool, cpu_count

    # Use module-level worker function (multiprocessing-safe)
    with Pool(max(1, cpu_count() - 1)) as p:
        X = p.map(_extract_features_worker, df["url"])

    # remove failed rows
    Xy = [(x, y) for x, y in zip(X, df["label"]) if x is not None]

    X = [x for x, _ in Xy]
    y = [y for _, y in Xy]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Tuned RandomForest: more trees, depth-limited to reduce overfitting
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=3,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    pred  = model.predict(X_test)
    acc   = accuracy_score(y_test, pred)
    logger.info(f"   ✅ Model trained — accuracy: {acc:.4f}")
    logger.info("\n" + classification_report(y_test, pred))

    # Attach metadata so stale model detection works
    model._phishguard_feature_count = FEATURE_COUNT

    return model


def load_or_train_model() -> RandomForestClassifier:
    """
    Load model.pkl if it exists AND was built with the current feature count.
    Otherwise retrain and save.
    """
    global TRAINING_MODE
    TRAINING_MODE = True
    os.environ["PHISHGUARD_TRAINING"] = "1"
    
    try:
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    model = pickle.load(f)
                # Validate feature count compatibility
                if getattr(model, "_phishguard_feature_count", None) == FEATURE_COUNT:
                    logger.info(f"📦 Loaded pre-trained model from {MODEL_PATH}")
                    return model
                else:
                    logger.warning("⚠ Stale model (feature count mismatch) — retraining…")
                    os.remove(MODEL_PATH)
            except Exception as e:
                logger.warning(f"⚠ Could not load model ({e}) — retraining…")
                if os.path.exists(MODEL_PATH):
                    os.remove(MODEL_PATH)

        model = _load_and_train()
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        logger.info(f"💾 Model saved to {MODEL_PATH}")
        return model
        
    finally:
        # BUG FIX: Guarantee training mode flags are destroyed so live scans work!
        TRAINING_MODE = False
        os.environ.pop("PHISHGUARD_TRAINING", None)
    


# ── Module-level model reference ──────────────────────────────────────────────
_model: RandomForestClassifier | None = None


def set_model(model: RandomForestClassifier) -> None:
    global _model
    _model = model


# ── Feature metadata for human-readable ML explanations ─────────────────────
_FEATURE_META = [

    (2,  lambda url,f: f"URL length ({int(f[2])} chars) associated with phishing URLs"),

    (3,  lambda url,f: f"High dot count ({int(f[3])}) — subdomain abuse pattern"),

    (4,  lambda url,f: f"Hyphen count ({int(f[4])}) typical of spoofed domains"),

    (7,  lambda url,f: "Raw IP address used as hostname — strong phishing indicator"),

    (8,  lambda url,f: "Plain HTTP instead of HTTPS — phishing pages often avoid encryption"),

    (9,  lambda url,f: "Credential-harvesting keywords detected in URL"),

    (11, lambda url,f: f"Excessive subdomains ({int(f[11])}) — common in phishing infrastructure"),

    (12, lambda url,f: f"High domain entropy ({f[12]:.2f}) — randomly generated domain"),

    (13, lambda url,f: "Suspicious TLD frequently abused in phishing campaigns"),

    (14, lambda url,f: "URL shortener used — destination hidden"),

    (15, lambda url,f: "Brand keyword used outside apex domain — impersonation attempt"),

    (16, lambda url,f: f"Digit-heavy domain ({f[16]:.0%}) — auto-generated hostname"),

    (20, lambda url,f: "Double slash in path — open redirect indicator"),

    (21, lambda url,f: "Punycode / IDN homograph detected — visual domain spoofing"),

    (23, lambda url,f: "Embedded URL in path — redirect chain phishing"),

    (24, lambda url,f: "TLD token appearing mid-path — domain confusion technique"),

    (25, lambda url,f: f"Multiple redirects detected ({int(f[25])})"),

    (26, lambda url,f: f"Multiple phishing keywords detected ({int(f[26])})"),

    (27, lambda url,f: "Highly random URL structure — algorithmically generated link"),

    (28, lambda url,f: "Domain resembles trusted brand — typosquatting detected"),

]


def _ml_fallback_reasons(url: str, features: list, phishing_prob: float) -> list:
    reasons = []
    importances = getattr(_model, "feature_importances_", None)

    if importances is not None and len(importances) == len(features):
        weighted = [(imp * (abs(fv) + 0.01), idx)
                    for idx, (imp, fv) in enumerate(zip(importances, features))]
        weighted.sort(reverse=True)
        top_indices = {idx for _, idx in weighted[:5]}
    else:
        top_indices = set(range(len(features)))

    # Map the actual suspicious thresholds for each feature index
    thresholds = {
        2: lambda f: f[2] > 75,       # URL length
        3: lambda f: f[3] > 4,        # Dot count
        4: lambda f: f[4] > 2,        # Hyphen count
        7: lambda f: f[7] > 0,        # IP as hostname
        8: lambda f: f[8] == 0,       # is_https (inverted, 0 means plain HTTP)
        9: lambda f: f[9] > 0,        # Sensitive words
        11: lambda f: f[11] > 2,      # Subdomain count
        12: lambda f: f[12] > 3.8,    # Domain entropy
        13: lambda f: f[13] > 0,      # Suspicious TLD
        14: lambda f: f[14] > 0,      # URL shortener
        15: lambda f: f[15] > 0,      # Brand impersonation
        16: lambda f: f[16] > 0.3,    # Digit ratio
        20: lambda f: f[20] > 0,      # Double slash
        21: lambda f: f[21] > 0,      # Punycode
        23: lambda f: f[23] > 0,      # Embedded URL
        24: lambda f: f[24] > 0,      # TLD in path
        25: lambda f: f[25] > 2,      # Redirects
        26: lambda f: f[26] > 1,      # Keyword hits
        27: lambda f: f[27] > 4.2,    # URL entropy
        28: lambda f: f[28] > 0,      # Typosquatting
    }

    for feat_idx, desc_fn in _FEATURE_META:
        # Check against the proper threshold, default to > 0 for booleans
        is_triggered_fn = thresholds.get(feat_idx, lambda f: f[feat_idx] > 0)
        
        if feat_idx in top_indices and is_triggered_fn(features):
            try:
                reasons.append(desc_fn(url, features))
            except Exception:
                pass

    confidence_pct = round(phishing_prob * 100, 1)
    reasons.append(
        f"ML model flagged this URL with {confidence_pct}% phishing probability "
        f"based on statistical patterns across ~68,000 known URLs"
    )

    # Deduplicate
    seen, unique = set(), []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


# ── Rule-based scoring overlay ────────────────────────────────────────────────
def _rule_score(reasons: list) -> float:
    """
    Convert reason count to a 0-1 additive score that boosts ML probability.
    Each triggered reason adds weight; soft-capped via exponential.
    """
    if not reasons:
        return 0.0
    raw = len(reasons) * 0.12
    return round(1.0 - math.exp(-raw), 4)


# ── Prediction ────────────────────────────────────────────────────────────────
def predict_url(url: str) -> dict:
    if _model is None:
        raise RuntimeError("Model not initialised. Call set_model() first.")

    features, reasons = extract_features_with_reasons(url)
    proba = _model.predict_proba([features])[0]

    ml_phishing_prob = float(proba[1])
    ml_safe_prob     = float(proba[0])

    # ── Feature index for is_legit (last feature, index 29) ───────────────────
    is_legit_flag = bool(features[-1])

    # ── Safety guard 1: Whitelist bypass ──────────────────────────────────────
    # If the domain is verified legitimate, heavily suppress the ML probability
    # BEFORE logging it or calculating the hybrid score.
    if is_legit_flag:
        is_open_redirect = bool(features[22]) # Feature 23: Embedded URL
        if not is_open_redirect:
            ml_phishing_prob = min(ml_phishing_prob, 0.05)
            ml_safe_prob = 1.0 - ml_phishing_prob
            # Clear ML-generated fallback reasons since we are overriding it
            reasons = [r for r in reasons if "High domain entropy" not in r and "High digit ratio" not in r]

    # Now the debug logs will show the accurate, clamped probabilities
    print("\n==== DEBUG URL ANALYSIS ====")
    print("URL:", url)
    print("ML phishing probability:", ml_phishing_prob)
    print("ML safe probability:", ml_safe_prob)
    print("Feature count:", len(features))
    print("Last feature (is_legit):", features[-1])
    print("Reasons:", reasons)
    print("Rule score:", _rule_score(reasons))
    print("============================\n")

    if is_legit_flag and ml_phishing_prob <= 0.05:
        return {
            "label": "SAFE",
            "confidence": ml_safe_prob,
            "risk_tier": "LOW",
            "ml_probability": ml_phishing_prob,
            "rule_score": 0.0,
            "reasons": ["Verified legitimate domain (ML path analysis bypassed)"],
            "detection_mode": "whitelist"
        }

    # Rule-based overlay
    rule_boost = _rule_score(reasons)

    # Hybrid score: weighted combination
    final_prob = (ml_phishing_prob * 0.65) + (rule_boost * 0.35)
    final_prob = round(min(final_prob, 1.0), 4)

    # ── Safety guard 2: ML-floor cap ──────────────────────────────────────────
    # Rule score alone cannot promote a URL to PHISHING.  If the ML model
    # assigns < 40% phishing probability, cap the label at SUSPICIOUS even if
    # the weighted hybrid score exceeds 0.65.
    if ml_phishing_prob < 0.40 and final_prob >= 0.65:
        final_prob = 0.64   # clamp just below PHISHING threshold

    # Classification
    if final_prob >= 0.65:
        label = "PHISHING"
        risk_tier = "HIGH"
        confidence = final_prob
    elif final_prob >= 0.35:
        label = "SUSPICIOUS"
        risk_tier = "MEDIUM"
        confidence = final_prob
    else:
        label = "SAFE"
        risk_tier = "LOW"
        confidence = round(ml_safe_prob, 4)

    # ── Detection mode ─────────────────────────────────────────────────────────
    # Assign BEFORE the reasons-fallback block so the mode always reflects
    # how the label was actually determined.
    if label in ("PHISHING", "SUSPICIOUS"):
        if reasons:
            detection_mode = "hybrid" if ml_phishing_prob >= 0.40 else "rule-based"
        else:
            detection_mode = "ml-pattern"
    else:
        detection_mode = "safe"

    # Ensure PHISHING/SUSPICIOUS never have empty reasons
    if label in ("PHISHING", "SUSPICIOUS") and not reasons:
        reasons = _ml_fallback_reasons(url, features, ml_phishing_prob)
        detection_mode = "ml-pattern"

    return {
        "label":          label,
        "confidence":     confidence,
        "risk_tier":      risk_tier,
        "ml_probability": round(ml_phishing_prob, 4),
        "rule_score":     rule_boost,
        "reasons":        reasons,
        "detection_mode": detection_mode,
    }


# ── CLI entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mdl = load_or_train_model()
    set_model(mdl)

    user_url = input("\nEnter URL to check: ").strip()
    result   = predict_url(user_url)
    label    = result["label"]
    conf     = result["confidence"] * 100
    icon     = "🚨" if label == "PHISHING" else ("⚠️" if label == "SUSPICIOUS" else "✅")
    print(f"\n{icon}  {label}  ({conf:.1f}% confidence)  [{result['risk_tier']} RISK]")
    if result["reasons"]:
        print("Reasons:")
        for r in result["reasons"]:
            print(f"  • {r}")
    else:
        print("No risk patterns detected.")