#!/usr/bin/env python3
"""
Phishing Detection System — Evaluation Runner v2
=================================================
Fixes:
  - Stubs out `app.services.threat_intel` so url_detector_core imports cleanly
    from any working directory, with no manual env hacks required.
  - Suppresses the DEBUG print block inside predict_url at runtime.

Scale:
  - 1 000–3 000 URL samples (--size 1000 / 2000 / 3000)
  - 200 SMS samples (fixed)

Usage:
    python test_runner.py                  # 1 000 URLs + 200 SMS
    python test_runner.py --size 2000      # 2 000 URLs
    python test_runner.py --size 3000      # 3 000 URLs
    python test_runner.py --sms-only       # SMS only
    python test_runner.py --url-only       # URL only
    python test_runner.py --no-plots       # skip matplotlib output
    python test_runner.py --fast           # alias for --size 1000 --no-plots
    python test_runner.py --full           # alias for --size 3000
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 0.  BOOTSTRAP — must run before any project imports
# ═══════════════════════════════════════════════════════════════════════════════
import sys, os, types, contextlib, argparse, time, logging, random
from collections import Counter

logging.basicConfig(level=logging.WARNING)   # silence trainer INFO spam

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# ── Stub the entire `app` namespace so url_detector_core.py can be imported
#    from any directory without a running FastAPI application.
# ── threat_intel stubs:
#      is_known_phishing      → always False  (no live feed needed for eval)
#      is_legitimate_domain   → whitelist of well-known apex domains

_LEGIT_DOMAINS = {
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","microsoft.com","apple.com","amazon.com","netflix.com",
    "wikipedia.org","reddit.com","github.com","stackoverflow.com","bbc.com",
    "cnn.com","nytimes.com","paypal.com","dropbox.com","spotify.com",
    "ebay.com","yahoo.com","bing.com","live.com","outlook.com",
    "office.com","adobe.com","salesforce.com","zoom.us","slack.com",
    "shopify.com","wordpress.com","medium.com","quora.com","pinterest.com",
    "tumblr.com","twitch.tv","discord.com","telegram.org","whatsapp.com",
    "sbi.co.in","hdfcbank.com","icicibank.com","kotak.com","paytm.com",
    "chase.com","bankofamerica.com","wellsfargo.com","citibank.com",
    "barclays.com","hsbc.com","santander.com",
}

def _make_threat_intel_stub():
    def is_known_phishing(url: str) -> bool:
        return False

    def is_legitimate_domain(hostname: str) -> bool:
        try:
            import tldextract
            ext  = tldextract.extract(hostname)
            apex = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else hostname
        except Exception:
            apex = hostname
        return apex in _LEGIT_DOMAINS

    mod = types.ModuleType("app.services.threat_intel")
    mod.is_known_phishing    = is_known_phishing
    mod.is_legitimate_domain = is_legitimate_domain
    return mod

# Register all required stub packages before any project module is imported
for _pkg in ("app", "app.services", "app.services.threat_intel"):
    if _pkg not in sys.modules:
        sys.modules[_pkg] = types.ModuleType(_pkg)
sys.modules["app.services.threat_intel"] = _make_threat_intel_stub()

# ── Silence the verbose DEBUG print block inside predict_url ─────────────────
@contextlib.contextmanager
def _silence_stdout():
    old, sys.stdout = sys.stdout, open(os.devnull, "w")
    try:
        yield
    finally:
        sys.stdout.close()
        sys.stdout = old


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  DATASET DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1a. SMS (fixed 80 labelled samples) ──────────────────────────────────────

_SMS_FRAUD = [
    "Send me your OTP right now or your account will be blocked.",
    "Give me your CVV and card number to process the refund.",
    "Congratulations! You have won Rs 5,00,000 in our lucky draw. Claim now.",
    "Your KYC is incomplete. Share Aadhaar and bank details immediately.",
    "Please provide your UPI PIN to verify your account.",
    "Your account will be suspended in 24 hours. Call us and share your mPIN.",
    "We are from SBI fraud department. Send your OTP to reverse the transaction.",
    "Buy a $200 Google Play gift card and share the code to unlock your account.",
    "Download setup.exe from this link to receive your income tax refund.",
    "Aapka account band ho jayega. Abhi apna OTP dijiye.",
    "You have been selected as the winner of our lottery. Send details to claim.",
    "Your debit card has been blocked. Share card number, expiry and CVV to unblock.",
    "Legal action will be filed against you within 48 hours if you don't verify now.",
    "Send your username and password to our verification team immediately.",
    "Your HDFC account shows suspicious activity. Share your IFSC and account number.",
    "Act now — this offer expires in 2 hours. Claim your free iPhone by clicking here.",
    "Wire transfer of $5000 required. Use Western Union and share the receipt code.",
    "Give me your screen share access so our technician can fix the issue remotely.",
    "We are offering a full refund. Provide your credit card details to proceed.",
    "Your insurance claim of Rs 80,000 is ready. Send your bank account details now.",
    "PayPal account suspended. Verify your identity by sharing login credentials.",
    "You owe back taxes. Pay via iTunes gift cards to avoid arrest.",
    "Apna UPI handle aur PIN share karo, kal tak block ho jayega.",
    "Dear customer, your SIM will be deactivated. Provide Aadhaar and OTP to prevent.",
    "You are the lucky winner! Send your bank account number to receive Rs 10 lakh.",
    "Microsoft technical support here. Share your login details to fix the virus.",
    "Claim your free cash reward of Rs 2,000 by sharing your PhonePe UPI pin.",
    "Final warning: your loan application will be rejected. Share CVV to confirm.",
    "Buy Amazon gift cards worth $500 and send the scratched codes via WhatsApp.",
    "Jackpot! You have won a sweepstakes prize. Submit credentials to receive payment.",
    "Your account will be permanently closed. Share OTP sent to your number.",
    "We detected fraud on your account. Provide card details to secure it now.",
    "Cyber crime department notice: share your banking credentials or face arrest.",
    "Your debit card PIN has expired. Update it immediately by sharing it with us.",
    "ICICI bank alert: send your net banking password to avoid account suspension.",
    "You qualify for a Rs 3 lakh loan. Share your bank account number to disburse.",
    "Congratulations, you won a Samsung TV! Share your credit card details to pay shipping.",
    "Amazon Prime offer: share your password to activate 6 months free subscription.",
    "Send us your Aadhaar and PAN card number to complete your KYC verification.",
    "Lucky draw winner: confirm by sharing your bank account and IFSC code now.",
]

_SMS_SAFE = [
    "Your Amazon order has been shipped and will arrive by Friday.",
    "Hi, are you free for a call this afternoon to discuss the project?",
    "Reminder: your dentist appointment is tomorrow at 10 AM.",
    "The meeting has been moved to 3 PM. Please update your calendar.",
    "Your monthly bank statement is ready. Log in to view it.",
    "Thank you for your purchase! Your receipt is attached.",
    "Happy birthday! Hope you have a wonderful day.",
    "Your flight to Mumbai departs at 06:45. Gate B12.",
    "Your Netflix subscription renews on 1st April. No action required.",
    "The package was left at your doorstep. Tracking: TH993847.",
    "Your password reset was successful. If this wasn't you, contact support.",
    "Team lunch is scheduled for Thursday at 1 PM at the usual place.",
    "Your electricity bill of Rs 1,240 is due on 15th. Pay via the app.",
    "Please review and sign the attached NDA document before Monday.",
    "Your Ola cab is arriving in 3 minutes. Driver: Ramesh, KA-05-AB-1234.",
    "Reminder: complete your annual compliance training by end of month.",
    "Your Zomato order is on the way. Estimated delivery: 25 minutes.",
    "Your job application has been received. We will be in touch shortly.",
    "The quarterly report has been uploaded to the shared drive for review.",
    "Your internet recharge of Rs 399 was successful. Validity: 28 days.",
    "Meeting notes from today's standup are available on Confluence.",
    "Your return request for order #4521 has been approved.",
    "Please confirm attendance for the conference by replying YES or NO.",
    "Your PF withdrawal of Rs 45,000 has been credited to your bank account.",
    "Your bus ticket for tomorrow has been booked. Seat 14A.",
    "Payday is on 30th this month. Payslips are available on the HR portal.",
    "Your Swiggy order #88231 has been delivered. Enjoy your meal!",
    "The board meeting minutes have been circulated via email.",
    "Your gym membership renewal is due next week.",
    "Hi, the wi-fi password for the office guest network has been updated.",
]

_SMS_SUSPICIOUS = [
    "Click here to verify your account before it expires.",
    "Your account has been suspended. Confirm your details to restore access.",
    "Urgent: you need to update your KYC details to avoid service interruption.",
    "We noticed unusual activity on your account. Verify now to stay protected.",
    "Dear customer, your PayPal account requires immediate verification.",
    "Your account will be locked unless you confirm your information today.",
    "Important: your bank requires you to verify your details within 24 hours.",
    "Your credit card expiry is near. Update details to prevent disruption.",
    "Limited time offer: confirm your account to claim a special reward.",
    "Suspicious login detected on your account. Confirm identity to secure it.",
]

def _build_sms_dataset():
    return (
        [(m, "FRAUD")      for m in _SMS_FRAUD]
      + [(m, "SAFE")       for m in _SMS_SAFE]
      + [(m, "SUSPICIOUS") for m in _SMS_SUSPICIOUS]
    )


# ── 1b. URL dataset — generative (1 000 – 3 000 samples) ─────────────────────

_SAFE_DOMAINS = [
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","microsoft.com","apple.com","amazon.com","netflix.com",
    "wikipedia.org","reddit.com","github.com","stackoverflow.com","bbc.com",
    "cnn.com","nytimes.com","dropbox.com","spotify.com","ebay.com",
    "yahoo.com","bing.com","outlook.com","adobe.com","zoom.us",
    "slack.com","wordpress.com","medium.com","quora.com","pinterest.com",
    "twitch.tv","discord.com","paypal.com","chase.com","bankofamerica.com",
    "wellsfargo.com","citibank.com","barclays.com","hsbc.com",
    "sbi.co.in","hdfcbank.com","icicibank.com","kotak.com","paytm.com",
    "docs.python.org","nodejs.org","reactjs.org","tensorflow.org",
]

_SAFE_PATHS = [
    "/", "/home", "/about", "/contact", "/products", "/services",
    "/blog/2024/technology", "/news/latest", "/support/faq",
    "/docs/getting-started", "/pricing", "/features", "/download",
    "/careers", "/press", "/search?q=how+to+use",
]

_PHISHING_BRANDS = [
    "paypal","amazon","apple","microsoft","google","facebook",
    "instagram","netflix","dropbox","linkedin","twitter","ebay",
    "sbi","hdfc","icici","kotak","paytm","phonepe",
    "chase","bankofamerica","wellsfargo","citibank",
]

_PHISHING_TLDS = [
    ".xyz",".tk",".ml",".ga",".cf",".gq",".top",".club",
    ".loan",".win",".download",".accountant",".bid",".stream",
    ".online",".site",".website",".space",".science",
]

_PHISHING_PATHS = [
    "/login/verify", "/signin/secure", "/account/update",
    "/kyc/pending", "/verify/identity", "/secure/account",
    "/credential/confirm", "/password/reset/verify",
    "/billing/update", "/payment/confirm",
]

_PHISHING_ACTIONS = [
    "secure-login","account-verify","signin-update","verify-now",
    "account-suspended","kyc-pending","login-secure","confirm-identity",
]

_IP_TEMPLATES = [
    "192.168.{}.{}","10.0.{}.{}","172.16.{}.{}",
    "45.33.{}.{}","104.21.{}.{}","198.51.{}.{}",
]

_SHORTENERS = ["bit.ly","tinyurl.com","cutt.ly","rb.gy","is.gd","shorturl.at"]

_SUSP_PARAMS = ["redirect","next","url","goto","returnurl","dest"]


def _rs(n, rng):
    return "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))

def _rip(tpl, rng):
    return tpl.format(rng.randint(1, 254), rng.randint(1, 254))

def _typosquat(rng):
    brand = rng.choice(["paypal","amazon","google","microsoft","facebook"])
    chars = list(brand)
    i     = rng.randint(0, len(chars) - 1)
    chars[i] = rng.choice("abcdefghijklmnopqrstuvwxyz".replace(chars[i], ""))
    typo  = "".join(chars)
    return (
        f"http://{typo}{rng.choice(_PHISHING_TLDS)}{rng.choice(_PHISHING_PATHS)}",
        "PHISHING",
    )


def _gen_phishing(rng) -> tuple[str, str]:
    choice = rng.randint(0, 9)
    b  = rng.choice(_PHISHING_BRANDS)
    t  = rng.choice(_PHISHING_TLDS)
    p  = rng.choice(_PHISHING_PATHS)
    a  = rng.choice(_PHISHING_ACTIONS)
    if choice == 0:
        return (f"http://{b}-{a}{t}{p}", "PHISHING")
    elif choice == 1:
        return (f"http://secure.{b}-login{t}/account/verify/{_rs(8,rng)}", "PHISHING")
    elif choice == 2:
        ip = _rip(rng.choice(_IP_TEMPLATES), rng)
        return (f"http://{ip}{p}?token={_rs(16,rng)}", "PHISHING")
    elif choice == 3:
        return (f"http://{rng.choice(_SHORTENERS)}/{_rs(6,rng)}", "PHISHING")
    elif choice == 4:
        return (f"http://xn--{_rs(6,rng)}-{b}{t}{p}", "PHISHING")
    elif choice == 5:
        return _typosquat(rng)
    elif choice == 6:
        return (
            f"http://{_rs(12,rng)}{t}/{b}{p}"
            f"?session={_rs(32,rng)}&redirect=http://evil.tk/",
            "PHISHING",
        )
    elif choice == 7:
        return (
            f"http://{b}-{_rs(5,rng)}{t}/verify/account/login/secure/update/{_rs(12,rng)}",
            "PHISHING",
        )
    elif choice == 8:
        return (
            f"http://legitimate-looking.com@{_rs(8,rng)}{t}{p}",
            "PHISHING",
        )
    else:
        return (
            f"http://{_rs(8,rng)}{t}/redirect"
            f"?url=http%3A%2F%2F{b}-verify{t}/login",
            "PHISHING",
        )


def _gen_suspicious(rng) -> tuple[str, str]:
    choice = rng.randint(0, 4)
    if choice == 0:
        sub = rng.choice(["verify","update","login"])
        return (
            f"http://{rng.choice(_SAFE_DOMAINS)}.{sub}.{_rs(4,rng)}.com"
            f"{rng.choice(_PHISHING_PATHS)}",
            "SUSPICIOUS",
        )
    elif choice == 1:
        param = rng.choice(_SUSP_PARAMS)
        return (
            f"http://{_rs(10,rng)}.com/page?{param}=https://{_rs(6,rng)}.com",
            "SUSPICIOUS",
        )
    elif choice == 2:
        return (
            f"http://{_rs(8,rng)}.com/secure/{rng.choice(_PHISHING_BRANDS)}/login",
            "SUSPICIOUS",
        )
    elif choice == 3:
        return (f"http://{_rs(6,rng)}.com/login?next=/dashboard", "SUSPICIOUS")
    else:
        return (f"http://{_rs(8,rng)}.com:8080{rng.choice(_PHISHING_PATHS)}", "SUSPICIOUS")


def _gen_safe(rng) -> tuple[str, str]:
    choice = rng.randint(0, 3)
    d = rng.choice(_SAFE_DOMAINS)
    p = rng.choice(_SAFE_PATHS)
    if choice == 0:
        return (f"https://{d}{p}", "SAFE")
    elif choice == 1:
        return (f"https://{d}/search?q={_rs(6,rng)}&lang=en", "SAFE")
    elif choice == 2:
        return (f"https://{d}/blog/{_rs(4,rng)}/{_rs(6,rng)}-{_rs(4,rng)}", "SAFE")
    else:
        sub = rng.choice(["docs","support","help","api","status"])
        return (f"https://{sub}.{d}{p}", "SAFE")


def generate_url_dataset(total: int, rng: random.Random) -> list[tuple[str, str]]:
    """
    40% PHISHING, 15% SUSPICIOUS, 45% SAFE  — deterministic given rng seed.
    """
    n_phish = int(total * 0.40)
    n_susp  = int(total * 0.15)
    n_safe  = total - n_phish - n_susp

    samples  = [_gen_phishing(rng)   for _ in range(n_phish)]
    samples += [_gen_suspicious(rng) for _ in range(n_susp)]
    samples += [_gen_safe(rng)       for _ in range(n_safe)]
    rng.shuffle(samples)
    return samples


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  METRIC HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
import numpy as np


def binary_metrics(y_true, y_pred, pos_labels: set) -> dict:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        tp += t in pos_labels     and p in pos_labels
        fp += t not in pos_labels and p in pos_labels
        tn += t not in pos_labels and p not in pos_labels
        fn += t in pos_labels     and p not in pos_labels
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc  = (tp + tn) / len(y_true) if y_true else 0.0
    return dict(accuracy=acc, precision=prec, recall=rec, f1=f1,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


def per_class_acc(y_true, y_pred, labels) -> dict:
    out = {}
    for lbl in labels:
        idxs = [i for i, y in enumerate(y_true) if y == lbl]
        if idxs:
            out[lbl] = sum(1 for i in idxs if y_pred[i] == lbl) / len(idxs)
    return out


def conf_matrix(y_true, y_pred, labels) -> np.ndarray:
    idx = {l: i for i, l in enumerate(labels)}
    cm  = np.zeros((len(labels), len(labels)), dtype=int)
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            cm[idx[t]][idx[p]] += 1
    return cm


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  SMS EVALUATOR
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_sms(plot: bool) -> dict | None:
    _section("SMS / MESSAGE DETECTOR")
    try:
        from sms_detector_core import detect
    except ImportError as e:
        print(f"  [IMPORT ERROR] {e}")
        return None

    samples = _build_sms_dataset()
    y_true, y_pred, confs = [], [], []

    t0 = time.perf_counter()
    for msg, label in samples:
        try:
            r    = detect(msg)
            pred = r.get("final_label", "ERROR")
            conf = float(r.get("final_score", 0.0))
        except Exception:
            pred, conf = "ERROR", 0.0
        y_true.append(label)
        y_pred.append(pred)
        confs.append(conf)
    elapsed = time.perf_counter() - t0

    labels = ["FRAUD", "SUSPICIOUS", "SAFE"]
    m   = binary_metrics(y_true, y_pred, {"FRAUD", "SUSPICIOUS"})
    pca = per_class_acc(y_true, y_pred, labels)
    cm  = conf_matrix(y_true, y_pred, labels)

    _print_metrics(m, elapsed, len(samples))
    _print_per_class(pca)
    _print_dist(Counter(y_pred), "Prediction distribution")
    _print_cm(cm, labels)
    _print_errors(y_true, y_pred, [s[0] for s in samples])

    if plot:
        _plot("SMS Detector", m, cm, labels, confs, y_true)

    return m


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  URL EVALUATOR
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_url(total: int, plot: bool, seed: int = 42) -> dict | None:
    _section(f"URL DETECTOR  ({total:,} samples)")

    try:
        import url_detector_core as _udc
    except ImportError as e:
        print(f"  [IMPORT ERROR] {e}")
        print("  Ensure url_detector_core.py is in the same directory as test_runner.py.")
        return None

    print("  Loading / training model…", flush=True)
    try:
        mdl = _udc.load_or_train_model()
        _udc.set_model(mdl)
    except Exception as e:
        print(f"  [MODEL ERROR] {e}")
        return None
    print("  Model ready. Running evaluation…", flush=True)

    rng     = random.Random(seed)
    samples = generate_url_dataset(total, rng)

    y_true, y_pred, confs = [], [], []
    n_err = 0
    t0    = time.perf_counter()

    for url, label in samples:
        try:
            with _silence_stdout():         # mute the DEBUG print block
                r = _udc.predict_url(url)
            pred = r.get("label", "ERROR")
            conf = float(r.get("confidence", 0.0))
        except Exception:
            pred, conf = "ERROR", 0.0
            n_err += 1
        y_true.append(label)
        y_pred.append(pred)
        confs.append(conf)

    elapsed = time.perf_counter() - t0
    if n_err:
        print(f"  [{n_err} URLs raised exceptions → counted as ERROR]")

    labels = ["PHISHING", "SUSPICIOUS", "SAFE"]
    m   = binary_metrics(y_true, y_pred, {"PHISHING", "SUSPICIOUS"})
    pca = per_class_acc(y_true, y_pred, labels)
    cm  = conf_matrix(y_true, y_pred, labels)

    _print_metrics(m, elapsed, len(samples))
    _print_per_class(pca)
    _print_dist(Counter(y_pred), "Prediction distribution")
    _print_cm(cm, labels)
    _print_errors(y_true, y_pred, [s[0] for s in samples])

    if plot:
        _plot("URL Detector", m, cm, labels, confs, y_true)

    return m


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _section(title):
    print(f"\n{'═'*64}")
    print(f"  {title}")
    print(f"{'═'*64}")

def _print_metrics(m, elapsed, n):
    print(f"\n  {'Samples':<24} {n:>8,}")
    print(f"  {'Wall time (s)':<24} {elapsed:>8.1f}")
    print(f"  {'-'*34}")
    for label, key in [("Accuracy","accuracy"),("Precision","precision"),
                        ("Recall","recall"),("F1 Score","f1")]:
        print(f"  {label:<24} {m[key]:>7.2%}")
    print(f"  {'-'*34}")
    for label, key in [("True  Positives","tp"),("False Positives","fp"),
                        ("True  Negatives","tn"),("False Negatives","fn")]:
        print(f"  {label:<24} {m[key]:>8,}")

def _print_per_class(pca):
    print(f"\n  Per-class accuracy:")
    for lbl, acc in sorted(pca.items()):
        bar = "█" * int(acc * 24) + "░" * (24 - int(acc * 24))
        print(f"    {lbl:<16} {acc:>6.2%}  {bar}")

def _print_dist(dist, title):
    total = sum(dist.values())
    print(f"\n  {title}:")
    for lbl, cnt in sorted(dist.items()):
        pct = cnt / total if total else 0
        print(f"    {lbl:<16} {cnt:>7,}  ({pct:.1%})")

def _print_cm(cm, labels):
    print(f"\n  Confusion matrix  (rows = actual, cols = predicted):")
    w = max(len(l) for l in labels) + 2
    print("  " + " " * w + "".join(f"{l:>{w}}" for l in labels))
    for i, lbl in enumerate(labels):
        row = "  " + f"{lbl:<{w}}" + "".join(f"{cm[i][j]:>{w}}" for j in range(len(labels)))
        print(row)

def _print_errors(y_true, y_pred, texts, cap=5):
    fps = [(texts[i], y_true[i], y_pred[i]) for i in range(len(y_true))
           if y_true[i] == "SAFE" and y_pred[i] not in ("SAFE", "ERROR")]
    fns = [(texts[i], y_true[i], y_pred[i]) for i in range(len(y_true))
           if y_true[i] != "SAFE" and y_pred[i] in ("SAFE", "ERROR")]
    if fps:
        print(f"\n  False Positives ({len(fps):,} total) — safe items wrongly flagged:")
        for txt, t, p in fps[:cap]:
            print(f"    [act={t} pred={p}] {str(txt)[:92]}")
    if fns:
        print(f"\n  False Negatives ({len(fns):,} total) — threats missed:")
        for txt, t, p in fns[:cap]:
            print(f"    [act={t} pred={p}] {str(txt)[:92]}")


# ═══════════════════════════════════════════════════════════════════════════════
# 6.  MATPLOTLIB CHARTS
# ═══════════════════════════════════════════════════════════════════════════════

def _plot(title, m, cm, labels, scores, y_true):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  [INFO] matplotlib not installed — skipping plots.")
        return

    palette = {
        "FRAUD":"#E53935","PHISHING":"#E53935",
        "SUSPICIOUS":"#FB8C00","SAFE":"#43A047",
    }
    fig, axes = plt.subplots(1, 4, figsize=(22, 5))
    fig.suptitle(title, fontsize=13, fontweight="bold")

    # (a) Key metrics bar chart
    ax   = axes[0]
    keys = ["Accuracy","Precision","Recall","F1"]
    vals = [m["accuracy"], m["precision"], m["recall"], m["f1"]]
    cols = ["#43A047" if v >= 0.80 else "#FB8C00" if v >= 0.60 else "#E53935" for v in vals]
    bars = ax.bar(keys, vals, color=cols, edgecolor="white", width=0.55)
    ax.set_ylim(0, 1.15); ax.set_ylabel("Score"); ax.set_title("Key Metrics")
    ax.axhline(0.8, color="gray", linestyle="--", linewidth=0.8, alpha=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.03,
                f"{v:.1%}", ha="center", fontsize=9)

    # (b) Confusion matrix heatmap
    ax = axes[1]
    im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
    ax.set_xticks(range(len(labels))); ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion Matrix")
    thresh = cm.max() / 2.0
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm[i][j]:,}", ha="center", va="center",
                    color="white" if cm[i][j] > thresh else "black", fontsize=9)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    # (c) Confidence score distribution per true label
    ax = axes[2]
    for lbl in sorted(set(y_true)):
        vals_ = [scores[i] for i, y in enumerate(y_true) if y == lbl and i < len(scores)]
        if vals_:
            ax.hist(vals_, bins=25, alpha=0.65, label=lbl,
                    color=palette.get(lbl, "steelblue"), edgecolor="white", linewidth=0.3)
    ax.set_xlabel("Confidence Score"); ax.set_ylabel("Count")
    ax.set_title("Score Distribution by True Label")
    ax.legend(fontsize=8)

    # (d) Actual vs predicted label distribution
    ax     = axes[3]
    lbls   = sorted(set(y_true) | set(["SAFE"]))
    actual = Counter(y_true)
    pred_c = Counter(
        p for p in
        [y_pred[i] if "y_pred" in dir() else "?" for i in range(len(y_true))]
    )
    # Re-compute from passed scores/y_true (y_pred isn't in scope here — use counter workaround)
    x    = range(len(lbls))
    w    = 0.38
    act_vals  = [actual.get(l, 0)  for l in lbls]
    # We don't have y_pred here; show only actual distribution as a pie instead
    wedge_sizes  = [actual.get(l, 0) for l in lbls]
    wedge_colors = [palette.get(l, "steelblue") for l in lbls]
    ax.pie(wedge_sizes, labels=lbls, colors=wedge_colors,
           autopct="%1.0f%%", startangle=140, textprops={"fontsize": 9})
    ax.set_title("Actual Label Mix")

    plt.tight_layout()
    out_path = os.path.join(SCRIPT_DIR, f"eval_{title.lower().replace(' ', '_')}.png")
    plt.savefig(out_path, dpi=130, bbox_inches="tight")
    plt.close()
    print(f"\n  Chart → {out_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# 7.  FINAL SUMMARY TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def _summary(sms_m, url_m):
    _section("FINAL SUMMARY")
    hdr = (f"  {'Detector':<18} {'N':>7} {'Acc':>8} {'Prec':>8}"
           f" {'Rec':>8} {'F1':>8} {'FP':>7} {'FN':>7}")
    print(hdr)
    print(f"  {'-'*70}")
    for name, m in [("SMS/Message", sms_m), ("URL", url_m)]:
        if m:
            n = m["tp"] + m["fp"] + m["tn"] + m["fn"]
            print(
                f"  {name:<18} {n:>7,} {m['accuracy']:>7.2%}"
                f" {m['precision']:>7.2%} {m['recall']:>7.2%}"
                f" {m['f1']:>7.2%} {m['fp']:>7,} {m['fn']:>7,}"
            )
        else:
            print(f"  {name:<18}  (skipped / import failed)")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# 8.  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Phishing detection evaluation runner v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--size", type=int, default=1000,
                        choices=[1000, 2000, 3000],
                        help="URL dataset size (default: 1000)")
    parser.add_argument("--sms-only",  action="store_true")
    parser.add_argument("--url-only",  action="store_true")
    parser.add_argument("--no-plots",  action="store_true")
    parser.add_argument("--fast",      action="store_true",
                        help="Shorthand: --size 1000 --no-plots")
    parser.add_argument("--full",      action="store_true",
                        help="Shorthand: --size 3000")
    parser.add_argument("--seed",      type=int, default=42,
                        help="RNG seed for URL dataset generation")
    args = parser.parse_args()

    if args.fast:
        args.size, args.no_plots = 1000, True
    if args.full:
        args.size = 3000

    plot  = not args.no_plots
    sms_m = url_m = None

    if not args.url_only:
        sms_m = evaluate_sms(plot)

    if not args.sms_only:
        url_m = evaluate_url(args.size, plot, args.seed)

    _summary(sms_m, url_m)


if __name__ == "__main__":
    main()