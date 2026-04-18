import os
import requests
import zipfile
import io
import tldextract

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)  # Ensure the data directory exists

# -----------------------------
# Feed URLs
# -----------------------------
OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
UMBRELLA_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# -----------------------------
# Global in-memory databases
# -----------------------------
OPENPHISH_DB = set()
PHISHTANK_DB = set()
URLHAUS_DB = set()
LEGITIMATE_DOMAINS = set()  # Master whitelist


# -----------------------------
# Threat Feed Loaders
# -----------------------------
def load_openphish():
    try:
        r = requests.get(OPENPHISH_URL, timeout=10)
        urls = set(r.text.splitlines())
        print(f"[ThreatIntel] Loaded {len(urls)} OpenPhish URLs")
        return urls
    except Exception as e:
        print("[ThreatIntel] OpenPhish load failed:", e)
        return set()

def load_phishtank():
    try:
        r = requests.get(PHISHTANK_URL, timeout=10)
        data = r.json()
        urls = {item["url"] for item in data}
        print(f"[ThreatIntel] Loaded {len(urls)} PhishTank URLs")
        return urls
    except Exception as e:
        print("[ThreatIntel] PhishTank load failed:", e)
        return set()

def load_urlhaus():
    try:
        r = requests.get(URLHAUS_URL, timeout=10)
        urls = {line.strip() for line in r.text.splitlines() if not line.startswith("#")}
        print(f"[ThreatIntel] Loaded {len(urls)} URLHaus URLs")
        return urls
    except Exception as e:
        print("[ThreatIntel] URLHaus load failed:", e)
        return set()


# -----------------------------
# Legitimate Domain Loaders
# -----------------------------
def _ensure_tranco_list():
    """Download the 150MB Tranco list on startup so it doesn't break GitHub."""
    file_path = os.path.join(DATA_DIR, "tranco_L6j4.csv")
    if not os.path.exists(file_path):
        print("[ThreatIntel] Downloading latest Tranco top 1M list...")
        try:
            r = requests.get(TRANCO_URL, timeout=30)
            r.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                csv_filename = z.namelist()[0]
                with open(file_path, "wb") as f:
                    f.write(z.read(csv_filename))
            print("[ThreatIntel] ✅ Tranco list downloaded successfully!")
        except Exception as e:
            print(f"[ThreatIntel] Failed to download Tranco list: {e}")

def load_legitimate_domains():
    """Loads Tranco, Local Top-1M, and Umbrella into a single master whitelist."""
    global LEGITIMATE_DOMAINS
    
    # 1. Ensure Tranco is downloaded
    _ensure_tranco_list()

    # 2. Load Local/Downloaded CSVs
    files = ["top-1m.csv", "tranco_L6j4.csv"]
    for fname in files:
        path = os.path.join(DATA_DIR, fname)
        if not os.path.exists(path):
            continue
            
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                        
                    parts = line.split(",")
                    raw_domain = parts[0] if len(parts) == 1 else parts[-1]
                    
                    # Safely extract root domain (e.g., mail.google.com -> google.com)
                    ext = tldextract.extract(raw_domain)
                    if ext.domain and ext.suffix:
                        LEGITIMATE_DOMAINS.add(f"{ext.domain}.{ext.suffix}")
        except Exception as e:
            print(f"[ThreatIntel] Failed loading {fname}:", e)

    # 3. Download and merge Umbrella Top 100k
    try:
        r = requests.get(UMBRELLA_URL, timeout=15)
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            data = z.read(z.namelist()[0]).decode()
            
            # Limit to top 100k to save memory
            for line in data.splitlines()[:100000]:
                parts = line.split(",")
                if len(parts) > 1:
                    ext = tldextract.extract(parts[1].strip())
                    if ext.domain and ext.suffix:
                        LEGITIMATE_DOMAINS.add(f"{ext.domain}.{ext.suffix}")
    except Exception as e:
        print("[ThreatIntel] Legit domain load failed:", e)

    print(f"[ThreatIntel] Total legitimate domains loaded: {len(LEGITIMATE_DOMAINS)}")


# -----------------------------
# Initialize Threat Intel
# -----------------------------
def initialize_threat_intel():
    global OPENPHISH_DB, PHISHTANK_DB, URLHAUS_DB
    OPENPHISH_DB = load_openphish()
    PHISHTANK_DB = load_phishtank()
    URLHAUS_DB = load_urlhaus()
    load_legitimate_domains()


# -----------------------------
# Helper Check Functions
# -----------------------------
def is_known_phishing(url: str):
    return url in OPENPHISH_DB or url in PHISHTANK_DB or url in URLHAUS_DB

def is_legitimate_domain(domain: str) -> bool:
    """
    Check whether a hostname belongs to a known-legitimate domain.
    Uses tldextract to bulletproof against 2-part TLDs (like .gov.in).
    """
    if not LEGITIMATE_DOMAINS:
        load_legitimate_domains()

    # Extract the registered root domain safely
    ext = tldextract.extract(domain)
    
    if ext.domain and ext.suffix:
        root_domain = f"{ext.domain}.{ext.suffix}"
        return root_domain in LEGITIMATE_DOMAINS
        
    return False