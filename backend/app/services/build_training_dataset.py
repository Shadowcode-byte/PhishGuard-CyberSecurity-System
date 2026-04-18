
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

OUT_FILE = os.path.join(DATA_DIR, "combined_dataset.csv")


def load_phishing():
    phishing_urls = []

    # 1️⃣ Phishing Database text feed
    phish_txt = os.path.join(DATA_DIR, "phishing-links-ACTIVE1.txt")
    if os.path.exists(phish_txt):
        with open(phish_txt) as f:
            for line in f:
                url = line.strip()

                if not url:
                    continue

                if url.startswith("#"):
                    continue

                if not url.startswith("http"):
                    continue

                if len(url) > 2000:
                    continue

                phishing_urls.append(url)

    # 2️⃣ dataset_link_phishing.csv
    csv1 = os.path.join(DATA_DIR, "dataset_link_phishing.csv")
    if os.path.exists(csv1):
        df = pd.read_csv(csv1, low_memory=False)

        df = df[["url", "status"]]

        df = df[df["status"].astype(str).str.lower() == "phishing"]

        urls = df["url"].dropna().astype(str)

        urls = urls[urls.str.startswith("http")]

        phishing_urls.extend(urls.tolist())

    # 3️⃣ phishing_url_dataset_unique.csv
    csv2 = os.path.join(DATA_DIR, "phishing_url_dataset_unique.csv")
    if os.path.exists(csv2):
        df = pd.read_csv(csv2)

        df = df[["url", "label"]]

        df = df[df["label"] == 1]

        urls = df["url"].dropna().astype(str)

        urls = urls[urls.str.startswith("http")]

        phishing_urls.extend(urls.tolist())

    phishing_urls = list(set(phishing_urls))

    print("Loaded phishing URLs:", len(phishing_urls))

    return pd.DataFrame({
        "url": phishing_urls,
        "label": 1
    })


def load_safe():
    safe_urls = []

    # Tranco dataset
    tranco = os.path.join(DATA_DIR, "tranco_L6J4.csv")

    if os.path.exists(tranco):
        df = pd.read_csv(tranco, header=None)

        for domain in df.iloc[:,1]:
            safe_urls.append(f"https://{domain}")

    # Umbrella Top1M
    umbrella = os.path.join(DATA_DIR, "top-1m.csv")

    if os.path.exists(umbrella):
        df = pd.read_csv(umbrella, header=None)

        for domain in df.iloc[:,1]:
            safe_urls.append(f"https://{domain}")

    safe_urls = list(set(safe_urls))

    print("Loaded safe domains:", len(safe_urls))

    return pd.DataFrame({
        "url": safe_urls,
        "label": 0
    })


def main():

    phish = load_phishing()
    safe = load_safe()

    if len(phish) == 0:
        raise Exception("No phishing URLs loaded")

    if len(safe) == 0:
        raise Exception("No safe URLs loaded")

    # balance dataset
    safe = safe.sample(len(phish), random_state=42)

    df = pd.concat([phish, safe], ignore_index=True)

    # keep only correct columns
    df = df[["url", "label"]]

    # clean url column
    df["url"] = df["url"].astype(str).str.strip()

    # remove invalid rows
    df = df[df["url"].str.startswith("http")]

    # enforce label type
    df["label"] = df["label"].astype(int)

    # remove duplicates
    df = df.drop_duplicates(subset=["url"])

    # shuffle dataset
    df = df.sample(frac=1, random_state=42)

    print("Final dataset size:", len(df))

    df.to_csv(OUT_FILE, index=False)

    print("Saved:", OUT_FILE)


if __name__ == "__main__":
    main()
