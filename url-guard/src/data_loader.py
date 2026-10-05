"""
data_loader.py - load, normalise and merge URL datasets into one labelled table.

Output columns:
    url      cleaned URL string (whitespace stripped, original scheme kept if present)
    label    0 = Benign, 1 = Malicious
    source   which dataset the row came from (kaggle / urlhaus / openphish / tranco)
    domain   registered domain (used for domain-grouped splitting)
    subtype  original fine-grained class where available (phishing, malware, ...)
"""
from __future__ import annotations

import pandas as pd

from features import registered_domain, extract_features_df, normalize_url

LABELS = {0: "Benign", 1: "Malicious"}


# ------------------------------------------------------------------ readers
def load_kaggle(path: str) -> pd.DataFrame:
    """Kaggle 'Malicious URLs dataset' (malicious_phish.csv): columns url, type."""
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    url_col = "url"
    type_col = "type" if "type" in df.columns else "label"
    out = pd.DataFrame({"url": df[url_col], "subtype": df[type_col].astype(str).str.lower().str.strip()})
    out["label"] = (out["subtype"] != "benign").astype(int)
    out["source"] = "kaggle_main"
    return out


def _lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def load_urlhaus(path: str) -> pd.DataFrame:
    """URLhaus text feed: one URL per line, '#' comment lines."""
    return pd.DataFrame({"url": _lines(path), "label": 1, "source": "urlhaus", "subtype": "malware"})


def load_openphish(path: str) -> pd.DataFrame:
    """OpenPhish community feed: one URL per line."""
    return pd.DataFrame({"url": _lines(path), "label": 1, "source": "openphish", "subtype": "phishing"})


def load_tranco(path: str, top_n: int = 50_000) -> pd.DataFrame:
    """Tranco list (rank,domain). These are bare homepages -> see bias warning in build_dataset."""
    df = pd.read_csv(path, header=None, names=["rank", "domain"]).head(top_n)
    return pd.DataFrame({"url": "https://" + df["domain"].astype(str), "label": 0,
                         "source": "tranco", "subtype": "benign"})


def load_generic_csv(path: str, url_col: str, label_col: str, malicious_values, source: str) -> pd.DataFrame:
    """Escape hatch for any other labelled CSV (e.g. a PhishTank export)."""
    df = pd.read_csv(path)
    mal = {str(v).lower() for v in malicious_values}
    return pd.DataFrame({"url": df[url_col], "label": df[label_col].astype(str).str.lower().isin(mal).astype(int),
                         "source": source, "subtype": df[label_col].astype(str).str.lower()})



def url_key(series: pd.Series) -> pd.Series:
    """Scheme-, case-, 'www.'- and trailing-slash-insensitive key for duplicate detection."""
    return (series.astype(str).str.strip().str.lower()
            .str.replace(r"^[a-z][a-z0-9+.\-]*://", "", regex=True)
            .str.replace(r"^www\.", "", regex=True)
            .str.rstrip("/"))


def load_balanced_urls(path: str) -> pd.DataFrame:
    """Kaggle 'Benign and Malicious URLs' (samahsadiq) balanced_urls.csv: columns url, label, result.

    `label` is text (benign/malicious), `result` is 0/1. We trust the text label and warn if
    the two disagree.
    """
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    lab_txt = df["label"].astype(str).str.lower().str.strip()
    y = lab_txt.str.contains("malic|phish|bad|defac|malware").astype(int)
    if "result" in df.columns:
        dis = int((y != pd.to_numeric(df["result"], errors="coerce")).sum())
        if dis:
            print(f"WARNING balanced_urls: label text and result disagree on {dis} rows - inspect them")
    return pd.DataFrame({"url": df["url"], "label": y, "source": "kaggle_balanced", "subtype": lab_txt})


_URLHAUS_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def load_urlhaus_csv(path: str, newest_n: int | None = None) -> pd.DataFrame:
    """URLhaus CSV database dump (csv.txt / csv_recent): '#' comment block, a '# id,dateadded,url,...'
    header line, then (usually quoted) data rows. Keep the file as downloaded - do not re-save it in Excel.

    newest_n: keep only the most recently added N rows (the full dump is huge and would swamp the
    malicious class with IP-address malware URLs).
    """
    import csv
    header, rows = None, []
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for line in f:
            t = line.strip()
            if not t or set(t) <= set("#,; "):
                continue
            if t.startswith("#"):
                if header is None and "dateadded" in t and "url" in t:
                    header = [c.strip().strip('"') for c in t.lstrip("# ").split(",")]
                continue
            rows.append(next(csv.reader([t], skipinitialspace=True)))
    header = header or _URLHAUS_COLS
    df = pd.DataFrame(rows, columns=header[:len(rows[0])] if rows else header)
    df["dateadded"] = pd.to_datetime(df["dateadded"], errors="coerce")
    df = df.dropna(subset=["url"]).sort_values("dateadded", ascending=False)
    if newest_n:
        df = df.head(newest_n)
    return pd.DataFrame({"url": df["url"].values, "label": 1, "source": "urlhaus",
                         "subtype": df["threat"].astype(str).str.lower().values,
                         "dateadded": df["dateadded"].values})


def overlap_report(a: pd.DataFrame, b: pd.DataFrame, name_a="A", name_b="B") -> dict:
    """How much do two sources share? Exact-URL overlap and registered-domain overlap."""
    ka, kb = set(url_key(a["url"])), set(url_key(b["url"]))
    da = set(a["domain"]) if "domain" in a else set(registered_domain(u) for u in a["url"])
    db = set(b["domain"]) if "domain" in b else set(registered_domain(u) for u in b["url"])
    out = {"exact_url_overlap": len(ka & kb), f"pct_of_{name_b}": round(100 * len(ka & kb) / max(len(kb), 1), 2),
           "domain_overlap": len(da & db), f"pct_domains_of_{name_b}": round(100 * len(da & db) / max(len(db), 1), 2)}
    print(f"{name_a} vs {name_b}:", out)
    return out

# ------------------------------------------------------------------ merge
def build_dataset(frames: list[pd.DataFrame], save_to: str | None = None) -> pd.DataFrame:
    """Concatenate, clean, de-duplicate and annotate. Prints a cleaning report."""
    df = pd.concat(frames, ignore_index=True)
    report = {"rows_in": len(df)}

    df["url"] = df["url"].astype("string").str.strip()
    df = df.dropna(subset=["url", "label"])
    df = df[df["url"] != ""]
    report["after_null_empty"] = len(df)

    ok = []
    for u in df["url"]:
        try:
            normalize_url(u)
            ok.append(True)
        except ValueError:
            ok.append(False)
    df = df[ok]

    df["domain"] = [registered_domain(u) for u in df["url"]]
    df = df[df["domain"] != ""]
    report["after_unparseable"] = len(df)

    # A URL labelled both ways (within or across sources) is untrustworthy -> drop every copy.
    # Must run BEFORE dedupe, otherwise the first copy would silently win.
    key = url_key(df["url"])
    conflict = df.groupby(key)["label"].transform("nunique") > 1
    report["dropped_label_conflicts"] = int(conflict.sum())
    df = df[~conflict]

    # Same URL twice (ignoring scheme/case/www/trailing slash) -> keep the FIRST occurrence,
    # so the order of `frames` decides which source owns a shared URL.
    key = url_key(df["url"])
    df = df.loc[~key.duplicated()]
    report["after_dedupe"] = len(df)

    df = df.reset_index(drop=True)
    df["label"] = df["label"].astype(int)
    report["rows_out"] = len(df)

    print("Cleaning report:", report)
    print("\nRows by source x label:\n", pd.crosstab(df["source"], df["label"].map(LABELS)))
    print("\nClass balance:\n", df["label"].map(LABELS).value_counts(normalize=True).round(3))
    print("\nUnique registered domains:", df["domain"].nunique())

    if save_to:
        df.to_parquet(save_to, index=False) if save_to.endswith(".parquet") else df.to_csv(save_to, index=False)
        print("Saved ->", save_to)
    return df


# ------------------------------------------------------------------ bias check
def source_bias_check(df: pd.DataFrame, sample_per_source: int = 20_000, seed: int = 42) -> pd.DataFrame:
    """Can the features alone tell WHICH SOURCE a URL came from, within one class?

    Within Benign: kaggle vs tranco.  Within Malicious: kaggle vs feeds.
    High accuracy means the model could learn source artifacts instead of maliciousness.
    Compare each accuracy to its majority-class baseline.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import GroupShuffleSplit

    results = []
    for label, name in LABELS.items():
        sub = df[df["label"] == label]
        if sub["source"].nunique() < 2:
            continue
        sub = sub.groupby("source", group_keys=False).apply(
            lambda g: g.sample(min(len(g), sample_per_source), random_state=seed))
        X = extract_features_df(sub["url"]).fillna(0)
        y = sub["source"].values
        tr, te = next(GroupShuffleSplit(1, test_size=0.3, random_state=seed).split(X, y, sub["domain"]))
        clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed).fit(X.iloc[tr], y[tr])
        acc = clf.score(X.iloc[te], y[te])
        base = pd.Series(y[te]).value_counts(normalize=True).max()
        results.append({"class": name, "sources": sorted(set(y)), "accuracy": round(acc, 3),
                        "majority_baseline": round(base, 3), "gap": round(acc - base, 3)})
    out = pd.DataFrame(results)
    print(out.to_string(index=False))
    print("\nRule of thumb: gap > ~0.15 means source artifacts are easy to learn; rebalance or drop features.")
    return out
