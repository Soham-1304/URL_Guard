"""
features.py - single source of truth for URL feature extraction.

Used identically by training, evaluation, the FastAPI service and Streamlit.
Rules:
  * Lexical / structural features only. NO network calls (never visits the URL).
  * Deterministic: same string in -> same numbers out.
  * Scheme-dependent features (https/http) are OFF by default, because many
    public datasets store URLs without a scheme, which makes "https" a dataset
    artifact rather than a real signal. Turn on with include_scheme=True and
    treat it as an ablation.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit, unquote

import pandas as pd
import tldextract

# Offline extractor: uses the bundled public-suffix snapshot, never fetches.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# ---------------------------------------------------------------- constants
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "banking", "password", "passwd", "wallet", "webscr",
    "billing", "invoice", "support", "unlock", "suspend", "recover", "authenticate",
    "free", "bonus", "prize", "gift", "crypto", "airdrop",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

# TLDs heavily abused in public blocklists. A hint, not a verdict; the model
# decides how much weight it deserves.
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "icu", "cyou", "buzz", "monster", "sbs", "cfd",
}

# Small built-in brand list for typosquat / brand-abuse features.
# Replace/extend with the Tranco top-N labels via set_brand_list() once loaded.
_DEFAULT_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple", "microsoft", "netflix",
    "instagram", "whatsapp", "linkedin", "twitter", "youtube", "github", "dropbox",
    "adobe", "ebay", "walmart", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hdfcbank", "icicibank", "sbi", "paytm", "phonepe", "flipkart", "outlook",
    "office365", "yahoo", "spotify", "steam", "binance", "coinbase", "metamask",
    "dhl", "fedex", "ups", "usps", "irs",
]
_BRANDS: list[str] = list(_DEFAULT_BRANDS)

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEX_IP = re.compile(r"^0x[0-9a-f]+$", re.I)
_DEC_IP = re.compile(r"^\d{8,10}$")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def set_brand_list(brands) -> None:
    """Swap in a larger brand list (e.g. top-1000 Tranco registered-domain labels)."""
    global _BRANDS
    _BRANDS = sorted({b.lower() for b in brands if b and len(b) >= 4})


# ---------------------------------------------------------------- helpers
def _levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Edit distance with early exit once it exceeds `cap`."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _is_ip_host(host: str) -> bool:
    h = host.strip("[]")
    if ":" in h:                      # IPv6 literal
        return True
    return bool(_IPV4.match(h) or _HEX_IP.match(h) or _DEC_IP.match(h))


def normalize_url(url: str) -> str:
    """Strip whitespace; ensure a scheme so urlsplit parses the host correctly."""
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    u = url.strip()
    if not u:
        raise ValueError("URL is empty")
    if not _SCHEME.match(u):
        u = "http://" + u.lstrip("/")
    return u


# ---------------------------------------------------------------- core
FEATURE_GROUPS = {
    "length": ["url_length", "hostname_length", "path_length", "query_length", "longest_token_len"],
    "counts": ["n_dots", "n_hyphens", "n_slashes", "n_digits", "n_special", "n_params", "n_pct_encoded",
               "n_at", "path_depth", "n_subdomains", "keyword_count"],
    "ratios": ["digit_ratio", "letter_ratio", "special_ratio"],
    "host": ["has_ip_host", "has_port", "has_punycode", "is_shortener", "risky_tld", "host_entropy",
             "domain_digit_count", "domain_hyphen_count"],
    "brand": ["min_brand_dist", "brand_in_subdomain", "brand_in_path"],
    "scheme": ["has_https"],
}


def feature_names(include_scheme: bool = False) -> list[str]:
    names = []
    for group, cols in FEATURE_GROUPS.items():
        if group == "scheme" and not include_scheme:
            continue
        names.extend(cols)
    return names


def extract_features(url: str, include_scheme: bool = False) -> dict:
    """Return an ordered dict of numeric features for one URL.

    Raises ValueError for empty / non-string / unparseable input.
    """
    raw = url.strip() if isinstance(url, str) else url
    had_scheme = bool(isinstance(raw, str) and _SCHEME.match(raw))
    u = normalize_url(url)
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as e:
        raise ValueError(f"Unparseable URL: {e}") from e
    if not host:
        raise ValueError("URL has no host")

    path, query = parts.path or "", parts.query or ""
    full_nos = u.split("://", 1)[1]            # URL text without the scheme
    decoded = unquote(full_nos).lower()

    ext = _EXTRACT(host)
    sub_labels = [l for l in ext.subdomain.split(".") if l]
    if sub_labels and sub_labels[0] == "www":
        sub_labels = sub_labels[1:]
    domain_label = ext.domain.lower()
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)

    n = len(full_nos)
    n_digits = sum(c.isdigit() for c in full_nos)
    n_letters = sum(c.isalpha() for c in full_nos)
    n_special = n - n_digits - n_letters
    tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", full_nos) if t]

    is_ip = _is_ip_host(host)
    brand_dist = min((_levenshtein(domain_label, b) for b in _BRANDS), default=5) if (domain_label and not is_ip) else 5
    sub_text = ".".join(sub_labels).lower()
    path_text = (path + "?" + query).lower()
    # brand named in subdomain/path while the registered domain is NOT that brand
    brand_hit_sub = int(any(b in sub_text and b != domain_label for b in _BRANDS))
    brand_hit_path = int(any(b in path_text and b != domain_label for b in _BRANDS))

    feats = {
        "url_length": n,
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "longest_token_len": max((len(t) for t in tokens), default=0),
        "n_dots": full_nos.count("."),
        "n_hyphens": full_nos.count("-"),
        "n_slashes": full_nos.count("/"),
        "n_digits": n_digits,
        "n_special": n_special,
        "n_params": len([p for p in query.split("&") if p]),
        "n_pct_encoded": len(_PCT.findall(full_nos)),
        "n_at": full_nos.count("@"),
        "path_depth": len([p for p in path.split("/") if p]),
        "n_subdomains": 0 if is_ip else len(sub_labels),
        "keyword_count": sum(decoded.count(k) for k in SUSPICIOUS_KEYWORDS),
        "digit_ratio": n_digits / n if n else 0.0,
        "letter_ratio": n_letters / n if n else 0.0,
        "special_ratio": n_special / n if n else 0.0,
        "has_ip_host": int(is_ip),
        "has_port": int(port is not None and port not in (80, 443)),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(registered in SHORTENERS),
        "risky_tld": int(ext.suffix.split(".")[-1] in RISKY_TLDS),
        "host_entropy": _entropy(host),
        "domain_digit_count": sum(c.isdigit() for c in domain_label),
        "domain_hyphen_count": domain_label.count("-"),
        "min_brand_dist": brand_dist,
        "brand_in_subdomain": brand_hit_sub,
        "brand_in_path": brand_hit_path,
    }
    if include_scheme:
        feats["has_https"] = int(had_scheme and parts.scheme.lower() == "https")
    return feats


def registered_domain(url: str) -> str:
    """Registered domain (e.g. 'example.co.uk') or the raw host for IPs. '' if unparseable."""
    try:
        host = urlsplit(normalize_url(url)).hostname or ""
    except ValueError:
        return ""
    if _is_ip_host(host):
        return host
    ext = _EXTRACT(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p).lower() or host.lower()


def extract_features_df(urls, include_scheme: bool = False) -> pd.DataFrame:
    """Vectorised helper. Rows that fail extraction become all-NaN (drop them upstream)."""
    cols = feature_names(include_scheme)
    rows = []
    for u in urls:
        try:
            f = extract_features(u, include_scheme)
            rows.append([f[c] for c in cols])
        except ValueError:
            rows.append([float("nan")] * len(cols))
    return pd.DataFrame(rows, columns=cols)
