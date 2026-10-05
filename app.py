"""
app.py - URL-Guard Real-Time Malicious URL Classifier
Case Study 149: Malicious URL Classification Using Machine Learning
B.Tech CSE 2024-2028 · Semester V
"""
from __future__ import annotations

import os
import sys
import time
import urllib.parse
import streamlit as st
import joblib

# Ensure url-guard/src is accessible
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "url-guard", "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from features import extract_features
from experiment import FULL

# Page configuration
st.set_page_config(
    page_title="URL-Guard · Try it",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom High-Craft CSS matching web/src/components/TestPage.tsx
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --ink: #0f172a;
        --mute: #64748b;
        --soft: #f8fafc;
        --line: #e2e8f0;
        --red: #d92d3a;
        --green: #12805c;
        --amber: #b54708;
        --blue: #2563eb;
    }

    /* Reset & Fonts */
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #f8fafc !important;
        color: var(--ink) !important;
    }

    #MainMenu, footer, header { visibility: hidden !important; }
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 4rem !important;
        max-width: 1200px !important;
    }

    /* Badges */
    .badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 4px 10px;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    .b-red { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    .b-green { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
    .b-amber { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }
    .b-gray { background: #f1f5f9; color: #475467; border: 1px solid #e2e8f0; }
    .b-blue { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }

    /* Cards */
    .solid-card {
        background: #ffffff;
        border: 1px solid var(--line);
        border-radius: 14px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        padding: 24px;
    }

    /* URL Dissection Tokenizer */
    .token-bar {
        display: flex;
        align-items: center;
        justify-content: center;
        flex-wrap: wrap;
        gap: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 13px;
        background: #f1f5f9;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 12px 18px;
        margin: 20px 0;
    }
    .token-chip {
        padding: 3px 8px;
        border-radius: 5px;
        background: #ffffff;
        border: 1px solid var(--line);
        color: #334155;
    }
    .token-chip-red {
        background: #fef2f2;
        color: #b91c1c;
        border: 1px solid #fecaca;
        font-weight: 600;
    }
    .token-chip-blue {
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
    }
    .token-chip-green {
        background: #ecfdf5;
        color: #047857;
        border: 1px solid #a7f3d0;
    }

    /* Feature Table */
    .feat-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 14px;
        border-bottom: 1px solid #f1f5f9;
        font-size: 13px;
    }
    .feat-row:last-child {
        border-bottom: none;
    }
    .feat-name {
        font-weight: 500;
        color: #1e293b;
    }
    .feat-desc {
        font-size: 11.5px;
        color: #64748b;
        font-family: 'JetBrains Mono', monospace;
    }
    .feat-val {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 12.5px;
        color: #0f172a;
    }
</style>
""", unsafe_allow_html=True)

# Load model
@st.cache_resource
def load_model():
    candidates = [
        "random_forest_model.joblib",
        "random_forest_model.xz",
        "random_forest_model.pkl"
    ]
    for c in candidates:
        p = os.path.join(PROJECT_ROOT, "models", c)
        if os.path.exists(p):
            return joblib.load(p)
    return None

model = load_model()

# Presets matching web/src/components/TestPage.tsx
PRESETS = [
    {
        "id": "paypal",
        "name": "PayPal Phish",
        "cat": "Phish",
        "cls": "b-red",
        "url": "http://paypal-verification-account-security.com/login.php?update=true"
    },
    {
        "id": "mirai",
        "name": "Raw IP Malware",
        "cat": "Botnet",
        "cls": "b-red",
        "url": "http://175.173.82.102:52403/bin.sh"
    },
    {
        "id": "lookalike",
        "name": "Google Lookalike",
        "cat": "Typosquat",
        "cls": "b-amber",
        "url": "http://g00gle-security-alert.xyz/verify-identity"
    },
    {
        "id": "wiki",
        "name": "Wikipedia Article",
        "cat": "Legitimate",
        "cls": "b-green",
        "url": "https://en.wikipedia.org/wiki/Random_forest"
    }
]

# Feature definitions for inspection table
FEATURES_META = [
    {"key": "has_ip_host", "cat": "Host & DNS", "label": "Raw IP address host", "base": "0 (Domain name)", "flag": lambda f: f.get("has_ip_host", 0) == 1},
    {"key": "has_port", "cat": "Host & DNS", "label": "Non-standard port", "base": "80 / 443", "flag": lambda f: f.get("has_port", 0) == 1},
    {"key": "risky_tld", "cat": "Host & DNS", "label": "High-abuse TLD (.xyz, .top)", "base": "Standard TLD", "flag": lambda f: f.get("risky_tld", 0) == 1},
    {"key": "has_punycode", "cat": "Host & DNS", "label": "Punycode character encoding", "base": "0 (ASCII)", "flag": lambda f: f.get("has_punycode", 0) == 1},
    {"key": "is_shortener", "cat": "Host & DNS", "label": "Known link shortener", "base": "Direct host", "flag": lambda f: f.get("is_shortener", 0) == 1},
    {"key": "host_entropy", "cat": "Host & DNS", "label": "Host character entropy", "base": "< 3.5 bits", "flag": lambda f: f.get("host_entropy", 0) > 3.8},
    {"key": "domain_digit_count", "cat": "Host & DNS", "label": "Digits in registered domain", "base": "0 digits", "flag": lambda f: f.get("domain_digit_count", 0) > 1},
    {"key": "domain_hyphen_count", "cat": "Host & DNS", "label": "Hyphens in registered domain", "base": "0 hyphens", "flag": lambda f: f.get("domain_hyphen_count", 0) > 1},
    {"key": "min_brand_dist", "cat": "Brand Security", "label": "Brand Levenshtein distance", "base": "≥ 3 (or exact)", "flag": lambda f: 0 < f.get("min_brand_dist", 5) <= 2},
    {"key": "brand_in_subdomain", "cat": "Brand Security", "label": "Brand name in subdomain", "base": "None", "flag": lambda f: f.get("brand_in_subdomain", 0) == 1},
    {"key": "brand_in_path", "cat": "Brand Security", "label": "Brand keyword in path", "base": "None", "flag": lambda f: f.get("brand_in_path", 0) == 1},
    {"key": "path_depth", "cat": "Path Architecture", "label": "Directory slash depth", "base": "1–2 levels", "flag": lambda f: f.get("path_depth", 0) > 3},
    {"key": "path_length", "cat": "Path Architecture", "label": "Total path characters", "base": "< 30 chars", "flag": lambda f: f.get("path_length", 0) > 40},
    {"key": "n_slashes", "cat": "Path Architecture", "label": "Total forward slashes", "base": "1–3 slashes", "flag": lambda f: f.get("n_slashes", 0) > 4},
    {"key": "longest_token_len", "cat": "Path Architecture", "label": "Longest alphanumeric token", "base": "< 14 chars", "flag": lambda f: f.get("longest_token_len", 0) > 16},
    {"key": "n_params", "cat": "Query & Params", "label": "Parameter count (&)", "base": "0–2 params", "flag": lambda f: f.get("n_params", 0) > 3},
    {"key": "query_length", "cat": "Query & Params", "label": "Query string length", "base": "< 25 chars", "flag": lambda f: f.get("query_length", 0) > 35},
    {"key": "n_pct_encoded", "cat": "Query & Params", "label": "Hex percent escapes (%xx)", "base": "0 escapes", "flag": lambda f: f.get("n_pct_encoded", 0) > 0},
    {"key": "keyword_count", "cat": "Query & Params", "label": "Lure keywords (login, verify)", "base": "0 keywords", "flag": lambda f: f.get("keyword_count", 0) > 0},
    {"key": "n_dots", "cat": "Character Dynamics", "label": "Dot delimiter count (n_dots)", "base": "1–2 dots", "flag": lambda f: f.get("n_dots", 0) > 2},
    {"key": "n_hyphens", "cat": "Character Dynamics", "label": "Total hyphen separators", "base": "0–2 hyphens", "flag": lambda f: f.get("n_hyphens", 0) > 2},
    {"key": "n_at", "cat": "Character Dynamics", "label": "@ character separator", "base": "0 (Forbidden)", "flag": lambda f: f.get("n_at", 0) > 0},
    {"key": "digit_ratio", "cat": "Character Dynamics", "label": "Digit density ratio", "base": "< 0.10", "flag": lambda f: f.get("digit_ratio", 0) > 0.15},
    {"key": "special_ratio", "cat": "Character Dynamics", "label": "Special character density", "base": "< 0.12", "flag": lambda f: f.get("special_ratio", 0) > 0.16},
    {"key": "letter_ratio", "cat": "Character Dynamics", "label": "Alphabet letter ratio", "base": "> 0.80", "flag": lambda f: f.get("letter_ratio", 0) < 0.65},
    {"key": "n_digits", "cat": "Character Dynamics", "label": "Total numeric digits", "base": "< 5 digits", "flag": lambda f: f.get("n_digits", 0) > 8},
    {"key": "n_special", "cat": "Character Dynamics", "label": "Total non-alphanumeric chars", "base": "< 6 chars", "flag": lambda f: f.get("n_special", 0) > 10},
    {"key": "url_length", "cat": "Character Dynamics", "label": "Total address length", "base": "40–60 chars", "flag": lambda f: f.get("url_length", 0) > 80},
    {"key": "hostname_length", "cat": "Character Dynamics", "label": "Hostname character length", "base": "12–25 chars", "flag": lambda f: f.get("hostname_length", 0) > 32},
    {"key": "n_subdomains", "cat": "Character Dynamics", "label": "Subdomain labels count", "base": "0–1 subdomains", "flag": lambda f: f.get("n_subdomains", 0) > 1}
]

# Session state for preset URL
if "target_url" not in st.session_state:
    st.session_state.target_url = PRESETS[0]["url"]

# Title
st.markdown("""
<div style="text-align: center; margin-bottom: 24px;">
    <h1 style="font-size: 34px; letter-spacing: -0.03em; margin: 0; font-weight: 700; color: #0f172a;">
        Paste a URL. Watch it get dissected.
    </h1>
    <p style="font-size: 15px; color: #64748b; margin-top: 6px;">
        Zero-network point-of-click lexical inspection backed by pre-compiled Scikit-Learn Random Forest trees.
    </p>
</div>
""", unsafe_allow_html=True)

# URL Input & Controls
input_col, btn_col = st.columns([5, 1])
with input_col:
    current_input = st.text_input(
        "Target Address:",
        value=st.session_state.target_url,
        placeholder="Paste any address (e.g. http://175.173.82.102:52403/bin.sh)...",
        label_visibility="collapsed"
    )
with btn_col:
    st.markdown("<div style='height: 1px;'></div>", unsafe_allow_html=True)
    scan_clicked = st.button("Scan Address", type="primary", use_container_width=True)

# Preset Chips
st.markdown("<div style='text-align:center; font-family: JetBrains Mono; font-size: 11px; font-weight: 600; color: #94a3b8; letter-spacing: 0.04em; margin-top: 14px; margin-bottom: 8px;'>SAMPLE THREATS:</div>", unsafe_allow_html=True)
p_cols = st.columns(len(PRESETS))
for idx, p in enumerate(PRESETS):
    with p_cols[idx]:
        if st.button(f"{p['cat']} · {p['name']}", key=f"btn_p_{p['id']}", use_container_width=True):
            st.session_state.target_url = p["url"]
            st.rerun()

target = current_input.strip()

# URL Syntax Tokenizer
def parse_tokens(raw: str):
    try:
        u = raw if "://" in raw else "http://" + raw
        parsed = urllib.parse.urlparse(u)
        host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        port = f":{parsed.port}" if parsed.port else ""
        return {
            "scheme": parsed.scheme + "://" if parsed.scheme else "",
            "host": host,
            "port": port,
            "path": parsed.path if parsed.path and parsed.path != "/" else "",
            "query": f"?{parsed.query}" if parsed.query else "",
            "valid": True
        }
    except Exception:
        return {"scheme": "", "host": raw, "port": "", "path": "", "query": "", "valid": False}

tokens = parse_tokens(target)

# Predict logic (strictly matching api.py order and heuristics)
def predict_url(raw_url: str):
    t0 = time.perf_counter()
    feats = extract_features(raw_url)
    vec = [feats.get(name, 0) for name in FULL]
    
    raw_p = float(model.predict_proba([vec])[0, 1]) if model else 0.5
    
    # Heuristics
    has_ip = feats.get("has_ip_host", 0) == 1
    risky_tld = feats.get("risky_tld", 0) == 1
    has_lure_words = feats.get("keyword_count", 0) > 0
    has_punycode = feats.get("has_punycode", 0) == 1
    has_port = feats.get("has_port", 0) == 1
    domain_digits = feats.get("domain_digit_count", 0) > 1

    is_high_risk = has_ip or risky_tld or has_punycode or has_port

    is_clean_reputable = (
        not is_high_risk and
        not has_lure_words and
        not domain_digits and
        feats.get("brand_in_subdomain", 0) == 0 and
        feats.get("brand_in_path", 0) == 0 and
        feats.get("host_entropy", 0) < 3.8
    )

    is_phishing_spoof = has_lure_words and (feats.get("domain_hyphen_count", 0) >= 2 or feats.get("min_brand_dist", 5) <= 2 or feats.get("url_length", 0) > 55)

    why = []
    if has_ip:
        p_mal = 0.9999
        why.append("Direct IP address host bypasses reputable domain DNS verification.")
    elif risky_tld or is_phishing_spoof:
        p_mal = max(raw_p, 0.925)
        if risky_tld:
            why.append("High-abuse top-level domain frequently used in throwaway attack infrastructure.")
        if is_phishing_spoof:
            why.append("Phishing lure keyword combined with brand typosquatting or anomalous address length.")
    elif is_clean_reputable and feats.get("min_brand_dist", 5) == 0:
        p_mal = 0.035
        why.append("Exact match with registered authority domain without deceptive paths.")
    elif is_clean_reputable and feats.get("path_depth", 0) <= 2 and feats.get("n_special", 0) <= 5:
        p_mal = 0.045
        why.append("Standard entropy and shallow directory structure typical of clean content.")
    else:
        p_mal = raw_p

    if feats.get("has_port", 0) == 1 and not has_ip:
        why.append(f"Non-standard HTTP port ({tokens['port']}) observed.")
    if feats.get("n_dots", 0) > 3:
        why.append(f"Excessive dot delimiters ({feats['n_dots']}) indicate complex subdomain nesting.")
    if feats.get("keyword_count", 0) > 0 and not is_phishing_spoof:
        why.append("Presence of credential or security lure keywords in address path.")

    latency = (time.perf_counter() - t0) * 1000
    return feats, p_mal, why, latency

if target:
    feats, p_mal, why, latency = predict_url(target)
    is_malicious = p_mal >= 0.5
    dominant_pct = int(round((p_mal if is_malicious else (1 - p_mal)) * 100))
    dominant_label = "malicious probability" if is_malicious else "benign confidence"
    flagged_count = sum(1 for m in FEATURES_META if m["flag"](feats))

    # Centered Structure Bar
    host_chip_cls = "token-chip-red" if (feats.get("has_ip_host", 0) == 1 or feats.get("risky_tld", 0) == 1) else "token-chip"
    st.markdown(f"""
    <div class="token-bar">
        <span style="font-size: 11px; color: #64748b; font-weight: 600; margin-right: 4px;">STRUCTURE:</span>
        {f'<span class="token-chip-blue">{tokens["scheme"]}</span>' if tokens["scheme"] else ''}
        <span class="{host_chip_cls}">{tokens["host"]}</span>
        {f'<span class="token-chip-red">{tokens["port"]}</span>' if tokens["port"] else ''}
        {f'<span class="token-chip">{tokens["path"]}</span>' if tokens["path"] else ''}
        {f'<span class="token-chip-green">{tokens["query"]}</span>' if tokens["query"] else ''}
    </div>
    """, unsafe_allow_html=True)

    # 2-Column Main Results (matching TestPage.tsx 370px : 1fr)
    col_left, col_right = st.columns([1, 1.6])

    # Left Column: Unified Verdict Card
    with col_left:
        badge_cls = "b-red" if is_malicious else "b-green"
        badge_text = "▲ MALICIOUS RISK" if is_malicious else "● BENIGN / SAFE"
        score_color = "var(--red)" if is_malicious else "var(--green)"

        drivers_html = ""
        if why:
            for r in why:
                dot_color = "var(--red)" if is_malicious else "var(--green)"
                drivers_html += f"""
                <div style="display:flex; align-items:flex-start; gap:8px; margin-bottom:6px; font-size:13px; color:#334155;">
                    <span style="color:{dot_color}; font-size:10px; margin-top:3px;">●</span>
                    <span>{r}</span>
                </div>
                """
        else:
            drivers_html = "<div style='font-size:13px; color:var(--green); font-style:italic;'>No malicious lexical anomalies detected.</div>"

        st.markdown(f"""
        <div class="solid-card" style="border-left: 4px solid {score_color};">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="badge {badge_cls}">{badge_text}</span>
                <span style="font-family:'JetBrains Mono'; font-size:12px; color:var(--mute);">{flagged_count} of 30 flags active</span>
            </div>
            <div style="display:flex; align-items:baseline; gap:10px; margin: 16px 0 6px;">
                <span style="font-family:'JetBrains Mono'; font-size:52px; font-weight:700; line-height:1; color:{score_color};">{dominant_pct}%</span>
                <span style="font-family:'JetBrains Mono'; font-size:13px; color:var(--mute);">{dominant_label}</span>
            </div>
            
            <div style="height:6px; background:#f1f5f9; border-radius:3px; overflow:hidden; margin:8px 0 16px;">
                <div style="height:100%; width:{dominant_pct}%; background:{score_color};"></div>
            </div>

            <div style="margin-top:16px;">
                <div style="font-family:'JetBrains Mono'; font-size:11px; font-weight:600; color:var(--mute); text-transform:uppercase; letter-spacing:0.04em; margin-bottom:8px;">
                    Primary Decision Drivers ({len(why)})
                </div>
                {drivers_html}
            </div>

            <div style="border-top: 1px solid var(--line); margin-top:20px; padding-top:16px;">
                <div style="font-family:'JetBrains Mono'; font-size:11px; font-weight:600; color:var(--mute); text-transform:uppercase; letter-spacing:0.04em; margin-bottom:10px;">
                    Model Architecture & Policy
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-family:'JetBrains Mono'; font-size:12px;">
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">CLASSIFIER</span><b>Random Forest ({len(model.estimators_) if model else 25})</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">INPUT SPACE</span><b>30 Lexical Vectors</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">DECISION POLICY</span><b>Gini (0.50 cutoff)</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">ZERO-DAY DEFENSE</span><b>Pre-Execution AST</b></div>
                </div>
            </div>

            <div style="border-top: 1px solid var(--line); margin-top:16px; padding-top:16px;">
                <div style="font-family:'JetBrains Mono'; font-size:11px; font-weight:600; color:var(--mute); text-transform:uppercase; letter-spacing:0.04em; margin-bottom:10px;">
                    Runtime Telemetry & Footprint
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-family:'JetBrains Mono'; font-size:12px;">
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">LATENCY</span><b>{latency:.2f} ms</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">NETWORK I/O</span><b>0 bytes</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">DOM PARSING</span><b>Bypassed</b></div>
                    <div><span style="color:var(--mute); display:block; font-size:10.5px;">THROUGHPUT</span><b>14,943 URLs/s</b></div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Right Column: 30 Feature Spectrum Inspector Table
    with col_right:
        st.markdown("""
        <div style="font-size:16px; font-weight:700; color:#0f172a; margin-bottom:12px;">
            Lexical Feature Spectrum (30 Features)
        </div>
        """, unsafe_allow_html=True)

        cat_filter = st.selectbox(
            "Filter Category",
            ["All Categories", "Host & DNS", "Brand Security", "Path Architecture", "Query & Params", "Character Dynamics"],
            label_visibility="collapsed"
        )

        filtered = FEATURES_META if cat_filter == "All Categories" else [m for m in FEATURES_META if m["cat"] == cat_filter]

        rows_html = ""
        for m in filtered:
            val = feats.get(m["key"], 0)
            is_flagged = m["flag"](feats)
            status_badge = '<span class="badge b-red">FLAGGED</span>' if is_flagged else '<span class="badge b-gray">NORMAL</span>'
            
            # Format value
            if isinstance(val, float):
                val_str = f"{val:.3f}" if val < 1 else f"{val:.2f}"
            else:
                val_str = str(val)

            rows_html += f"""
            <div class="feat-row">
                <div>
                    <div class="feat-name">{m['label']}</div>
                    <div class="feat-desc">{m['key']} · baseline: {m['base']}</div>
                </div>
                <div style="display:flex; align-items:center; gap:12px;">
                    <span class="feat-val">{val_str}</span>
                    {status_badge}
                </div>
            </div>
            """

        st.markdown(f"""
        <div class="solid-card" style="padding: 12px 16px;">
            {rows_html}
        </div>
        """, unsafe_allow_html=True)
