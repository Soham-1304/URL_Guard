"""
app.py - URL-Guard Real-Time Malicious URL Classifier
Case Study 149: Malicious URL Classification Using Machine Learning
B.Tech CSE 2024-2028 · Semester V
"""
from __future__ import annotations

import os
import sys
import time
import pandas as pd
import streamlit as st
import joblib

# Ensure url-guard/src is accessible
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "url-guard", "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from features import extract_features, feature_names, normalize_url

# Page configuration
st.set_page_config(
    page_title="URL-Guard · Malicious URL Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# High-Craft Editorial CSS Stylesheet
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,600;1,6..72,400&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #0f172a;
    }

    .editorial-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #f1f5f9;
        border: 1px solid #cbd5e1;
        padding: 4px 10px;
        border-radius: 9999px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: #475569;
        margin-bottom: 0.75rem;
    }

    .editorial-badge .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #10b981;
        box-shadow: 0 0 8px #10b981;
    }

    .hero-title {
        font-family: 'Newsreader', Georgia, serif;
        font-size: 2.8rem;
        font-weight: 600;
        line-height: 1.1;
        letter-spacing: -0.02em;
        color: #0f172a;
        margin-bottom: 0.5rem;
    }

    .hero-subtitle {
        font-size: 1.05rem;
        line-height: 1.6;
        color: #475569;
        margin-bottom: 1.5rem;
        max-width: 850px;
    }

    .card-panel {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        margin-bottom: 1rem;
    }

    .verdict-benign {
        background: #ecfdf5;
        border: 1.5px solid #10b981;
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
    }

    .verdict-malicious {
        background: #fef2f2;
        border: 1.5px solid #ef4444;
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
    }

    .verdict-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        font-weight: 700;
        margin-bottom: 0.4rem;
    }

    .verdict-text-benign { color: #047857; }
    .verdict-text-malicious { color: #b91c1c; }

    .verdict-score {
        font-family: 'Newsreader', Georgia, serif;
        font-size: 3rem;
        font-weight: 700;
        line-height: 1;
        margin: 0.5rem 0;
    }

    .stat-pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .stat-pill-good { background: #dcfce7; color: #166534; }
    .stat-pill-danger { background: #fee2e2; color: #991b1b; }
    .stat-pill-warn { background: #fef3c7; color: #92400e; }
    .stat-pill-neutral { background: #f1f5f9; color: #334155; }
</style>
""", unsafe_allow_html=True)

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

# Sidebar: Controls & Presets
with st.sidebar:
    st.markdown('<div class="editorial-badge"><span class="status-dot"></span> LIVE SCIKIT-LEARN ENGINE</div>', unsafe_allow_html=True)
    st.title("URL-Guard")
    st.caption("Machine Learning Case Study 149")
    st.markdown("---")

    st.subheader("Model Specifications")
    st.markdown("""
    - **Architecture:** Random Forest (100 Trees)
    - **Test Accuracy:** `87.50%`
    - **Precision (Benign):** `87.70%`
    - **ROC-AUC:** `0.9402`
    - **Zero-Shot Fresh Recall:** `88.28%`
    - **Inference Latency:** `< 0.15 ms`
    - **Network Traffic:** `0 bytes` (Zero network requests)
    """)

    st.markdown("---")
    st.subheader("Interactive Presets")
    preset_urls = {
        "Legitimate: Google Search": "https://www.google.com/search?q=machine+learning+research",
        "Legitimate: Wikipedia Article": "https://en.wikipedia.org/wiki/Random_forest",
        "Phishing: PayPal Fake Account": "http://paypal-verification-account-security.com/login.php?update=true",
        "Malware: Raw IP Host (Mozi/Mirai)": "http://175.173.82.102:52403/bin.sh",
        "Typosquatting: Google Lookalike": "http://g00gle-security-alert.xyz/verify-identity",
        "Credential Harvest: Bank Login": "https://secure-banking-login-auth.net/portal/signin?ref=account"
    }

    selected_preset = st.selectbox("Choose a sample attack vector:", ["-- Custom URL --"] + list(preset_urls.keys()))

st.markdown('<div class="editorial-badge"><span class="status-dot"></span> EVIDENCE-BASED CYBERSECURITY · CASE STUDY 149</div>', unsafe_allow_html=True)
st.markdown('<h1 class="hero-title">Malicious URL Classification.<br><span style="color:#2563eb;">With evidence.</span></h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="hero-subtitle">Classify URLs as <strong>Benign</strong> or <strong>Malicious</strong> purely from lexical and structural characters. Sub-millisecond inference at point-of-click without visiting the target page.</p>',
    unsafe_allow_html=True
)

# Input Box
initial_url = preset_urls[selected_preset] if selected_preset != "-- Custom URL --" else "https://en.wikipedia.org/wiki/Support_vector_machine"
user_url = st.text_input("Enter target URL string:", value=initial_url, placeholder="e.g. https://example.com/login?token=abc")

col1, col2 = st.columns([1, 4])
with col1:
    inspect_btn = st.button("Analyze URL", type="primary", use_container_width=True)

if user_url and model is not None:
    try:
        t_start = time.perf_counter()
        feats = extract_features(user_url)
        cols = feature_names(include_scheme=False)
        X_df = pd.DataFrame([[feats[c] for c in cols]], columns=cols)
        
        prob_malicious = float(model.predict_proba(X_df)[0, 1])
        prediction = int(prob_malicious >= 0.5)
        inference_time_ms = (time.perf_counter() - t_start) * 1000

        # Primary Verdict Box
        if prediction == 1:
            st.markdown(f"""
            <div class="verdict-malicious">
                <div class="verdict-header verdict-text-malicious">🚨 Threat Detected · High Risk Vector</div>
                <div class="verdict-score verdict-text-malicious">{prob_malicious:.1%}</div>
                <p style="margin:0; font-size:1.05rem; color:#7f1d1d;"><strong>CLASSIFIED AS MALICIOUS:</strong> This URL exhibits patterns characteristic of phishing lures, raw IP malware hosting, or deceptive subdomains.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="verdict-benign">
                <div class="verdict-header verdict-text-benign">✅ Clean Verification · Low Risk</div>
                <div class="verdict-score verdict-text-benign">{(1 - prob_malicious):.1%}</div>
                <p style="margin:0; font-size:1.05rem; color:#064e3b;"><strong>CLASSIFIED AS BENIGN:</strong> Structural, lexical, and host entropy profiles conform to standard reputable web domains.</p>
            </div>
            """, unsafe_allow_html=True)

        st.progress(prob_malicious)

        # Core Metrics Bar
        st.markdown("### Behavioral Factor Breakdown")
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            dot_state = "danger" if feats["n_dots"] >= 4 else ("warn" if feats["n_dots"] >= 3 else "good")
            st.metric("Dot Count (n_dots)", feats["n_dots"], delta="#1 Predictive Feature")
        with m2:
            st.metric("Total Length", f"{feats['url_length']} chars")
        with m3:
            ip_val = "Raw IP (🚨)" if feats["has_ip_host"] == 1 else "Domain Host (✓)"
            st.metric("Host Architecture", ip_val)
        with m4:
            st.metric("Subdomain Count", feats["n_subdomains"])
        with m5:
            st.metric("Inference Latency", f"{inference_time_ms:.2f} ms")

        # Deep Diagnostic Tabs
        tab_inspect, tab_vector, tab_benchmark = st.tabs(["🔬 Suspicious Pattern Diagnostics", "📋 30-Feature Lexical Vector", "📊 6-Model Academic Lab"])

        with tab_inspect:
            col_diag1, col_diag2 = st.columns(2)
            with col_diag1:
                st.markdown("#### High-Risk Signals")
                threats_found = []
                if feats["has_ip_host"] == 1:
                    threats_found.append("🚨 **Raw IP Host Identified:** URL circumvents DNS registrars by pointing directly to an IP address.")
                if feats["has_port"] == 1:
                    threats_found.append("⚠️ **Non-Standard Port:** URL directs to an unusual network port (not 80/443).")
                if feats["keyword_count"] > 0:
                    threats_found.append(f"⚠️ **Suspicious Action Keywords:** Detected {feats['keyword_count']} sensitive token(s) (e.g. login, verify, account, secure).")
                if feats["brand_in_subdomain"] == 1:
                    threats_found.append("🚨 **Subdomain Brand Spoofing:** Recognized brand keyword injected into a foreign subdomain.")
                if feats["brand_in_path"] == 1:
                    threats_found.append("⚠️ **Path Brand Lure:** Recognized brand keyword placed in path parameters.")
                if feats["risky_tld"] == 1:
                    threats_found.append("⚠️ **High-Risk TLD:** Top-level domain is statistically prevalent in blocklists and spam abuse.")
                if feats["min_brand_dist"] in (1, 2):
                    threats_found.append("🚨 **Typosquatting Hazard:** Registered domain is an edit distance of 1–2 from a known major brand.")

                if threats_found:
                    for t in threats_found:
                        st.markdown(t)
                else:
                    st.success("✓ Zero severe structural anomalies or brand spoofing markers identified.")

            with col_diag2:
                st.markdown("#### Lexical & Entropy Ratios")
                st.markdown(f"- **Digit-to-Length Ratio:** `{feats['digit_ratio']:.3f}` ({feats['n_digits']} digits)")
                st.markdown(f"- **Special Character Ratio:** `{feats['special_ratio']:.3f}` ({feats['n_special']} special chars)")
                st.markdown(f"- **Host Shannon Entropy:** `{feats['host_entropy']:.2f}` bits (Higher entropy indicates algorithmic DGA generation)")
                st.markdown(f"- **Path Directory Depth:** `{feats['path_depth']}` levels")
                st.markdown(f"- **Query Parameters:** `{feats['n_params']}` key-value pairs")

        with tab_vector:
            st.dataframe(X_df.T.rename(columns={0: "Extracted Value"}), use_container_width=True)

        with tab_benchmark:
            st.markdown("#### Six-Algorithm Comparative Study (Domain-Grouped Held-Out Test Set)")
            summary_csv = os.path.join(PROJECT_ROOT, "outputs", "summary_table.csv")
            if os.path.exists(summary_csv):
                st.dataframe(pd.read_csv(summary_csv), use_container_width=True)
            
            b1, b2 = st.columns(2)
            with b1:
                p1 = os.path.join(PROJECT_ROOT, "outputs", "model_comparison.png")
                if os.path.exists(p1):
                    st.image(p1, caption="Figure 1: 6-Model Performance Comparison")
            with b2:
                p2 = os.path.join(PROJECT_ROOT, "outputs", "feature_importance.png")
                if os.path.exists(p2):
                    st.image(p2, caption="Figure 2: Permutation Feature Importance (Top 15)")

    except Exception as err:
        st.error(f"Error processing URL: {err}")
elif model is None:
    st.error("Champion model not found at `models/random_forest_model.pkl`. Please verify file placement.")
