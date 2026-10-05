# URL-Guard: Malicious URL Classification Using Machine Learning
> **B.Tech CSE 2024–2028 · Semester V · Machine Learning Case Study 149**

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](http://localhost:8501)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, real-time malicious URL classification engine that detects phishing, malware, and defacement URLs **without visiting websites, without network calls, and without WHOIS lookups**.

---

## 📁 Project Structure

```text
├── app.py                         # Streamlit real-time detection web app
├── requirements.txt               # Dependencies for local run & cloud deployment
├── .gitignore                     # Git rules (excludes large data/models >100MB)
├── PS.md                          # Case Study 149 Problem Statement & guidelines
├── REPORT.md                      # Comprehensive academic research report
│
├── data/
│   ├── urls_merged.csv            # Clean, deduplicated merged dataset (780k rows)
│   ├── urls_features.parquet      # Pre-extracted 30-feature matrix
│   └── reference_data/            # Raw reference feeds
│       ├── malicious_phish.csv    # Kaggle main training pool
│       ├── balanced_urls.csv      # Held-out external collector
│       └── urls.csv               # Live abuse.ch URLhaus malware feed
│
├── models/
│   └── random_forest_model.pkl    # Champion Random Forest model (87.5% acc, 0.94 AUC)
│
├── outputs/                       # Research figures and metric tables
│   ├── model_comparison.png       # 6-Model benchmark comparison panels
│   ├── confusion_test.png         # 2x3 Confusion matrix grid
│   ├── feature_importance.png     # Top 15 permutation feature importances
│   ├── summary_table.csv          # Complete metrics summary across all models
│   ├── breakdown.csv              # Subtype, IP host & zero-shot domain breakdown
│   ├── ablation_feature_sets.csv  # 5-stage feature engineering ablation
│   └── ablation_length.csv        # URL length ablation study
│
└── url-guard/                     # Experimental core
    ├── notebooks/                 # Colab & Kaggle reproducible pipelines
    ├── src/                       # Extraction, loaders, training, plotting
    └── tests/                     # 27 unit tests (all passing)
```

---

## 🚀 Quick Start: Launch the Streamlit App

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Streamlit application:**
   ```bash
   streamlit run app.py
   ```

3. Open `http://localhost:8501` in your browser. Enter any URL to get an instant verdict (**Benign** 🟢 vs. **Malicious** 🔴), threat probability, and breakdown of suspicious indicators.

---

## 📊 Benchmark Results (The 6 Algorithms)

Evaluated on a **domain-grouped split** with 50 URLs/domain capping to eliminate data leakage:

| Model | Test Accuracy | Test Precision | Test Recall | Test F1 | Test ROC-AUC | Recall URLhaus (Zero-Shot) | Inference Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** ⭐ | **87.50%** | **87.70%** | 79.16% | **0.8321** | **0.9402** | 88.28% | **0.12 ms/URL** |
| **Gradient Boosting** | 86.78% | 83.72% | **82.20%** | 0.8295 | 0.9319 | **90.45%** | 0.016 ms/URL |
| **KNN** | 85.85% | 85.01% | 77.51% | 0.8109 | 0.9192 | 89.45% | 3.6 ms/URL (108s total) |
| **Decision Tree** | 85.06% | 80.77% | 81.16% | 0.8097 | 0.8949 | 90.39% | 0.001 ms/URL |
| **Logistic Regression** | 79.48% | 72.30% | 77.10% | 0.7462 | 0.8663 | 90.73% | 0.01 ms/URL |
| **Naive Bayes** | 67.26% | 81.91% | 20.98% | 0.3340 | 0.7434 | 87.21% | 0.006 ms/URL |

---

## 🔬 Core Research Findings

1. **URL-Only Classification is Viable:** Achieves **87.50% accuracy** and **0.9402 ROC-AUC** with zero page visits.
2. **Most Predictive Feature:** `n_dots` is overwhelmingly #1 (~0.11 ROC-AUC impact), followed by structural path & query depth (`path_length`, `n_params`, `n_slashes`, `hostname_length`, `n_subdomains`).
3. **Best Algorithm:** **Random Forest** is the champion due to highest precision (87.70%), lowest false alarms (7.1%), and strong generalization.
4. **URL Length Alone is Weak:** Length alone yields only **0.5551 ROC-AUC** (mean benign is 56.9 chars vs malicious 59.2 chars). It only contributes value when combined with structural features (+2.0% F1).
5. **Feature Engineering Gains:** Full engineered features boosted F1 from **0.7657** to **0.8317** (+6.6% absolute gain).
6. **Zero-Shot Domain Generalization:** The model flags **88.8%** of malicious URLs on domains never seen during training and **100%** of raw IP-hosted malware.

---

## 🧪 Testing

Run the test suite:
```bash
python -m pytest url-guard/tests
```
All 27 unit tests verify feature consistency, parser integrity, domain-grouped split independence, and metric reliability.
