# Case Study 149: Malicious URL Classification Using Machine Learning
**B.Tech CSE 2024–2028 · Semester V · Machine Learning Project Report**

---

## Executive Summary
In this project, we designed, built, and evaluated an end-to-end, real-time malicious URL classification system without network calls, page visits, or WHOIS lookups. Using **30 engineered lexical and structural features**, we trained and benchmarked all six required machine learning algorithms on a rigorous domain-grouped dataset of **780,573 deduplicated URLs**. 

**Champion Model:** **Random Forest** achieved the best overall performance with **87.50% Test Accuracy**, **87.70% Precision**, **0.8321 F1-Score**, **0.9402 ROC-AUC**, and **88.28% zero-shot recall on fresh URLhaus malware** in **0.12 milliseconds per URL**.

---

## 1. Problem Statement & Objectives
Users frequently access URLs through search engines, email, advertisements, and social media. Malicious URLs redirect users to phishing vectors, malware distribution hosts, or fraudulent services.

### Objectives:
1. Extract numerical, lexical, and structural features directly from the URL text string.
2. Build and compare six classic machine learning classification algorithms.
3. Conduct ablation studies on URL length and engineered feature sets.
4. Test zero-shot generalization on live, unseen malicious domains (URLhaus feed).
5. Deploy a real-time **Streamlit web application** for interactive single-URL prediction.

---

## 2. Dataset Architecture & Leakage Prevention
Most public literature reports artificially inflated classification metrics because duplicate or related URLs from the same domain leak across random train/test splits. We implemented strict data hygiene:

| Split / Dataset | Source | Total Rows | Domains | % Malicious | Domain Leakage Protection |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Train** | `kaggle_main` | 286,919 | 110,271 | 39.3% | StratifiedGroupKFold (Capped at 50/domain) |
| **Validation** | `kaggle_main` | 57,538 | 22,130 | 39.0% | Strictly disjoint domains from Train |
| **Test** | `kaggle_main` | 55,292 | 22,061 | 38.9% | Strictly disjoint domains from Train & Val |
| **External Malicious** | `kaggle_balanced` | 85,835 | 44,087 | 100.0% | Held-out collector (URL-deduped against main) |
| **External Benign** | `kaggle_balanced` | 4,190 | 3,862 | 0.0% | Held-out collector |
| **Fresh Malware Feed** | `URLhaus (abuse.ch)` | 43,599 | 17,030 | 100.0% | Live feed (99.0% unseen zero-shot domains) |

### Key Data Audit Discoveries:
1. **84.6% Source Overlap:** `balanced_urls.csv` shared 522,260 identical URLs with `malicious_phish.csv`. Deduplication was mandatory to prevent test contamination.
2. **13,124 Label Conflicts Dropped:** URLs labeled both *Benign* and *Malicious* across different dumps were removed as untrustworthy.
3. **Source Bias Check (Gap = 0.447):** A random forest classifier easily predicted which source a URL came from with a 0.447 accuracy gap over baseline. This confirmed that training across heterogeneous collectors induces shortcut learning, justifying our decision to train exclusively on `kaggle_main` with held-out external evaluation.

---

## 3. Comparative Study: The Six Machine Learning Algorithms

All models were evaluated on the exact same domain-grouped test split (`n = 55,292`) and external zero-shot datasets:

| Algorithm | Val F1 | Test Accuracy | Test Precision | Test Recall | Test F1 | Test ROC-AUC | Recall URLhaus (Zero-Shot) | Inference Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** ⭐ | **0.8332** | **87.50%** | **87.70%** | 79.16% | **0.8321** | **0.9402** | 88.28% | **0.12 ms/URL** |
| **Gradient Boosting** | 0.8228 | 86.78% | 83.72% | **82.20%** | 0.8295 | 0.9319 | **90.45%** | 0.016 ms/URL |
| **K-Nearest Neighbors (KNN)** | 0.8037 | 85.85% | 85.01% | 77.51% | 0.8109 | 0.9192 | 89.45% | 3.6 ms/URL (108s total) |
| **Decision Tree** | 0.8065 | 85.06% | 80.77% | 81.16% | 0.8097 | 0.8949 | 90.39% | 0.001 ms/URL |
| **Logistic Regression** | 0.7479 | 79.48% | 72.30% | 77.10% | 0.7462 | 0.8663 | 90.73% | 0.01 ms/URL |
| **Naive Bayes (Gaussian)** | 0.3212 | 67.26% | 81.91% | 20.98% | 0.3340 | 0.7434 | 87.21% | 0.006 ms/URL |

### Performance Analysis:
- **Random Forest (Champion):** Dominates across Accuracy (**87.50%**), Precision (**87.70%**), F1 (**0.8321**), and ROC-AUC (**0.9402**). Its 87.7% precision is critical for cybersecurity because it minimizes false alarms on benign business traffic.
- **Gradient Boosting (Runner-up):** Strongest recall on malicious URLs (**82.20%** on test, **90.45%** on fresh URLhaus) with sub-millisecond scoring.
- **K-Nearest Neighbors:** Reasonable accuracy (**85.85%**), but its $O(N \cdot D)$ brute-force distance computation took **108.3 seconds** to evaluate test samples, making it unviable for real-time edge deployment.
- **Naive Bayes:** Suffered severe recall collapse (**20.98%**) because lexical URL features (length, path depth, token counts) exhibit strong mutual correlations that violently violate the conditional independence assumption.

---

## 4. Answers to the Six Core Research Questions

### Question 1: Can malicious URLs be classified without visiting the website?
**YES.** Lexical and structural features extracted purely from the URL string are highly discriminative. The Random Forest model achieved **87.50% test accuracy**, **0.9402 ROC-AUC**, and **88.28% recall on fresh URLhaus malware** without making a single network request, DNS query, or inspecting page content. This ensures safe, zero-latency protection at the point of click.

### Question 2: Which URL features are most predictive?
Permutation importance (measuring test ROC-AUC drop when a feature is shuffled) revealed:
1. **`n_dots` (Overwhelmingly #1):** Causes a **~0.11 drop in test ROC-AUC**. Malicious URLs heavily rely on multiple subdomains, dotted IP addresses, and file extensions.
2. **`path_length` (~0.033 drop):** Phishing and malware URLs feature deep, convoluted path strings.
3. **`n_params` (~0.027 drop):** Tracking and exfiltration query parameters.
4. **`n_slashes` (~0.020 drop):** Directory traversal and obfuscation depth.
5. **`hostname_length` (~0.019 drop) & `n_subdomains` (~0.018 drop):** Domain impersonation and complex hierarchy.

### Question 3: Which algorithm performs best?
**Random Forest** is the best overall algorithm. It yields the highest accuracy (**87.50%**), the highest precision (**87.70%**), and the highest ROC-AUC (**0.9402**). It outperforms single decision trees by reducing variance through bagging and outpaces linear models by capturing non-linear threshold interactions (e.g., combinations of raw IP host + non-standard port).

### Question 4: Does URL length contribute to classification?
**Only in combination with other structural features.**
- **Length Alone is Ineffective:** A classifier trained solely on `url_length` achieved an F1 of only **0.4756** and ROC-AUC of **0.5551** (virtually a random coin toss).
- **Distribution Parity:** Benign URLs in the wild averaged **56.9 characters** (median 46.0) while Malicious URLs averaged **59.2 characters** (median 45.0).
- **Additive Synergy:** Removing the length group from the full feature set dropped Random Forest F1 from **0.8317 to 0.8110** (-2.07%). Length provides value only when contextualized by path depth, token length, and character ratios.

### Question 5: How does feature engineering improve results?
**Feature engineering yielded a +6.6% absolute gain in F1 and +0.047 in ROC-AUC.**
- **Step 1 (Raw Baseline - 6 chars/counts):** F1 = `0.7657`, ROC-AUC = `0.8907`
- **Step 2 (+ Structural Ratios, Query, Depth - 18 features):** F1 = `0.8189`, ROC-AUC = `0.9314` *(+5.3% jump)*
- **Step 3 (+ Host Signals, IP, Port, Entropy - 26 features):** F1 = `0.8279`, ROC-AUC = `0.9349`
- **Step 4 (+ Suspicious Keywords - 27 features):** F1 = `0.8280`, ROC-AUC = `0.9358`
- **Step 5 (+ Brand Typosquatting / Distance - 30 features):** F1 = **`0.8317`**, ROC-AUC = **`0.9375`**

### Question 6: Can the system classify previously unseen URLs?
**YES.** Evaluated on zero-shot domain generalization:
- On **29,715 URLs from completely unseen domains** in URLhaus, the model flagged **88.8%** correctly as malicious.
- On **IP-address hosted malware**, the model achieved **100.0% recall** (caught all 25,372 instances).
- Subtype breakdown: Caught **87.0% of Malware**, **82.2% of Defacements**, and **74.7% of Phishing** URLs.
- The false positive rate on benign traffic was kept low at **7.1%**.

---

## 5. Deployment Architecture (Streamlit App)
A production-grade web application was built in [`app.py`](file:///Users/sohamkarandikar/Desktop/AI_ML_SEM_V_Exam/app.py):
1. **Interactive URL Inspection:** Allows users to input any live URL string or select presets.
2. **Sub-millisecond Feature Pipeline:** Computes all 30 lexical features on the fly.
3. **Verdict & Confidence Gauge:** Outputs instant `Benign` vs `Malicious` verdicts with calibrated probability scores.
4. **Threat Vector Diagnostics:** Highlights specific triggers (IP host, brand impersonation, high-entropy tokens, risky TLDs).

To run the application locally:
```bash
streamlit run app.py
```
