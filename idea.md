# Malicious URL Classification: Problem and Data

## 1. Problem Definition

**Context.** Users reach URLs through search results, email, ads, and social media. A malicious URL can lead to phishing pages, malware downloads, or fraudulent sites. Blocklists only catch URLs that have already been reported, and visiting a suspicious URL to inspect it is itself risky and slow.

**Problem.** Given only the URL string, classify it as **Benign** or **Malicious** before anyone visits it.

**Approach.** Treat it as binary classification on lexical and structural features extracted from the URL text. No network calls, no page content, no WHOIS lookups. This keeps prediction fast (milliseconds), safe, and usable at the point of click.

**What makes this project different.** Most URL classifiers report inflated accuracy because related URLs leak across a random train/test split. We evaluate honestly:
- Train/test split grouped by registered domain, so no domain appears on both sides.
- A held-out source: a dataset the model never saw during training.
- A fresh-URL test using recently reported malicious URLs.
- (Stretch) An evasion test: how easily can an attacker mutate a malicious URL to slip past the model, and does adversarial retraining help?

**Two roles for the models.**
- *Comparison (for the report):* all six algorithms are trained on the same split and compared on accuracy, precision, recall, F1, and confusion matrix.
- *Deployment:* only the best-performing model (chosen on grouped validation and fresh-URL results, not accuracy alone) is served through the API and the Streamlit app.

## 2. Research Questions

| # | Question | How we answer it |
|---|----------|------------------|
| 1 | Can malicious URLs be classified without visiting the website? | Test-set and fresh-URL performance using URL-only features |
| 2 | Which URL features are most predictive? | Tree-based importance plus permutation importance |
| 3 | Which algorithm performs best? | Six-model comparison on identical splits, including the fresh-URL gap |
| 4 | Does URL length contribute? | Ablation (with vs without length features) and length distribution by class |
| 5 | How does feature engineering improve results? | Baseline raw features vs full engineered feature set |
| 6 | Can the system classify unseen URLs? | Domain-grouped split, held-out source, and live-feed URLs |

## 3. Dataset Plan

We build one combined dataset from several sources, then run a single shared feature extractor over it.

| Source | Role | Content |
|--------|------|---------|
| Kaggle "Malicious URLs dataset" (large labelled set: benign, phishing, malware, defacement) | Main training pool | Mixed labelled URLs; collapse all non-benign classes to Malicious |
| PhishTank / OpenPhish | Fresh malicious (phishing) | Recently reported phishing URLs |
| URLhaus (abuse.ch) | Fresh malicious (malware) | Recently reported malware-distribution URLs |
| Tranco top-sites list | Benign hosts | Popular, reputable domains (used to source realistic benign URLs) |

*Availability, licensing, and exact row counts to be confirmed at download time and recorded here.*

**Label scheme.** Binary: `Benign = 0`, `Malicious = 1`.

**Cleaning rules.**
- Drop null, empty, and malformed URLs.
- Normalize case on scheme and host, strip whitespace, remove exact duplicates.
- Extract the registered domain for each URL (used for grouped splitting).
- Record the source of every row (used for the held-out-source test and bias checks).

**Known risk: source bias.** If benign URLs come only from Tranco (mostly bare homepages) and malicious URLs from feeds (long paths), the model can learn "has a path" instead of "is malicious." Mitigations:
- Include benign URLs with realistic paths and queries.
- Run a *source-prediction check*: if features can easily predict which source a URL came from, we have leakage and must rebalance.

**Class balance.** Check the ratio after merging. Use `class_weight="balanced"` and threshold tuning rather than SMOTE; run SMOTE only as an optional ablation inside training folds.

**Splits.**
1. Train / validation / test, grouped by registered domain.
2. One source held out entirely as an extra test set.
3. A fresh-URL set collected on the day of the experiment, never used for training or tuning.