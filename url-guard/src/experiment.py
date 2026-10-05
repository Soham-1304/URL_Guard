"""
experiment.py - domain-grouped splits, six-model comparison, feature ablations, importances.

Design (driven by the real data audit):
  * TRAIN / VAL / TEST come from ONE source (kaggle_main), where both classes were collected
    the same way, so the label cannot be predicted from "which dataset did this come from".
    The split is grouped by registered domain, so no domain appears on two sides.
  * Domains are capped (default 50 URLs per domain per class) so a few giant domains
    cannot dominate a fold or be memorised.
  * kaggle_balanced (URL-deduped against main) and urlhaus are NEVER trained on. They are
    external sets: 'unseen URLs from other collectors'. Their class mix is arbitrary, so we
    report recall (malicious sets) and specificity (benign set), not precision/accuracy.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

from features import FEATURE_GROUPS, feature_names

MAIN_SOURCE = "kaggle_main"
EXTERNAL_SETS = {                      # name -> (source, label)
    "balanced_malicious": ("kaggle_balanced", 1),
    "balanced_benign": ("kaggle_balanced", 0),
    "urlhaus": ("urlhaus", 1),
}
MODEL_ORDER = ["Logistic Regression", "Naive Bayes", "KNN", "Decision Tree", "Random Forest", "Gradient Boosting"]

# ------------------------------------------------------------------ feature sets (for ablations)
BASELINE = ["url_length", "n_dots", "n_digits", "n_special", "n_slashes", "n_hyphens"]
STRUCTURE = BASELINE + ["hostname_length", "path_length", "query_length", "longest_token_len", "n_params",
                        "n_pct_encoded", "n_at", "path_depth", "n_subdomains",
                        "digit_ratio", "letter_ratio", "special_ratio"]
HOST = STRUCTURE + ["has_ip_host", "has_port", "has_punycode", "is_shortener", "risky_tld", "host_entropy",
                    "domain_digit_count", "domain_hyphen_count"]
PATTERNS = HOST + ["keyword_count"]
FULL = PATTERNS + ["min_brand_dist", "brand_in_subdomain", "brand_in_path"]
NO_LENGTH = [c for c in FULL if c not in FEATURE_GROUPS["length"]]

FEATURE_SETS = {
    "1 baseline: raw length + char counts": BASELINE,
    "2 + structure (host/path/query, ratios)": STRUCTURE,
    "3 + host signals (IP, port, TLD, entropy)": HOST,
    "4 + suspicious keywords": PATTERNS,
    "5 + brand/typosquat (full)": FULL,
}
LENGTH_SETS = {
    "url_length only": ["url_length"],
    "all features minus length group": NO_LENGTH,
    "all features": FULL,
}

FEATURE_DESCRIPTIONS = {
    "url_length": "total characters in the URL (scheme excluded)",
    "hostname_length": "characters in the host name",
    "path_length": "characters in the path",
    "query_length": "characters in the query string",
    "longest_token_len": "longest run of letters/digits (random-looking tokens are long)",
    "n_dots": "number of '.'", "n_hyphens": "number of '-'", "n_slashes": "number of '/'",
    "n_digits": "number of digits", "n_special": "characters that are neither letters nor digits",
    "n_params": "query parameters", "n_pct_encoded": "%xx escapes (obfuscation)",
    "n_at": "'@' characters (can hide the real host)", "path_depth": "directory depth of the path",
    "n_subdomains": "subdomain labels (leading www ignored)", "keyword_count": "login/verify/secure-style words",
    "digit_ratio": "digits / length", "letter_ratio": "letters / length", "special_ratio": "special chars / length",
    "has_ip_host": "host is an IP address", "has_port": "non-default port present",
    "has_punycode": "xn-- host (lookalike characters)", "is_shortener": "known URL shortener",
    "risky_tld": "TLD commonly abused in blocklists", "host_entropy": "randomness of the host name",
    "domain_digit_count": "digits inside the registered domain label",
    "domain_hyphen_count": "hyphens inside the registered domain label",
    "min_brand_dist": "edit distance of the domain label to the nearest known brand (typosquat signal)",
    "brand_in_subdomain": "a brand name appears in the subdomain of a different domain",
    "brand_in_path": "a brand name appears in the path of a different domain",
}


# ------------------------------------------------------------------ splitting
def cap_per_domain(df: pd.DataFrame, cap: int = 50, seed: int = 42) -> pd.DataFrame:
    """Keep at most `cap` random URLs per (registered domain, class)."""
    return df.sample(frac=1.0, random_state=seed).groupby(["domain", "label"], sort=False).head(cap).sort_index()


@dataclass
class Splits:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame
    external: dict

    def summary(self) -> pd.DataFrame:
        rows = []
        for name, d in {"train": self.train, "val": self.val, "test": self.test, **self.external}.items():
            rows.append({"set": name, "rows": len(d), "domains": d["domain"].nunique(),
                         "malicious_%": round(100 * d["label"].mean(), 1),
                         "domain_seen_in_train_%": round(100 * d["domain_seen_in_train"].mean(), 1)
                         if "domain_seen_in_train" in d else np.nan})
        return pd.DataFrame(rows)


def make_splits(df: pd.DataFrame, cap: int = 50, seed: int = 42, urlhaus_train_frac: float = 0.0) -> Splits:
    """Domain-grouped, class-stratified ~71/14/14 split of the main source + capped external sets.

    urlhaus_train_frac: 0.0 -> URLhaus is purely external (train on main only).
        e.g. 0.7 -> the OLDEST 70% of URLhaus (by dateadded) joins the training set and the NEWEST 30%
        stays as the fresh test. A time split, so 'unseen' still means 'added later'. Use this if the
        main-only model cannot catch IP-address malware URLs.
    """
    main = cap_per_domain(df[df["source"] == MAIN_SOURCE], cap, seed).reset_index(drop=True)
    outer = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=seed)
    rest_i, test_i = next(outer.split(main, main["label"], main["domain"]))
    rest = main.iloc[rest_i].reset_index(drop=True)
    inner = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=seed)
    tr_i, va_i = next(inner.split(rest, rest["label"], rest["domain"]))
    train, val, test = rest.iloc[tr_i].copy(), rest.iloc[va_i].copy(), main.iloc[test_i].copy()

    dt, dv, ds = set(train["domain"]), set(val["domain"]), set(test["domain"])
    assert not (dt & dv) and not (dt & ds) and not (dv & ds), "domain leakage between splits!"

    uh_old = None
    if urlhaus_train_frac > 0:
        uh = df[df["source"] == "urlhaus"].sort_values("dateadded")
        k = int(len(uh) * urlhaus_train_frac)
        uh_old, uh_new_idx = uh.iloc[:k], uh.index[k:]
        uh_old = cap_per_domain(uh_old, cap, seed)
        train = pd.concat([train, uh_old], ignore_index=True)
        dt = set(train["domain"])

    ext = {}
    for name, (src, lab) in EXTERNAL_SETS.items():
        e = df[(df["source"] == src) & (df["label"] == lab)]
        if name == "urlhaus" and uh_old is not None:
            e = e.loc[e.index.isin(uh_new_idx)]
        e = cap_per_domain(e, cap, seed).reset_index(drop=True)
        e["domain_seen_in_train"] = e["domain"].isin(dt)
        ext[name] = e
    return Splits(train.reset_index(drop=True), val.reset_index(drop=True), test.reset_index(drop=True), ext)


# ------------------------------------------------------------------ models and metrics
def get_models(seed: int = 42, fast: bool = False) -> dict:
    log = lambda: FunctionTransformer(np.log1p, validate=False)   # features are all >= 0
    trees = 20 if fast else 200
    return {
        "Logistic Regression": make_pipeline(log(), StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
        "Naive Bayes": make_pipeline(log(), StandardScaler(), GaussianNB()),
        "KNN": make_pipeline(log(), StandardScaler(), KNeighborsClassifier(n_neighbors=15, n_jobs=-1)),
        "Decision Tree": DecisionTreeClassifier(max_depth=15, min_samples_leaf=5, class_weight="balanced", random_state=seed),
        "Random Forest": RandomForestClassifier(n_estimators=trees, min_samples_leaf=2, class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=seed),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=20 if fast else 150, max_depth=4, random_state=seed),
    }


def _fit(name, model, X, y):
    if name == "Gradient Boosting":
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)


def evaluate(y, pred, proba=None) -> dict:
    """Metrics that stay valid on single-class sets (undefined ones are NaN)."""
    y, pred = np.asarray(y), np.asarray(pred)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    n = len(y)
    prec = tp / (tp + fp) if (tp + fp) else np.nan
    rec = tp / (tp + fn) if (tp + fn) else np.nan
    spec = tn / (tn + fp) if (tn + fp) else np.nan
    f1 = 2 * prec * rec / (prec + rec) if (prec == prec and rec == rec and (prec + rec) > 0) else np.nan
    both = len(set(y.tolist())) == 2 and proba is not None
    return {"n": n, "accuracy": (tp + tn) / n, "precision": prec, "recall": rec, "specificity": spec, "f1": f1,
            "roc_auc": roc_auc_score(y, proba) if both else np.nan,
            "pr_auc": average_precision_score(y, proba) if both else np.nan,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


BREAKDOWNS = {"test": ["subtype"], "balanced_malicious": ["domain_seen_in_train"],
              "balanced_benign": ["domain_seen_in_train"], "urlhaus": ["has_ip_host", "domain_seen_in_train"]}


@dataclass
class Comparison:
    results: pd.DataFrame      # one row per (model, eval_set)
    breakdown: pd.DataFrame    # flagged-as-malicious rate per subgroup
    timing: pd.DataFrame
    models: dict
    cols: list


def run_comparison(splits: Splits, cols=None, model_names=None, train_cap: int = 120_000, eval_cap: int = 30_000,
                   seed: int = 42, fast: bool = False, verbose: bool = True) -> Comparison:
    """Train every model on the SAME (capped) training sample and score the SAME eval samples."""
    cols = list(cols or FULL)
    train = splits.train.sample(n=min(train_cap, len(splits.train)), random_state=seed)
    Xtr, ytr = train[cols].values, train["label"].values
    evals = {"val": splits.val, "test": splits.test, **splits.external}
    evals = {k: (d.sample(n=min(eval_cap, len(d)), random_state=seed)) for k, d in evals.items()}

    models = get_models(seed, fast)
    names = [m for m in MODEL_ORDER if m in models and (model_names is None or m in model_names)]
    rows, brk, tim, fitted = [], [], [], {}
    for name in names:
        m = models[name]
        t0 = time.time(); _fit(name, m, Xtr, ytr); fit_s = time.time() - t0
        fitted[name] = m
        pred_s = 0.0
        for set_name, d in evals.items():
            t0 = time.time()
            proba = m.predict_proba(d[cols].values)[:, 1]
            pred = (proba >= 0.5).astype(int)
            pred_s += time.time() - t0
            rows.append({"model": name, "eval_set": set_name, **evaluate(d["label"].values, pred, proba)})
            for by in BREAKDOWNS.get(set_name, []):
                key = d[by].astype(str) if by != "has_ip_host" else d[by].map({1: "IP-address host", 0: "domain host"})
                if by == "domain_seen_in_train":
                    key = d[by].map({True: "domain seen in training", False: "unseen domain"})
                for g, idx in key.groupby(key).groups.items():
                    pos = d.index.get_indexer(idx)
                    brk.append({"model": name, "eval_set": set_name, "by": by, "group": g,
                                "n": len(pos), "flagged_malicious_rate": float(pred[pos].mean())})
        tim.append({"model": name, "fit_s": round(fit_s, 1), "predict_s_total": round(pred_s, 1)})
        if verbose:
            t = rows[[r["model"] for r in rows].index(name) + list(evals).index("test")]
            print(f"{name:20s} fit {fit_s:6.1f}s | test F1 {t['f1']:.4f}  AUC {t['roc_auc']:.4f}")
    return Comparison(pd.DataFrame(rows), pd.DataFrame(brk), pd.DataFrame(tim), fitted, cols)


def summary_table(comp: Comparison) -> pd.DataFrame:
    """One row per model: main-test metrics + external recall/specificity + speed."""
    r = comp.results.set_index(["model", "eval_set"])
    out = []
    for m in comp.results["model"].unique():
        t = r.loc[(m, "test")]
        out.append({"model": m, "val_f1": r.loc[(m, "val"), "f1"], "test_accuracy": t["accuracy"],
                    "test_precision": t["precision"], "test_recall": t["recall"], "test_f1": t["f1"],
                    "test_roc_auc": t["roc_auc"], "test_pr_auc": t["pr_auc"],
                    "recall_urlhaus": r.loc[(m, "urlhaus"), "recall"],
                    "recall_balanced_malicious": r.loc[(m, "balanced_malicious"), "recall"],
                    "specificity_balanced_benign": r.loc[(m, "balanced_benign"), "specificity"]})
    s = pd.DataFrame(out).merge(comp.timing, on="model")
    return s.round(4)


def feature_set_ablation(splits: Splits, sets: dict, model_names=("Logistic Regression", "Random Forest"), **kw) -> pd.DataFrame:
    """Same models, same splits, different feature sets -> answers 'does feature engineering help?'"""
    rows = []
    for set_name, cols in sets.items():
        comp = run_comparison(splits, cols, model_names=list(model_names), verbose=False, **kw)
        s = summary_table(comp)
        for _, x in s.iterrows():
            rows.append({"feature_set": set_name, "n_features": len(cols), "model": x["model"],
                         "test_f1": x["test_f1"], "test_roc_auc": x["test_roc_auc"],
                         "recall_urlhaus": x["recall_urlhaus"],
                         "recall_balanced_malicious": x["recall_balanced_malicious"],
                         "specificity_balanced_benign": x["specificity_balanced_benign"]})
    return pd.DataFrame(rows)


def feature_importance(model, df: pd.DataFrame, cols, n: int = 20_000, n_repeats: int = 3, seed: int = 42) -> pd.DataFrame:
    """Permutation importance (drop in ROC-AUC when a feature is shuffled) + impurity importance if available."""
    from sklearn.inspection import permutation_importance
    d = df.sample(n=min(n, len(df)), random_state=seed)
    pi = permutation_importance(model, d[list(cols)].values, d["label"].values, scoring="roc_auc",
                                n_repeats=n_repeats, random_state=seed, n_jobs=-1)
    out = pd.DataFrame({"feature": list(cols), "perm_importance": pi.importances_mean, "perm_std": pi.importances_std})
    if hasattr(model, "feature_importances_"):
        out["impurity_importance"] = model.feature_importances_
    out["meaning"] = out["feature"].map(FEATURE_DESCRIPTIONS)
    return out.sort_values("perm_importance", ascending=False).reset_index(drop=True)
