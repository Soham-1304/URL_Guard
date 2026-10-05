import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import numpy as np, pandas as pd, pytest
import experiment as ex
from features import extract_features_df, feature_names


def _synthetic(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    words = ["shop", "news", "blog", "mail", "docs", "maps", "cloud", "game", "food", "tech"]
    def benign():
        d = f"{rng.choice(words)}{rng.integers(0, 300)}.com"
        return f"{d}/{rng.choice(words)}/{rng.choice(words)}.html"
    def phish():
        return f"{rng.choice(words)}-login-verify{rng.integers(0, 9999)}.xyz/account/secure/{rng.integers(0, 10**6)}"
    def ipmal():
        return f"http://{rng.integers(1,255)}.{rng.integers(1,255)}.{rng.integers(1,255)}.{rng.integers(1,255)}:{rng.integers(1000,60000)}/bin.sh"
    rows = []
    for _ in range(n):
        y = int(rng.random() < 0.35)
        rows.append((phish() if y else benign(), y, "kaggle_main", "phishing" if y else "benign"))
    for _ in range(300):
        rows.append((phish(), 1, "kaggle_balanced", "malicious"))
    for _ in range(60):
        rows.append((benign(), 0, "kaggle_balanced", "benign"))
    for _ in range(300):
        rows.append((ipmal(), 1, "urlhaus", "malware_download"))
    df = pd.DataFrame(rows, columns=["url", "label", "source", "subtype"])
    from features import registered_domain
    df["domain"] = [registered_domain(u) for u in df.url]
    return pd.concat([df, extract_features_df(df.url)], axis=1)


@pytest.fixture(scope="module")
def df():
    return _synthetic()


def test_feature_sets_consistent():
    assert set(ex.FULL) == set(feature_names()) and len(ex.FULL) == len(set(ex.FULL))
    for cols in list(ex.FEATURE_SETS.values()) + list(ex.LENGTH_SETS.values()):
        assert set(cols) <= set(feature_names())
    assert set(ex.FEATURE_DESCRIPTIONS) == set(feature_names())


def test_splits_are_domain_disjoint_and_external_untouched(df):
    s = ex.make_splits(df, cap=5)
    for a, b in [(s.train, s.val), (s.train, s.test), (s.val, s.test)]:
        assert not (set(a.domain) & set(b.domain))
    assert set(s.train.source) == {"kaggle_main"}
    assert set(s.external) == set(ex.EXTERNAL_SETS)
    assert s.external["urlhaus"].label.eq(1).all() and s.external["balanced_benign"].label.eq(0).all()
    assert s.train.groupby(["domain", "label"]).size().max() <= 5
    assert {0, 1} <= set(s.train.label) and {0, 1} <= set(s.test.label)


def test_comparison_runs_and_metrics_sane(df):
    s = ex.make_splits(df, cap=20)
    comp = ex.run_comparison(s, train_cap=2000, eval_cap=500, fast=True, verbose=False)
    assert set(comp.results.model) == set(ex.MODEL_ORDER)
    tab = ex.summary_table(comp)
    assert len(tab) == 6 and tab[["test_f1", "test_roc_auc", "recall_urlhaus"]].notna().all().all()
    assert (tab.test_f1 > 0.9).all()                      # synthetic task is easy; catches wiring bugs
    assert set(comp.breakdown.by) >= {"subtype", "has_ip_host", "domain_seen_in_train"}
    assert comp.breakdown.flagged_malicious_rate.between(0, 1).all()


def test_ablation_and_importance(df):
    s = ex.make_splits(df, cap=20)
    ab = ex.feature_set_ablation(s, {"base": ex.BASELINE, "full": ex.FULL}, model_names=["Random Forest"],
                                 train_cap=1500, eval_cap=400, fast=True)
    assert len(ab) == 2
    comp = ex.run_comparison(s, model_names=["Random Forest"], train_cap=1500, eval_cap=400, fast=True, verbose=False)
    imp = ex.feature_importance(comp.models["Random Forest"], s.test, comp.cols, n=800, n_repeats=2)
    assert len(imp) == len(ex.FULL) and imp.meaning.notna().all()


def test_plots_render(df, tmp_path):
    import matplotlib; matplotlib.use("Agg")
    import plots
    s = ex.make_splits(df, cap=20)
    comp = ex.run_comparison(s, train_cap=1500, eval_cap=400, fast=True, verbose=False)
    plots.plot_confusion_grid(comp.results, "test", str(tmp_path / "cm.png"))
    plots.plot_metric_panels(ex.summary_table(comp), str(tmp_path / "m.png"))
    assert (tmp_path / "cm.png").stat().st_size > 5000 and (tmp_path / "m.png").stat().st_size > 5000


def test_urlhaus_time_split(df):
    d = df.copy()
    d["dateadded"] = pd.NaT
    m = d.source == "urlhaus"
    d.loc[m, "dateadded"] = pd.date_range("2026-09-01", periods=int(m.sum()), freq="h")
    s = ex.make_splits(d, cap=50, urlhaus_train_frac=0.7)
    assert (s.train.source == "urlhaus").sum() > 0 and (s.train.source == "kaggle_main").sum() > 0
    assert not s.val.source.eq("urlhaus").any() and not s.test.source.eq("urlhaus").any()
    new = s.external["urlhaus"]
    assert 0 < len(new) < int(m.sum())
    assert new.dateadded.min() >= s.train.loc[s.train.source == "urlhaus", "dateadded"].max()
    s0 = ex.make_splits(d, cap=50)
    assert not s0.train.source.eq("urlhaus").any()
