"""plots.py - small-multiple charts for the comparison. One hue, thin marks, direct labels, light grid."""
from __future__ import annotations

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

INK, INK2, SURFACE, GRID, BLUE = "#0b0b0b", "#52514e", "#fcfcfb", "#e6e5e0", "#2a78d6"
SEQ = LinearSegmentedColormap.from_list("seq_blue", ["#eef3fb", BLUE, "#143e73"])   # one hue, light -> dark


def _style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)


def plot_confusion_grid(results, eval_set="test", path=None):
    """Row-normalised confusion matrices (share of each actual class), counts annotated."""
    df = results[results["eval_set"] == eval_set]
    models = list(df["model"])
    fig, axes = plt.subplots(2, 3, figsize=(11, 7), facecolor=SURFACE)
    for ax, (_, r) in zip(axes.ravel(), df.iterrows()):
        cm = np.array([[r.tn, r.fp], [r.fn, r.tp]], dtype=float)
        norm = cm / cm.sum(axis=1, keepdims=True)
        ax.imshow(norm, cmap=SEQ, vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{int(cm[i, j]):,}\n{norm[i, j]:.1%}", ha="center", va="center", fontsize=10,
                        color="white" if norm[i, j] > 0.55 else INK)
        ax.set_xticks([0, 1], ["Benign", "Malicious"]); ax.set_yticks([0, 1], ["Benign", "Malicious"])
        ax.set_xlabel("Predicted", color=INK2, fontsize=9); ax.set_ylabel("Actual", color=INK2, fontsize=9)
        ax.set_title(r["model"], color=INK, fontsize=11, loc="left")
        _style(ax)
    for ax in axes.ravel()[len(models):]:
        ax.axis("off")
    fig.suptitle(f"Confusion matrices on the {eval_set} set (cell colour = share of the actual class)", color=INK, fontsize=12, x=0.01, ha="left")
    fig.tight_layout()
    if path: fig.savefig(path, dpi=150, facecolor=SURFACE)
    return fig


def plot_metric_panels(summary, path=None):
    """One panel per question, one bar per model (fixed model order in every panel)."""
    panels = [("Main test: F1", "test_f1", (0, 1)), ("Main test: ROC-AUC", "test_roc_auc", (0, 1)),
              ("Fresh URLhaus: malicious caught", "recall_urlhaus", (0, 1)),
              ("Other-source malicious: caught", "recall_balanced_malicious", (0, 1)),
              ("Other-source benign: correctly passed", "specificity_balanced_benign", (0, 1)),
              ("Training time (seconds)", "fit_s", None)]
    models = list(summary["model"])
    fig, axes = plt.subplots(2, 3, figsize=(12, 6.5), facecolor=SURFACE)
    y = np.arange(len(models))[::-1]
    for ax, (title, col, lim) in zip(axes.ravel(), panels):
        vals = summary[col].values.astype(float)
        ax.barh(y, vals, color=BLUE, height=0.55)
        for yi, v in zip(y, vals):
            ax.text(v + (0.01 if lim else max(vals) * 0.02), yi, f"{v:.3f}" if lim else f"{v:.1f}", va="center", fontsize=9, color=INK)
        ax.set_yticks(y, models if ax in axes[:, 0] else [""] * len(models))
        if lim: ax.set_xlim(0, 1.12)
        ax.set_title(title, color=INK, fontsize=10.5, loc="left")
        ax.xaxis.grid(True, color=GRID, lw=0.8); ax.set_axisbelow(True)
        _style(ax)
    fig.tight_layout()
    if path: fig.savefig(path, dpi=150, facecolor=SURFACE)
    return fig


def plot_importance(imp, top=15, path=None):
    d = imp.head(top).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7.5, 5.2), facecolor=SURFACE)
    ax.barh(d["feature"], d["perm_importance"], xerr=d["perm_std"], color=BLUE, height=0.6,
            error_kw={"ecolor": INK2, "lw": 0.8, "capsize": 2})
    ax.set_title("Permutation importance: drop in test ROC-AUC when the feature is shuffled", color=INK, fontsize=10.5, loc="left")
    ax.xaxis.grid(True, color=GRID, lw=0.8); ax.set_axisbelow(True)
    _style(ax); fig.tight_layout()
    if path: fig.savefig(path, dpi=150, facecolor=SURFACE)
    return fig
