# url-guard: malicious URL classification
- `src/features.py`     single source of truth for features (train, API, Streamlit all import it)
- `src/data_loader.py`  readers for the 3 sources, merge/clean, overlap report, source-bias check
- `src/experiment.py`   domain-grouped splits, six-model comparison, feature ablations, importances
- `src/plots.py`        confusion matrices, metric panels, importance chart
- `notebooks/01_data_and_features.ipynb`        load -> overlap -> merge -> bias check -> features
- `notebooks/02_split_compare_ablate.ipynb`     split -> six models -> breakdowns -> ablations -> importances
- `tests/`  `python -m pytest -q tests`  (27 tests)

Sources: malicious_phish.csv (train/val/test), balanced_urls.csv (external), URLhaus CSV dump (external / time split).
