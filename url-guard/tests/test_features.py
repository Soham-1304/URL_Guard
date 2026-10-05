import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import math
import pytest
from features import extract_features, extract_features_df, feature_names, registered_domain


def test_basic_counts():
    f = extract_features("https://www.example.com/a/b?x=1&y=2")
    assert f["n_subdomains"] == 0                  # leading www ignored
    assert f["path_depth"] == 2
    assert f["n_params"] == 2
    assert f["has_ip_host"] == 0


def test_subdomains_and_multipart_tld():
    f = extract_features("http://a.b.login.example.co.uk/")
    assert f["n_subdomains"] == 3                  # a, b, login
    assert registered_domain("http://a.b.example.co.uk/x") == "example.co.uk"


def test_ip_host_variants():
    assert extract_features("http://192.168.1.10/login")["has_ip_host"] == 1
    assert extract_features("http://0x7f000001/")["has_ip_host"] == 1
    assert extract_features("http://[::1]:8080/")["has_ip_host"] == 1


def test_at_symbol_and_keywords():
    f = extract_features("http://paypal.com@evil.example.xyz/verify/account/login")
    assert f["n_at"] == 1
    assert f["keyword_count"] >= 3
    assert f["risky_tld"] == 1


def test_typosquat_distance():
    assert extract_features("http://paypa1.com/")["min_brand_dist"] == 1
    assert extract_features("http://paypal.com/")["min_brand_dist"] == 0
    assert extract_features("http://completelyunrelatedname.org/")["min_brand_dist"] > 2


def test_brand_in_subdomain_not_triggered_for_real_brand():
    assert extract_features("http://paypal.com.secure-login.xyz/")["brand_in_subdomain"] == 1
    assert extract_features("https://www.paypal.com/signin")["brand_in_subdomain"] == 0


def test_scheme_optional_and_consistent():
    a = extract_features("example.com/path")
    b = extract_features("http://example.com/path")
    assert a["url_length"] == b["url_length"]      # scheme excluded from length: no dataset artifact


def test_scheme_feature_off_by_default():
    assert "has_https" not in extract_features("https://example.com")
    assert extract_features("https://example.com", include_scheme=True)["has_https"] == 1
    assert extract_features("example.com", include_scheme=True)["has_https"] == 0


def test_entropy_higher_for_random_host():
    assert extract_features("http://xk3j9qz7vb2m.com/")["host_entropy"] > extract_features("http://aaaa.com/")["host_entropy"]


@pytest.mark.parametrize("bad", ["", "   ", None, 123, "http://", "http://[bad"])
def test_invalid_raises(bad):
    with pytest.raises(ValueError):
        extract_features(bad)


def test_df_helper_marks_bad_rows_nan():
    df = extract_features_df(["http://ok.com", "", "http://also-ok.org/x"])
    assert list(df.columns) == feature_names()
    assert df.iloc[1].isna().all() and df.iloc[0].notna().all()
