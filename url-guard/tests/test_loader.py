import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import pandas as pd
import data_loader as dl

URLHAUS = """################
# abuse.ch URLhaus Database Dump (CSV)
# Last updated: 2026-10-04 07:47:14 (UTC)
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3","2026-10-04 07:47:14","http://1.2.3.4:5555/i","online","2026-10-04 07:47:14","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/3/","a"
"2","2026-10-03 07:47:14","http://evil.example.top/a.exe","offline","","malware_download","None","https://urlhaus.abuse.ch/url/2/","b"
"1","2026-10-01 07:47:14","http://1.2.3.4:5555/i","online","","malware_download","None","https://urlhaus.abuse.ch/url/1/","c"
"""


def test_urlhaus_csv_parses_header_and_newest(tmp_path):
    p = tmp_path / "csv.txt"; p.write_text(URLHAUS)
    df = dl.load_urlhaus_csv(str(p))
    assert len(df) == 3 and (df["label"] == 1).all() and df["source"].eq("urlhaus").all()
    assert df["dateadded"].is_monotonic_decreasing
    assert len(dl.load_urlhaus_csv(str(p), newest_n=1)) == 1


def test_balanced_urls_labels(tmp_path):
    p = tmp_path / "b.csv"
    pd.DataFrame({"url": ["https://a.com/x", "https://b.xyz/login"], "label": ["benign", "malicious"],
                  "result": [0, 1]}).to_csv(p, index=False)
    assert dl.load_balanced_urls(str(p))["label"].tolist() == [0, 1]


def test_kaggle_main_binary_labels(tmp_path):
    p = tmp_path / "m.csv"
    pd.DataFrame({"url": ["a.com", "b.com", "c.com", "d.com"],
                  "type": ["benign", "phishing", "malware", "defacement"]}).to_csv(p, index=False)
    df = dl.load_kaggle(str(p))
    assert df["label"].tolist() == [0, 1, 1, 1] and df["source"].eq("kaggle_main").all()


def test_cross_source_dedupe_first_source_wins():
    a = pd.DataFrame({"url": ["en.wikipedia.org/wiki/Cat"], "label": 0, "source": "kaggle_main", "subtype": "benign"})
    b = pd.DataFrame({"url": ["https://www.en.wikipedia.org/wiki/Cat/"], "label": 0, "source": "kaggle_balanced", "subtype": "benign"})
    df = dl.build_dataset([a, b])
    assert len(df) == 1 and df.loc[0, "source"] == "kaggle_main"


def test_conflicting_labels_dropped():
    a = pd.DataFrame({"url": ["x.com/p"], "label": 0, "source": "s1", "subtype": "b"})
    b = pd.DataFrame({"url": ["http://x.com/p"], "label": 1, "source": "s2", "subtype": "m"})
    # same key, different label: first copy survives dedupe, so conflict must be caught BEFORE dedupe
    df = dl.build_dataset([a, b])
    assert len(df) == 0
