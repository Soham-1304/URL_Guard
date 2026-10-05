import React, { useState } from 'react';

interface ModelRow {
  name: string;
  valF1: number;
  acc: number;
  prec: number;
  rec: number;
  f1: number;
  auc: number;
  prAuc: number;
  urlhaus: number;
  balancedMal: number;
  balancedBen: number;
  fitSec: number;
  predictSec: number;
}

const MODELS: ModelRow[] = [
  {
    name: 'Random Forest',
    valF1: 0.8332,
    acc: 0.875,
    prec: 0.877,
    rec: 0.7916,
    f1: 0.8321,
    auc: 0.9402,
    prAuc: 0.9273,
    urlhaus: 0.8828,
    balancedMal: 0.2764,
    balancedBen: 0.6723,
    fitSec: 46.7,
    predictSec: 3.7
  },
  {
    name: 'Gradient Boosting',
    valF1: 0.8228,
    acc: 0.8678,
    prec: 0.8372,
    rec: 0.822,
    f1: 0.8295,
    auc: 0.9319,
    prAuc: 0.9149,
    urlhaus: 0.9045,
    balancedMal: 0.3529,
    balancedBen: 0.6222,
    fitSec: 66.6,
    predictSec: 0.5
  },
  {
    name: 'KNN',
    valF1: 0.8037,
    acc: 0.8585,
    prec: 0.8501,
    rec: 0.7751,
    f1: 0.8109,
    auc: 0.9192,
    prAuc: 0.89,
    urlhaus: 0.8945,
    balancedMal: 0.32,
    balancedBen: 0.6905,
    fitSec: 0.1,
    predictSec: 108.3
  },
  {
    name: 'Decision Tree',
    valF1: 0.8065,
    acc: 0.8506,
    prec: 0.8077,
    rec: 0.8116,
    f1: 0.8097,
    auc: 0.8949,
    prAuc: 0.8546,
    urlhaus: 0.9039,
    balancedMal: 0.3903,
    balancedBen: 0.6826,
    fitSec: 1.9,
    predictSec: 0.04
  },
  {
    name: 'Logistic Regression',
    valF1: 0.7479,
    acc: 0.7948,
    prec: 0.723,
    rec: 0.771,
    f1: 0.7462,
    auc: 0.8663,
    prAuc: 0.839,
    urlhaus: 0.9073,
    balancedMal: 0.4248,
    balancedBen: 0.4368,
    fitSec: 3.7,
    predictSec: 0.3
  },
  {
    name: 'Naive Bayes',
    valF1: 0.3212,
    acc: 0.6726,
    prec: 0.8191,
    rec: 0.2098,
    f1: 0.334,
    auc: 0.7434,
    prAuc: 0.6729,
    urlhaus: 0.8721,
    balancedMal: 0.1605,
    balancedBen: 0.9864,
    fitSec: 0.2,
    predictSec: 0.2
  }
];

const METRIC_NAMES = ['ROC-AUC', 'F1 Score', 'Accuracy', 'Precision', 'Recall', 'PR-AUC', 'URLhaus Zero-Shot'] as const;
type MetricKey = 'auc' | 'f1' | 'acc' | 'prec' | 'rec' | 'prAuc' | 'urlhaus';
const METRIC_KEYS: MetricKey[] = ['auc', 'f1', 'acc', 'prec', 'rec', 'prAuc', 'urlhaus'];

const ATTACK_TYPES = [
  { name: 'Malware', count: 1288, val: 0.8696, cls: 'g', desc: 'Direct executable downloads, payloads, scripts' },
  { name: 'Defacement', count: 4836, val: 0.8222, cls: 'g', desc: 'Vandalized sites, web shell paths, altered pages' },
  { name: 'Phishing', count: 5618, val: 0.7474, cls: 'a', desc: 'Credential harvesters mimicking legitimate hosts' },
  { name: 'Benign (false alarms)', count: 18258, val: 0.0714, cls: 'r', desc: 'Legitimate URLs incorrectly flagged (lower is better)' }
];

const TOP_FEATURES = [
  { name: 'n_dots', perm: 0.1109, gini: 0.177, meaning: "Total '.' count. Subdomains and file extensions." },
  { name: 'path_length', perm: 0.0324, gini: 0.1209, meaning: 'Characters in path. Deep nested exploitation routes.' },
  { name: 'n_params', perm: 0.0268, gini: 0.0448, meaning: 'Query parameters (?id=&token=). State injection.' },
  { name: 'n_slashes', perm: 0.0197, gini: 0.0659, meaning: "Total '/' count. URL path hierarchy depth." },
  { name: 'hostname_length', perm: 0.0187, gini: 0.0548, meaning: 'Length of host. Dynamic DNS and lookalike names.' },
  { name: 'n_subdomains', perm: 0.0181, gini: 0.0358, meaning: 'Subdomain labels count (ignoring leading www).' },
  { name: 'path_depth', perm: 0.0132, gini: 0.0364, meaning: 'Directory folder depth along the URL path.' },
  { name: 'longest_token_len', perm: 0.0102, gini: 0.0407, meaning: 'Longest alphanumeric segment. Random tokens are long.' },
  { name: 'url_length', perm: 0.0063, gini: 0.0437, meaning: 'Total characters in URL (excluding scheme).' },
  { name: 'query_length', perm: 0.0059, gini: 0.029, meaning: 'Length of the query string following question mark.' }
];

const ABLATION_STEPS = [
  { name: '1. Raw length + char counts (6)', f1: 0.7657, auc: 0.8907, gain: 'Baseline' },
  { name: '2. + Structure (host/path/query, ratios) (18)', f1: 0.8189, auc: 0.9314, gain: '+5.32% F1' },
  { name: '3. + Host signals (IP, port, TLD, entropy) (26)', f1: 0.8279, auc: 0.9349, gain: '+0.90% F1' },
  { name: '4. + Suspicious keywords (27)', f1: 0.828, auc: 0.9358, gain: '+0.01% F1' },
  { name: '5. + Brand / typosquat distance (30)', f1: 0.8317, auc: 0.9375, gain: '+0.37% F1' }
];

export const DashboardPage: React.FC = () => {
  const [activeMetricIdx, setActiveMetricIdx] = useState<number>(0); // Default to ROC-AUC
  const [activeFigure, setActiveFigure] = useState<'none' | 'confusion' | 'importance' | 'models'>('none');

  const activeKey = METRIC_KEYS[activeMetricIdx];
  const pct = (v: number) => (v * 100).toFixed(2) + '%';

  return (
    <main id="p-dashboard" className="on">
      <div className="wrap pg">
        <h2>Evidence & Benchmark Suite</h2>
        <p className="lede" style={{ fontSize: 17 }}>
          Evaluated across 55,292 domain-grouped test URLs, 85,835 external threats, and 43,599 fresh
          URLhaus feeds. All data derived directly from model evaluation logs.
        </p>

        {/* Top KPI strip */}
        <div className="kpis solid" style={{ marginTop: 0 }}>
          <div>
            <strong>0.9402</strong>
            <span>ROC-AUC (Random Forest)</span>
          </div>
          <div>
            <strong>87.70%</strong>
            <span>Test precision (least false alarms)</span>
          </div>
          <div>
            <strong>100.0%</strong>
            <span>Recall on 25,372 IP-based malware</span>
          </div>
          <div>
            <strong>0.067 ms</strong>
            <span>Inference latency per URL (15k/sec)</span>
          </div>
        </div>

        {/* Model comparison with metric switcher */}
        <section className="sec solid">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <h3>Model Comparison Across Key Metrics</h3>
              <p>Pick a metric to see real measured differences. Bars start at zero to avoid exaggerated visual bias.</p>
            </div>
            <button
              type="button"
              className="btn"
              style={{ fontSize: 13, padding: '6px 12px' }}
              onClick={() => setActiveFigure(activeFigure === 'models' ? 'none' : 'models')}
            >
              {activeFigure === 'models' ? 'Hide Chart Plot' : 'View Publication Plot ↗'}
            </button>
          </div>

          <div className="seg">
            {METRIC_NAMES.map((name, i) => (
              <button
                key={name}
                type="button"
                aria-pressed={i === activeMetricIdx}
                onClick={() => setActiveMetricIdx(i)}
              >
                {name}
              </button>
            ))}
          </div>

          <div style={{ marginTop: 8 }}>
            {(() => {
              const maxVal = Math.max(...MODELS.map(m => m[activeKey]));
              return MODELS.map(m => {
                const val = m[activeKey];
                const isRf = m.name === 'Random Forest';
                const isTop = val === maxVal;
                return (
                  <div key={m.name} className={`bar ${isTop ? 'w' : ''}`}>
                    <span>
                      {m.name} {isRf && <span style={{ color: 'var(--blue)', marginLeft: 4, fontSize: 14 }}>★</span>}
                    </span>
                    <div className="t">
                      <i style={{ width: `${Math.max(0, Math.min(100, val * 100))}%` }} />
                    </div>
                    <b>{pct(val)}</b>
                  </div>
                );
              });
            })()}
          </div>

          {activeFigure === 'models' && (
            <div className="figure-preview">
              <img src="/outputs/model_comparison.png" alt="Model comparison bar chart" />
              <div className="figure-caption">
                Figure 1: Cross-model performance comparison across Test Accuracy, F1, ROC-AUC, and Zero-shot URLhaus Recall.
              </div>
            </div>
          )}
        </section>

        {/* Complete Benchmark Table */}
        <section className="sec solid">
          <h3>Full 6-Model Benchmark Table (Domain-Grouped Test Split)</h3>
          <p>Scored on 55,292 URLs with zero domain overlap with the training set.</p>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Test Acc</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1 Score</th>
                  <th>ROC-AUC</th>
                  <th>PR-AUC</th>
                  <th>URLhaus Recall</th>
                  <th>Train Fit</th>
                  <th>Score Time (55k)</th>
                </tr>
              </thead>
              <tbody>
                {MODELS.map(m => (
                  <tr key={m.name} style={{ background: m.name === 'Random Forest' ? 'rgba(43,80,255,0.03)' : undefined }}>
                    <td style={{ fontWeight: m.name === 'Random Forest' ? 600 : 400 }}>
                      {m.name} {m.name === 'Random Forest' && '★'}
                    </td>
                    <td>{pct(m.acc)}</td>
                    <td>{pct(m.prec)}</td>
                    <td>{pct(m.rec)}</td>
                    <td>{m.f1.toFixed(4)}</td>
                    <td>{m.auc.toFixed(4)}</td>
                    <td>{m.prAuc.toFixed(4)}</td>
                    <td>{pct(m.urlhaus)}</td>
                    <td>{m.fitSec.toFixed(1)}s</td>
                    <td>{m.predictSec.toFixed(1)}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="note">
            ★ Random Forest achieves the top ROC-AUC (0.9402), PR-AUC (0.9273), and Precision (87.70%), while scoring 55,292 URLs in just 3.7 seconds (0.067 ms/URL).
          </p>
        </section>

        {/* 2-column: Confusion Matrix & Threat Category Breakdown */}
        <div className="grid2">
          {/* Confusion Matrix Interactive Block */}
          <section className="sec solid">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h3>Confusion Matrix (Random Forest)</h3>
                <p>N = 55,292 unseen test URLs</p>
              </div>
              <button
                type="button"
                className="btn"
                style={{ fontSize: 12, padding: '4px 10px' }}
                onClick={() => setActiveFigure(activeFigure === 'confusion' ? 'none' : 'confusion')}
              >
                {activeFigure === 'confusion' ? 'Hide Heatmap' : 'View Plot ↗'}
              </button>
            </div>

            <div className="cm-container">
              <div />
              <div className="cm-header">PREDICTED BENIGN</div>
              <div className="cm-header">PREDICTED MALICIOUS</div>

              <div className="cm-row-label">ACTUAL BENIGN</div>
              <div className="cm-cell good">
                <div className="cm-num">31,364</div>
                <div className="cm-sub">True Negative (92.9%)</div>
              </div>
              <div className="cm-cell bad">
                <div className="cm-num">2,404</div>
                <div className="cm-sub">False Alarm (7.1% FP)</div>
              </div>

              <div className="cm-row-label">ACTUAL MALICIOUS</div>
              <div className="cm-cell bad">
                <div className="cm-num">4,486</div>
                <div className="cm-sub">Missed (20.8% FN)</div>
              </div>
              <div className="cm-cell good">
                <div className="cm-num">17,038</div>
                <div className="cm-sub">True Positive (79.2% TP)</div>
              </div>
            </div>

            {activeFigure === 'confusion' && (
              <div className="figure-preview">
                <img src="/outputs/confusion_test.png" alt="Confusion matrix plot" />
                <div className="figure-caption">
                  Figure 2: Normalized confusion matrix on test split. High specificity ensures user browsing is not obstructed by false positives.
                </div>
              </div>
            )}
          </section>

          {/* Threat Subtypes Breakdown */}
          <section className="sec solid">
            <h3>Detection by Attack Category</h3>
            <p>Detection rate across diverse threat typologies in test partition.</p>
            <div style={{ marginTop: 14 }}>
              {ATTACK_TYPES.map(a => (
                <div key={a.name} style={{ marginBottom: 12 }}>
                  <div className={`bar ${a.cls}`} style={{ padding: '2px 0' }}>
                    <span>{a.name}</span>
                    <div className="t">
                      <i style={{ width: `${Math.max(0, Math.min(100, a.val * 100))}%` }} />
                    </div>
                    <b>{pct(a.val)}</b>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--mute)', display: 'flex', justifyContent: 'space-between', paddingLeft: 2 }}>
                    <span>{a.desc}</span>
                    <span style={{ fontFamily: 'var(--mono)' }}>{a.count.toLocaleString()} samples</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Feature Importance & Impurity Comparison */}
        <section className="sec solid">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <h3>Feature Permutation Importance vs. Impurity</h3>
              <p>
                Permutation importance measures actual drop in test ROC-AUC when a feature is shuffled. It is unbiased unlike Gini impurity.
              </p>
            </div>
            <button
              type="button"
              className="btn"
              style={{ fontSize: 13, padding: '6px 12px' }}
              onClick={() => setActiveFigure(activeFigure === 'importance' ? 'none' : 'importance')}
            >
              {activeFigure === 'importance' ? 'Hide Feature Plot' : 'View Feature Importance Plot ↗'}
            </button>
          </div>

          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Rank & Feature</th>
                  <th>Permutation Drop (ROC-AUC)</th>
                  <th>Gini Impurity Score</th>
                  <th>Security Significance</th>
                </tr>
              </thead>
              <tbody>
                {TOP_FEATURES.map((f, i) => (
                  <tr key={f.name}>
                    <td style={{ fontFamily: 'var(--mono)', fontWeight: i === 0 ? 600 : 400 }}>
                      #{i + 1} <code>{f.name}</code>
                    </td>
                    <td style={{ color: i === 0 ? 'var(--blue)' : undefined, fontWeight: i === 0 ? 600 : 400 }}>
                      −{f.perm.toFixed(4)}
                    </td>
                    <td>{f.gini.toFixed(3)}</td>
                    <td style={{ fontFamily: 'var(--sans)', textAlign: 'left', color: 'var(--ink)' }}>
                      {f.meaning}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {activeFigure === 'importance' && (
            <div className="figure-preview">
              <img src="/outputs/feature_importance.png" alt="Feature importance bar chart" />
              <div className="figure-caption">
                Figure 3: Top 15 features sorted by permutation importance on the holdout test set with 95% confidence intervals.
              </div>
            </div>
          )}
        </section>

        {/* Inference Latency & Line-Rate Throughput */}
        <section className="sec solid">
          <h3>Inference Speed & Line-Rate Evaluation</h3>
          <p>
            A security firewall model must decide before an HTTP SYN completes. KNN is catastrophically slow, while Random Forest handles 15,000 URLs/sec.
          </p>
          <div className="side-cards">
            <div className="side-card">
              <h4>
                <span>Random Forest</span>
                <span className="badge b-green">Production Grade</span>
              </h4>
              <p>
                Scores all <strong>55,292 URLs in 3.7 seconds</strong> (~0.067 ms / URL). Employs parallel decision trees with pre-compiled lexical array traversals. Easily runs in client browser or edge proxy.
              </p>
              <div style={{ marginTop: 12, font: '600 18px var(--mono)', color: 'var(--green)' }}>
                14,943 URLs / second
              </div>
            </div>

            <div className="side-card faint">
              <h4>
                <span>K-Nearest Neighbors (K=5)</span>
                <span className="badge b-red">Bottleneck</span>
              </h4>
              <p>
                Takes <strong>108.3 seconds</strong> to score the same test split (~1.96 ms / URL). Memory-bound distance calculations scale with O(N·D), rendering KNN unusable for high-speed network gateways.
              </p>
              <div style={{ marginTop: 12, font: '600 18px var(--mono)', color: 'var(--red)' }}>
                510 URLs / second
              </div>
            </div>
          </div>
        </section>

        {/* Ablation Study */}
        <section className="sec solid">
          <h3>Feature Group Ablation Progression</h3>
          <p>Measured performance increase as feature groups were progressively enabled.</p>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Feature Set</th>
                  <th>Test F1</th>
                  <th>ROC-AUC</th>
                  <th>Incremental Contribution</th>
                </tr>
              </thead>
              <tbody>
                {ABLATION_STEPS.map((s, idx) => (
                  <tr key={s.name} style={{ background: idx === 4 ? 'rgba(43,80,255,0.03)' : undefined }}>
                    <td style={{ fontWeight: idx === 4 ? 600 : 400 }}>{s.name}</td>
                    <td>{s.f1.toFixed(4)}</td>
                    <td>{s.auc.toFixed(4)}</td>
                    <td>
                      <span className={`badge ${idx === 4 ? 'b-blue' : idx === 0 ? '' : 'b-green'}`}>
                        {s.gain}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="note">
            URL length alone achieves ROC-AUC 0.5551 (indistinguishable from a coin flip). But combined with path ratios and subdomain tokens, it forms an essential composite signal.
          </p>
        </section>

        {/* Dataset Partitions & Leakage Audit */}
        <section className="sec solid">
          <h3>Dataset Partitions & Domain Firewall</h3>
          <p>
            Training, validation, and test sets are strictly partitioned by registrable domain. No domain appears across splits, and each domain is capped at 50 URLs to prevent high-frequency domain memorization.
          </p>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Partition</th>
                  <th>Rows</th>
                  <th>Distinct Domains</th>
                  <th>% Malicious</th>
                  <th>Domain Overlap with Train</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Train</strong></td>
                  <td>286,919</td>
                  <td>110,271</td>
                  <td>39.3%</td>
                  <td>100.0% (Self)</td>
                </tr>
                <tr>
                  <td><strong>Validation</strong></td>
                  <td>57,538</td>
                  <td>22,130</td>
                  <td>39.0%</td>
                  <td><span className="badge b-green">0.0% (Firewalled)</span></td>
                </tr>
                <tr>
                  <td><strong>Test</strong></td>
                  <td>55,292</td>
                  <td>22,061</td>
                  <td>38.9%</td>
                  <td><span className="badge b-green">0.0% (Firewalled)</span></td>
                </tr>
                <tr>
                  <td><strong>External Malicious</strong></td>
                  <td>85,835</td>
                  <td>44,087</td>
                  <td>100.0%</td>
                  <td>8.5%</td>
                </tr>
                <tr>
                  <td><strong>External Benign</strong></td>
                  <td>4,190</td>
                  <td>3,862</td>
                  <td>0.0%</td>
                  <td>18.4%</td>
                </tr>
                <tr>
                  <td><strong>URLhaus Fresh Feed</strong></td>
                  <td>43,599</td>
                  <td>17,030</td>
                  <td>100.0%</td>
                  <td><span className="badge b-green">1.0% (Zero-Shot)</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Where it Struggles */}
        <section className="sec solid warn">
          <h3>Honest Limitation: Where the Model Struggles</h3>
          <p>
            On the external collector, Random Forest flags only 27.6% of malicious URLs and clears 67.2%
            of benign ones. Phishing is caught 74.7% of the time, noticeably lower than malware (87.0%)
            and raw IP hosts (100.0%).
          </p>
          <p style={{ marginTop: 10 }}>
            <strong>Why this occurs:</strong> Sophisticated phishing campaigns use hijacked legitimate domains
            (e.g., WordPress sites, cloud storage, Google forms) with clean URLs. A pure lexical classifier
            cannot inspect HTML forms, TLS certificates, or DOM elements. We openly report this boundary rather
            than presenting an unrealistic 99% metric.
          </p>
        </section>
      </div>
    </main>
  );
};
