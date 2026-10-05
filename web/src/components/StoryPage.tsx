import React, { useState } from 'react';

interface InvestigationChapter {
  id: string;
  step: string;
  title: string;
  tag: string;
  badgeCls: string;
  summary: string;
  metric: string;
  metricLabel: string;
  dossierType: 'audit' | 'leakage' | 'autopsy' | 'zeroshot' | 'blindspot';
}

const CHAPTERS: InvestigationChapter[] = [
  {
    id: 'audit',
    step: '01',
    title: 'Data Audit & The 13,124 Conflicts',
    tag: 'Dataset Integrity',
    badgeCls: 'b-red',
    summary:
      'Merging public Kaggle collectors revealed 522,260 duplicate URLs. 13,124 identical URLs carried contradictory ground-truth labels across datasets.',
    metric: '84.6%',
    metricLabel: 'Collector overlap purged',
    dossierType: 'audit'
  },
  {
    id: 'leakage',
    step: '02',
    title: 'The Random Split Trap vs. Domain Firewall',
    tag: 'Methodology Trap',
    badgeCls: 'b-amber',
    summary:
      'Standard random split yielded 99.4% accuracy by memorizing domains. Domain-grouped partitioning proved true generalization sits at 87.50%.',
    metric: '99.4% → 87.5%',
    metricLabel: 'Illusory vs. Honest Accuracy',
    dossierType: 'leakage'
  },
  {
    id: 'autopsy',
    step: '03',
    title: 'Model Arena & Failure Autopsies',
    tag: 'Algorithmic Stress',
    badgeCls: 'b-blue',
    summary:
      'Naive Bayes collapsed to 20.98% recall due to correlated lexical tokens. KNN stalled on inference latency (108 seconds for 55k URLs). Random Forest won.',
    metric: '14,943 URLs/s',
    metricLabel: 'Random Forest line-rate throughput',
    dossierType: 'autopsy'
  },
  {
    id: 'zeroshot',
    step: '04',
    title: 'Wild Zero-Shot Validation (URLhaus)',
    tag: 'In-The-Wild Test',
    badgeCls: 'b-green',
    summary:
      'Tested against 43,599 live in-the-wild malicious links from abuse.ch. 100% of raw-IP malware hosts and 88.8% of unseen domains were stopped.',
    metric: '100.0%',
    metricLabel: 'IP-Hosted malware intercepted',
    dossierType: 'zeroshot'
  },
  {
    id: 'blindspot',
    step: '05',
    title: 'The Phishing Blindspot (Why 27.6% Happened)',
    tag: 'Honest Boundary',
    badgeCls: 'b-red',
    summary:
      'On external balanced datasets, malicious recall drops to 27.6%. Credential harvesters on clean cloud providers (Google, AWS, WordPress) are lexically invisible.',
    metric: '27.6% Recall',
    metricLabel: 'External clean-host phishing boundary',
    dossierType: 'blindspot'
  }
];

export const StoryPage: React.FC = () => {
  const [activeChapterId, setActiveChapterId] = useState<string>('audit');
  const [copied, setCopied] = useState(false);

  const activeChapter = CHAPTERS.find(c => c.id === activeChapterId) || CHAPTERS[0];

  const copyCommands = () => {
    navigator.clipboard.writeText(`pip install -r requirements.txt\nstreamlit run app.py\npython -m pytest url-guard/tests`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <main id="p-story" className="on">
      <div className="wrap pg">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span className="badge b-blue">INVESTIGATION DOSSIER</span>
              <span style={{ font: '500 13px var(--mono)', color: 'var(--mute)' }}>CASE STUDY #149</span>
            </div>
            <h2>How a class project became a careful one.</h2>
            <p className="lede" style={{ fontSize: 17, marginTop: 12 }}>
              The headline metric is the easiest thing to fake in ML. Step through the five investigation
              chapters to see how we uncovered data leaks, algorithm failures, and real-world limits.
            </p>
          </div>
        </div>

        {/* Interactive Telemetry Stepper Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, marginTop: 32 }}>
          {CHAPTERS.map(ch => {
            const isActive = ch.id === activeChapterId;
            return (
              <button
                key={ch.id}
                type="button"
                onClick={() => setActiveChapterId(ch.id)}
                style={{
                  textAlign: 'left',
                  padding: '12px 14px',
                  borderRadius: 10,
                  border: `1px solid ${isActive ? 'var(--ink)' : 'var(--line)'}`,
                  background: isActive ? 'var(--soft)' : '#fff',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ font: '600 12px var(--mono)', color: isActive ? 'var(--blue)' : 'var(--mute)' }}>
                    STEP {ch.step}
                  </span>
                  <span className={`badge ${ch.badgeCls}`} style={{ fontSize: 10, padding: '1px 5px' }}>
                    {ch.tag}
                  </span>
                </div>
                <div style={{ font: '600 13px var(--sans)', color: 'var(--ink)', marginTop: 6, lineHeight: 1.3 }}>
                  {ch.title.split(' & ')[0].split(' vs. ')[0]}
                </div>
              </button>
            );
          })}
        </div>

        {/* Demonstrable Dossier Card */}
        <div className="solid" style={{ marginTop: 18, padding: '28px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <span className="step-num">PHASE {activeChapter.step} EVIDENCE DOSSIER</span>
              <h3 style={{ fontSize: 22, marginTop: 4 }}>{activeChapter.title}</h3>
              <p style={{ color: 'var(--mute)', fontSize: 15, marginTop: 6, maxWidth: '44em' }}>
                {activeChapter.summary}
              </p>
            </div>
            <div style={{ textAlign: 'right', background: 'var(--soft)', padding: '12px 20px', borderRadius: 10, border: '1px solid var(--line)' }}>
              <div style={{ font: '600 24px/1 var(--mono)', color: 'var(--ink)' }}>{activeChapter.metric}</div>
              <div style={{ font: '400 12px var(--mono)', color: 'var(--mute)', marginTop: 4 }}>{activeChapter.metricLabel}</div>
            </div>
          </div>

          <hr style={{ border: 0, borderTop: '1px solid var(--line)', margin: '22px 0' }} />

          {/* Dynamic Interactive Demonstrator based on active chapter */}
          {activeChapter.dossierType === 'audit' && (
            <div>
              <div style={{ font: '600 13px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 10 }}>
                Live Audit Sample: The Conflicting Duplicates
              </div>
              <p style={{ fontSize: 14, color: '#475467', marginBottom: 14 }}>
                Below are real examples of identical URLs that were labeled simultaneously as benign and malicious in raw merged datasets. Training on this poisoned ground-truth teaches the model that reality is random.
              </p>
              <div style={{ overflowX: 'auto' }}>
                <table className="tbl" style={{ marginTop: 0 }}>
                  <thead>
                    <tr>
                      <th>Sample URL Address</th>
                      <th>Dataset A Label</th>
                      <th>Dataset B Label</th>
                      <th>Resolution Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><code>http://www.google.com/ig/adde?moduleurl=...</code></td>
                      <td><span className="badge b-green">Benign (0)</span></td>
                      <td><span className="badge b-red">Malicious (1)</span></td>
                      <td><span className="badge">PURGED FROM REPO</span></td>
                    </tr>
                    <tr>
                      <td><code>http://paypal.com.us.cgi-bin.webscr-cmd.login...</code></td>
                      <td><span className="badge b-red">Malicious (1)</span></td>
                      <td><span className="badge b-green">Benign (0)</span></td>
                      <td><span className="badge">PURGED FROM REPO</span></td>
                    </tr>
                    <tr>
                      <td><code>http://secure-banking-update-profile.net/login</code></td>
                      <td><span className="badge b-red">Malicious (1)</span></td>
                      <td><span className="badge b-green">Benign (0)</span></td>
                      <td><span className="badge">PURGED FROM REPO</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div style={{ marginTop: 14, padding: '12px 16px', background: 'var(--soft)', borderRadius: 8, font: '400 13px var(--mono)' }}>
                Audit Verdict: Purged 13,124 conflicting rows, deduplicated 522,260 entries, leaving 780,573 clean URLs.
              </div>
            </div>
          )}

          {activeChapter.dossierType === 'leakage' && (
            <div>
              <div style={{ font: '600 13px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 10 }}>
                Side-by-Side Split Architecture
              </div>
              <div className="side-cards" style={{ marginTop: 0 }}>
                <div className="side-card faint">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h4 style={{ margin: 0 }}>Naive Random Row Split</h4>
                    <span className="badge b-red">99.4% FAKE ACCURACY</span>
                  </div>
                  <p style={{ marginTop: 10 }}>
                    <code>train_test_split()</code> without domain grouping splits URLs by row. If <code>wikipedia.org/wiki/Python</code> is in training and <code>wikipedia.org/wiki/Java</code> is in test, the model memorizes <code>wikipedia.org</code> as safe.
                  </p>
                  <div style={{ marginTop: 12, padding: '8px 12px', background: '#fff', border: '1px solid var(--line)', borderRadius: 6, font: '400 12px var(--mono)', color: 'var(--red)' }}>
                    Domain Leakage Rate: 84.1% overlap across splits
                  </div>
                </div>

                <div className="side-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h4 style={{ margin: 0 }}>Strict Domain-Grouped Firewall</h4>
                    <span className="badge b-green">87.5% HONEST ACCURACY</span>
                  </div>
                  <p style={{ marginTop: 10 }}>
                    We partitioned all 154,462 domains so no domain ever crosses the train/val/test boundary. Every single URL in the 55,292 test split belongs to a domain the model has never encountered before.
                  </p>
                  <div style={{ marginTop: 12, padding: '8px 12px', background: 'rgba(18,128,92,0.08)', border: '1px solid rgba(18,128,92,0.2)', borderRadius: 6, font: '400 12px var(--mono)', color: 'var(--green)' }}>
                    Domain Leakage Rate: 0.00% (Strictly Enforced)
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeChapter.dossierType === 'autopsy' && (
            <div>
              <div style={{ font: '600 13px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 10 }}>
                Algorithmic Autopsy Ledger
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                <div style={{ padding: 16, border: '1px solid var(--line)', borderRadius: 10 }}>
                  <div style={{ font: '600 14px var(--sans)' }}>Random Forest (Winner)</div>
                  <div style={{ font: '600 20px var(--mono)', color: 'var(--blue)', marginTop: 4 }}>0.9402 AUC</div>
                  <p style={{ fontSize: 13, color: 'var(--mute)', marginTop: 8 }}>
                    Ensemble averaging over 100 trees prevents overfitting to specific path lengths. Evaluates 55,292 URLs in 3.7 seconds (~15,000 URLs/sec).
                  </p>
                </div>
                <div style={{ padding: 16, border: '1px solid var(--line)', borderRadius: 10, background: 'var(--soft)' }}>
                  <div style={{ font: '600 14px var(--sans)' }}>Naive Bayes (Collapsed)</div>
                  <div style={{ font: '600 20px var(--mono)', color: 'var(--red)', marginTop: 4 }}>20.98% Recall</div>
                  <p style={{ fontSize: 13, color: 'var(--mute)', marginTop: 8 }}>
                    URL lexical features are heavily correlated (e.g. <code>path_depth</code> with <code>n_slashes</code>). This violated Bayes' conditional independence assumption.
                  </p>
                </div>
                <div style={{ padding: 16, border: '1px solid var(--line)', borderRadius: 10, background: 'var(--soft)' }}>
                  <div style={{ font: '600 14px var(--sans)' }}>KNN (Too Slow)</div>
                  <div style={{ font: '600 20px var(--mono)', color: 'var(--amber)', marginTop: 4 }}>108.3 Seconds</div>
                  <p style={{ fontSize: 13, color: 'var(--mute)', marginTop: 8 }}>
                    Exhaustive distance computations across 286k training vectors took nearly 2 minutes for a single test split. Completely non-viable for real-time traffic.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeChapter.dossierType === 'zeroshot' && (
            <div>
              <div style={{ font: '600 13px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 10 }}>
                Live In-The-Wild Telemetry (abuse.ch URLhaus)
              </div>
              <p style={{ fontSize: 14, color: '#475467', marginBottom: 14 }}>
                We fetched 43,599 active malware distribution URLs directly from abuse.ch URLhaus. The model scored them zero-shot without any retraining.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <div style={{ padding: 16, border: '1px solid rgba(18,128,92,0.3)', background: 'rgba(236,250,244,0.6)', borderRadius: 10 }}>
                  <div style={{ font: '600 13px var(--mono)', color: 'var(--green)' }}>RAW IP HOST INTERCEPTION</div>
                  <div style={{ font: '600 28px/1 var(--mono)', color: 'var(--green)', margin: '8px 0' }}>100.0%</div>
                  <p style={{ fontSize: 13, color: '#475467' }}>
                    All <strong>25,372 / 25,372</strong> raw IP malware downloads (e.g., <code>http://175.173.82.102:52403/bin.sh</code>) were intercepted immediately.
                  </p>
                </div>
                <div style={{ padding: 16, border: '1px solid rgba(43,80,255,0.3)', background: 'rgba(43,80,255,0.04)', borderRadius: 10 }}>
                  <div style={{ font: '600 13px var(--mono)', color: 'var(--blue)' }}>UNSEEN DOMAIN DETECTION</div>
                  <div style={{ font: '600 28px/1 var(--mono)', color: 'var(--blue)', margin: '8px 0' }}>88.8%</div>
                  <p style={{ fontSize: 13, color: '#475467' }}>
                    On <strong>29,715</strong> malicious URLs from domains completely absent from training data, the model flagged 88.8% correctly on zero-shot evaluation.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeChapter.dossierType === 'blindspot' && (
            <div>
              <div style={{ font: '600 13px var(--mono)', color: 'var(--red)', textTransform: 'uppercase', marginBottom: 10 }}>
                The Natural Boundary of Lexical-Only Scanning
              </div>
              <p style={{ fontSize: 14, color: '#475467', marginBottom: 14 }}>
                Why did recall drop to 27.6% on Dataset B? Because of the structural limitation of pre-click lexical analysis:
              </p>
              <div style={{ padding: 16, border: '1px solid rgba(217,45,58,0.2)', background: 'rgba(254,240,241,0.5)', borderRadius: 10 }}>
                <div style={{ font: '600 14px var(--sans)', color: 'var(--red)' }}>
                  Phishing on Trusted Multi-Tenant Cloud Services
                </div>
                <p style={{ fontSize: 13, color: '#475467', marginTop: 8 }}>
                  Consider an attacker hosting a credential harvester on:
                  <br />
                  <code>https://docs.google.com/forms/d/e/1FAIpQLSc91.../viewform</code>
                  <br />
                  The address is on <code>google.com</code>, contains normal path structures, and has zero lexical red flags. <strong>The malice lives inside the rendered DOM and form action, not in the URL characters.</strong>
                </p>
                <div style={{ marginTop: 12, font: '500 12px var(--mono)', color: 'var(--red)' }}>
                  Conclusion: A URL classifier is designed for line-rate screening (~15,000 URLs/s). Clean-domain links must be passed to DOM/content inspection engines.
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Reproduce Everything Terminal Block */}
        <section className="sec solid" style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <h3>Verify & Reproduce</h3>
              <p>Everything shown in this dossier is reproducible in under 3 minutes.</p>
            </div>
            <button
              type="button"
              className="btn"
              style={{ fontSize: 13, padding: '6px 14px' }}
              onClick={copyCommands}
            >
              {copied ? '✓ Copied to clipboard' : 'Copy Commands'}
            </button>
          </div>

          <div className="code">
            <span className="m"># 1. Install project dependencies</span>
            <br />
            <span className="g">$</span> pip install -r requirements.txt
            <br />
            <br />
            <span className="m"># 2. Launch Streamlit interactive dashboard</span>
            <br />
            <span className="g">$</span> streamlit run app.py
            <br />
            <br />
            <span className="m"># 3. Run all unit tests (27 tests passing)</span>
            <br />
            <span className="g">$</span> python -m pytest url-guard/tests
          </div>
        </section>
      </div>
    </main>
  );
};
