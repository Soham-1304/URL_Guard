import React, { useState } from 'react';

export const StoryPage: React.FC = () => {
  const [copied, setCopied] = useState(false);

  const copyCommands = () => {
    navigator.clipboard.writeText(`pip install -r requirements.txt\nstreamlit run app.py\npython -m pytest url-guard/tests`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <main id="p-story" className="on">
      <div className="wrap pg">
        <h2>How a class project became a careful one.</h2>
        <p className="lede" style={{ fontSize: 17 }}>
          The headline accuracy is the least interesting part of machine learning. The choices made to avoid
          fooling ourselves are what make the result believable.
        </p>

        {/* Phase Stepper Investigation Cards */}
        <div className="tl">
          {/* Phase 01 */}
          <div className="ev solid">
            <span className="step-num">PHASE 01 · THE PROBLEM</span>
            <h3>The Risk of Visiting the Link</h3>
            <p>
              Traditional blocklists only protect against URLs that someone has already reported and verified.
              Heuristic web scanners fetch the page to analyze JavaScript, DOM trees, and TLS certificates —
              but making the HTTP request is the exact action that triggers the drive-by exploit.
            </p>
            <p style={{ marginTop: 8 }}>
              <strong>The core objective:</strong> Decide whether a link is hostile purely from its character
              sequence in under a millisecond, before any socket connection is opened.
            </p>
          </div>

          {/* Phase 02: Leakage Discovery */}
          <div className="ev solid">
            <span className="step-num">PHASE 02 · DATA AUDIT</span>
            <h3>The Datasets Were Lying</h3>
            <p>
              When we merged the two popular Kaggle malicious URL datasets, we discovered an alarming data
              integrity flaw: <strong>522,260 URLs</strong> were exact duplicates across both files. Worse,
              <strong> 13,124 identical URLs had conflicting labels</strong> (labeled benign in one file, malicious in the other).
            </p>
            <div style={{ marginTop: 12 }}>
              <span className="stat">84.6% overlap across files</span>
              <span className="stat" style={{ marginLeft: 8 }}>13,124 contradictory labels purged</span>
            </div>
          </div>

          {/* Phase 03: The Random Split Trap */}
          <div className="ev solid">
            <span className="step-num">PHASE 03 · THE FIREWALL</span>
            <h3>The Naive Split Trap vs. Domain Firewall</h3>
            <p>
              Standard <code>train_test_split()</code> splits rows uniformly at random. In URL classification,
              this creates massive data leakage: if <code>wikipedia.org/wiki/Cat</code> is in train and{' '}
              <code>wikipedia.org/wiki/Dog</code> is in test, the model memorizes the domain name rather than learning lexical syntax.
            </p>

            <div className="side-cards">
              <div className="side-card faint">
                <h4>
                  <span>Naive Random Split</span>
                  <span className="badge b-red">99.4% Accuracy (Fake)</span>
                </h4>
                <p>
                  High overlap of registrable domains between train and test. The model acted as an accidental domain lookup table, failing completely when faced with new domains in production.
                </p>
              </div>

              <div className="side-card">
                <h4>
                  <span>Domain-Grouped Split</span>
                  <span className="badge b-green">87.5% Accuracy (Honest)</span>
                </h4>
                <p>
                  Strict firewall: every single domain in the 55,292-row test set was excluded from training. URLs per domain were capped at 50 to prevent dominance by high-frequency hosts.
                </p>
              </div>
            </div>
          </div>

          {/* Phase 04: Source Bias */}
          <div className="ev solid">
            <span className="step-num">PHASE 04 · FINGERPRINTING</span>
            <h3>The Model Was Guessing the Collector</h3>
            <p>
              During exploratory audits, we trained a classifier to predict which dataset source a URL came from.
              It succeeded with a <strong>0.447 source-bias gap</strong> above chance. The model was learning the collection methodology (e.g. how scraping bots harvested URLs) rather than malicious intent.
            </p>
            <p style={{ marginTop: 8 }}>
              <strong>The fix:</strong> We restricted model training strictly to a single primary source (Dataset A) and held out the entire second dataset (Dataset B) as an external zero-shot test set.
            </p>
          </div>

          {/* Phase 05: Algorithm Selection */}
          <div className="ev solid">
            <span className="step-num">PHASE 05 · BENCHMARKING</span>
            <h3>Six Algorithms, One Honest Comparison</h3>
            <p>
              We trained and evaluated six different machine learning architectures on the exact same domain-grouped partition.
            </p>
            <ul style={{ margin: '12px 0 0 18px', color: '#475467', fontSize: 14 }}>
              <li>
                <strong>Random Forest (Winner):</strong> Best test accuracy (87.50%), precision (87.70%), and ROC-AUC (0.9402). Handles non-linear feature interactions cleanly and evaluates in 0.067 ms/URL.
              </li>
              <li style={{ marginTop: 6 }}>
                <strong>Naive Bayes (Collapsed):</strong> Test recall plunged to 20.98%. Strong correlations between lexical features (e.g., <code>path_depth</code> and <code>n_slashes</code>) completely broke Naive Bayes' feature independence assumption.
              </li>
              <li style={{ marginTop: 6 }}>
                <strong>K-Nearest Neighbors (Too Slow):</strong> Required 108.3 seconds just to score the test set. O(N) distance checks cannot operate at line-rate in a network security firewall.
              </li>
            </ul>
          </div>

          {/* Phase 06: Zero-Shot Wild Testing */}
          <div className="ev solid">
            <span className="step-num">PHASE 06 · REAL-WORLD VALIDATION</span>
            <h3>Zero-Shot Testing Against Live URLhaus Malware</h3>
            <p>
              We evaluated the champion model against 43,599 fresh, in-the-wild malicious URLs downloaded from abuse.ch's live URLhaus feed.
            </p>
            <div style={{ marginTop: 12 }}>
              <span className="stat">88.8% recall on 29,715 unseen domains</span>
              <span className="stat" style={{ marginLeft: 8 }}>100.0% recall on 25,372 raw IP hosts</span>
            </div>
          </div>

          {/* Phase 07: The Honest Limitations */}
          <div className="ev solid bad">
            <span className="step-num" style={{ background: 'rgba(217,45,58,0.08)', color: 'var(--red)', borderColor: 'rgba(217,45,58,0.2)' }}>
              PHASE 07 · HONEST DISCLOSURE
            </span>
            <h3>Where the Model Falls Short</h3>
            <p>
              On the external balanced collector, Random Forest flags only 27.6% of malicious URLs and clears 67.2% of benign ones.
            </p>
            <p style={{ marginTop: 8 }}>
              <strong>The structural boundary:</strong> Phishing attacks that leverage compromised reputable domains
              (e.g., Google Docs, WordPress, OneDrive) produce URLs that look completely normal lexically. A URL-only
              model cannot inspect page content or login forms. We report this weakness openly because an ML security
              system that hides its failure modes is a hazard.
            </p>
          </div>
        </div>

        {/* Six Research Questions */}
        <section className="sec solid" style={{ marginTop: 34 }}>
          <h3>The Six Research Questions Answered</h3>
          <p>Key quantitative findings addressing Case Study #149.</p>

          <div style={{ marginTop: 14 }}>
            <details open>
              <summary>
                <span>RQ1: Can malicious URLs be classified accurately without visiting the site?</span>
                <span className="badge b-green">Yes · 87.5% Acc</span>
              </summary>
              <p>
                Yes. Random Forest achieves <strong>87.50% accuracy</strong> and <strong>0.9402 ROC-AUC</strong>
                from lexical characteristics alone, requiring zero network requests, DNS queries, or DOM parsing.
              </p>
            </details>

            <details>
              <summary>
                <span>RQ2: Which lexical features are most predictive of malicious intent?</span>
                <span className="badge b-blue">Top: n_dots</span>
              </summary>
              <p>
                Permutation importance tests reveal <code>n_dots</code> is by far the most predictive feature
                (shuffling it drops ROC-AUC by <strong>−0.1109</strong>, more than 3× any other feature). It is
                followed by <code>path_length</code> (−0.0324), <code>n_params</code> (−0.0268),{' '}
                <code>n_slashes</code> (−0.0197), and <code>hostname_length</code> (−0.0187).
              </p>
            </details>

            <details>
              <summary>
                <span>RQ3: Which ML algorithm performs best overall?</span>
                <span className="badge b-green">Random Forest</span>
              </summary>
              <p>
                <strong>Random Forest</strong> is the superior operational model. It achieved highest test accuracy
                (87.50%), precision (87.70%), and ROC-AUC (0.9402). Gradient Boosting achieved slightly higher recall
                (82.20% vs 79.16%) but required longer training and had a higher false-positive rate (16.28%).
              </p>
            </details>

            <details>
              <summary>
                <span>RQ4: Does overall URL length contribute meaningfully?</span>
                <span className="badge b-amber">Only in Composite</span>
              </summary>
              <p>
                In isolation, URL length achieves an ROC-AUC of just <strong>0.5551</strong> (nearly a random coin flip).
                Benign URLs average 56.9 characters while malicious URLs average 59.2 characters. However, removing length
                features from the full 30-feature ensemble drops F1 by 2.07%, demonstrating that length is valuable only
                when contextualized with path depth and token ratios.
              </p>
            </details>

            <details>
              <summary>
                <span>RQ5: How much does domain-informed feature engineering help?</span>
                <span className="badge b-green">+6.6% F1 Gain</span>
              </summary>
              <p>
                Ablation studies show that expanding from 6 basic character counts to the 30-feature engineered set
                boosted F1 from <strong>0.7657 to 0.8317</strong> and ROC-AUC from <strong>0.8907 to 0.9375</strong>.
                Structural features contributed the largest jump (+5.32% F1), followed by host entropy and IP host detection.
              </p>
            </details>

            <details>
              <summary>
                <span>RQ6: Can the model generalize to unseen and novel attack campaigns?</span>
                <span className="badge b-amber">Yes, with Boundaries</span>
              </summary>
              <p>
                The model achieved <strong>88.8% recall</strong> on 29,715 zero-shot URLhaus URLs from unseen domains,
                and caught 100% of IP-hosted malware. However, on the external balanced collector, malicious recall dropped to
                27.6%, proving that phishing attacks hosted on legitimate multi-tenant clouds remain the primary blind spot of lexical models.
              </p>
            </details>
          </div>
        </section>

        {/* Reproduce Everything */}
        <section className="sec solid" style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <h3>Reproduce the Pipeline</h3>
              <p>Run the training, evaluation suite, and full test battery locally.</p>
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
            <span className="m"># 1. Install dependencies</span>
            <br />
            <span className="g">$</span> pip install -r requirements.txt
            <br />
            <br />
            <span className="m"># 2. Launch interactive Streamlit investigation dashboard</span>
            <br />
            <span className="g">$</span> streamlit run app.py
            <br />
            <br />
            <span className="m"># 3. Execute unit test suite (27 passing tests)</span>
            <br />
            <span className="g">$</span> python -m pytest url-guard/tests
          </div>
        </section>
      </div>
    </main>
  );
};
