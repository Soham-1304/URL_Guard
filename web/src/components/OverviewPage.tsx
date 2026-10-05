import React from 'react';

export const OverviewPage: React.FC = () => {
  return (
    <main id="p-home" className="on" style={{ paddingBottom: 96 }}>
      <div className="wrap">
        <section className="hero">
          <h1>A malicious link gives itself away in its own spelling.</h1>
          <p className="lede">
            URL-Guard reads only the address (dots, depth, hosts, keywords) and returns a verdict in
            0.12 ms. It never visits the page and never makes a network call.
          </p>
          <div className="cta">
            <a className="btn p" href="#/test">
              Test a URL
            </a>
            <a className="btn" href="#/dashboard">
              See the evidence
            </a>
          </div>
          <p className="hint">
            <b />
            Move your cursor over the background. Synthetic streams evaluated instantly via client-side lexical heuristics.
          </p>
        </section>

        <div className="kpis solid">
          <div>
            <strong>87.5%</strong>
            <span>test accuracy, domain-grouped</span>
          </div>
          <div>
            <strong>0.9402</strong>
            <span>ROC-AUC, Random Forest</span>
          </div>
          <div>
            <strong>88.3%</strong>
            <span>recall on fresh URLhaus malware</span>
          </div>
          <div>
            <strong>780,573</strong>
            <span>deduplicated training URLs</span>
          </div>
        </div>

        <div className="tour">
          <a className="solid" href="#/dashboard">
            <h3>Dashboard</h3>
            <p>
              Six models, ablations, feature importance and detection by attack type, all from the real
              result tables.
            </p>
            <em>Open dashboard</em>
          </a>
          <a className="solid" href="#/test">
            <h3>Try it</h3>
            <p>
              Paste any URL and watch all 30 features get extracted, then see which ones drove the
              verdict.
            </p>
            <em>Test a URL</em>
          </a>
          <a className="solid" href="#/story">
            <h3>The story</h3>
            <p>
              The leaky datasets, the honest splits, and the weak spot we found and kept in the
              report.
            </p>
            <em>Read the story</em>
          </a>
        </div>
      </div>
    </main>
  );
};
