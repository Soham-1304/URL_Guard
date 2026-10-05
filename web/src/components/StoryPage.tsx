import React from 'react';

export const StoryPage: React.FC = () => {
  return (
    <main id="p-story" className="on" style={{ paddingBottom: 100 }}>
      <div className="wrap pg">
        <h2>How a class project became a careful one.</h2>
        <p className="lede" style={{ fontSize: 17, marginBottom: 34 }}>
          The headline accuracy is the least interesting part. The decisions behind it are what make it
          believable.
        </p>

        <div className="tl">
          <div className="ev solid">
            <h3>The problem</h3>
            <p>
              Blocklists only know URLs someone already reported, and opening a suspicious link to
              inspect it is the risk itself. The goal: decide from the string alone, before anyone clicks.
            </p>
          </div>

          <div className="ev solid">
            <h3>The data was lying</h3>
            <p>
              Merging the Kaggle collectors, 522,260 URLs turned out to be identical across two files.
              We deduplicated them and dropped 13,124 URLs labeled both benign and malicious.
            </p>
            <span className="stat">84.6% overlap · 13,124 label conflicts</span>
          </div>

          <div className="ev solid">
            <h3>The model could guess the source</h3>
            <p>
              A forest could predict which collector a URL came from far above chance, a sign it would
              learn the collector instead of the threat. So training uses one source only, and the
              others are held out for testing.
            </p>
            <span className="stat">source-bias gap 0.447</span>
          </div>

          <div className="ev solid">
            <h3>Splits by domain, not by row</h3>
            <p>
              Related URLs from one domain leak across a random split and inflate scores. Train,
              validation and test share no domains, with at most 50 URLs per domain.
            </p>
          </div>

          <div className="ev solid">
            <h3>Six algorithms, one honest comparison</h3>
            <p>
              Random Forest won on accuracy, precision and AUC. KNN needed 108 seconds just to score
              the test set. Naive Bayes collapsed to 21% recall because URL features are strongly
              correlated, which breaks its independence assumption.
            </p>
            <span className="stat">Random Forest · 0.9402 ROC-AUC</span>
          </div>

          <div className="ev solid">
            <h3>What the model actually looks at</h3>
            <p>
              The dot count dominates: shuffling it costs about 0.11 ROC-AUC, more than three times any
              other feature. Malicious URLs lean on subdomains, dotted IPs and file extensions.
            </p>
          </div>

          <div className="ev solid">
            <h3>Fresh malware it had never seen</h3>
            <p>
              On 29,715 URLhaus URLs from unseen domains, it flagged 88.8%. Every one of the 25,372
              raw-IP URLs was caught.
            </p>
            <span className="stat">88.8% zero-shot · 100% IP hosts</span>
          </div>

          <div className="ev solid bad">
            <h3>Where it falls short</h3>
            <p>
              On the external balanced collector, only 27.6% of malicious URLs are flagged and 67.2%
              of benign ones cleared. A URL-only model also cannot catch a clean-looking URL on a hacked
              legitimate site. Phishing, which imitates normal addresses, is the hardest class.
            </p>
            <span className="stat">27.6% recall · 67.2% specificity on external set</span>
          </div>
        </div>

        <div className="code" style={{ marginTop: 36 }}>
          <span className="m"># reproduce everything</span>
          <br />
          <span className="g">$</span> pip install -r requirements.txt
          <br />
          <span className="g">$</span> streamlit run app.py
          <br />
          <span className="g">$</span> python -m pytest url-guard/tests <span className="m"># 27 tests</span>
        </div>
      </div>
    </main>
  );
};
