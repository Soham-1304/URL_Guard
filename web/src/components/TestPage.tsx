import React, { useState } from 'react';
import {
  feats,
  score,
  PRESETS,
  FEATURE_GROUPS,
  HOT_FEATURES
} from '../lib/features';
import type { Features, ScoreResult } from '../lib/features';

export const TestPage: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>(PRESETS[2].url); // Default to Fake PayPal
  const [extractedFeatures, setExtractedFeatures] = useState<Features | null>(() => feats(PRESETS[2].url));
  const [scoreResult, setScoreResult] = useState<ScoreResult | null>(() => {
    const f = feats(PRESETS[2].url);
    return f ? score(f) : null;
  });

  const runAnalysis = (url: string) => {
    const f = feats(url);
    setExtractedFeatures(f);
    if (f) {
      setScoreResult(score(f));
    } else {
      setScoreResult(null);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runAnalysis(inputUrl);
  };

  const handleChipClick = (presetUrl: string) => {
    setInputUrl(presetUrl);
    runAnalysis(presetUrl);
  };

  const isMalicious = scoreResult ? scoreResult.p >= 0.5 : false;

  return (
    <main id="p-test" className="on">
      <div className="wrap pg">
        <h2>Paste a URL. Watch it get read.</h2>
        <p className="lede" style={{ fontSize: 17 }}>
          The 30 features below are computed by a TypeScript port of the project's extractor. The
          verdict comes from a transparent preview scorer, because the trained forest runs in Python.
        </p>

        <form className="tin solid" onSubmit={handleSubmit}>
          <input
            id="inp"
            aria-label="URL to scan"
            value={inputUrl}
            onChange={e => setInputUrl(e.target.value)}
            placeholder="http://paypal-verification-account-security.com/login.php?update=true"
            autoComplete="off"
            spellCheck="false"
          />
          <button className="btn p" type="submit">
            Analyze
          </button>
        </form>

        <div className="chips">
          {PRESETS.map(preset => (
            <button
              key={preset.label}
              type="button"
              onClick={() => handleChipClick(preset.url)}
            >
              {preset.label}
            </button>
          ))}
        </div>

        <div className="res">
          {!extractedFeatures || !scoreResult ? (
            <div className="sec solid" style={{ gridColumn: '1/-1', margin: 0 }}>
              <h3>That doesn't look like a URL</h3>
              <p>
                Enter a host and optional path, for example <code>example.com/login?id=1</code>.
              </p>
            </div>
          ) : (
            <>
              {/* Verdict Card */}
              <div className={`verd solid ${isMalicious ? 'bad' : 'ok'}`}>
                <div className="v">{isMalicious ? 'Malicious' : 'Benign'}</div>
                <div className="pc">{Math.round(scoreResult.p * 100)}%</div>
                <div style={{ fontSize: 13, color: '#475467' }}>preview probability</div>
                {scoreResult.why.length > 0 ? (
                  <ul>
                    {scoreResult.why.slice(0, 5).map((reason, i) => (
                      <li key={i}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No structural red flags found.</p>
                )}
              </div>

              {/* 30 Features Breakdown Grid */}
              <div className="sec solid" style={{ margin: 0 }}>
                <h3>30 features extracted</h3>
                <div className="fgrid">
                  {Object.entries(FEATURE_GROUPS).map(([groupName, keys]) => (
                    <div className="fg" key={groupName}>
                      <h4>{groupName}</h4>
                      {keys.map(key => {
                        const val = extractedFeatures[key];
                        const isHot = HOT_FEATURES.has(key) && Boolean(val);
                        return (
                          <div className={`fr ${isHot ? 'hot' : ''}`} key={key}>
                            <span>{key}</span>
                            <b>{val}</b>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        <p className="note" style={{ marginTop: 20 }}>
          For the real Random Forest verdict, run <code>streamlit run app.py</code> from the repo.
          The preview scorer here is a hand-weighted rule set over the same features and will
          disagree with the model on edge cases.
        </p>
      </div>
    </main>
  );
};
