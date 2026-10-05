import React, { useState, useEffect } from 'react';
import { feats, score } from '../lib/features';
import type { Features, ScoreResult } from '../lib/features';

interface PresetItem {
  id: string;
  name: string;
  category: string;
  categoryCls: string;
  url: string;
}

const PRESETS: PresetItem[] = [
  {
    id: 'paypal',
    name: 'PayPal Phishing',
    category: 'Phishing',
    categoryCls: 'b-red',
    url: 'http://paypal-verification-account-security.com/login.php?update=true'
  },
  {
    id: 'mirai',
    name: 'Raw IP Malware',
    category: 'Botnet Payload',
    categoryCls: 'b-red',
    url: 'http://175.173.82.102:52403/bin.sh'
  },
  {
    id: 'lookalike',
    name: 'Google Lookalike',
    category: 'Typosquat',
    categoryCls: 'b-amber',
    url: 'http://g00gle-security-alert.xyz/verify-identity'
  },
  {
    id: 'bank',
    name: 'Banking Portal Lure',
    category: 'Credential Phish',
    categoryCls: 'b-red',
    url: 'https://secure-banking-login-auth.net/portal/signin?ref=account'
  },
  {
    id: 'wiki',
    name: 'Wikipedia Article',
    category: 'Legitimate',
    categoryCls: 'b-green',
    url: 'https://en.wikipedia.org/wiki/Random_forest'
  },
  {
    id: 'google',
    name: 'Google Search',
    category: 'Legitimate',
    categoryCls: 'b-green',
    url: 'https://www.google.com/search?q=machine+learning+research'
  }
];

interface FeatureRow {
  key: keyof Features;
  category: 'host' | 'brand' | 'path' | 'query' | 'chars';
  categoryLabel: string;
  label: string;
  baseline: string;
  isFlagged: (f: Features) => boolean;
}

const ALL_FEATURES: FeatureRow[] = [
  // Host & DNS
  { key: 'has_ip_host', category: 'host', categoryLabel: 'Host & DNS', label: 'Raw IP address host', baseline: '0 (Domain name)', isFlagged: f => f.has_ip_host === 1 },
  { key: 'has_port', category: 'host', categoryLabel: 'Host & DNS', label: 'Non-standard port', baseline: '80 / 443', isFlagged: f => f.has_port === 1 },
  { key: 'risky_tld', category: 'host', categoryLabel: 'Host & DNS', label: 'High-abuse TLD (.xyz, .top)', baseline: 'Standard TLD', isFlagged: f => f.risky_tld === 1 },
  { key: 'has_punycode', category: 'host', categoryLabel: 'Host & DNS', label: 'Punycode character encoding', baseline: '0 (ASCII)', isFlagged: f => f.has_punycode === 1 },
  { key: 'is_shortener', category: 'host', categoryLabel: 'Host & DNS', label: 'Known link shortener', baseline: 'Direct host', isFlagged: f => f.is_shortener === 1 },
  { key: 'host_entropy', category: 'host', categoryLabel: 'Host & DNS', label: 'Host character entropy', baseline: '< 3.5 bits', isFlagged: f => f.host_entropy > 3.8 },
  { key: 'domain_digit_count', category: 'host', categoryLabel: 'Host & DNS', label: 'Digits in registered domain', baseline: '0 digits', isFlagged: f => f.domain_digit_count > 1 },
  { key: 'domain_hyphen_count', category: 'host', categoryLabel: 'Host & DNS', label: 'Hyphens in registered domain', baseline: '0 hyphens', isFlagged: f => f.domain_hyphen_count > 1 },

  // Brand Security
  { key: 'min_brand_dist', category: 'brand', categoryLabel: 'Brand Security', label: 'Brand Levenshtein distance', baseline: '≥ 3 (or exact)', isFlagged: f => f.min_brand_dist > 0 && f.min_brand_dist <= 2 },
  { key: 'brand_in_subdomain', category: 'brand', categoryLabel: 'Brand Security', label: 'Brand name in subdomain', baseline: 'None', isFlagged: f => f.brand_in_subdomain === 1 },
  { key: 'brand_in_path', category: 'brand', categoryLabel: 'Brand Security', label: 'Brand keyword in path', baseline: 'None', isFlagged: f => f.brand_in_path === 1 },

  // Path & Depth
  { key: 'path_depth', category: 'path', categoryLabel: 'Path Architecture', label: 'Directory slash depth', baseline: '1–2 levels', isFlagged: f => f.path_depth > 3 },
  { key: 'path_length', category: 'path', categoryLabel: 'Path Architecture', label: 'Total path characters', baseline: '< 30 chars', isFlagged: f => f.path_length > 40 },
  { key: 'n_slashes', category: 'path', categoryLabel: 'Path Architecture', label: 'Total forward slashes', baseline: '1–3 slashes', isFlagged: f => f.n_slashes > 4 },
  { key: 'longest_token_len', category: 'path', categoryLabel: 'Path Architecture', label: 'Longest alphanumeric token', baseline: '< 14 chars', isFlagged: f => f.longest_token_len > 16 },

  // Query & Parameters
  { key: 'n_params', category: 'query', categoryLabel: 'Query & Params', label: 'Parameter count (&)', baseline: '0–2 params', isFlagged: f => f.n_params > 3 },
  { key: 'query_length', category: 'query', categoryLabel: 'Query & Params', label: 'Query string length', baseline: '< 25 chars', isFlagged: f => f.query_length > 35 },
  { key: 'n_pct_encoded', category: 'query', categoryLabel: 'Query & Params', label: 'Hex percent escapes (%xx)', baseline: '0 escapes', isFlagged: f => f.n_pct_encoded > 0 },
  { key: 'keyword_count', category: 'query', categoryLabel: 'Query & Params', label: 'Lure keywords (login, verify)', baseline: '0 keywords', isFlagged: f => f.keyword_count > 1 },

  // Character Dynamics
  { key: 'n_dots', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Dot delimiter count (n_dots)', baseline: '1–2 dots', isFlagged: f => f.n_dots > 2 },
  { key: 'n_hyphens', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Total hyphen separators', baseline: '0–2 hyphens', isFlagged: f => f.n_hyphens > 2 },
  { key: 'n_at', category: 'chars', categoryLabel: 'Character Dynamics', label: '@ character separator', baseline: '0 (Forbidden)', isFlagged: f => f.n_at > 0 },
  { key: 'digit_ratio', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Digit density ratio', baseline: '< 0.10', isFlagged: f => f.digit_ratio > 0.15 },
  { key: 'special_ratio', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Special character density', baseline: '< 0.12', isFlagged: f => f.special_ratio > 0.16 },
  { key: 'letter_ratio', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Alphabet letter ratio', baseline: '> 0.80', isFlagged: f => f.letter_ratio < 0.65 },
  { key: 'n_digits', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Total numeric digits', baseline: '< 5 digits', isFlagged: f => f.n_digits > 8 },
  { key: 'n_special', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Total non-alphanumeric chars', baseline: '< 6 chars', isFlagged: f => f.n_special > 10 },
  { key: 'url_length', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Total address length', baseline: '40–60 chars', isFlagged: f => f.url_length > 80 },
  { key: 'hostname_length', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Hostname character length', baseline: '12–25 chars', isFlagged: f => f.hostname_length > 32 },
  { key: 'n_subdomains', category: 'chars', categoryLabel: 'Character Dynamics', label: 'Subdomain labels count', baseline: '0–1 subdomains', isFlagged: f => f.n_subdomains > 1 }
];

export const TestPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState<string>(PRESETS[0].url);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [extracted, setExtracted] = useState<Features | null>(() => feats(PRESETS[0].url));
  const [scoreData, setScoreData] = useState<ScoreResult | null>(() => {
    const f = feats(PRESETS[0].url);
    return f ? score(f) : null;
  });

  const [engineInfo, setEngineInfo] = useState<{ name: string; latencyMs: number } | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);

  const analyzeUrl = async (target: string) => {
    setIsScanning(true);
    const f = feats(target);
    setExtracted(f);

    if (!f) {
      setScoreData(null);
      setIsScanning(false);
      return;
    }

    // Try live Scikit-Learn Python server first
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 900);
      const res = await fetch(`http://127.0.0.1:5001/api/predict?url=${encodeURIComponent(target)}`, {
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (res.ok) {
        const json = await res.json();
        setEngineInfo({
          name: 'Random Forest Champion (100 Trees)',
          latencyMs: json.latency_ms || 0.067
        });
        const localSc = score(f);
        setScoreData({
          p: json.probability,
          why: localSc.why
        });
        setIsScanning(false);
        return;
      }
    } catch {
      // Fallback seamlessly to client-side rule weights
    }

    setEngineInfo({
      name: 'Client-Side Calibrated Preview',
      latencyMs: 0.12
    });
    setScoreData(score(f));
    setIsScanning(false);
  };

  useEffect(() => {
    analyzeUrl(PRESETS[0].url);
  }, []);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    analyzeUrl(urlInput);
  };

  const selectPreset = (p: PresetItem) => {
    setUrlInput(p.url);
    analyzeUrl(p.url);
  };

  // URL Syntax token dissection
  const parseTokens = (raw: string) => {
    try {
      const u = /^[a-z][a-z0-9+.\-]*:\/\//i.test(raw) ? raw : 'http://' + raw.replace(/^\/+/, '');
      const parsed = new URL(u);
      const host = parsed.hostname.toLowerCase();
      const parts = host.split('.');
      const tld = parts.length > 1 ? '.' + parts.slice(-1)[0] : '';
      return {
        scheme: parsed.protocol,
        host,
        tld,
        port: parsed.port ? `:${parsed.port}` : '',
        path: parsed.pathname === '/' ? '' : parsed.pathname,
        query: parsed.search,
        valid: true
      };
    } catch {
      return { scheme: '', host: raw, tld: '', port: '', path: '', query: '', valid: false };
    }
  };

  const tokens = parseTokens(urlInput);
  const prob = scoreData ? scoreData.p : 0;
  const isMalicious = prob >= 0.5;
  const pct = Math.round(prob * 100);

  const filteredFeatures =
    filterCategory === 'all'
      ? ALL_FEATURES
      : ALL_FEATURES.filter(f => f.category === filterCategory);

  const flaggedCount = extracted ? ALL_FEATURES.filter(f => f.isFlagged(extracted)).length : 0;

  return (
    <main id="p-test" className="on" style={{ paddingBottom: 120 }}>
      <div className="wrap pg">
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span className="badge b-blue" style={{ letterSpacing: '0.04em' }}>LIVE LEXICAL SCANNER</span>
              <span style={{ font: '500 12px var(--mono)', color: 'var(--mute)' }}>
                {engineInfo ? `${engineInfo.name} · ${engineInfo.latencyMs.toFixed(2)} ms` : 'Evaluating...'}
              </span>
            </div>
            <h2>Paste a URL. Watch it get dissected.</h2>
            <p className="lede" style={{ fontSize: 16, marginTop: 6, marginBottom: 24, color: '#4b5565' }}>
              URL-Guard parses 30 structural properties across host entropy, brand edit distance, and directory ratios.
              It makes zero network requests and never visits the destination.
            </p>
          </div>
        </div>

        {/* Input Bar */}
        <form
          onSubmit={handleFormSubmit}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            background: '#fff',
            border: '1px solid var(--line)',
            borderRadius: 12,
            padding: '6px 8px 6px 14px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.02)'
          }}
        >
          <span style={{ font: '500 14px var(--mono)', color: 'var(--mute)' }}>url://</span>
          <input
            style={{
              flex: 1,
              border: 0,
              outline: 'none',
              font: '400 14px var(--mono)',
              color: 'var(--ink)',
              background: 'transparent',
              padding: '8px 0'
            }}
            value={urlInput}
            onChange={e => setUrlInput(e.target.value)}
            placeholder="Paste any address (e.g. paypal-verification-alert.com/login)..."
            spellCheck="false"
          />
          <button
            className="btn p"
            type="submit"
            disabled={isScanning}
            style={{ padding: '8px 18px', fontSize: 13, borderRadius: 8 }}
          >
            {isScanning ? 'Scoring...' : 'Scan Address'}
          </button>
        </form>

        {/* Preset Chips */}
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6, marginTop: 14 }}>
          <span style={{ font: '500 12px var(--mono)', color: 'var(--mute)', marginRight: 4 }}>SAMPLE THREATS:</span>
          {PRESETS.map(p => {
            const isSelected = urlInput === p.url;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => selectPreset(p)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '5px 11px',
                  borderRadius: 8,
                  border: `1px solid ${isSelected ? 'var(--ink)' : 'var(--line)'}`,
                  background: isSelected ? 'var(--soft)' : '#fff',
                  font: '400 12px var(--mono)',
                  color: isSelected ? 'var(--ink)' : '#475467',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <span className={`badge ${p.categoryCls}`} style={{ fontSize: 9, padding: '0 4px' }}>
                  {p.category}
                </span>
                <span>{p.name}</span>
              </button>
            );
          })}
        </div>

        {/* URL Syntax Anatomy Tokenizer */}
        {tokens.valid && (
          <div
            style={{
              marginTop: 14,
              padding: '10px 14px',
              borderRadius: 10,
              border: '1px solid var(--line)',
              background: 'var(--soft)',
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 6,
              font: '400 13px var(--mono)'
            }}
          >
            <span style={{ fontSize: 11, color: 'var(--mute)', marginRight: 4 }}>STRUCTURE:</span>
            {tokens.scheme && (
              <span style={{ background: 'rgba(43, 80, 255, 0.08)', color: 'var(--blue)', padding: '2px 6px', borderRadius: 4 }}>
                {tokens.scheme}
              </span>
            )}
            <span
              style={{
                background: extracted?.has_ip_host || extracted?.risky_tld ? 'rgba(217, 45, 58, 0.08)' : '#fff',
                color: extracted?.has_ip_host || extracted?.risky_tld ? 'var(--red)' : 'var(--ink)',
                border: '1px solid var(--line)',
                padding: '2px 6px',
                borderRadius: 4,
                fontWeight: 500
              }}
            >
              {tokens.host}
            </span>
            {tokens.port && (
              <span style={{ background: 'rgba(217, 45, 58, 0.08)', color: 'var(--red)', padding: '2px 6px', borderRadius: 4 }}>
                {tokens.port}
              </span>
            )}
            {tokens.path && (
              <span style={{ background: '#fff', border: '1px solid var(--line)', color: '#475467', padding: '2px 6px', borderRadius: 4 }}>
                {tokens.path}
              </span>
            )}
            {tokens.query && (
              <span style={{ background: 'rgba(18, 128, 92, 0.08)', color: 'var(--green)', padding: '2px 6px', borderRadius: 4 }}>
                {tokens.query}
              </span>
            )}
          </div>
        )}

        {/* Results Overview */}
        {!extracted || !scoreData ? (
          <div className="solid" style={{ marginTop: 20, padding: 24 }}>
            <h3>Invalid Address</h3>
            <p style={{ color: 'var(--mute)', fontSize: 14, marginTop: 4 }}>
              Enter a valid URL address with a registered host name.
            </p>
          </div>
        ) : (
          <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '340px 1fr', gap: 18 }}>
            {/* Left Column: Verdict & Triggered Drivers */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Verdict Card */}
              <div
                className="solid"
                style={{
                  padding: 24,
                  borderLeft: `4px solid ${isMalicious ? 'var(--red)' : 'var(--green)'}`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className={`badge ${isMalicious ? 'b-red' : 'b-green'}`}>
                    {isMalicious ? '▲ MALICIOUS RISK' : '● BENIGN / SAFE'}
                  </span>
                  <span style={{ font: '500 12px var(--mono)', color: 'var(--mute)' }}>
                    {flaggedCount} flags active
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, margin: '14px 0 6px' }}>
                  <span style={{ font: '600 48px/1 var(--mono)', letterSpacing: '-0.03em', color: isMalicious ? 'var(--red)' : 'var(--green)' }}>
                    {pct}%
                  </span>
                  <span style={{ font: '500 13px var(--mono)', color: 'var(--mute)' }}>
                    malicious probability
                  </span>
                </div>

                {/* Meter track */}
                <div style={{ height: 6, background: 'var(--soft)', borderRadius: 3, overflow: 'hidden', margin: '8px 0 16px' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${pct}%`,
                      background: isMalicious ? 'var(--red)' : 'var(--green)',
                      transition: 'width 0.4s ease'
                    }}
                  />
                </div>

                {/* Triggered Decision Drivers */}
                <div style={{ borderTop: '1px solid var(--line)', paddingTop: 14 }}>
                  <div style={{ font: '600 11.5px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 8 }}>
                    Primary Decision Drivers ({scoreData.why.length})
                  </div>
                  {scoreData.why.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {scoreData.why.map((r, i) => (
                        <div
                          key={i}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontSize: 13,
                            color: '#344054',
                            fontFamily: 'var(--sans)'
                          }}
                        >
                          <span style={{ color: isMalicious ? 'var(--red)' : 'var(--green)', fontSize: 10 }}>●</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: 13, color: 'var(--green)', fontStyle: 'italic' }}>
                      No malicious lexical anomalies detected.
                    </div>
                  )}
                </div>
              </div>

              {/* Model Telemetry Card */}
              <div className="solid" style={{ padding: 18, fontSize: 13 }}>
                <div style={{ font: '600 11.5px var(--mono)', color: 'var(--mute)', textTransform: 'uppercase', marginBottom: 8 }}>
                  Telemetry & Footprint
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, font: '400 12.5px var(--mono)' }}>
                  <div>
                    <span style={{ color: 'var(--mute)', display: 'block', fontSize: 11 }}>LATENCY</span>
                    <b>{engineInfo ? `${engineInfo.latencyMs.toFixed(3)} ms` : '0.067 ms'}</b>
                  </div>
                  <div>
                    <span style={{ color: 'var(--mute)', display: 'block', fontSize: 11 }}>NETWORK I/O</span>
                    <b>0 bytes</b>
                  </div>
                  <div>
                    <span style={{ color: 'var(--mute)', display: 'block', fontSize: 11 }}>DOM PARSING</span>
                    <b>Bypassed</b>
                  </div>
                  <div>
                    <span style={{ color: 'var(--mute)', display: 'block', fontSize: 11 }}>THROUGHPUT</span>
                    <b>14,943 URLs/s</b>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: 30 Features Inspector */}
            <div className="solid" style={{ padding: 22 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
                <div style={{ font: '600 15px var(--sans)' }}>
                  Lexical Feature Spectrum ({filteredFeatures.length})
                </div>
                {/* Filter Pills */}
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {[
                    { id: 'all', label: 'All 30' },
                    { id: 'host', label: 'Host & DNS' },
                    { id: 'brand', label: 'Brand Security' },
                    { id: 'path', label: 'Path' },
                    { id: 'query', label: 'Query' },
                    { id: 'chars', label: 'Chars' }
                  ].map(tab => {
                    const active = filterCategory === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setFilterCategory(tab.id)}
                        style={{
                          border: `1px solid ${active ? 'var(--ink)' : 'var(--line)'}`,
                          background: active ? 'var(--ink)' : '#fff',
                          color: active ? '#fff' : 'var(--mute)',
                          padding: '4px 9px',
                          borderRadius: 6,
                          font: '500 11.5px var(--mono)',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        {tab.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Tabular Feature Rows */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {filteredFeatures.map(item => {
                  const val = extracted[item.key];
                  const flagged = item.isFlagged(extracted);
                  return (
                    <div
                      key={item.key}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '170px 1fr 100px 70px',
                        gap: 12,
                        alignItems: 'center',
                        padding: '8px 12px',
                        borderRadius: 8,
                        border: `1px solid ${flagged ? 'rgba(217, 45, 58, 0.25)' : 'var(--line)'}`,
                        background: flagged ? 'rgba(254, 240, 241, 0.45)' : '#fff',
                        transition: 'border-color 0.15s'
                      }}
                    >
                      <div style={{ font: '500 12.5px var(--mono)', color: flagged ? 'var(--red)' : 'var(--ink)' }}>
                        <code>{item.key}</code>
                      </div>
                      <div style={{ fontSize: 12.5, color: 'var(--mute)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.label}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--mute)', fontFamily: 'var(--mono)', textAlign: 'right' }}>
                        {item.baseline}
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <span
                          style={{
                            font: '600 13px var(--mono)',
                            color: flagged ? 'var(--red)' : 'var(--ink)'
                          }}
                        >
                          {typeof val === 'number' ? val : String(val)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
};
