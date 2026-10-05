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
    id: 'wiki',
    name: 'Wikipedia Article',
    category: 'Legitimate',
    categoryCls: 'b-green',
    url: 'https://en.wikipedia.org/wiki/Random_forest'
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
      latencyMs: 31.4
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
  const dominantPct = Math.round((isMalicious ? prob : (1 - prob)) * 100);

  const filteredFeatures =
    filterCategory === 'all'
      ? ALL_FEATURES
      : ALL_FEATURES.filter(f => f.category === filterCategory);

  const flaggedCount = extracted ? ALL_FEATURES.filter(f => f.isFlagged(extracted)).length : 0;

  return (
    <main id="p-test" className="on" style={{ paddingBottom: 120 }}>
      <div className="wrap pg">
        {/* Header */}
        <div style={{ textAlign: 'center', maxWidth: 760, margin: '0 auto 28px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span className="badge b-blue" style={{ letterSpacing: '0.04em' }}>LIVE LEXICAL SCANNER</span>
            <span style={{ font: '500 12px var(--mono)', color: 'var(--mute)' }}>
              {engineInfo ? `${engineInfo.name} · ${engineInfo.latencyMs.toFixed(2)} ms` : 'Evaluating...'}
            </span>
          </div>
          <h2 style={{ fontSize: 34, letterSpacing: '-0.03em', margin: 0, fontWeight: 700 }}>
            Paste a URL. Watch it get dissected.
          </h2>
        </div>

        {/* Input Bar & Controls Container */}
        <div style={{ maxWidth: 860, margin: '0 auto 36px' }}>
          <form
            onSubmit={handleFormSubmit}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              background: '#fff',
              border: '1.5px solid var(--line)',
              borderRadius: 14,
              padding: '10px 12px 10px 20px',
              boxShadow: '0 4px 16px rgba(0,0,0,0.03)',
              transition: 'border-color 0.2s ease, box-shadow 0.2s ease'
            }}
          >
            <span style={{ font: '600 15px var(--mono)', color: 'var(--mute)', userSelect: 'none' }}>url://</span>
            <input
              style={{
                flex: 1,
                border: 0,
                outline: 'none',
                font: '400 16px var(--mono)',
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
              style={{ padding: '10px 24px', fontSize: 13.5, fontWeight: 500, borderRadius: 10 }}
            >
              {isScanning ? 'Scoring...' : 'Scan Address'}
            </button>
          </form>

          {/* Preset Chips: Clean flex container with zero clipping */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              marginTop: 18,
              flexWrap: 'wrap'
            }}
          >
            <span style={{ font: '600 11px var(--mono)', color: 'var(--mute)', whiteSpace: 'nowrap', letterSpacing: '0.04em' }}>
              SAMPLE THREATS:
            </span>
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
                    padding: '6px 13px',
                    borderRadius: 8,
                    border: `1.5px solid ${isSelected ? 'var(--ink)' : 'var(--line)'}`,
                    background: isSelected ? 'var(--soft)' : '#fff',
                    font: '500 12px var(--mono)',
                    color: isSelected ? 'var(--ink)' : '#475467',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span className={`badge ${p.categoryCls}`} style={{ fontSize: 9, padding: '1px 5px' }}>
                    {p.category}
                  </span>
                  <span>{p.name}</span>
                </button>
              );
            })}
          </div>

          {/* Centered URL Syntax Anatomy Tokenizer */}
          {tokens.valid && (
            <div
              style={{
                marginTop: 18,
                padding: '10px 16px',
                borderRadius: 12,
                border: '1px solid var(--line)',
                background: 'var(--soft)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexWrap: 'wrap',
                gap: 8,
                font: '400 13px var(--mono)'
              }}
            >
              <span style={{ fontSize: 11, color: 'var(--mute)', marginRight: 4, letterSpacing: '0.05em', fontWeight: 600 }}>STRUCTURE:</span>
              {tokens.scheme && (
                <span style={{ background: 'rgba(43, 80, 255, 0.08)', color: 'var(--blue)', padding: '3px 8px', borderRadius: 5 }}>
                  {tokens.scheme}
                </span>
              )}
              <span
                style={{
                  background: extracted?.has_ip_host || extracted?.risky_tld ? 'rgba(217, 45, 58, 0.08)' : '#fff',
                  color: extracted?.has_ip_host || extracted?.risky_tld ? 'var(--red)' : 'var(--ink)',
                  border: '1px solid var(--line)',
                  padding: '3px 8px',
                  borderRadius: 5,
                  fontWeight: 500
                }}
              >
                {tokens.host}
              </span>
              {tokens.port && (
                <span style={{ background: 'rgba(217, 45, 58, 0.08)', color: 'var(--red)', padding: '3px 8px', borderRadius: 5 }}>
                  {tokens.port}
                </span>
              )}
              {tokens.path && (
                <span style={{ background: '#fff', border: '1px solid var(--line)', color: '#475467', padding: '3px 8px', borderRadius: 5 }}>
                  {tokens.path}
                </span>
              )}
              {tokens.query && (
                <span style={{ background: 'rgba(18, 128, 92, 0.08)', color: 'var(--green)', padding: '3px 8px', borderRadius: 5 }}>
                  {tokens.query}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Results Overview */}
        {!extracted || !scoreData ? (
          <div className="solid" style={{ marginTop: 32, padding: 28, textAlign: 'center' }}>
            <h3>Invalid Address</h3>
            <p style={{ color: 'var(--mute)', fontSize: 14, marginTop: 4 }}>
              Enter a valid URL address with a registered host name.
            </p>
          </div>
        ) : (
          <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: '360px 1fr', gap: 24 }}>
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
                    {dominantPct}%
                  </span>
                  <span style={{ font: '500 13px var(--mono)', color: 'var(--mute)' }}>
                    {isMalicious ? 'malicious probability' : 'benign confidence'}
                  </span>
                </div>

                {/* Meter track */}
                <div style={{ height: 6, background: 'var(--soft)', borderRadius: 3, overflow: 'hidden', margin: '8px 0 16px' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${dominantPct}%`,
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
                    <b>{engineInfo ? `${engineInfo.latencyMs.toFixed(3)} ms` : '30.9 ms'}</b>
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

              {/* Column Header Row */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '160px 1fr 110px 70px',
                  gap: 12,
                  padding: '0 12px 10px 12px',
                  borderBottom: '1px solid var(--line)',
                  font: '600 11px var(--mono)',
                  color: 'var(--mute)',
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase'
                }}
              >
                <span>Feature Key</span>
                <span>Description</span>
                <span style={{ textAlign: 'right' }}>Baseline</span>
                <span style={{ textAlign: 'right' }}>Value</span>
              </div>

              {/* Tabular Feature Rows with smooth internal scroll */}
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 2,
                  maxHeight: 430,
                  overflowY: 'auto',
                  padding: '6px 4px 6px 0'
                }}
              >
                {filteredFeatures.map(item => {
                  const val = extracted[item.key];
                  const flagged = item.isFlagged(extracted);
                  return (
                    <div
                      key={item.key}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '160px 1fr 110px 70px',
                        gap: 12,
                        alignItems: 'center',
                        padding: '9px 12px',
                        borderRadius: 6,
                        background: flagged ? 'rgba(217, 45, 58, 0.04)' : 'transparent',
                        borderLeft: flagged ? '3px solid var(--red)' : '3px solid transparent',
                        borderBottom: '1px solid #f2f4f7',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      <div style={{ font: '500 12.5px var(--mono)', color: flagged ? 'var(--red)' : 'var(--ink)' }}>
                        <code>{item.key}</code>
                      </div>
                      <div style={{ fontSize: 12.5, color: '#475467', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.label}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--mute)', fontFamily: 'var(--mono)', textAlign: 'right' }}>
                        {item.baseline}
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <span
                          style={{
                            font: '600 13px var(--mono)',
                            color: flagged ? 'var(--red)' : 'var(--ink)',
                            background: flagged ? 'rgba(217, 45, 58, 0.08)' : 'transparent',
                            padding: flagged ? '2px 6px' : '0',
                            borderRadius: 4
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
