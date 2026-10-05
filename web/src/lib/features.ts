// Port of url-guard/src/features.py and preview scorer from DEMO.html

export interface Features {
  url_length: number;
  hostname_length: number;
  path_length: number;
  query_length: number;
  longest_token_len: number;
  n_dots: number;
  n_hyphens: number;
  n_slashes: number;
  n_digits: number;
  n_special: number;
  n_params: number;
  n_pct_encoded: number;
  n_at: number;
  path_depth: number;
  n_subdomains: number;
  keyword_count: number;
  digit_ratio: number;
  letter_ratio: number;
  special_ratio: number;
  has_ip_host: number;
  has_port: number;
  has_punycode: number;
  is_shortener: number;
  risky_tld: number;
  host_entropy: number;
  domain_digit_count: number;
  domain_hyphen_count: number;
  min_brand_dist: number;
  brand_in_subdomain: number;
  brand_in_path: number;
}

export interface ScoreResult {
  p: number;
  why: string[];
}

export const KW = [
  "login", "signin", "sign-in", "verify", "verification", "secure", "account",
  "update", "confirm", "banking", "password", "passwd", "wallet", "webscr",
  "billing", "invoice", "support", "unlock", "suspend", "recover",
  "authenticate", "free", "bonus", "prize", "gift", "crypto", "airdrop"
];

export const SHORT = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly"
]);

export const RISKY = new Set([
  "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
  "country", "work", "support", "rest", "icu", "cyou", "buzz", "monster", "sbs", "cfd"
]);

export const BRANDS = [
  "google", "facebook", "paypal", "amazon", "apple", "microsoft", "netflix",
  "instagram", "whatsapp", "linkedin", "twitter", "youtube", "github", "dropbox",
  "adobe", "ebay", "walmart", "chase", "wellsfargo", "bankofamerica", "citibank",
  "hdfcbank", "icicibank", "sbi", "paytm", "phonepe", "flipkart", "outlook",
  "office365", "yahoo", "spotify", "steam", "binance", "coinbase", "metamask",
  "dhl", "fedex", "ups", "usps", "irs"
];

export const FEATURE_GROUPS: Record<string, (keyof Features)[]> = {
  Length: ["url_length", "hostname_length", "path_length", "query_length", "longest_token_len"],
  Counts: ["n_dots", "n_hyphens", "n_slashes", "n_digits", "n_special", "n_params", "n_pct_encoded", "n_at", "path_depth", "n_subdomains", "keyword_count"],
  Ratios: ["digit_ratio", "letter_ratio", "special_ratio"],
  Host: ["has_ip_host", "has_port", "has_punycode", "is_shortener", "risky_tld", "host_entropy", "domain_digit_count", "domain_hyphen_count"],
  Brand: ["min_brand_dist", "brand_in_subdomain", "brand_in_path"]
};

export const HOT_FEATURES = new Set<keyof Features>([
  "has_ip_host", "has_port", "risky_tld", "brand_in_subdomain", "brand_in_path", "has_punycode", "is_shortener", "n_at"
]);

export function lev(a: string, b: string, cap = 4): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let p = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const c = [i];
    for (let j = 1; j <= b.length; j++) {
      c.push(Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
    }
    if (Math.min(...c) > cap) return cap + 1;
    p = c;
  }
  return p[b.length];
}

export function ent(s: string): number {
  if (!s) return 0;
  const m: Record<string, number> = {};
  for (const c of s) m[c] = (m[c] || 0) + 1;
  return -Object.values(m).reduce((a, v) => a + (v / s.length) * Math.log2(v / s.length), 0);
}

export function feats(raw: string): Features | null {
  raw = (raw || "").trim();
  if (!raw) return null;
  const u = /^[a-z][a-z0-9+.\-]*:\/\//i.test(raw) ? raw : "http://" + raw.replace(/^\/+/, "");
  let P: URL;
  try {
    P = new URL(u);
  } catch {
    return null;
  }
  const host = P.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return null;
  const nos = u.split("://")[1];
  const m = nos.match(/^([^/?#]*)([^?#]*)(?:\?([^#]*))?/);
  const path = (m && m[2]) || "";
  const query = (m && m[3]) || "";
  let dec = nos;
  try {
    dec = decodeURIComponent(nos);
  } catch {}
  dec = dec.toLowerCase();
  const ip = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host) || host.includes(":");
  const L = host.split(".");
  const two = L.length >= 3 && L[L.length - 1].length === 2 && ["co", "com", "org", "net", "gov", "ac", "edu"].includes(L[L.length - 2]);
  const sl = two ? 2 : 1;
  const domain = ip ? "" : L[L.length - sl - 1] || "";
  const suffix = L.slice(L.length - sl).join(".");
  let sub = ip ? [] : L.slice(0, Math.max(0, L.length - sl - 1));
  if (sub[0] === "www") sub = sub.slice(1);
  const reg = ip ? host : [domain, suffix].filter(Boolean).join(".");
  const n = nos.length;
  const dg = (nos.match(/\d/g) || []).length;
  const lt = (nos.match(/[a-z]/gi) || []).length;
  const sp = n - dg - lt;
  const tk = nos.split(/[^a-zA-Z0-9]+/).filter(Boolean);
  const bd = domain && !ip ? Math.min(...BRANDS.map(b => lev(domain, b))) : 5;
  const st = sub.join(".").toLowerCase();
  const pt = (path + "?" + query).toLowerCase();
  const port = P.port === "" ? null : +P.port;

  return {
    url_length: n,
    hostname_length: host.length,
    path_length: path.length,
    query_length: query.length,
    longest_token_len: Math.max(0, ...tk.map(t => t.length)),
    n_dots: (nos.match(/\./g) || []).length,
    n_hyphens: (nos.match(/-/g) || []).length,
    n_slashes: (nos.match(/\//g) || []).length,
    n_digits: dg,
    n_special: sp,
    n_params: query.split("&").filter(Boolean).length,
    n_pct_encoded: (nos.match(/%[0-9a-f]{2}/gi) || []).length,
    n_at: (nos.match(/@/g) || []).length,
    path_depth: path.split("/").filter(Boolean).length,
    n_subdomains: ip ? 0 : sub.length,
    keyword_count: KW.reduce((a, k) => a + dec.split(k).length - 1, 0),
    digit_ratio: +(dg / n).toFixed(3),
    letter_ratio: +(lt / n).toFixed(3),
    special_ratio: +(sp / n).toFixed(3),
    has_ip_host: +ip,
    has_port: +(port !== null && port !== 80 && port !== 443),
    has_punycode: +host.includes("xn--"),
    is_shortener: +SHORT.has(reg),
    risky_tld: +RISKY.has(suffix.split(".").pop() || ""),
    host_entropy: +ent(host).toFixed(2),
    domain_digit_count: (domain.match(/\d/g) || []).length,
    domain_hyphen_count: (domain.match(/-/g) || []).length,
    min_brand_dist: bd,
    brand_in_subdomain: +BRANDS.some(b => st.includes(b) && b !== domain),
    brand_in_path: +BRANDS.some(b => pt.includes(b) && b !== domain)
  };
}

export function score(f: Features): ScoreResult {
  let s = -1.8;
  const w: [number, string][] = [];
  const add = (v: number, t: string) => {
    if (v > 0) {
      s += v;
      w.push([v, t]);
    }
  };
  add(f.has_ip_host * 3, "IP address used as host");
  add(f.has_port * 1, "non-standard port");
  add(Math.max(0, f.n_dots - 2) * 0.45, f.n_dots + " dots");
  add(Math.min(f.n_subdomains, 4) * 0.35 * (f.n_subdomains > 1 ? 1 : 0), f.n_subdomains + " subdomains");
  add(Math.min(f.keyword_count, 4) * 0.55, f.keyword_count + " suspicious keyword" + (f.keyword_count > 1 ? "s" : ""));
  add(f.risky_tld * 1.3, "risky top-level domain");
  add(f.domain_hyphen_count * 0.3, f.domain_hyphen_count + " hyphens in domain");
  add(Math.min(f.domain_digit_count, 3) * 0.15, "digits inside domain name");
  add(f.brand_in_subdomain * 1.6, "brand name used as a subdomain");
  add(f.brand_in_path * 0.9, "brand name in path");
  add(f.min_brand_dist > 0 && f.min_brand_dist <= 2 ? 1 : 0, "domain close to a known brand");
  add(f.n_at * 1.5, "@ symbol");
  add(f.is_shortener * 0.8, "link shortener");
  add(f.has_punycode, "punycode host");
  add(f.n_params * 0.35, f.n_params + " query parameter" + (f.n_params > 1 ? "s" : ""));
  add(Math.max(0, f.path_length - 40) * 0.02, "long path");
  add(Math.min(f.n_pct_encoded, 5) * 0.2, "percent-encoded characters");
  add(f.host_entropy > 3.8 ? 0.5 : 0, "high-entropy host");
  return {
    p: 1 / (1 + Math.exp(-s)),
    why: w.sort((a, b) => b[0] - a[0]).map(x => x[1])
  };
}

export const PRESETS = [
  { label: "Google search", url: "https://www.google.com/search?q=machine+learning+research" },
  { label: "Wikipedia", url: "https://en.wikipedia.org/wiki/Random_forest" },
  { label: "Fake PayPal", url: "http://paypal-verification-account-security.com/login.php?update=true" },
  { label: "Raw IP malware", url: "http://175.173.82.102:52403/bin.sh" },
  { label: "Google lookalike", url: "http://g00gle-security-alert.xyz/verify-identity" },
  { label: "Bank login lure", url: "https://secure-banking-login-auth.net/portal/signin?ref=account" }
];
