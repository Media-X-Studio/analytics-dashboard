const { GoogleAuth } = require('google-auth-library');

// ─────────────────────────────────────────────────────────────
// CONFIG  (public dashboard — hardened against abuse/scraping)
// ─────────────────────────────────────────────────────────────

// GA4 properties that may be queried
const ALLOWED_PROPERTIES = new Set([
  '516232011', // ignitedminds.academy
  '533738808', // intelliexams.com
  '539481048', // mediax.academy
  '514290667', // mindlogicx.com / mindlogicx.com.my
  '514443920', // themediax.ai
]);

// Only these GA4 dimensions / metrics may be requested, and only small page sizes.
// Stops callers from extracting more detail than the dashboard itself shows.
const ALLOWED_DIMENSIONS = new Set([
  'date', 'pagePath', 'sessionDefaultChannelGroup', 'country', 'sessionSource',
]);
const ALLOWED_METRICS = new Set([
  'totalUsers', 'newUsers', 'sessions', 'bounceRate', 'averageSessionDuration', 'screenPageViews',
]);
const MAX_LIMIT = 100;
const MAX_DATE_RANGES = 2;

// Lock browser CORS to the dashboard's own origin (set DASHBOARD_ORIGIN in Vercel env).
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || '';

// Best-effort per-IP rate limit (per warm instance).
const RL_MAX = 90;            // requests
const RL_WINDOW = 60 * 1000;  // per minute
const hits = new Map();
function rateLimit(key) {
  const now = Date.now();
  const e = hits.get(key);
  if (!e || now > e.reset) { hits.set(key, { count: 1, reset: now + RL_WINDOW }); return true; }
  e.count++;
  return e.count <= RL_MAX;
}

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

// ── GA4 service-account token (read-only) ──
let cachedToken = null;
let tokenExpiry = 0;
async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry - 60000) return cachedToken;
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT;
  if (!raw) throw httpErr(500, 'GOOGLE_SERVICE_ACCOUNT env var not set');
  const credentials = JSON.parse(raw);
  const auth = new GoogleAuth({ credentials, scopes: ['https://www.googleapis.com/auth/analytics.readonly'] });
  const client = await auth.getClient();
  const res = await client.getAccessToken();
  cachedToken = res.token;
  tokenExpiry = now + 55 * 60 * 1000;
  return cachedToken;
}

// ── Validate the requested report body ──
function validateBody(b) {
  if (b.dimensions != null) {
    if (!Array.isArray(b.dimensions) || b.dimensions.length > 3) throw httpErr(400, 'Invalid dimensions');
    for (const d of b.dimensions) {
      if (!d || !ALLOWED_DIMENSIONS.has(d.name)) throw httpErr(403, `Dimension not allowed: ${d && d.name}`);
    }
  }
  if (b.metrics != null) {
    if (!Array.isArray(b.metrics) || b.metrics.length === 0 || b.metrics.length > 8) throw httpErr(400, 'Invalid metrics');
    for (const m of b.metrics) {
      if (!m || !ALLOWED_METRICS.has(m.name)) throw httpErr(403, `Metric not allowed: ${m && m.name}`);
    }
  }
  if (b.dateRanges != null) {
    if (!Array.isArray(b.dateRanges) || b.dateRanges.length === 0 || b.dateRanges.length > MAX_DATE_RANGES) throw httpErr(400, 'Invalid dateRanges');
  }
  if (b.limit != null) {
    const n = Number(b.limit);
    if (!Number.isFinite(n) || n <= 0 || n > MAX_LIMIT) throw httpErr(400, `limit must be 1-${MAX_LIMIT}`);
  }
}

// ─────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  // CORS — restrict to dashboard origin when configured (browser-only protection).
  const origin = req.headers.origin;
  if (DASHBOARD_ORIGIN) {
    if (origin === DASHBOARD_ORIGIN) { res.setHeader('Access-Control-Allow-Origin', DASHBOARD_ORIGIN); res.setHeader('Vary', 'Origin'); }
  } else if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    if (!rateLimit(ip)) throw httpErr(429, 'Too many requests. Please slow down.');

    const { propertyId, ...reportBody } = req.body || {};
    if (!propertyId) throw httpErr(400, 'propertyId is required');
    if (!ALLOWED_PROPERTIES.has(String(propertyId))) throw httpErr(403, 'Property not authorized');
    validateBody(reportBody);

    const token = await getAccessToken();
    const gaRes = await fetch(
      `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`,
      { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(reportBody) }
    );
    const data = await gaRes.json();
    if (!gaRes.ok) {
      console.error('GA4 error:', data);
      return res.status(gaRes.status).json({ error: data.error?.message || 'GA4 API error' });
    }

    // Short CDN cache to cut quota usage; safe because data is non-personal & public.
    res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=60');
    return res.status(200).json(data);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) console.error('Handler error:', err);
    return res.status(status).json({ error: err.message });
  }
};
