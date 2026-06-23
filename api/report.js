const { GoogleAuth } = require('google-auth-library');

// Allowed GA4 property IDs — only these can be queried
const ALLOWED_PROPERTIES = new Set([
    '516232011', // ignitedminds.academy
    '533738808', // intelliexams.com
    '539481048', // mediax.academy
    '514290667', // mindlogicx.com / mindlogicx.com.my
    '514443920', // themediax.ai
  ]);

let cachedToken = null;
let tokenExpiry = 0;

async function getAccessToken() {
    const now = Date.now();
    if (cachedToken && now < tokenExpiry - 60000) return cachedToken;

    const raw = process.env.GOOGLE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT env var not set');

    const credentials = JSON.parse(raw);
    const auth = new GoogleAuth({
          credentials,
          scopes: ['https://www.googleapis.com/auth/analytics.readonly'],
        });

    const client = await auth.getClient();
    const res = await client.getAccessToken();

    cachedToken = res.token;
    // Token valid 1 hour; cache for 55 min
    tokenExpiry = now + 55 * 60 * 1000;
    return cachedToken;
  }

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
          const { propertyId, ...reportBody } = req.body;

          if (!propertyId) return res.status(400).json({ error: 'propertyId is required' });
          if (!ALLOWED_PROPERTIES.has(String(propertyId))) {
                  return res.status(403).json({ error: 'Property not authorized' });
                }

          const token = await getAccessToken();

          const gaRes = await fetch(
                  `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`,
                  {
                            method: 'POST',
                            headers: {
                                        Authorization: `Bearer ${token}`,
                                        'Content-Type': 'application/json',
                                      },
                            body: JSON.stringify(reportBody),
                          }
                );

          const data = await gaRes.json();

          if (!gaRes.ok) {
                  console.error('GA4 error:', data);
                  return res.status(gaRes.status).json({ error: data.error?.message || 'GA4 API error' });
                }

          // Cache responses for 5 minutes to reduce API quota usage
          res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=60');
          return res.status(200).json(data);

        } catch (err) {
          console.error('Handler error:', err);
          return res.status(500).json({ error: err.message });
        }
  };
