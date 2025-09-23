// server.js
// Full Node.js backend (Express) for Render
// - Postgres DB (DATABASE_URL)
// - Authentication: /register, /login, /logout
// - Single-device session enforcement (active_device)
// - Paytm integration: /create-order, /paytm-callback, /verify-order
// - Access gating: /access
//
// Required env vars (see README block below)

const express = require('express');
const fetch = require('node-fetch'); // if Node 18+, you can use global fetch
const pg = require('pg');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const PaytmChecksum = require('paytmchecksum'); // npm i paytmchecksum
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ----- Environment variables (must be set in Render) -----
const {
  PORT = 3000,
  DATABASE_URL,
  JWT_SECRET = 'replace_this',
  COOKIE_NAME = 'g10_auth',
  PAYTM_MID,
  PAYTM_KEY,
  PAYTM_WEBSITE = 'DEFAULT',
  PAYTM_CHANNEL_ID = 'WEB',
  PAYTM_INDUSTRY_TYPE = 'Retail',
  PAYTM_ENV = 'staging', // 'staging' or 'production'
  BASE_URL // e.g. https://your-backend.onrender.com  (used for callbacks)
} = process.env;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
if (!PAYTM_MID || !PAYTM_KEY || !BASE_URL) {
  console.warn('PAYTM_MID, PAYTM_KEY and BASE_URL are recommended for Paytm integration.');
  // not fatal — but payment endpoints will fail without them
}

// ----- Postgres setup -----
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  // allow self-signed or render defaults
});

// Create tables automatically
async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text,
      email_or_phone text UNIQUE,
      password_hash text,
      has_paid boolean DEFAULT false,
      active_device text DEFAULT NULL,
      created_at timestamptz DEFAULT now()
    );
  `).catch(async err => {
    // Postgres on Render might not have gen_random_uuid extension - fallback to uuid_generate_v4
    if (err && /gen_random_uuid/.test(err.message)) {
      await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text,
          email_or_phone text UNIQUE,
          password_hash text,
          has_paid boolean DEFAULT false,
          active_device text DEFAULT NULL,
          created_at timestamptz DEFAULT now()
        );
      `);
    } else {
      console.error('Error creating users table', err);
      process.exit(1);
    }
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id uuid REFERENCES users(id) ON DELETE CASCADE,
      order_id text,
      txn_id text,
      amount numeric,
      status text,
      meta jsonb,
      created_at timestamptz DEFAULT now()
    );
  `);
}

createTables().then(() => console.log('Tables ensured')).catch(err => {
  console.error(err); process.exit(1);
});

// ----- Helpers -----
function generateDeviceId() {
  return crypto.randomBytes(18).toString('hex');
}

function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

async function getUserById(id) {
  const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return r.rows[0];
}

async function getUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email_or_phone = $1', [email]);
  return r.rows[0];
}

// ----- Middleware -----
async function authMiddleware(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ ok: false, message: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUserById(payload.id);
    if (!user) return res.status(401).json({ ok: false, message: 'Invalid user' });

    // enforce single-device: token must carry device_id and match DB
    if (!payload.device_id || user.active_device !== payload.device_id) {
      // invalidate cookie
      res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'Lax' });
      return res.status(401).json({ ok: false, message: 'Session invalidated (another device logged in)' });
    }

    req.user = user;
    next();
  } catch (err) {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'Lax' });
    return res.status(401).json({ ok: false, message: 'Authentication failed' });
  }
}

// ----- Auth routes -----

// POST /register
// { name, email_or_phone, password }
app.post('/register', async (req, res) => {
  try {
    const { name, email_or_phone, password } = req.body;
    if (!email_or_phone || !password) return res.status(400).json({ ok: false, message: 'email_or_phone and password required' });
    const existing = await getUserByEmail(email_or_phone);
    if (existing) return res.status(400).json({ ok: false, message: 'User already exists' });
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (name, email_or_phone, password_hash) VALUES ($1,$2,$3) RETURNING *`,
      [name || null, email_or_phone, hash]
    );
    const user = r.rows[0];
    res.json({ ok: true, user: { id: user.id, email_or_phone: user.email_or_phone } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// POST /login
// { email_or_phone, password }
// returns HttpOnly cookie with JWT
app.post('/login', async (req, res) => {
  try {
    const { email_or_phone, password } = req.body;
    if (!email_or_phone || !password) return res.status(400).json({ ok: false, message: 'Missing credentials' });
    const user = await getUserByEmail(email_or_phone);
    if (!user) return res.status(400).json({ ok: false, message: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ ok: false, message: 'Invalid credentials' });

    // generate device id and set as active_device (enforce single device)
    const device_id = generateDeviceId();
    await pool.query('UPDATE users SET active_device = $1 WHERE id = $2', [device_id, user.id]);

    const token = signJwt({ id: user.id, device_id });
    // set cookie (HttpOnly)
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: (PAYTM_ENV === 'production'), // secure cookie in production
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({ ok: true, message: 'Logged in', user: { id: user.id, email_or_phone: user.email_or_phone, has_paid: user.has_paid } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// POST /logout
app.post('/logout', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE users SET active_device = NULL WHERE id = $1', [req.user.id]);
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'Lax' });
    res.json({ ok: true, message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// GET /me
app.get('/me', authMiddleware, async (req, res) => {
  const u = req.user;
  res.json({ ok: true, user: { id: u.id, email_or_phone: u.email_or_phone, name: u.name, has_paid: u.has_paid } });
});

// ----- Access gating -----
// GET /access
// returns { allowed: boolean, reason: string }
app.get('/access', authMiddleware, async (req, res) => {
  const user = req.user;
  if (user.has_paid) return res.json({ allowed: true });
  return res.json({ allowed: false, reason: 'not_paid' });
});

// ----- Paytm helpers -----
function paytmBaseUrl() {
  if (PAYTM_ENV === 'production') {
    return 'https://securegw.paytm.in';
  } else {
    return 'https://securegw-stage.paytm.in';
  }
}

// Initiate transaction by creating order and getting txnToken
// POST /create-order
// { amount } -> returns { orderId, txnToken, mid, amount, checkoutUrl }
app.post('/create-order', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const amount = Number(req.body.amount || 49); // default fee if not supplied
    if (!(amount > 0)) return res.status(400).json({ ok: false, message: 'Invalid amount' });

    const orderId = `ORD_${Date.now()}_${Math.floor(Math.random()*1000)}`;
    // insert pending payment
    await pool.query(`INSERT INTO payments (user_id, order_id, amount, status) VALUES ($1,$2,$3,$4)`, [user.id, orderId, amount, 'PENDING']);

    // Prepare Paytm params for initiateTransaction
    const body = {
      requestType: "Payment",
      mid: PAYTM_MID,
      websiteName: PAYTM_WEBSITE || (PAYTM_ENV === 'production' ? 'DEFAULT' : 'WEBSTAGING'),
      orderId: orderId,
      callbackUrl: `${BASE_URL}/paytm-callback`,
      txnAmount: {
        value: String(amount.toFixed(2)),
        currency: "INR"
      },
      userInfo: {
        custId: user.id
      }
    };
    const head = {};
    const checksum = await PaytmChecksum.generateSignature(JSON.stringify(body), PAYTM_KEY);
    head.signature = checksum;

    const params = { body, head };

    // initiateTransaction endpoint
    // https://securegw-stage.paytm.in/theia/api/v1/initiateTransaction?mid=...&orderId=...
    const url = `${paytmBaseUrl()}/theia/api/v1/initiateTransaction?mid=${PAYTM_MID}&orderId=${orderId}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    const data = await response.json();

    // data.body.txnToken will be used by frontend checkoutjs
    if (!data) return res.status(500).json({ ok: false, message: 'Paytm error' });
    // Save meta
    await pool.query('UPDATE payments SET meta = $1 WHERE order_id = $2', [data, orderId]);

    // Respond to frontend
    res.json({
      ok: true,
      orderId,
      txnToken: data?.body?.txnToken || null,
      mid: PAYTM_MID,
      amount,
      checkoutUrl: `${paytmBaseUrl()}/theia/api/v1/showPaymentPage?mid=${PAYTM_MID}&orderId=${orderId}`, // fallback
      paytm_response: data
    });
  } catch (err) {
    console.error('create-order error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// ----- Paytm callback (server-to-server verification) -----
// Paytm will call callbackUrl or redirect to it. But often it's better to verify transaction status server-side.
app.post('/paytm-callback', async (req, res) => {
  // Paytm may POST form parameters or JSON depending on config.
  // We'll try to read body.orderId or body.ORDERID.
  try {
    const payload = req.body || {};
    const orderId = payload.orderId || payload.ORDERID || (payload.body && payload.body.orderId);
    console.log('paytm-callback payload', payload);

    if (!orderId) {
      // send 200 to Paytm to avoid retries
      return res.status(200).send('OK');
    }

    // Query transaction status from Paytm Transaction Status API
    const paytmParams = {};
    paytmParams.body = {
      mid: PAYTM_MID,
      orderId: orderId
    };
    const checksum = await PaytmChecksum.generateSignature(JSON.stringify(paytmParams.body), PAYTM_KEY);
    paytmParams.head = { signature: checksum };

    const statusUrl = `${paytmBaseUrl()}/v3/order/status`; // in some docs /v3/order/status, else use /order/status endpoint
    // We'll try the v3 endpoint first
    let statusResp = null;
    try {
      const raw = await fetch(statusUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(paytmParams)
      });
      statusResp = await raw.json();
    } catch (err) {
      console.warn('v3 status failed, fallback to older endpoint', err);
      // fallback to /order/status
      const fallback = `${paytmBaseUrl()}/theia/api/v1/order/status`;
      const raw2 = await fetch(fallback, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(paytmParams)
      });
      statusResp = await raw2.json();
    }

    // statusResp structure depends on endpoint. Try to extract txnId and status
    const txn = (statusResp && (statusResp.body || statusResp)) || {};
    const txnStatus = txn.resultInfo ? txn.resultInfo.resultStatus : (txn.STATUS || txn.status || null);
    const txnId = txn.txnId || txn.TXNID || (txn.body && txn.body.txnId) || null;

    const statusNormalized = (txnStatus && String(txnStatus).toLowerCase().includes('success')) ? 'SUCCESS' : 'FAILED';

    // Update DB payment entry
    await pool.query('UPDATE payments SET status=$1, txn_id=$2, meta=$3 WHERE order_id=$4', [statusNormalized, txnId, statusResp, orderId]);

    // If success, mark user as paid
    if (statusNormalized === 'SUCCESS') {
      // find user_id
      const r = await pool.query('SELECT user_id FROM payments WHERE order_id = $1', [orderId]);
      if (r.rows.length) {
        const userId = r.rows[0].user_id;
        await pool.query('UPDATE users SET has_paid = true WHERE id = $1', [userId]);
      }
    }

    res.status(200).json({ ok: true, status: statusNormalized });
  } catch (err) {
    console.error('error in paytm-callback', err);
    res.status(500).send('OK');
  }
});

// POST /verify-order
// { orderId } -> server checks Paytm status and returns final result
app.post('/verify-order', authMiddleware, async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ ok: false, message: 'orderId required' });

    const paytmParams = { body: { mid: PAYTM_MID, orderId } };
    const checksum = await PaytmChecksum.generateSignature(JSON.stringify(paytmParams.body), PAYTM_KEY);
    paytmParams.head = { signature: checksum };

    const statusUrl = `${paytmBaseUrl()}/v3/order/status`;
    let statusResp;
    try {
      const resp = await fetch(statusUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(paytmParams)
      });
      statusResp = await resp.json();
    } catch (err) {
      const fallback = `${paytmBaseUrl()}/theia/api/v1/order/status`;
      const resp = await fetch(fallback, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(paytmParams)
      });
      statusResp = await resp.json();
    }

    // extract result and update DB similarly to callback
    const txn = (statusResp && (statusResp.body || statusResp)) || {};
    const txnStatus = txn.resultInfo ? txn.resultInfo.resultStatus : (txn.STATUS || txn.status || null);
    const txnId = txn.txnId || txn.TXNID || (txn.body && txn.body.txnId) || null;
    const statusNormalized = (txnStatus && String(txnStatus).toLowerCase().includes('success')) ? 'SUCCESS' : 'FAILED';

    await pool.query('UPDATE payments SET status=$1, txn_id=$2, meta=$3 WHERE order_id=$4', [statusNormalized, txnId, statusResp, orderId]);

    if (statusNormalized === 'SUCCESS') {
      const r = await pool.query('SELECT user_id FROM payments WHERE order_id = $1', [orderId]);
      if (r.rows.length) {
        const userId = r.rows[0].user_id;
        await pool.query('UPDATE users SET has_paid = true WHERE id = $1', [userId]);
      }
    }

    res.json({ ok: true, status: statusNormalized, raw: statusResp });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

// ----- Utility endpoints for dev testing -----
app.get('/health', (req, res) => res.json({ ok: true, now: Date.now() }));

// ----- Static hosting or CORS -----
// If your frontend is hosted on GitHub Pages, you might set CORS. For simplicity allow CORS origins via env or wildcard.
const cors = require('cors');
app.use(cors({
  origin: true,
  credentials: true
}));

// Start server
const port = PORT || 3000;
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
