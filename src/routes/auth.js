/**
 * Auth routes: register, login, JWT issue, and OAuth callback.
 * OAuth callback is under /api/auth/callback (no "ghl" in URL – GoHighLevel rejects redirect URIs containing "ghl").
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');
const { getLocationIdFromGhlToken } = require('../utils/ghl-token');
const { fetchLocationIdFromApi } = require('../utils/ghl-api');
const ghlTokenService = require('../services/ghl-token-service');

const router = express.Router();

// --- Google OAuth (Continue with Google) ---
// GET /api/auth/google – redirect to Google sign-in. Query: returnTo (URL to redirect with token after login).
router.get('/google', (req, res) => {
  const host = (req.get('host') || '').toLowerCase();
  const hasNgrokSkipHeader = !!(req.get('ngrok-skip-browser-warning') || req.get('Ngrok-Skip-Browser-Warning'));
  if (host.includes('ngrok') && !hasNgrokSkipHeader) {
    const protocol = host.includes('ngrok') ? 'https' : req.protocol;
    const fullUrl = `${protocol}://${req.get('host')}${req.originalUrl}`;
    return res.type('html').send(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Redirecting to Google…</title></head><body><p>Redirecting to sign in…</p><script>
fetch(${JSON.stringify(fullUrl)}, { headers: { "ngrok-skip-browser-warning": "1" }, redirect: "manual" })
  .then(function(r) { var loc = r.headers.get("Location"); if (loc) window.location = loc; else document.body.innerHTML = "<p>Failed. <a href='/'>Try again</a></p>"; })
  .catch(function() { document.body.innerHTML = "<p>Failed. <a href='/'>Try again</a></p>"; });
</script></body></html>`
    );
  }

  const { clientId, redirectUri } = config.google || {};
  if (!clientId || !redirectUri) {
    console.warn('[Google OAuth] GOOGLE_CLIENT_ID or BACKEND_BASE_URL not set');
    const frontend = config.frontendUrl || 'http://localhost:5173';
    return res.redirect(`${frontend}/login?error=${encodeURIComponent('Google sign-in not configured')}`);
  }
  const returnTo = (req.query.returnTo || '').trim() || `${config.frontendUrl}/dashboard`;
  const state = Buffer.from(returnTo, 'utf8').toString('base64url');
  const scope = encodeURIComponent('openid email profile');
  const url = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}&access_type=offline&prompt=consent`;
  res.redirect(url);
});

// GET /api/auth/google/callback – exchange code, get profile, find or create user, redirect with token.
router.get('/google/callback', async (req, res) => {
  const host = (req.get('host') || '').toLowerCase();
  const hasNgrokSkipHeader = !!(req.get('ngrok-skip-browser-warning') || req.get('Ngrok-Skip-Browser-Warning'));
  if (host.includes('ngrok') && !hasNgrokSkipHeader) {
    const sep = req.originalUrl.includes('?') ? '&' : '?';
    const protocol = host.includes('ngrok') ? 'https' : req.protocol;
    const fullUrl = `${protocol}://${req.get('host')}${req.originalUrl}${sep}_redirect_body=1`;
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    return res.type('html').send(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in…</title></head><body><p>Completing sign-in…</p><script>
var u = ${JSON.stringify(fullUrl)} + (${JSON.stringify(fullUrl)}.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
fetch(u, { headers: { "ngrok-skip-browser-warning": "1" }, cache: "no-store", mode: "cors" })
  .then(function(r) {
    var loc = r.headers.get("Location");
    if (loc && (r.status === 301 || r.status === 302 || r.status === 303)) { window.location = loc; return; }
    return r.text().then(function(t) {
      if (!r.ok) throw { status: r.status, body: t };
      try { var d = JSON.parse(t); if (d && d.redirect) { window.location = d.redirect; return; } } catch(e) {}
      throw { status: r.status, body: t };
    });
  })
  .catch(function(e) {
    var msg = "Sign-in failed.";
    if (e && (e.status || e.body)) msg += " Status: " + (e.status || "?") + ". " + (typeof e.body === "string" ? e.body.slice(0, 200) : "");
    else if (e && e.message) msg += " " + e.message;
    document.body.innerHTML = "<p>" + msg + "</p><p><a href='#' onclick='location.reload();return false'>Try again</a></p>";
  });
</script></body></html>`
    );
  }

  const { code, state, error: oauthError } = req.query;
  let returnTo = `${config.frontendUrl}/dashboard`;
  if (state) {
    try {
      returnTo = Buffer.from(state, 'base64url').toString('utf8');
    } catch (_) {}
  }
  const redirectUrl = (url) => {
    if (req.query._redirect_body && hasNgrokSkipHeader) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.json({ redirect: url });
    }
    return res.redirect(url);
  };
  const redirectError = (msg) => {
    console.error('[Google OAuth] redirectError:', msg);
    return redirectUrl(`${returnTo.split('?')[0]}?error=${encodeURIComponent(msg)}`);
  };

  if (oauthError) {
    return redirectError(oauthError === 'access_denied' ? 'Sign-in cancelled' : oauthError);
  }
  if (!code) {
    return redirectError('Missing authorization code');
  }

  const { clientId, clientSecret, redirectUri } = config.google || {};
  if (!clientId || !clientSecret || !redirectUri) {
    return redirectError('Google sign-in not configured');
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }).toString(),
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) {
      console.error('[Google OAuth] token exchange error', tokenData);
      return redirectError(tokenData.error_description || tokenData.error || 'Token exchange failed');
    }
    const accessToken = tokenData.access_token;

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!profileRes.ok) {
      return redirectError('Failed to load profile');
    }
    const profile = await profileRes.json();
    const googleId = profile.id;
    const email = (profile.email || '').trim().toLowerCase();
    const fullName = (profile.name || '').trim() || null;

    if (!email) {
      return redirectError('Google account has no email');
    }

    const [existingByGoogle] = await db.query('SELECT id, email, full_name, role, credits_remaining FROM users WHERE google_id = ?', [googleId]);
    if (existingByGoogle) {
      const user = existingByGoogle;
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      const sep = returnTo.includes('?') ? '&' : '?';
      return redirectUrl(`${returnTo}${sep}token=${encodeURIComponent(token)}`);
    }

    const [existingByEmail] = await db.query('SELECT id, email, full_name, role, credits_remaining FROM users WHERE email = ?', [email]);
    if (existingByEmail.length) {
      await db.query('UPDATE users SET google_id = ? WHERE id = ?', [googleId, existingByEmail[0].id]);
      const user = existingByEmail[0];
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      const sep = returnTo.includes('?') ? '&' : '?';
      return redirectUrl(`${returnTo}${sep}token=${encodeURIComponent(token)}`);
    }

    const [plan] = await db.query("SELECT id FROM plans WHERE slug = 'free' LIMIT 1");
    const planId = plan ? plan.id : 1;
    await db.query(
      'INSERT INTO users (email, password_hash, full_name, plan_id, credits_remaining, google_id) VALUES (?, NULL, ?, ?, 5, ?)',
      [email, fullName, planId, googleId]
    );
    const [newUser] = await db.query(
      'SELECT id, email, full_name, role, credits_remaining FROM users WHERE google_id = ?',
      [googleId]
    );
    const user = newUser;
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
    const sep = returnTo.includes('?') ? '&' : '?';
    return redirectUrl(`${returnTo}${sep}token=${encodeURIComponent(token)}`);
  } catch (err) {
    console.error('[Google OAuth] callback error', err);
    let msg = err.message || 'Sign-in failed';
    if (err.message && (err.message.includes('google_id') || err.message.includes('password_hash'))) {
      msg = 'Database setup required. Run: backend/database/alter-users-google-oauth.sql';
    }
    return redirectError(msg);
  }
});

// GET /api/auth/callback – OAuth redirect from CRM (GoHighLevel). No "ghl" in path so GHL accepts the redirect URI.
router.get('/callback', async (req, res) => {
  const host = (req.get('host') || '').toLowerCase();
  const hasNgrokSkipHeader = !!(req.get('ngrok-skip-browser-warning') || req.get('Ngrok-Skip-Browser-Warning'));
  if (host.includes('ngrok') && !hasNgrokSkipHeader) {
    const sep = req.originalUrl.includes('?') ? '&' : '?';
    const protocol = host.includes('ngrok') ? 'https' : req.protocol;
    const fullUrl = `${protocol}://${req.get('host')}${req.originalUrl}${sep}_redirect_body=1`;
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    return res.type('html').send(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Connecting…</title></head><body><p>Completing GHL connection…</p><script>
var u = ${JSON.stringify(fullUrl)} + (${JSON.stringify(fullUrl)}.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
fetch(u, { headers: { "ngrok-skip-browser-warning": "1" }, cache: "no-store", mode: "cors" })
  .then(function(r) {
    var loc = r.headers.get("Location");
    if (loc && (r.status === 301 || r.status === 302 || r.status === 303)) { window.location = loc; return; }
    return r.text().then(function(t) {
      if (!r.ok) throw { status: r.status, body: t };
      try { var d = JSON.parse(t); if (d && d.redirect) { window.location = d.redirect; return; } } catch(e) {}
      throw { status: r.status, body: t };
    });
  })
  .catch(function(e) {
    var msg = "Connection failed.";
    if (e && (e.status || e.body)) msg += " Status: " + (e.status || "?") + ". " + (typeof e.body === "string" ? e.body.slice(0, 200) : "");
    else if (e && e.message) msg += " " + e.message;
    document.body.innerHTML = "<p>" + msg + "</p><p><a href='#' onclick='location.reload();return false'>Try again</a></p>";
  });
</script></body></html>`
    );
  }

  const hasNgrokSkipHeaderGhl = !!(req.get('ngrok-skip-browser-warning') || req.get('Ngrok-Skip-Browser-Warning'));
  const sendRedirect = (url) => {
    if (req.query._redirect_body && hasNgrokSkipHeaderGhl) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.json({ redirect: url });
    }
    return res.redirect(url);
  };

  const { code, state, locationId: queryLocationId, location_id: queryLocationIdSnake } = req.query;
  const queryKeys = Object.keys(req.query).filter((k) => k !== 'code');

  // --- DEBUG: Step 4 – Callback hit (GHL redirected user here) ---
  console.log('[GHL callback] Step 4: Callback hit', { hasCode: !!code, state, queryKeys });
  if (queryLocationId || queryLocationIdSnake) {
    console.log('[GHL callback] locationId in redirect URL:', queryLocationId || queryLocationIdSnake);
  }

  if (!code || !state) {
    console.log('[GHL callback] Step 4 FAIL: Missing code or state – redirecting to dashboard?ghl=error');
    return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('Missing code or state')}`);
  }
  const userId = parseInt(state, 10);
  if (Number.isNaN(userId)) {
    console.error('[GHL callback] Step 4 FAIL: state is not a number:', state);
    return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('Invalid state')}`);
  }

  try {
    const redirectUri = config.ghl?.redirectUri || '';
    if (!redirectUri) {
      console.error('[GHL callback] Step 5 FAIL: GHL_REDIRECT_URI is not set');
      return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('GHL_REDIRECT_URI not set')}`);
    }
    const exchangeClientId = (config.ghl.clientId || '').split('-')[0] || '';
    console.log('[GHL callback] Step 5: Exchanging code for token', { clientIdPrefix: exchangeClientId, redirectUri });

    const formBody = new URLSearchParams({
      client_id: config.ghl.clientId,
      client_secret: config.ghl.clientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      user_type: 'Location',
    }).toString();
    const tokenRes = await fetch('https://services.leadconnectorhq.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        Version: '2021-07-28',
      },
      body: formBody,
    });
    const data = await tokenRes.json();

    // --- DEBUG: Step 6 – Token response ---
    const refreshTokenLen = data.refresh_token ? String(data.refresh_token).length : 0;
    console.log('[GHL callback] Step 6: Token response', {
      status: tokenRes.status,
      hasAccessToken: !!data.access_token,
      hasRefreshToken: !!data.refresh_token,
      refresh_token_length: refreshTokenLen,
      keys: Object.keys(data),
    });
    if (refreshTokenLen > 512) {
      console.warn('[GHL callback] refresh_token length', refreshTokenLen, '> 512 – if your DB column is VARCHAR(512), run backend/database/alter-ghl-refresh-token-length.sql to fix truncation.');
    }
    if (!data.refresh_token) {
      console.warn('[GHL callback] no refresh_token in response – GHL may require "offline access" or "Auto refresh token" in Marketplace → your app → Auth.');
      return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('GHL did not return a refresh token. In GHL Marketplace → your app → Auth, enable "Auto refresh token" or offline access, then try Connect again.')}`);
    }
    if (!data.access_token) {
      const rawMsg = data.message || data.error || JSON.stringify(data);
      const errMsg = Array.isArray(rawMsg) ? rawMsg.join(' ') : String(rawMsg);
      console.error('[GHL callback] Step 6 FAIL: No access_token. Full response:', JSON.stringify(data));
      return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent(errMsg)}`);
    }
    // GHL returns locationId for Location installs, companyId for Agency; some responses use snake_case.
    // Callback URL can also include locationId (or location_id) as a query param for location installs.
    let locationId = data.locationId ?? data.location_id ?? data.companyId ?? queryLocationId ?? queryLocationIdSnake ?? null;
    if (!locationId) {
      locationId = getLocationIdFromGhlToken(data.access_token);
      if (locationId) console.log('[GHL callback] got locationId from JWT payload');
    }
    if (!locationId) {
      try {
        const decoded = jwt.decode(data.access_token);
        if (decoded && typeof decoded === 'object') {
          console.log('[GHL callback] JWT payload keys (no locationId in response):', Object.keys(decoded));
        }
      } catch (_) {}
      locationId = await fetchLocationIdFromApi(data.access_token);
      if (locationId) console.log('[GHL callback] got locationId from locations/search API');
    }
    if (!locationId) {
      console.warn('[GHL callback] could not get locationId from token response, JWT, or API. Reconnect may show "Not connected" until location is resolved.');
    }

    console.log('[GHL callback] Step 7: Saving tokens for userId', userId);
    await ghlTokenService.saveTokens(userId, {
      access_token: data.access_token,
      refresh_token: data.refresh_token || null,
      expires_in: data.expires_in ?? 24 * 60 * 60,
      locationId: locationId || null,
    });
    console.log('[GHL callback] Step 8: Tokens saved. Redirecting to dashboard?ghl=connected');
    return sendRedirect(`${config.frontendUrl}/dashboard?ghl=connected`);
  } catch (err) {
    console.error('[GHL callback] Step FAIL (exception):', err?.message || err);
    return sendRedirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent(err?.message || 'Callback error')}`);
  }
});

// POST /api/auth/register – create account (dashboard signup)
router.post('/register', async (req, res) => {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed. Use POST to /api/auth/register' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { email, password, full_name } = body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const existing = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [plan] = await db.query("SELECT id FROM plans WHERE slug = 'free' LIMIT 1");
    const planId = plan ? plan.id : 1;
    await db.query(
      'INSERT INTO users (email, password_hash, full_name, plan_id, credits_remaining) VALUES (?, ?, ?, ?, 5)',
      [email, password_hash, full_name || null, planId]
    );
    const [user] = await db.query(
      'SELECT id, email, full_name, role, credits_remaining FROM users WHERE email = ?',
      [email]
    );
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
    res.status(201).json({ user: user, token });
  } catch (err) {
    console.error('Register error:', err);
    const msg = err.message || '';
    if (msg.includes('plan') || msg.includes('foreign key') || msg.includes('ER_NO_REFERENCED_ROW')) {
      return res.status(500).json({ error: 'Database not seeded. In backend run: npm run db:seed' });
    }
    res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Registration failed' : msg || 'Registration failed' });
  }
});

// POST /api/auth/login – email + password, returns JWT
router.post('/login', async (req, res) => {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed. Use POST to /api/auth/login' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { email, password } = body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const [user] = await db.query(
      'SELECT id, email, password_hash, full_name, role, credits_remaining FROM users WHERE email = ?',
      [email]
    );
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (!user.password_hash) {
      return res.status(401).json({ error: 'This account uses Google sign-in. Use "Login with Google" instead.' });
    }
    if (!(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
    delete user.password_hash;
    res.json({ user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, credits_remaining: user.credits_remaining }, token });
  } catch (err) {
    console.error('Login error:', err);
    const msg = process.env.NODE_ENV === 'production' ? 'Login failed' : (err.message || 'Login failed');
    res.status(500).json({ error: msg });
  }
});

// GET /api/auth/me – current user (requires JWT)
router.get('/me', requireAuth, async (req, res) => {
  try {
    const [user] = await db.query(
      'SELECT id, email, full_name, role, plan_id, credits_remaining, credits_reset_at FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
