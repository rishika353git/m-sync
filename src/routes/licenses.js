/**
 * Licenses: per-user license keys used by the extension.
 * - GET /api/licenses/me (auth): list current user's licenses (masked).
 * - POST /api/licenses/verify (no auth): verify { email, license_key } and return user id for extension login.
 *
 * NOTE: full license keys are only returned at creation time (from Stripe flows),
 * not from this router. Keys are stored as SHA-256 hashes + short prefix.
 */

const express = require('express');
const crypto = require('crypto');
const db = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function normalizeLicenseKey(raw) {
  return String(raw || '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}

function formatLicenseKey(rawHex) {
  const upper = normalizeLicenseKey(rawHex);
  // Group as XXXX-XXXX-XXXX-XXXX (up to 16 chars)
  const groups = [];
  for (let i = 0; i < upper.length && groups.length < 4; i += 4) {
    groups.push(upper.slice(i, i + 4));
  }
  return groups.join('-');
}

function generateLicenseKey() {
  const bytes = crypto.randomBytes(16).toString('hex').toUpperCase(); // 32 hex chars
  const formatted = formatLicenseKey(bytes);
  const compact = normalizeLicenseKey(formatted);
  const prefix = compact.slice(0, 8);
  const hash = crypto.createHash('sha256').update(compact).digest('hex');
  return { key: formatted, prefix, hash };
}

async function createLicensesForUser(userId, quantity, { stripeCustomerId = null, stripeSubscriptionId = null } = {}) {
  const count = Math.max(1, parseInt(quantity, 10) || 1);
  const created = [];
  for (let i = 0; i < count; i += 1) {
    const { key, prefix, hash } = generateLicenseKey();
    // Ignore duplicate hash errors (extremely unlikely)
    // eslint-disable-next-line no-await-in-loop
    await db
      .query(
        'INSERT INTO licenses (user_id, key_prefix, key_hash, status, stripe_customer_id, stripe_subscription_id) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, prefix, hash, 'active', stripeCustomerId, stripeSubscriptionId]
      )
      .catch(() => {});
    created.push(key);
  }
  return created;
}

async function verifyLicenseInternal(email, licenseKey) {
  const normalizedKey = normalizeLicenseKey(licenseKey);
  if (!normalizedKey || normalizedKey.length < 8) return null;
  const prefix = normalizedKey.slice(0, 8);
  const hash = crypto.createHash('sha256').update(normalizedKey).digest('hex');

  const [user] = await db.query('SELECT id, email, full_name, role FROM users WHERE email = ?', [String(email || '').trim().toLowerCase()]);
  if (!user) return null;
  const rows = await db.query(
    'SELECT id, status FROM licenses WHERE user_id = ? AND key_prefix = ? AND key_hash = ? LIMIT 1',
    [user.id, prefix, hash]
  );
  const lic = rows && rows[0];
  if (!lic) return null;
  if (lic.status !== 'active') return null;
  return user;
}

// GET /api/licenses/me – list current user's licenses (masked)
router.get('/me', requireAuth, async (req, res) => {
  try {
    const rows = await db.query(
      'SELECT id, key_prefix, status, stripe_customer_id, stripe_subscription_id, created_at, expires_at FROM licenses WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    const items = (rows || []).map((r) => ({
      id: r.id,
      masked_key: `${r.key_prefix}-XXXX-XXXX`,
      status: r.status,
      created_at: r.created_at,
      expires_at: r.expires_at,
      stripe_customer_id: r.stripe_customer_id,
      stripe_subscription_id: r.stripe_subscription_id,
    }));
    res.json({ licenses: items });
  } catch (err) {
    console.error('[licenses] /me error', err);
    res.status(500).json({ error: 'Failed to load licenses' });
  }
});

// POST /api/licenses/verify – { email, license_key } → { ok, user }
router.post('/verify', async (req, res) => {
  try {
    const email = req.body?.email;
    const licenseKey = req.body?.license_key || req.body?.licenseKey;
    if (!email || !licenseKey) return res.status(400).json({ error: 'email and license_key are required' });
    const user = await verifyLicenseInternal(email, licenseKey);
    if (!user) return res.status(401).json({ error: 'Invalid or inactive license' });
    res.json({ ok: true, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role } });
  } catch (err) {
    console.error('[licenses] /verify error', err);
    res.status(500).json({ error: 'License verification failed' });
  }
});

// Export router and helpers for Stripe / auth flows
router.createLicensesForUser = createLicensesForUser;
router.verifyLicenseInternal = verifyLicenseInternal;

module.exports = router;

