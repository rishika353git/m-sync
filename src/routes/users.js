/**
 * User profile and credits (for extension + dashboard).
 */

const express = require('express');
const db = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// All routes require login
router.use(requireAuth);

// GET /api/users/profile – profile + plan + credits
router.get('/profile', async (req, res) => {
  try {
    const [row] = await db.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.credits_remaining, u.credits_reset_at, p.name AS plan_name, p.slug AS plan_slug, p.credits_per_month
       FROM users u
       LEFT JOIN plans p ON u.plan_id = p.id
       WHERE u.id = ?`,
      [req.user.id]
    );
    if (!row) return res.status(404).json({ error: 'User not found' });
    res.json(row);
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/credits – just credits (for extension quick check)
router.get('/credits', async (req, res) => {
  try {
    const [row] = await db.query('SELECT credits_remaining FROM users WHERE id = ?', [req.user.id]);
    if (!row) return res.status(404).json({ error: 'User not found' });
    res.json({ credits_remaining: row.credits_remaining });
  } catch (err) {
    console.error('Credits error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/feature-flags – flags for extension (e.g. auto_save_on_send)
router.get('/feature-flags', async (req, res) => {
  try {
    const rows = await db.query('SELECT flag_key, enabled FROM feature_flags');
    const flags = {};
    (rows || []).forEach((r) => { flags[r.flag_key] = !!r.enabled; });
    res.json({ flags });
  } catch (err) {
    console.error('Feature-flags error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/synced-emails – list emails synced to CRM by this user only (never other users')
router.get('/synced-emails', async (req, res) => {
  try {
    const userId = parseInt(req.user.id, 10);
    if (!userId || Number.isNaN(userId)) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const rows = await db.query(
      `SELECT id, gmail_message_id, ghl_contact_id, subject, email_body, synced_at
       FROM synced_emails WHERE user_id = ? ORDER BY synced_at DESC LIMIT ? OFFSET ?`,
      [userId, limit, offset]
    );
    const countResult = await db.query('SELECT COUNT(*) AS total FROM synced_emails WHERE user_id = ?', [userId]);
    const total = countResult[0]?.total ?? 0;
    res.json({ emails: rows, total });
  } catch (err) {
    console.error('Synced emails error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
