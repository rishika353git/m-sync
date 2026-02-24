/**
 * Admin dashboard: users list, plans, credits, synced emails, stats, system, API keys.
 */

const crypto = require('crypto');
const express = require('express');
const db = require('../config/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.use(requireAuth);
router.use(requireAdmin);

// GET /api/admin/stats – dashboard stats for admin
router.get('/stats', async (req, res) => {
  try {
    const usersRows = await db.query('SELECT COUNT(*) AS total FROM users');
    const emailsRows = await db.query('SELECT COUNT(*) AS total FROM synced_emails');
    const ghlRows = await db.query('SELECT COUNT(*) AS total FROM ghl_connections');
    const plansRows = await db.query('SELECT COUNT(*) AS total FROM plans');
    res.json({
      total_users: usersRows[0]?.total ?? 0,
      total_synced_emails: emailsRows[0]?.total ?? 0,
      total_ghl_connections: ghlRows[0]?.total ?? 0,
      total_plans: plansRows[0]?.total ?? 0,
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/users – list users with plan, credits, and usage (synced count, last sync)
router.get('/users', async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.credits_remaining, u.credits_reset_at, u.created_at, p.name AS plan_name, p.slug AS plan_slug, p.id AS plan_id,
        (SELECT COUNT(*) FROM synced_emails s WHERE s.user_id = u.id) AS synced_count,
        (SELECT MAX(s.synced_at) FROM synced_emails s WHERE s.user_id = u.id) AS last_synced_at
       FROM users u
       LEFT JOIN plans p ON u.plan_id = p.id
       ORDER BY u.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/plans – list plans
router.get('/plans', async (req, res) => {
  try {
    const rows = await db.query('SELECT * FROM plans ORDER BY id');
    res.json(rows);
  } catch (err) {
    console.error('Admin plans error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/admin/users/:id – update user (plan, credits, role, full_name)
router.patch('/users/:id', async (req, res) => {
  const { plan_id, credits_remaining, role, full_name } = req.body;
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid user id' });
  try {
    const updates = [];
    const params = [];
    if (plan_id !== undefined) { updates.push('plan_id = ?'); params.push(plan_id); }
    if (credits_remaining !== undefined) { updates.push('credits_remaining = ?'); params.push(credits_remaining); }
    if (role !== undefined) { updates.push('role = ?'); params.push(role); }
    if (full_name !== undefined) { updates.push('full_name = ?'); params.push(full_name); }
    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    params.push(id);
    await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin update user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/admin/users/:id – delete user (and cascade: ghl_connections, synced_emails)
router.delete('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid user id' });
  if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  try {
    const result = await db.query('DELETE FROM users WHERE id = ?', [id]);
    if (result && result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/synced-emails – list all synced emails (all users)
router.get('/synced-emails', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const offset = parseInt(req.query.offset, 10) || 0;
    const rows = await db.query(
      `SELECT s.id, s.user_id, s.gmail_message_id, s.ghl_contact_id, s.subject, s.email_body, s.synced_at, u.email AS user_email
       FROM synced_emails s
       JOIN users u ON s.user_id = u.id
       ORDER BY s.synced_at DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    const countRows = await db.query('SELECT COUNT(*) AS total FROM synced_emails');
    res.json({ emails: rows, total: countRows[0]?.total ?? 0 });
  } catch (err) {
    console.error('Admin synced emails error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/sync-logs – paginated sync attempts (success + failure), filter by user_id / date / errors_only
router.get('/sync-logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const offset = parseInt(req.query.offset, 10) || 0;
    const userId = req.query.user_id ? parseInt(req.query.user_id, 10) : null;
    const dateFrom = req.query.date_from || null; // YYYY-MM-DD
    const dateTo = req.query.date_to || null;   // YYYY-MM-DD
    const errorsOnly = req.query.errors_only === '1' || req.query.errors_only === 'true';

    let where = [];
    let params = [];
    if (userId) { where.push('l.user_id = ?'); params.push(userId); }
    if (dateFrom) { where.push('DATE(l.synced_at) >= ?'); params.push(dateFrom); }
    if (dateTo) { where.push('DATE(l.synced_at) <= ?'); params.push(dateTo); }
    if (errorsOnly) { where.push('l.error_message IS NOT NULL AND l.error_message != \'\''); }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const rows = await db.query(
      `SELECT l.id, l.user_id, l.gmail_message_id, l.ghl_contact_id, l.subject, l.synced_at, l.error_message, u.email AS user_email
       FROM sync_logs l
       JOIN users u ON l.user_id = u.id
       ${whereClause}
       ORDER BY l.synced_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    const countRows = await db.query(
      `SELECT COUNT(*) AS total FROM sync_logs l ${whereClause}`,
      params
    );
    res.json({ logs: rows, total: countRows[0]?.total ?? 0 });
  } catch (err) {
    console.error('Admin sync-logs error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/feature-flags – list all flags (admin)
router.get('/feature-flags', async (req, res) => {
  try {
    const rows = await db.query('SELECT id, flag_key, enabled, description, updated_at FROM feature_flags ORDER BY flag_key');
    res.json(rows);
  } catch (err) {
    console.error('Admin feature-flags GET error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/admin/feature-flags – set a flag (admin)
router.patch('/feature-flags', async (req, res) => {
  const { flag_key, enabled } = req.body;
  if (!flag_key || typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'flag_key and enabled (boolean) required' });
  }
  try {
    const result = await db.query('UPDATE feature_flags SET enabled = ? WHERE flag_key = ?', [enabled ? 1 : 0, flag_key]);
    if (result && result.affectedRows === 0) return res.status(404).json({ error: 'Flag not found' });
    res.json({ ok: true, flag_key, enabled });
  } catch (err) {
    console.error('Admin feature-flags PATCH error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/admin/api-keys – list API keys (prefix, name, user; no actual key)
router.get('/api-keys', async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT k.id, k.user_id, k.name, k.key_prefix, k.created_at, u.email AS user_email
       FROM api_keys k
       JOIN users u ON k.user_id = u.id
       ORDER BY k.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Admin api-keys GET error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/admin/api-keys – create API key (name, user_id). Returns { key } once; store it.
router.post('/api-keys', async (req, res) => {
  const { name, user_id: userId } = req.body;
  if (!name || !userId) {
    return res.status(400).json({ error: 'name and user_id required' });
  }
  const uid = parseInt(userId, 10);
  if (!uid) return res.status(400).json({ error: 'Invalid user_id' });
  try {
    const rawKey = 'msk_' + crypto.randomBytes(24).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.slice(0, 12) + '…';
    await db.query(
      'INSERT INTO api_keys (user_id, name, key_prefix, key_hash) VALUES (?, ?, ?, ?)',
      [uid, String(name).slice(0, 100), keyPrefix, keyHash]
    );
    res.status(201).json({ key: rawKey, name, user_id: uid, message: 'Copy the key now; it will not be shown again.' });
  } catch (err) {
    console.error('Admin api-keys POST error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/admin/api-keys/:id – revoke API key
router.delete('/api-keys/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  try {
    const result = await db.query('DELETE FROM api_keys WHERE id = ?', [id]);
    if (result && result.affectedRows === 0) return res.status(404).json({ error: 'API key not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin api-keys DELETE error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
