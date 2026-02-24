/**
 * Plans API for logged-in users (upgrade page).
 */
const express = require('express');
const db = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  try {
    const rows = await db.query(
      'SELECT id, name, slug, credits_per_month, is_paid, price_cents FROM plans ORDER BY credits_per_month ASC'
    );
    res.json(rows);
  } catch (err) {
    console.error('[Plans] error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
