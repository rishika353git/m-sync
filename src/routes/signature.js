/**
 * Email signature parsing.
 * Extension sends raw signature text; we parse and return structured fields.
 * Results can be cached in parsed_signatures table.
 */

const express = require('express');
const db = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Simple regex-based signature parser (beginner-friendly).
// In production you might use a proper library or ML.
function parseSignature(text) {
  if (!text || typeof text !== 'string') return {};
  const t = text.trim();
  const result = { full_name: null, company: null, phone: null, email: null, raw_text: t };

  // Phone: common patterns; if multiple numbers (e.g. "|" or ","), take first only
  const phoneMatch = t.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d+)?/g);
  if (phoneMatch && phoneMatch.length > 0) {
    const first = phoneMatch[0].trim();
    result.phone = first;
  }

  // Email in signature
  const emailMatch = t.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  if (emailMatch) result.email = emailMatch[0];

  // Company: often after "|" or "at" or on its own line (simplified: take first line that looks like company)
  const lines = t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length >= 2) {
    const secondLine = lines[1];
    if (secondLine && !secondLine.includes('@') && secondLine.length < 80) result.company = secondLine;
  }
  if (lines.length >= 1 && lines[0].length < 60 && !lines[0].includes('@')) result.full_name = lines[0];

  return result;
}

// POST /api/signature/parse – parse signature, optionally save for user
router.post('/parse', requireAuth, async (req, res) => {
  try {
    const { raw_text, email_message_id, save } = req.body;
    const parsed = parseSignature(raw_text);
    if (save && email_message_id) {
      await db.query(
        `INSERT INTO parsed_signatures (user_id, email_message_id, full_name, company, phone, raw_text)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE full_name = VALUES(full_name), company = VALUES(company), phone = VALUES(phone), raw_text = VALUES(raw_text)`,
        [req.user.id, email_message_id, parsed.full_name, parsed.company, parsed.phone, parsed.raw_text || raw_text]
      );
    }
    res.json(parsed);
  } catch (err) {
    console.error('Parse signature error:', err);
    res.status(500).json({ error: 'Parse failed' });
  }
});

module.exports = router;
