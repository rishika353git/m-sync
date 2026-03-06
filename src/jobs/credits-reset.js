/**
 * Monthly credits reset job.
 * Run daily via node-cron; for each user where current date >= credits_reset_at (or null),
 * set credits_remaining = plan.credits_per_month and credits_reset_at = next month.
 */
const cron = require('node-cron');
const db = require('../config/db');

function getNextResetDate(currentResetDateOrNull) {
  const base = currentResetDateOrNull ? new Date(currentResetDateOrNull) : new Date();
  base.setMonth(base.getMonth() + 1);
  return base.toISOString().slice(0, 10); // YYYY-MM-DD
}

async function runCreditsReset() {
  try {
    const rows = await db.query(
      `SELECT u.id AS user_id, u.credits_reset_at, p.id AS plan_id, p.credits_per_month
       FROM users u
       INNER JOIN plans p ON u.plan_id = p.id
       WHERE u.credits_reset_at IS NULL OR CURDATE() >= u.credits_reset_at`
    );
    if (!rows || rows.length === 0) return;
    for (const row of rows) {
      const nextReset = getNextResetDate(row.credits_reset_at);
      await db.query(
        'UPDATE users SET credits_remaining = ?, credits_reset_at = ? WHERE id = ?',
        [row.credits_per_month, nextReset, row.user_id]
      );
    }
    console.log('[credits-reset] reset', rows.length, 'user(s)');
  } catch (err) {
    console.error('[credits-reset] error', err.message);
  }
}

function scheduleCreditsReset() {
  cron.schedule('5 0 * * *', runCreditsReset, { timezone: 'UTC' }); // 00:05 UTC daily
  console.log('[credits-reset] scheduled daily at 00:05 UTC');
}

module.exports = { runCreditsReset, scheduleCreditsReset };
