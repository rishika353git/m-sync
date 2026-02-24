/**
 * Seed default plans: Free (5 credits/month) and Paid.
 * Run after db:init: npm run db:seed
 */

const db = require('../src/config/db');

async function seed() {
  await db.query(
    `INSERT INTO plans (name, slug, credits_per_month, is_paid, price_cents) VALUES
     ('Free', 'free', 5, 0, NULL),
     ('Pro', 'pro', 500, 1, 2900)
     ON DUPLICATE KEY UPDATE name = VALUES(name), credits_per_month = VALUES(credits_per_month), is_paid = VALUES(is_paid), price_cents = VALUES(price_cents)`
  );
  console.log('Plans seeded.');
}

seed()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
