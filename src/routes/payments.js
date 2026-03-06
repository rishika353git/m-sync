/**
 * Payments: Stripe Checkout session creation, activation (payment-link flow), and webhook.
 * - POST /api/payments/create-checkout-session (auth): create session, return url
 * - GET /api/payments/activate?session_id=xxx: after Payment Link checkout, create user if new, assign plan, return JWT
 * - POST /api/payments/webhook (raw body): handle checkout.session.completed
 */
const express = require('express');
const crypto = require('crypto');
const db = require('../config/db');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const licenseRoutes = require('./licenses');
const bcrypt = require('bcrypt');

const router = express.Router();
const stripeSecret = (process.env.STRIPE_SECRET_KEY || '').trim();
const stripeWebhookSecret = (process.env.STRIPE_WEBHOOK_SECRET || '').trim();
const Stripe = stripeSecret ? require('stripe')(stripeSecret) : null;

// POST /api/payments/create-checkout-session – create Stripe Checkout Session (metadata: user_id, plan_id, quantity)
router.post('/create-checkout-session', requireAuth, async (req, res) => {
  if (!Stripe) return res.status(503).json({ error: 'Stripe is not configured' });
  const { plan_id, quantity = 1 } = req.body;
  if (!plan_id) return res.status(400).json({ error: 'plan_id required' });
  const qty = Math.max(1, parseInt(quantity, 10) || 1);
  try {
    const planRows = await db.query(
      'SELECT id, name, slug, credits_per_month, price_cents FROM plans WHERE id = ?',
      [plan_id]
    );
    const p = planRows && planRows[0];
    if (!p) return res.status(404).json({ error: 'Plan not found' });
    if (!p.price_cents || p.price_cents < 1) return res.status(400).json({ error: 'Plan is not set up for payment' });
    const amount = p.price_cents * qty;
    const baseUrl = (process.env.FRONTEND_URL || process.env.CORS_ORIGIN || '').split(',')[0].trim() || 'http://localhost:5173';
    const session = await Stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: req.user.email,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: `${p.name} (${qty} license${qty > 1 ? 's' : ''})` },
          unit_amount: p.price_cents || 0,
          recurring: { interval: 'month' },
        },
        quantity: qty,
      }],
      success_url: `${baseUrl.replace(/\/$/, '')}/dashboard?payment=success`,
      cancel_url: `${baseUrl.replace(/\/$/, '')}/dashboard/checkout`,
      metadata: {
        user_id: String(req.user.id),
        plan_id: String(p.id),
        quantity: String(qty),
      },
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[payments] create-checkout-session error', err);
    res.status(500).json({ error: err.message || 'Failed to create checkout session' });
  }
});

/**
 * GET /api/payments/activate?session_id=xxx
 * Used after Stripe Payment Link or Checkout success. No auth required.
 * Retrieves session; creates user if new (by customer_email); assigns plan; returns JWT so frontend can log them in.
 */
router.get('/activate', async (req, res) => {
  if (!Stripe) return res.status(503).json({ error: 'Stripe is not configured' });
  const sessionId = (req.query.session_id || '').trim();
  if (!sessionId) return res.status(400).json({ error: 'session_id required' });
  try {
    const session = await Stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
    if (session.status !== 'complete' && session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not complete' });
    }
    const email = session.customer_email || session.customer_details?.email || session.customer_details?.email_address;
    if (!email) return res.status(400).json({ error: 'No customer email on session' });
    let planId = session.metadata?.plan_id ? String(session.metadata.plan_id).trim() : null;
    const quantity = Math.max(1, parseInt(session.metadata?.quantity, 10) || 1);
    if (!planId) {
      const freeRows = await db.query("SELECT id FROM plans WHERE slug = 'free' LIMIT 1");
      planId = freeRows && freeRows[0] ? freeRows[0].id : null;
    }
    const planRows = await db.query(
      'SELECT id, credits_per_month FROM plans WHERE id = ?',
      [planId]
    );
    const plan = planRows && planRows[0];
    if (!plan) return res.status(400).json({ error: 'Plan not found' });
    const amountCents = session.amount_total != null ? session.amount_total : null;

    let userId;
    const existingRows = await db.query('SELECT id, plan_id FROM users WHERE email = ?', [email]);
    const existing = existingRows && existingRows[0];
    if (existing) {
      userId = existing.id;
      await db.query(
        'UPDATE users SET plan_id = ?, credits_remaining = ?, license_count = ?, credits_reset_at = DATE_ADD(COALESCE(credits_reset_at, CURDATE()), INTERVAL 1 MONTH), stripe_customer_id = COALESCE(stripe_customer_id, ?), stripe_subscription_id = COALESCE(stripe_subscription_id, ?), subscription_status = ? WHERE id = ?',
        [
          plan.id,
          plan.credits_per_month,
          quantity,
          session.customer || null,
          session.subscription || null,
          session.subscription ? 'active' : null,
          userId,
        ]
      );
    } else {
      const tempPassword = crypto.randomBytes(24).toString('hex');
      const passwordHash = await bcrypt.hash(tempPassword, 10);
      await db.query(
        'INSERT INTO users (email, password_hash, full_name, plan_id, credits_remaining, license_count, credits_reset_at, stripe_customer_id, stripe_subscription_id, subscription_status) VALUES (?, ?, NULL, ?, ?, ?, DATE_ADD(CURDATE(), INTERVAL 1 MONTH), ?, ?, ?)',
        [
          email,
          passwordHash,
          plan.id,
          plan.credits_per_month,
          quantity,
          session.customer || null,
          session.subscription || null,
          session.subscription ? 'active' : null,
        ]
      );
      const newRows = await db.query('SELECT id, email, role FROM users WHERE email = ?', [email]);
      userId = newRows && newRows[0] ? newRows[0].id : null;
      if (!userId) return res.status(500).json({ error: 'User creation failed' });
    }
    await db.query(
      'INSERT INTO purchases (user_id, plan_id, quantity, amount_cents, stripe_session_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, plan.id, quantity, amountCents, session.id, 'completed']
    ).catch(() => {});

    // Generate license keys for this user (one per seat) and return them so the dashboard/landing can show them once.
    const licenses = await licenseRoutes.createLicensesForUser(userId, quantity, {
      stripeCustomerId: session.customer || null,
      stripeSubscriptionId: session.subscription || null,
    });

    const token = jwt.sign(
      { id: userId, email, role: 'user' },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
    console.log('[payments] activate: session', sessionId, 'email', email, 'userId', userId);
    res.json({ token, email, licenses });
  } catch (err) {
    console.error('[payments] activate error', err);
    res.status(500).json({ error: err.message || 'Activation failed' });
  }
});

/**
 * Webhook handler – must be invoked with raw body (mounted in server.js before express.json()).
 * Handle checkout.session.completed: set user plan, credits, license_count; insert purchase.
 */
async function handleWebhook(req, res) {
  if (!stripeWebhookSecret || !Stripe) {
    return res.status(503).json({ error: 'Webhook not configured' });
  }
  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).send('Missing stripe-signature');
  let event;
  try {
    event = Stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);
  } catch (err) {
    console.error('[payments] webhook signature verification failed', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.user_id;
    const planId = session.metadata?.plan_id;
    const quantity = Math.max(1, parseInt(session.metadata?.quantity, 10) || 1);
    if (!userId || !planId) {
      console.error('[payments] webhook missing metadata user_id or plan_id');
      return res.status(400).json({ error: 'Missing metadata' });
    }
    try {
      const planRows = await db.query(
        'SELECT id, credits_per_month FROM plans WHERE id = ?',
        [planId]
      );
      const plan = planRows && planRows[0];
      if (!plan) {
        console.error('[payments] plan not found', planId);
        return res.status(400).json({ error: 'Plan not found' });
      }
      const amountCents = session.amount_total != null ? session.amount_total : null; // Stripe sends amount in cents
      await db.query(
        'UPDATE users SET plan_id = ?, credits_remaining = ?, license_count = ?, credits_reset_at = DATE_ADD(COALESCE(credits_reset_at, CURDATE()), INTERVAL 1 MONTH), stripe_customer_id = COALESCE(stripe_customer_id, ?), stripe_subscription_id = COALESCE(stripe_subscription_id, ?), subscription_status = ? WHERE id = ?',
        [
          planId,
          plan.credits_per_month,
          quantity,
          session.customer || null,
          session.subscription || null,
          session.subscription ? 'active' : null,
          userId,
        ]
      );
      await db.query(
        'INSERT INTO purchases (user_id, plan_id, quantity, amount_cents, stripe_session_id, status) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, planId, quantity, amountCents, session.id || null, 'completed']
      );
      // Create license keys on webhook as well (safety in case /activate is not used)
      await licenseRoutes.createLicensesForUser(userId, quantity, {
        stripeCustomerId: session.customer || null,
        stripeSubscriptionId: session.subscription || null,
      });
      console.log('[payments] activated plan for user', userId, 'plan', planId, 'quantity', quantity);
      return res.json({ received: true });
    } catch (err) {
      console.error('[payments] webhook processing error', err);
      return res.status(500).json({ error: 'Webhook processing failed' });
    }
  }

  if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const customerId = subscription.customer;
    const status = subscription.status || (event.type === 'customer.subscription.deleted' ? 'canceled' : null);
    try {
      await db.query(
        'UPDATE users SET stripe_subscription_id = ?, subscription_status = ? WHERE stripe_customer_id = ?',
        [subscription.id, status, customerId]
      );
    } catch (err) {
      console.error('[payments] subscription event error', err);
    }
    return res.json({ received: true });
  }

  if (event.type === 'invoice.payment_succeeded') {
    // For now we just acknowledge; license/plan is handled on checkout.session.completed
    return res.json({ received: true });
  }

  return res.json({ received: true });
}

router.handleWebhook = handleWebhook;
module.exports = router;
