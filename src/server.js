/**
 * M-Sync API server.
 * Entry point: starts Express, mounts routes, enables CORS.
 */

const express = require('express');
const cors = require('cors');
const config = require('./config');
const db = require('./config/db');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const ghlRoutes = require('./routes/ghl');
const signatureRoutes = require('./routes/signature');
const adminRoutes = require('./routes/admin');
const plansRoutes = require('./routes/plans');
const paymentRoutes = require('./routes/payments');
const licenseRoutes = require('./routes/licenses');
const { scheduleCreditsReset } = require('./jobs/credits-reset');

const app = express();

// Stripe webhook needs raw body for signature verification (mount before express.json())
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  paymentRoutes.handleWebhook(req, res);
});

// Allow extension + dashboard origins (for CORS preflight and responses)
const allowedOrigins = new Set(config.corsOrigin || []);

function isOriginAllowed(origin) {
  if (!origin) return true;
  if (allowedOrigins.has(origin)) return true;
  if (origin.startsWith('chrome-extension://')) return true;
  if (origin === 'https://mail.google.com') return true;
  // In development, allow any localhost port (Vite may use 5173, 5174, 5175, etc.)
  if (process.env.NODE_ENV !== 'production' && /^https?:\/\/localhost(:\d+)?$/.test(origin)) return true;
  return false;
}

// Handle preflight (OPTIONS) first so extension always gets CORS headers
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, ngrok-skip-browser-warning');
    res.setHeader('Access-Control-Expose-Headers', 'Location');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.sendStatus(204);
});

// Parse JSON body (for login, register, sync, etc.)
app.use(express.json());

// CORS for actual requests
app.use(cors({
  origin(origin, cb) {
    if (isOriginAllowed(origin)) return cb(null, origin || true);
    cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'ngrok-skip-browser-warning'],
  exposedHeaders: ['Location'],
}));

// Health check (no auth)
app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'm-sync-api' });
});

// Root: avoid 404 when someone opens the ngrok/base URL in a browser (e.g. during GHL setup)
app.get('/', (req, res) => {
  res.json({
    service: 'm-sync-api',
    message: 'API is running. Use /api/* endpoints. GHL OAuth callback: /api/auth/callback',
    health: '/health',
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/ghl', ghlRoutes);
app.use('/api/signature', signatureRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/plans', plansRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/licenses', licenseRoutes);

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

async function ensureSyncLogsTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS sync_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        gmail_message_id VARCHAR(255) DEFAULT NULL,
        ghl_contact_id VARCHAR(100) DEFAULT NULL,
        subject VARCHAR(500) DEFAULT NULL,
        synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        error_message TEXT DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await db.query('CREATE INDEX idx_sync_logs_user ON sync_logs(user_id)').catch(() => {});
    await db.query('CREATE INDEX idx_sync_logs_synced_at ON sync_logs(synced_at)').catch(() => {});
  } catch (err) {
    console.warn('[server] ensureSyncLogsTable:', err.message);
  }
}

async function ensureFeatureFlagsTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS feature_flags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        flag_key VARCHAR(100) NOT NULL UNIQUE,
        enabled TINYINT(1) NOT NULL DEFAULT 0,
        description VARCHAR(500) DEFAULT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    const rows = await db.query('SELECT id FROM feature_flags WHERE flag_key = ?', ['auto_save_on_send']);
    if (!rows || rows.length === 0) {
      await db.query(
        'INSERT INTO feature_flags (flag_key, enabled, description) VALUES (?, 0, ?)',
        ['auto_save_on_send', 'When on, extension can auto-sync email to CRM when user sends and Save to CRM is enabled']
      );
    }
  } catch (err) {
    console.warn('[server] ensureFeatureFlagsTable:', err.message);
  }
}

async function ensureApiKeysTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(100) NOT NULL,
        key_prefix VARCHAR(20) NOT NULL,
        key_hash VARCHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uq_key_hash (key_hash)
      )
    `);
    await db.query('CREATE INDEX idx_api_keys_user ON api_keys(user_id)').catch(() => {});
    await db.query('CREATE INDEX idx_api_keys_hash ON api_keys(key_hash)').catch(() => {});
  } catch (err) {
    console.warn('[server] ensureApiKeysTable:', err.message);
  }
}

async function ensurePurchasesTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS purchases (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        plan_id INT NOT NULL,
        quantity INT NOT NULL DEFAULT 1,
        amount_cents INT DEFAULT NULL,
        stripe_session_id VARCHAR(255) DEFAULT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (plan_id) REFERENCES plans(id)
      )
    `);
    await db.query('CREATE INDEX idx_purchases_user ON purchases(user_id)').catch(() => {});
    await db.query('CREATE INDEX idx_purchases_stripe ON purchases(stripe_session_id)').catch(() => {});
  } catch (err) {
    console.warn('[server] ensurePurchasesTable:', err.message);
  }
}

async function ensureLicenseCountColumn() {
  try {
    await db.query('ALTER TABLE users ADD COLUMN license_count INT NOT NULL DEFAULT 1 AFTER credits_reset_at');
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') console.warn('[server] ensureLicenseCountColumn:', err.message);
  }
}

async function ensureLicensesTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        key_prefix VARCHAR(16) NOT NULL,
        key_hash VARCHAR(64) NOT NULL,
        status ENUM('active','expired','cancelled') NOT NULL DEFAULT 'active',
        stripe_customer_id VARCHAR(255) DEFAULT NULL,
        stripe_subscription_id VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uq_licenses_hash (key_hash),
        KEY idx_licenses_user (user_id),
        KEY idx_licenses_customer (stripe_customer_id),
        KEY idx_licenses_subscription (stripe_subscription_id)
      )
    `);
  } catch (err) {
    console.warn('[server] ensureLicensesTable:', err.message);
  }
}

async function ensureStripeColumnsOnUsers() {
  try {
    await db.query('ALTER TABLE users ADD COLUMN stripe_customer_id VARCHAR(255) DEFAULT NULL');
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') console.warn('[server] ensureStripeColumnsOnUsers (customer_id):', err.message);
  }
  try {
    await db.query('ALTER TABLE users ADD COLUMN stripe_subscription_id VARCHAR(255) DEFAULT NULL');
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') console.warn('[server] ensureStripeColumnsOnUsers (subscription_id):', err.message);
  }
  try {
    await db.query('ALTER TABLE users ADD COLUMN subscription_status VARCHAR(50) DEFAULT NULL');
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') console.warn('[server] ensureStripeColumnsOnUsers (status):', err.message);
  }
}

/** Fix GHL token truncation: access/refresh tokens can exceed 512 chars. Alters columns to TEXT. */
async function ensureGhlTokenColumns() {
  try {
    await db.query('ALTER TABLE ghl_connections MODIFY COLUMN access_token TEXT NOT NULL');
    await db.query('ALTER TABLE ghl_connections MODIFY COLUMN refresh_token TEXT DEFAULT NULL');
    console.log('[server] GHL token columns ensured (TEXT)');
  } catch (err) {
    console.warn('[server] ensureGhlTokenColumns:', err.message);
  }
}

const PORT = config.port;
const listenUrl = config.nodeEnv === 'production' && config.backendBaseUrl
  ? config.backendBaseUrl
  : `http://localhost:${PORT}`;

Promise.all([
  ensureSyncLogsTable(),
  ensureFeatureFlagsTable(),
  ensureApiKeysTable(),
  ensurePurchasesTable(),
  ensureLicenseCountColumn(),
  ensureLicensesTable(),
  ensureStripeColumnsOnUsers(),
  ensureGhlTokenColumns(),
]).then(() => {
  app.listen(PORT, () => {
    console.log(`M-Sync API running on ${listenUrl}`);
    scheduleCreditsReset();
  });
}).catch((err) => {
  console.error('Startup failed:', err);
  process.exit(1);
});
