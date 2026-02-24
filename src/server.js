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

const app = express();

// Allow extension + dashboard origins (for CORS preflight and responses)
const allowedOrigins = new Set(config.corsOrigin || []);

function isOriginAllowed(origin) {
  if (!origin) return true;
  if (allowedOrigins.has(origin)) return true;
  if (origin.startsWith('chrome-extension://')) return true;
  if (origin === 'https://mail.google.com') return true;
  // Allow Vercel deployments (*.vercel.app) so preview and production URLs work without listing each
  if (origin.endsWith('.vercel.app') && origin.startsWith('https://')) return true;
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

const PORT = config.port;
const listenUrl = config.nodeEnv === 'production' && config.backendBaseUrl
  ? config.backendBaseUrl
  : `http://localhost:${PORT}`;

async function start() {
  try {
    await db.testConnection();
    console.log('[server] Database connection OK');
  } catch (err) {
    console.error('[server] Database connection failed:', err.code || '', err.message);
    if (process.env.DB_SSL === 'true') {
      console.error('[server] TiDB Cloud: ensure DB_SSL=true, DB_PORT=4000, correct DB_HOST/DB_USER/DB_PASSWORD/DB_NAME, and IP allowlist.');
    }
    throw err;
  }
  await Promise.all([ensureSyncLogsTable(), ensureFeatureFlagsTable(), ensureApiKeysTable()]);
  app.listen(PORT, () => {
    console.log(`M-Sync API running on ${listenUrl}`);
  });
}

start().catch((err) => {
  console.error('Startup failed:', err);
  process.exit(1);
});
