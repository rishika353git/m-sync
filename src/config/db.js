/**
 * MySQL/TiDB Cloud database connection using mysql2.
 * Connection pool with TLS support for TiDB Cloud public endpoint.
 *
 * Env: DB_HOST, DB_PORT (4000 for TiDB), DB_USER, DB_PASSWORD, DB_NAME,
 *      DB_SSL=true, optional DB_CA_PATH, optional DB_SSL_REJECT_UNAUTHORIZED=false (dev only).
 */

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Load env from multiple possible locations (backend/.env or root .env)
const backendEnv = path.resolve(__dirname, '../../.env');
const rootEnv = path.resolve(__dirname, '../../../.env');
if (fs.existsSync(backendEnv)) require('dotenv').config({ path: backendEnv });
else if (fs.existsSync(rootEnv)) require('dotenv').config({ path: rootEnv });
else require('dotenv').config();

const host = process.env.DB_HOST || 'localhost';
const dbPort = parseInt(process.env.DB_PORT, 10) || 3306;
const enableSsl = process.env.DB_SSL === 'true' || process.env.DB_SSL === '1';
const caPath = (process.env.DB_CA_PATH || '').trim();
const rejectUnauthorized = process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false';

// Build SSL config for TiDB Cloud (TLS 1.2+ required)
let ssl = null;
if (enableSsl) {
  ssl = {
    minVersion: 'TLSv1.2',
    rejectUnauthorized,
    // SNI: required by many cloud DBs (e.g. TiDB Cloud)
    servername: host,
  };
  if (caPath) {
    const resolved = path.isAbsolute(caPath) ? caPath : path.resolve(process.cwd(), caPath);
    if (fs.existsSync(resolved)) {
      try {
        ssl.ca = fs.readFileSync(resolved);
      } catch (e) {
        console.error('[db] Failed to read DB_CA_PATH:', resolved, e.message);
      }
    } else {
      console.warn('[db] DB_CA_PATH not found:', resolved);
    }
  }
  // TiDB Cloud Starter/Essential: no CA file needed; Node uses default CAs
}

const poolConfig = {
  host,
  port: dbPort,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'msync',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  supportBigNumbers: true,
  connectTimeout: 20000,
  ...(ssl && { ssl }),
};

const pool = mysql.createPool(poolConfig);

// Log pool errors (e.g. connection lost, auth failure)
pool.on('error', (err) => {
  console.error('[db] Pool error:', err.code || err.message, err.message);
});

/**
 * Test connectivity (call at startup to fail fast and log clear errors).
 * Returns { ok: true } or throws with a descriptive error.
 */
async function testConnection() {
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.ping();
    return { ok: true };
  } finally {
    if (conn) conn.release();
  }
}

/**
 * Run a query and return rows.
 * Usage: const rows = await query('SELECT * FROM users WHERE id = ?', [userId]);
 */
async function query(sql, params = []) {
  try {
    const [rows] = await pool.execute(sql, params);
    return rows;
  } catch (err) {
    console.error('[db] Query error:', err.code || '', err.message);
    throw err;
  }
}

/**
 * Get a single connection from pool (for transactions).
 * Remember to connection.release() when done.
 */
async function getConnection() {
  return pool.getConnection();
}

module.exports = { pool, query, getConnection, testConnection };
