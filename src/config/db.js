/**
 * MySQL database connection using mysql2.
 * We use a connection pool so multiple requests can use DB without opening
 * a new connection every time.
 * Supports TiDB Cloud: set DB_SSL=true and DB_PORT=4000; optionally DB_CA_PATH for TLS CA.
 */

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
require('dotenv').config();

const dbPort = parseInt(process.env.DB_PORT, 10) || 3306;
const enableSsl = process.env.DB_SSL === 'true' || process.env.DB_SSL === '1';
const caPath = (process.env.DB_CA_PATH || '').trim();

let ssl = null;
if (enableSsl) {
  ssl = { minVersion: 'TLSv1.2' };
  if (caPath) {
    const resolved = path.isAbsolute(caPath) ? caPath : path.resolve(process.cwd(), caPath);
    if (fs.existsSync(resolved)) {
      ssl.ca = fs.readFileSync(resolved);
    }
  }
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: dbPort,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'msync',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  supportBigNumbers: true,
  ...(ssl && { ssl }),
});

/**
 * Helper: run a query and return rows.
 * Usage: const [rows] = await query('SELECT * FROM users WHERE id = ?', [userId]);
 */
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/**
 * Get a single connection from pool (for transactions).
 * Remember to connection.release() when done.
 */
async function getConnection() {
  return pool.getConnection();
}

module.exports = { pool, query, getConnection };
