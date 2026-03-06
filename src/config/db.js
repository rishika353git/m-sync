/**
 * MySQL database connection using mysql2.
 * We use a connection pool so multiple requests can use DB without opening
 * a new connection every time.
 */

const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'msync',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
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
