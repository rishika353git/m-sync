/**
 * Initialize database: create DB if not exists, then run schema.
 * Run: npm run db:init
 * Requires MySQL running and .env with DB_USER, DB_PASSWORD, DB_NAME.
 */

const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const DB_NAME = process.env.DB_NAME || 'msync';

async function init() {
  // Connect without database first to create it
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
  });

  console.log('Creating database if not exists:', DB_NAME);
  await conn.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await conn.end();

  // Now connect to the database and run schema
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: DB_NAME,
    multipleStatements: true,
  });

  const schemaPath = path.join(__dirname, '..', 'database', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(schema);
  console.log('Schema applied successfully.');
  await pool.end();
}

init().catch((err) => {
  console.error('Init failed:', err.message);
  process.exit(1);
});
