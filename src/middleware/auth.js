/**
 * JWT and API key authentication middleware.
 * Use on routes that require a logged-in user.
 * Expects: Authorization: Bearer <jwt_or_api_key> or token in body/query (for extension).
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');
const db = require('../config/db');

/**
 * Get token from header, body, or query (extension might send in body).
 */
function getToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  const apiKey = req.headers['x-api-key'];
  if (apiKey) return apiKey;
  if (req.body && req.body.token) return req.body.token;
  if (req.query && req.query.token) return req.query.token;
  return null;
}

/**
 * Hash an API key for storage/lookup (SHA-256).
 */
function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Middleware: require valid JWT or API key. Sets req.user = { id, email, role }.
 */
async function requireAuth(req, res, next) {
  const token = getToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = { id: decoded.id, email: decoded.email, role: decoded.role };
    return next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      // Not a valid JWT; try API key if it looks like one (msk_...)
      if (typeof token === 'string' && token.startsWith('msk_')) {
        try {
          const keyHash = hashApiKey(token);
          const rows = await db.query(
            'SELECT k.id, k.user_id, u.email, u.role FROM api_keys k JOIN users u ON k.user_id = u.id WHERE k.key_hash = ?',
            [keyHash]
          );
          if (rows && rows.length > 0) {
            req.user = { id: rows[0].user_id, email: rows[0].email, role: rows[0].role };
            return next();
          }
        } catch (dbErr) {
          console.error('API key lookup error:', dbErr);
        }
      }
    }
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * Middleware: require admin role. Use after requireAuth.
 */
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'Admin access required' });
}

module.exports = { getToken, requireAuth, requireAdmin };
