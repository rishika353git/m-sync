/**
 * Central config used across the app.
 * All values come from environment variables (see .env.example).
 * Tries multiple .env locations so root (m-sync/.env) or backend/.env both work.
 */

const path = require('path');
const fs = require('fs');

const rootEnv = path.resolve(process.cwd(), '..', '.env');      // m-sync/.env when run from backend/
const rootEnvAlt = path.resolve(__dirname, '../../../.env');   // m-sync/.env from file path
const backendEnv = path.resolve(process.cwd(), '.env');        // backend/.env
const backendEnvAlt = path.resolve(__dirname, '../../.env');

if (fs.existsSync(rootEnv)) require('dotenv').config({ path: rootEnv });
else if (fs.existsSync(rootEnvAlt)) require('dotenv').config({ path: rootEnvAlt });
if (fs.existsSync(backendEnv)) require('dotenv').config({ path: backendEnv });
else if (fs.existsSync(backendEnvAlt)) require('dotenv').config({ path: backendEnvAlt });

const corsOrigin = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim())
  : ['http://localhost:5173', 'http://localhost:3000'];

module.exports = {
  port: parseInt(process.env.PORT, 10) || 4000,
  nodeEnv: process.env.NODE_ENV || 'development',

  // CORS: allow these origins (extension + dashboard). Comma-separated.
  corsOrigin,

  // Frontend URL: where to redirect after OAuth. In production use https://mydomain.com
  frontendUrl: (process.env.FRONTEND_URL || '').trim() || corsOrigin[0] || 'http://localhost:5173',

  // Backend public URL (for webhooks/callbacks if needed). Production: http://localhost:4000
  backendBaseUrl: (process.env.BACKEND_BASE_URL || '').trim() || '',

  jwt: {
    secret: process.env.JWT_SECRET || 'dev-secret-change-me',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },

  db: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'msync',
  },

  // Google OAuth (for "Continue with Google"). Redirect URI must match Google Cloud Console.
  google: (() => {
    let baseUrl = (process.env.BACKEND_BASE_URL || '').trim().replace(/\/$/, '');
    if (!baseUrl && process.env.NODE_ENV !== 'production') {
      const port = parseInt(process.env.PORT, 10) || 4000;
      baseUrl = `http://localhost:${port}`;
    }
    if (baseUrl && baseUrl.includes('ngrok')) baseUrl = baseUrl.replace(/^http:\/\//, 'https://');
    const redirectUri = baseUrl ? `${baseUrl}/api/auth/google/callback` : '';
    return {
      clientId: (process.env.GOOGLE_CLIENT_ID || '').trim(),
      clientSecret: (process.env.GOOGLE_CLIENT_SECRET || '').trim(),
      redirectUri,
    };
  })(),

  ghl: (() => {
    const clientId = (process.env.GHL_CLIENT_ID || '').trim();
    const explicitAppId = (process.env.GHL_APP_ID || '').trim();
    // appId: only for chooselocation URL. Do NOT send in token exchange (causes noAppVersionIdFound).
    // Use GHL_APP_ID, or derive from Client ID: "appId-suffix" -> appId, else full clientId
    const appId = explicitAppId || (clientId.includes('-') ? clientId.split('-')[0] : clientId) || '';
    const installationUrl = (process.env.GHL_INSTALLATION_URL || '').trim();
    // Redirect URI: explicit GHL_REDIRECT_URI, or derive from BACKEND_BASE_URL (e.g. ngrok) for local testing
    let baseUrl = (process.env.BACKEND_BASE_URL || '').trim().replace(/\/$/, '');
    if (baseUrl && baseUrl.includes('ngrok')) baseUrl = baseUrl.replace(/^http:\/\//, 'https://');
    const explicitRedirect = (process.env.GHL_REDIRECT_URI || '').trim();
    const rawRedirect = explicitRedirect || (baseUrl ? `${baseUrl}/api/auth/callback` : '');
    // Normalize: no trailing slash so it matches GHL Marketplace redirect URL exactly
    const redirectUri = rawRedirect ? rawRedirect.replace(/\/$/, '') : '';
    // Use LeadConnector marketplace when your app is on leadconnectorhq.com (avoids "No integration found" on gohighlevel.com)
    const useLeadConnector = (process.env.GHL_MARKETPLACE || '').toLowerCase() === 'leadconnector';
    const chooselocationBase = useLeadConnector
      ? 'https://marketplace.leadconnectorhq.com/oauth/chooselocation'
      : 'https://marketplace.gohighlevel.com/oauth/chooselocation';
    return {
      clientId,
      clientSecret: process.env.GHL_CLIENT_SECRET || '',
      redirectUri,
      appId,
      installationUrl,
      chooselocationBase,
    };
  })(),
};
