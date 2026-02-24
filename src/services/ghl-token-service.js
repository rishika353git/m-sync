/**
 * GhlTokenService – single source of truth for GHL tokens.
 * DB only. No in-memory token store. One refresh at a time per user (lock).
 */

const db = require('../config/db');
const config = require('../config');
const { getLocationIdFromGhlToken } = require('../utils/ghl-token');
const { ghlFetch, fetchLocationIdFromApi } = require('../utils/ghl-api');

// Refresh before token expires so we rarely hit 401 from GHL (they may use shorter TTL than we store).
const TOKEN_EXPIRY_BUFFER_MS = 10 * 60 * 1000;
const REFRESH_COOLDOWN_MS = 2 * 60 * 1000;

/** Per-user lock: only one refresh at a time. */
const userLocks = new Map();

/** Last disconnect reason per userId (so status can tell the extension why connected is false). Cleared when user connects again. */
const lastDisconnectReasons = new Map();

function normalizeRefreshToken(access_token, refresh_token) {
  if (!refresh_token) return null;
  if (refresh_token === access_token) return null;
  return refresh_token;
}

/**
 * Run fn under a per-user lock. Prevents multiple concurrent refreshes for same user.
 */
async function withUserLock(userId, fn) {
  let promise = userLocks.get(userId);
  if (!promise) {
    promise = (async () => {
      try {
        return await fn();
      } finally {
        if (userLocks.get(userId) === promise) userLocks.delete(userId);
      }
    })();
    userLocks.set(userId, promise);
  }
  return promise;
}

async function saveTokens(userId, tokens) {
  const access_token = tokens.access_token;
  const refresh_token = normalizeRefreshToken(access_token, tokens.refresh_token ?? null);
  if (tokens.refresh_token && !refresh_token) {
    console.warn('[GHL] refresh_token same as access_token – not storing');
  }
  const expires_in = typeof tokens.expires_in === 'number' ? tokens.expires_in : 24 * 60 * 60;
  const expiresAt = new Date(Date.now() + expires_in * 1000);
  const expiresAtForDb = expiresAt.toISOString().slice(0, 19).replace('T', ' ');
  const locationId = tokens.locationId ?? null;

  await db.query(
    `INSERT INTO ghl_connections (user_id, access_token, refresh_token, location_id, token_expires_at)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE access_token = VALUES(access_token), refresh_token = VALUES(refresh_token), location_id = COALESCE(VALUES(location_id), location_id), token_expires_at = VALUES(token_expires_at)`,
    [userId, access_token, refresh_token, locationId, expiresAtForDb]
  );
  lastDisconnectReasons.delete(userId);
}

async function getTokens(userId) {
  const rows = await db.query(
    'SELECT access_token, refresh_token, location_id, token_expires_at, updated_at FROM ghl_connections WHERE user_id = ?',
    [userId]
  );
  const row = Array.isArray(rows) ? rows[0] : null;
  if (!row || !row.access_token) return null;
  const accessToken = row.access_token;
  const refreshToken = normalizeRefreshToken(accessToken, row.refresh_token ?? null) ?? null;
  const expiresAt = row.token_expires_at != null ? new Date(row.token_expires_at).getTime() : null;
  const updatedAt = row.updated_at != null ? new Date(row.updated_at).getTime() : null;
  return {
    accessToken,
    refreshToken,
    expiresAt,
    locationId: row.location_id ?? null,
    updatedAt,
  };
}

async function isExpired(userId) {
  const tokens = await getTokens(userId);
  if (!tokens || tokens.expiresAt == null) return false;
  return tokens.expiresAt - TOKEN_EXPIRY_BUFFER_MS <= Date.now();
}

async function isCooldownActive(userId) {
  const tokens = await getTokens(userId);
  if (!tokens || tokens.updatedAt == null) return false;
  return Date.now() - tokens.updatedAt < REFRESH_COOLDOWN_MS;
}

async function isConnected(userId) {
  const tokens = await getTokens(userId);
  if (!tokens) {
    return { status: 'disconnected', connected: false, accessToken: null, locationId: null };
  }
  if (!tokens.refreshToken) {
    return { status: 'disconnected', connected: false, accessToken: null, locationId: null };
  }
  const now = Date.now();
  const inCooldown = tokens.updatedAt != null && now - tokens.updatedAt < REFRESH_COOLDOWN_MS;
  if (inCooldown) {
    return { status: 'refreshing', connected: true, accessToken: tokens.accessToken, locationId: tokens.locationId };
  }
  return { status: 'connected', connected: true, accessToken: tokens.accessToken, locationId: tokens.locationId };
}

/**
 * @param {number} userId
 * @param {{ forceRefresh?: boolean }} [opts] - forceRefresh: when GHL API returned 401, try refresh even if in cooldown
 */
async function refreshIfNeeded(userId, opts = {}) {
  const forceRefresh = !!opts.forceRefresh;
  return withUserLock(userId, async () => {
    const tokens = await getTokens(userId);
    const refreshToken = tokens?.refreshToken ?? null;
    const now = Date.now();
    const updatedAt = tokens?.updatedAt ?? 0;
    const inCooldown = !!(updatedAt && now - updatedAt < REFRESH_COOLDOWN_MS);
    if (!config.ghl?.clientId || !config.ghl?.clientSecret) {
      console.log('[GHL refresh] failed (no config)');
      return { accessToken: null };
    }
    if (!refreshToken || refreshToken === tokens?.accessToken) {
      console.log('[GHL refresh] skipped (no valid refresh_token)');
      return { accessToken: null };
    }
    if (!forceRefresh && updatedAt && now - updatedAt < REFRESH_COOLDOWN_MS) {
      console.log('[GHL refresh] skipped (cooldown)');
      return { accessToken: null, inCooldown: true };
    }
    if (forceRefresh && inCooldown) console.log('[GHL refresh] forcing refresh (GHL API returned 401)');
    const redirectUri = (config.ghl?.redirectUri || '').trim().replace(/\/$/, '') || '';
    const params = {
      client_id: config.ghl.clientId,
      client_secret: config.ghl.clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      user_type: 'Location',
    };
    const clientIdPrefix = (config.ghl?.clientId || '').split('-')[0] || '';
    console.log('[GHL refresh] client_id:', clientIdPrefix, '| will try without redirect_uri first, then with');

    async function doRefresh(includeRedirectUri) {
      const p = { ...params };
      if (includeRedirectUri && redirectUri) p.redirect_uri = redirectUri;
      const body = new URLSearchParams(p).toString();
      const res = await ghlFetch('https://services.leadconnectorhq.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body,
      });
      return res.json().catch(() => ({}));
    }

    let data;
    try {
      data = await doRefresh(false);
      if (!data.access_token && redirectUri) {
        console.log('[GHL refresh] no success without redirect_uri, retrying with redirect_uri…');
        data = await doRefresh(true);
      }
    } catch (err) {
      console.log('[GHL refresh] failed (network)', err?.message);
      return { accessToken: null };
    }

    if (!data.access_token) {
      console.log('[GHL refresh] failed', JSON.stringify(data));
      const isInvalidRefresh =
        (data.error === 'UnAuthorized!' || data.error === 'invalid_grant') ||
        (String(data.error_description || '').toLowerCase().includes('refresh token'));
      if (isInvalidRefresh) {
        console.log('[GHL refresh] invalid refresh token – clearing connection. User must reconnect in dashboard.');
        console.log('[GHL refresh] If this happens right after connecting, ensure GHL Marketplace → Auth → Redirect URLs matches GHL_REDIRECT_URI exactly (no trailing slash).');
        await disconnect(userId, 'GHL returned "Invalid refresh token" when refreshing. Disconnect and reconnect in the dashboard; ensure Redirect URL in GHL Marketplace matches your backend (e.g. ngrok URL/api/auth/callback) exactly.');
      }
      return { accessToken: null };
    }
    let locationId = data.locationId ?? data.location_id ?? getLocationIdFromGhlToken(data.access_token);
    if (!locationId) locationId = await fetchLocationIdFromApi(data.access_token);
    const expires_in = typeof data.expires_in === 'number' ? data.expires_in : 24 * 60 * 60;
    const newRefresh = normalizeRefreshToken(data.access_token, data.refresh_token || refreshToken) || (refreshToken !== tokens?.accessToken ? refreshToken : null);
    await saveTokens(userId, {
      access_token: data.access_token,
      refresh_token: newRefresh,
      expires_in,
      locationId: locationId || tokens?.locationId || null,
    });
    if (locationId && !tokens?.locationId) {
      await db.query('UPDATE ghl_connections SET location_id = ? WHERE user_id = ?', [locationId, userId]);
    }
    console.log('[GHL refresh] success');
    return { accessToken: data.access_token };
  });
}

async function getValidToken(userId) {
  const tokens = await getTokens(userId);
  if (!tokens) return { accessToken: null, locationId: null };
  const now = Date.now();
  const inCooldown = tokens.updatedAt != null && now - tokens.updatedAt < REFRESH_COOLDOWN_MS;
  const expired = tokens.expiresAt != null && tokens.expiresAt - TOKEN_EXPIRY_BUFFER_MS <= now;
  if (expired && tokens.refreshToken && !inCooldown) {
    const refreshResult = await refreshIfNeeded(userId);
    if (refreshResult?.accessToken) {
      const updated = await getTokens(userId);
      let locationId = updated?.locationId ?? null;
      if (!locationId && updated?.accessToken) {
        locationId = getLocationIdFromGhlToken(updated.accessToken);
        if (!locationId) locationId = await fetchLocationIdFromApi(updated.accessToken);
        if (locationId) await db.query('UPDATE ghl_connections SET location_id = ? WHERE user_id = ?', [locationId, userId]);
      }
      return { accessToken: refreshResult.accessToken, locationId: locationId ?? tokens.locationId };
    }
    return { accessToken: null, locationId: null };
  }
  let locationId = tokens.locationId;
  if (tokens.accessToken && !locationId) {
    locationId = getLocationIdFromGhlToken(tokens.accessToken);
    if (!locationId) locationId = await fetchLocationIdFromApi(tokens.accessToken);
    if (locationId) await db.query('UPDATE ghl_connections SET location_id = ? WHERE user_id = ?', [locationId, userId]);
  }
  return { accessToken: tokens.accessToken || null, locationId: locationId || null };
}

/**
 * Disconnect user from GHL. Optionally set a reason so the extension can show why (e.g. after session expired).
 */
async function disconnect(userId, reason) {
  await db.query('DELETE FROM ghl_connections WHERE user_id = ?', [userId]);
  if (reason) lastDisconnectReasons.set(userId, reason);
  console.log('[GHL] disconnected user', userId, reason ? 'reason: ' + reason : '');
}

function getDisconnectReason(userId) {
  return lastDisconnectReasons.get(userId) || null;
}

module.exports = {
  saveTokens,
  getTokens,
  isExpired,
  isCooldownActive,
  isConnected,
  refreshIfNeeded,
  getValidToken,
  withUserLock,
  disconnect,
  getDisconnectReason,
};
