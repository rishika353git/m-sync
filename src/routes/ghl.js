/**
 * GoHighLevel (GHL) integration. All token state from GhlTokenService (DB).
 */

const express = require('express');
const db = require('../config/db');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');
const { ghlFetch } = require('../utils/ghl-api');
const ghlTokenService = require('../services/ghl-token-service');

const router = express.Router();

const GHL_SESSION_EXPIRED_MSG = 'GHL session expired. Reconnect your GoHighLevel account in the dashboard.';

// In-memory cache: userId -> last contactId used in profile fetch (so task update can use it)
const lastContactIdByUser = new Map();

function isGhlUnauthorized(res, data) {
  if (res.status !== 401) return false;
  if (data?.message === 'Invalid JWT' || data?.statusCode === 401) return true;
  if (data?.message && typeof data.message === 'string' && /jwt|token|unauthorized/i.test(data.message)) return true;
  return true;
}

router.post('/disconnect', requireAuth, async (req, res) => {
  try {
    await ghlTokenService.disconnect(req.user.id);
    return res.json({ ok: true, message: 'GHL disconnected. Connect again to re-authorize.' });
  } catch (err) {
    console.error('[GHL disconnect] error', err);
    return res.status(500).json({ error: 'Failed to disconnect' });
  }
});

router.get('/connect', requireAuth, (req, res) => {
  const host = (req.get('host') || '').toLowerCase();
  const hasNgrokSkipHeader = !!(req.get('ngrok-skip-browser-warning') || req.get('Ngrok-Skip-Browser-Warning'));
  // When backend is behind ngrok and request has no skip header, return interstitial so browser can fetch with header and follow redirect to GHL
  if (host.includes('ngrok') && !hasNgrokSkipHeader) {
    const protocol = host.includes('ngrok') ? 'https' : req.protocol;
    const fullUrl = `${protocol}://${req.get('host')}${req.originalUrl}`;
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    return res.type('html').send(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Connecting to GoHighLevel…</title></head><body><p>Redirecting to GoHighLevel…</p><script>
var u = ${JSON.stringify(fullUrl)} + (${JSON.stringify(req.originalUrl)}.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
fetch(u, { headers: { "ngrok-skip-browser-warning": "1" }, redirect: "manual" })
  .then(function(r) { var loc = r.headers.get("Location"); if (loc) window.location = loc; else document.body.innerHTML = "<p>Connection failed. <a href='/'>Try again</a></p>"; })
  .catch(function() { document.body.innerHTML = "<p>Connection failed. <a href='/'>Try again</a></p>"; });
</script></body></html>`
    );
  }

  const userId = req.user.id;
  const state = String(userId);
  const installationUrl = (config.ghl?.installationUrl || '').trim();
  const appId = (config.ghl?.clientId || '').split('-')[0] || '';

  console.log('[GHL connect] Step 1: Connect requested', {
    userId,
    hasInstallationUrl: !!installationUrl,
    hasRedirectUri: !!config.ghl?.redirectUri,
    hasClientId: !!config.ghl?.clientId,
    redirectUriPreview: config.ghl?.redirectUri ? config.ghl?.redirectUri.slice(0, 50) + '...' : '(not set)',
  });

  if (installationUrl) {
    console.log('[GHL connect] Step 2: Using GHL_INSTALLATION_URL (client_id prefix:', appId, ')');
    if (!config.ghl?.redirectUri) {
      console.log('[GHL connect] Step 2 FAIL: GHL_REDIRECT_URI not set');
      return res.redirect(
        `${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('Set GHL_REDIRECT_URI')}`
      );
    }
    const sep = installationUrl.includes('?') ? '&' : '?';
    const finalUrl = `${installationUrl}${sep}state=${state}`;
    console.log('[GHL connect] Step 3: Redirecting to GHL, URL length:', finalUrl.length);
    return res.redirect(finalUrl);
  }
  if (!config.ghl?.clientId || !config.ghl?.redirectUri) {
    console.log('[GHL connect] Step 2 FAIL: Missing GHL_CLIENT_ID or GHL_REDIRECT_URI');
    return res.redirect(`${config.frontendUrl}/dashboard?ghl=error&msg=${encodeURIComponent('Set GHL_CLIENT_ID, GHL_REDIRECT_URI')}`);
  }
  console.log('[GHL connect] Step 2: Using built chooselocation URL for app', appId, '(add this app’s redirect URL in GHL Marketplace → Auth)');
  const base = 'https://marketplace.gohighlevel.com/oauth/chooselocation';
  const params = {
    response_type: 'code',
    client_id: config.ghl.clientId,
    redirect_uri: config.ghl.redirectUri,
    scope: 'contacts.readonly contacts.write locations.readonly businesses.readonly users.readonly products.readonly',
    state,
  };
  if (config.ghl.appId) params.appId = config.ghl.appId;
  console.log('[GHL connect] Step 3: Redirecting to GHL (built URL)');
  res.redirect(`${base}?${new URLSearchParams(params).toString()}`);
});

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function withGhlRetry(req, res, fn) {
  const userId = req.user.id;
  const { accessToken: token, locationId } = await ghlTokenService.getValidToken(userId);
  if (!token) {
    return res.status(400).json({ error: 'GHL not connected' });
  }
  if (!locationId) {
    return res.status(400).json({ error: 'No location' });
  }
  let out = await fn(token);
  if (!isGhlUnauthorized(out.res, out.data)) {
    return res.status(out.res.status).json(out.data);
  }
  const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
  const newToken = refreshResult?.accessToken ?? null;
  if (newToken) {
    out = await fn(newToken);
    if (!isGhlUnauthorized(out.res, out.data)) {
      return res.status(out.res.status).json(out.data);
    }
    // Retry still 401 – GHL may need a moment for the new token to propagate. Retry once after delay.
    await sleep(1500);
    out = await fn(newToken);
    if (!isGhlUnauthorized(out.res, out.data)) {
      return res.status(out.res.status).json(out.data);
    }
    // Do NOT disconnect – keep tokens; may be propagation delay. Return 401 so user can retry or reconnect manually.
    console.warn('[GHL withGhlRetry] userId', userId, 'retry returned 401 after refresh – returning 401 without disconnect (tokens kept; user may retry)');
    return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
  }
  await ghlTokenService.disconnect(userId, 'GHL API returned 401 and refresh failed. Reconnect in the dashboard; check Redirect URL in GHL Marketplace.');
  return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
}

router.get('/status', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    let { accessToken, locationId } = await ghlTokenService.getValidToken(userId);
    if (!accessToken) {
      const reason = ghlTokenService.getDisconnectReason(userId) || 'No GHL connection for this account. Connect GoHighLevel in the dashboard (use the same account in the extension; keep the dashboard tab open after login so the extension syncs).';
      console.log('[GHL status] disconnected (no valid token) –', reason);
      return res.json({ status: 'disconnected', connected: false, location_id: null, disconnect_reason: reason });
    }
    // Probe GHL so we don't report "connected" when the token is already invalid/revoked.
    // Otherwise the extension shows "connected" then Load contact returns 401 and we disconnect.
    const probe = await ghlFetch('https://services.leadconnectorhq.com/oauth/installedLocations', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const probeData = await probe.json().catch(() => ({}));
    if (probe.status === 401 || (probe.ok === false && probeData?.message && /unauthorized|invalid|expired/i.test(String(probeData.message)))) {
      // Probe failed – try refresh to fix the token. GHL may return 401 for new tokens briefly (propagation delay).
      const tokensBeforeRefresh = await ghlTokenService.getTokens(userId);
      const updatedAt = tokensBeforeRefresh?.updatedAt != null ? Number(tokensBeforeRefresh.updatedAt) : 0;
      const connectionAgeMs = Date.now() - updatedAt;
      const FRESH_CONNECTION_MS = 2 * 60 * 1000; // 2 minutes
      const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
      const newToken = refreshResult?.accessToken ?? null;
      if (newToken) {
        const updated = await ghlTokenService.getValidToken(userId);
        return res.json({ status: 'connected', connected: true, location_id: updated?.locationId ?? locationId });
      }
      // Refresh failed – for fresh connections, don't disconnect (token may propagate shortly)
      if (connectionAgeMs < FRESH_CONNECTION_MS) {
        console.log('[GHL status] probe failed, refresh failed, connection fresh – returning connected optimistically');
        return res.json({ status: 'connected', connected: true, location_id: locationId });
      }
      const msg = 'Status probe got 401 from GHL and refresh failed (invalid refresh token). Disconnect and reconnect in the dashboard; check Redirect URL in GHL Marketplace.';
      await ghlTokenService.disconnect(userId, msg);
      return res.json({ status: 'disconnected', connected: false, location_id: null, disconnect_reason: msg });
    }
    if (!probe.ok) {
      // Non-401 error (e.g. 500, rate limit): still report connected; token might be fine
      console.log('[GHL status] probe non-401 failure', probe.status, probeData?.message || '');
    }
    console.log('[GHL status] connected');
    return res.json({ status: 'connected', connected: true, location_id: locationId });
  } catch (err) {
    console.error('[GHL status] error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/ghl/contacts – list contacts for user's location (paginated)
router.get('/contacts', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  let { accessToken: token, locationId } = await ghlTokenService.getValidToken(userId);
  if (!token || !locationId) {
    return res.status(200).json({ contacts: [], total: 0, page: 1, limit });
  }

  async function fetchPage(accessToken, pageNum) {
    const r = await ghlFetch('https://services.leadconnectorhq.com/contacts/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ locationId, pageLimit: limit }),
    });
    return { res: r, data: await r.json().catch(() => ({})) };
  }

  try {
    let out = await fetchPage(token, page);
    if (isGhlUnauthorized(out.res, out.data)) {
      const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
      const newToken = refreshResult?.accessToken ?? null;
      if (!newToken) {
        await ghlTokenService.disconnect(userId, 'List contacts got 401 and refresh failed.');
        return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
      }
      token = newToken;
      out = await fetchPage(token, page);
      if (isGhlUnauthorized(out.res, out.data)) {
        await ghlTokenService.disconnect(userId, 'List contacts got 401 after refresh.');
        return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
      }
    }
    const data = out.data;
    if (!out.res.ok) {
      return res.status(out.res.status).json(data && typeof data === 'object' ? data : { error: 'GHL request failed' });
    }
    const contacts = Array.isArray(data.contacts) ? data.contacts : [];
    const total = data.total != null ? data.total : contacts.length;
    return res.json({ contacts, total, page, limit });
  } catch (err) {
    console.error('[GHL list contacts] error', err);
    return res.status(500).json({ error: 'Failed to list contacts' });
  }
});

router.get('/contacts/:email', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { accessToken: token, locationId } = await ghlTokenService.getValidToken(userId);
  if (!token) {
    console.log('[GHL contacts] no token for userId:', userId, '– user may have connected GHL on a different account. Extension must use same user as dashboard.');
    return res.status(400).json({ error: 'GHL not connected' });
  }
  if (!locationId) return res.status(400).json({ error: 'No location' });
  const searchQuery = (req.params.email || '').trim().toLowerCase();
  if (!searchQuery) {
    return res.status(400).json({ error: 'Please enter an email address (e.g. contact@company.com)' });
  }
  console.log('[GHL contacts] search userId:', userId, 'locationId:', locationId, 'query:', searchQuery);

  const dupUrl = `https://services.leadconnectorhq.com/contacts/search/duplicate?locationId=${encodeURIComponent(locationId)}&email=${encodeURIComponent(searchQuery)}`;

  async function tryDuplicate(accessToken) {
    const res = await ghlFetch(dupUrl, { headers: { Authorization: `Bearer ${accessToken}` } });
    const data = await res.json().catch(() => ({}));
    return { res, data };
  }

  // GHL POST /contacts/search rejects queryString and limit; expects pageLimit (number). We use minimal body and filter by email in code.
  const searchBody = { locationId, pageLimit: 50 };

  async function doSearch(accessToken) {
    const r = await ghlFetch('https://services.leadconnectorhq.com/contacts/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(searchBody),
    });
    return r;
  }

  function normalizeEmail(c) {
    if (!c) return '';
    const e = c?.email ?? c?.emails?.[0] ?? (Array.isArray(c?.emails) ? c.emails[0] : null);
    const str = (e && typeof e === 'string' ? e : (e && typeof e === 'object' ? (e?.value ?? e?.address ?? e?.email) : ''));
    return String(str || '').trim().toLowerCase();
  }

  function hasContact(data) {
    if (!data) return false;
    const c = data.contact ?? data;
    return !!(c && (c.id || c.contactId || data.id || data.contactId || normalizeEmail(c) || normalizeEmail(data)));
  }

  function toContactList(data) {
    const contact = data?.contact ?? data;
    const list = Array.isArray(contact) ? contact : (contact ? [contact] : []);
    return list;
  }

  try {
    let { res: dupRes, data: dupData } = await tryDuplicate(token);
    if (dupRes.ok && hasContact(dupData)) {
      const list = toContactList(dupData);
      if (list.length > 0) {
        return res.status(200).json({ contacts: list, contact: list[0], message: null });
      }
    }
    if (dupRes.status === 404 || (dupRes.ok && !hasContact(dupData))) {
      if (dupRes.ok && dupData && Object.keys(dupData).length > 0) {
        console.log('[GHL contacts] duplicate 200 but no contact – keys:', Object.keys(dupData));
      }
      return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
    }

    if (dupRes.status === 401) {
      const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
      const newToken = refreshResult?.accessToken ?? null;
      if (newToken) {
        const retryDup = await tryDuplicate(newToken);
        if (retryDup.res.ok && hasContact(retryDup.data)) {
          const list = toContactList(retryDup.data);
          if (list.length > 0) {
            return res.status(200).json({ contacts: list, contact: list[0], message: null });
          }
        }
        if (retryDup.res.status === 404 || (retryDup.res.ok && !hasContact(retryDup.data))) {
          return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
        }
      }
    }

    let r = await doSearch(token);
    let data = await r.json();
    if (!isGhlUnauthorized(r, data)) {
      if (r.status === 422) {
        console.log('[GHL contacts] 422 from GHL – body:', JSON.stringify(data));
        const reason = (Array.isArray(data?.message) && data.message.join('; ')) || data?.message || data?.error || (Array.isArray(data?.errors) && data.errors.map(e => e.message || e.msg || e.field || JSON.stringify(e)).join('; ')) || (data?.errors && typeof data.errors === 'object' && !Array.isArray(data.errors) && JSON.stringify(data.errors)) || 'GoHighLevel rejected the contact search request (422). Check backend logs for GHL response.';
        return res.status(422).json({ error: typeof reason === 'string' ? reason : JSON.stringify(reason), ...data });
      }
      if (r.ok && data?.contacts && Array.isArray(data.contacts)) {
        const match = data.contacts.find(c => normalizeEmail(c) === searchQuery);
        if (match) {
          return res.status(200).json({ contacts: [match], contact: match, message: null });
        }
        return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
      }
      if (r.status === 404 || (r.ok && (!data?.contacts || data.contacts.length === 0))) {
        return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
      }
      return res.status(r.status).json(data);
    }

    const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
    const newToken = refreshResult?.accessToken ?? null;
    if (newToken) {
      const retryDup = await tryDuplicate(newToken);
      if (retryDup.res.ok && hasContact(retryDup.data)) {
        const list = toContactList(retryDup.data);
        if (list.length > 0) {
          return res.status(200).json({ contacts: list, contact: list[0], message: null });
        }
      }
      if (retryDup.res.status === 404 || (retryDup.res.ok && !hasContact(retryDup.data))) {
        return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
      }

      r = await doSearch(newToken);
      const retryData = await r.json();
      if (!isGhlUnauthorized(r, retryData)) {
        if (r.status === 422) {
          console.log('[GHL contacts] 422 from GHL (retry) – body:', JSON.stringify(retryData));
          const reason = (Array.isArray(retryData?.message) && retryData.message.join('; ')) || retryData?.message || retryData?.error || (Array.isArray(retryData?.errors) && retryData.errors.map(e => e.message || e.msg || e.field || JSON.stringify(e)).join('; ')) || (retryData?.errors && typeof retryData.errors === 'object' && !Array.isArray(retryData.errors) && JSON.stringify(retryData.errors)) || 'GoHighLevel rejected the contact search request (422). Check backend logs for GHL response.';
          return res.status(422).json({ error: typeof reason === 'string' ? reason : JSON.stringify(reason), ...retryData });
        }
        if (r.ok && retryData?.contacts && Array.isArray(retryData.contacts)) {
          const match = retryData.contacts.find(c => normalizeEmail(c) === searchQuery);
          if (match) {
            return res.status(200).json({ contacts: [match], contact: match, message: null });
          }
          return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
        }
        if (r.status === 404 || (r.ok && (!retryData?.contacts || retryData.contacts.length === 0))) {
          return res.status(200).json({ contacts: [], contact: null, message: `No contact found for "${searchQuery}". Add the contact in GoHighLevel or check the email.` });
        }
        return res.status(r.status).json(retryData);
      }
      console.warn('[GHL contacts] userId', userId, 'retry returned 401 – returning 401 without disconnect');
      return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
    }
    console.warn('[GHL contacts] userId', userId, 'refresh failed (invalid token) – disconnecting');
    await ghlTokenService.disconnect(userId, 'Load contact got 401 from GHL and refresh failed (invalid refresh token). Reconnect in the dashboard; ensure Redirect URL in GHL Marketplace matches your backend.');
    console.log('[GHL contacts] returned 401 session expired for userId:', userId);
    return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
  } catch (err) {
    console.error('[GHL contacts] error', err);
    res.status(500).json({ error: 'Failed to fetch contact' });
  }
});

router.get('/contacts/:contactId/profile', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { accessToken: token, locationId } = await ghlTokenService.getValidToken(userId);
  if (!token) return res.status(400).json({ error: 'GHL not connected' });
  if (!locationId) return res.status(400).json({ error: 'No location' });
  const { contactId } = req.params;
  lastContactIdByUser.set(userId, contactId);
  try {
    const [contactRes, tasksRes] = await Promise.all([
      ghlFetch(`https://services.leadconnectorhq.com/contacts/${contactId}?locationId=${locationId}`, { headers: { Authorization: `Bearer ${token}` } }),
      ghlFetch(`https://services.leadconnectorhq.com/contacts/${contactId}/tasks?locationId=${locationId}`, { headers: { Authorization: `Bearer ${token}` } }),
    ]);
    const contact = await contactRes.json();
    const tasks = tasksRes.ok ? await tasksRes.json() : { tasks: [] };
    const injectContactId = (list) => (list || []).map((t) => ({ ...t, contactId: t.contactId || contactId }));
    if (!isGhlUnauthorized(contactRes, contact)) {
      return res.json({ contact, tasks: injectContactId(tasks.tasks || tasks) });
    }
    const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
    const newToken = refreshResult?.accessToken ?? null;
    if (newToken) {
      const [c2, t2] = await Promise.all([
        ghlFetch(`https://services.leadconnectorhq.com/contacts/${contactId}?locationId=${locationId}`, { headers: { Authorization: `Bearer ${newToken}` } }),
        ghlFetch(`https://services.leadconnectorhq.com/contacts/${contactId}/tasks?locationId=${locationId}`, { headers: { Authorization: `Bearer ${newToken}` } }),
      ]);
      const contact2 = await c2.json();
      const tasks2 = t2.ok ? await t2.json() : { tasks: [] };
      if (!isGhlUnauthorized(c2, contact2)) return res.json({ contact: contact2, tasks: injectContactId(tasks2.tasks || tasks2) });
      console.warn('[GHL profile] userId', userId, 'retry returned 401 – returning 401 without disconnect');
      return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
    }
    console.warn('[GHL profile] userId', userId, 'refresh failed – disconnecting');
    await ghlTokenService.disconnect(userId, 'Profile request got 401 from GHL and refresh failed. Reconnect in the dashboard.');
    return res.status(401).json({ error: GHL_SESSION_EXPIRED_MSG });
  } catch (err) {
    console.error('[GHL profile] error', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET /api/ghl/contacts/:contactId/tags – get contact tags (from contact object)
router.get('/contacts/:contactId/tags', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${contactId}?locationId=${locationId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const rawTags = r.ok ? (data?.tags || data?.contact?.tags || []) : [];
      const tags = Array.isArray(rawTags) ? rawTags : [];
      return { res: r, data: { tags } };
    });
  } catch (err) {
    console.error('[GHL tags] error', err);
    res.status(500).json({ error: 'Failed to fetch tags' });
  }
});

// POST /api/ghl/contacts/:contactId/tags – add tags to contact (body: { tags: ['tag1', 'tag2'] })
router.post('/contacts/:contactId/tags', requireAuth, async (req, res) => {
  try {
    const tags = req.body?.tags;
    if (!Array.isArray(tags) || tags.length === 0) return res.status(400).json({ error: 'tags array required' });
    return await withGhlRetry(req, res, async (token) => {
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${contactId}/tags`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ tags: tags.map((t) => (typeof t === 'string' ? t : t?.name || t?.id || String(t))).filter(Boolean) }),
        }
      );
      const data = await r.json().catch(() => ({}));
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL add tags] error', err);
    res.status(500).json({ error: 'Failed to add tags' });
  }
});

// GET /api/ghl/contacts/:contactId/notes – get contact notes (timeline)
router.get('/contacts/:contactId/notes', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${contactId}/notes?locationId=${locationId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const notes = data?.notes || data || [];
      return { res: r, data: { notes: Array.isArray(notes) ? notes : [] } };
    });
  } catch (err) {
    console.error('[GHL notes] error', err);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// POST /api/ghl/contacts/:contactId/notes – create note (body: { body: 'text' })
router.post('/contacts/:contactId/notes', requireAuth, async (req, res) => {
  try {
    const body = req.body?.body ?? req.body?.text ?? req.body?.note;
    if (!body || typeof body !== 'string') return res.status(400).json({ error: 'body (note text) required' });
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${contactId}/notes?locationId=${encodeURIComponent(locationId)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ body: body.trim() }),
        }
      );
      const data = await r.json().catch(() => ({}));
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL create note] error', err);
    res.status(500).json({ error: 'Failed to create note' });
  }
});

// GET /api/ghl/contacts/:contactId/opportunities – list opportunities/deals for contact
router.get('/contacts/:contactId/opportunities', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/opportunities/search?contactId=${encodeURIComponent(contactId)}&locationId=${encodeURIComponent(locationId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const opportunities = data?.opportunities || data?.data || data || [];
      return { res: r, data: { opportunities: Array.isArray(opportunities) ? opportunities : [] } };
    });
  } catch (err) {
    console.error('[GHL opportunities] error', err);
    res.status(500).json({ error: 'Failed to fetch opportunities' });
  }
});

// GET /api/ghl/pipelines – list opportunity pipelines + stages for the user's location
router.get('/pipelines', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/opportunities/pipelines?locationId=${encodeURIComponent(locationId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const list = data?.pipelines ?? data?.pipelines?.pipelines ?? data?.data?.pipelines ?? data?.data ?? data;
      const pipelines = (Array.isArray(list) ? list : []).map((p) => {
        const stagesRaw = p?.stages ?? p?.pipelineStages ?? p?.stages?.stages ?? [];
        const stages = (Array.isArray(stagesRaw) ? stagesRaw : []).map((s) => ({
          id: s?.id ?? s?._id ?? s?.stageId ?? s?.opportunityStageId,
          name: s?.name ?? s?.title ?? s?.label ?? 'Stage',
        })).filter((s) => s.id);
        return {
          id: p?.id ?? p?._id ?? p?.pipelineId,
          name: p?.name ?? p?.title ?? 'Pipeline',
          stages,
        };
      }).filter((p) => p.id);
      return { res: r, data: { pipelines } };
    });
  } catch (err) {
    console.error('[GHL pipelines] error', err);
    res.status(500).json({ error: 'Failed to fetch pipelines' });
  }
});

// POST /api/ghl/opportunities – create an opportunity/deal for a contact
router.post('/opportunities', requireAuth, async (req, res) => {
  try {
    const contactId = req.body?.contactId ?? req.body?.contact_id;
    const pipelineId = req.body?.pipelineId ?? req.body?.pipeline_id;
    const stageId = req.body?.stageId ?? req.body?.stage_id;
    const name = (req.body?.name ?? req.body?.title ?? '').trim();
    const monetaryValueRaw = req.body?.monetaryValue ?? req.body?.value ?? req.body?.amount;

    if (!contactId || !pipelineId || !stageId || !name) {
      return res.status(400).json({ error: 'contactId, pipelineId, stageId, and name are required' });
    }
    const monetaryValue = monetaryValueRaw == null || monetaryValueRaw === '' ? undefined : Number(monetaryValueRaw);
    if (monetaryValueRaw != null && monetaryValueRaw !== '' && Number.isNaN(monetaryValue)) {
      return res.status(400).json({ error: 'monetaryValue must be a number' });
    }

    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const body = {
        locationId,
        contactId,
        pipelineId,
        stageId,
        name,
        status: 'open',
      };
      if (monetaryValue !== undefined) body.monetaryValue = monetaryValue;
      const r = await ghlFetch('https://services.leadconnectorhq.com/opportunities/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL create opportunity] error', err);
    res.status(500).json({ error: 'Failed to create opportunity' });
  }
});

// GET /api/ghl/contacts/:contactId/appointments – list appointments for contact
router.get('/contacts/:contactId/appointments', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${contactId}/appointments?locationId=${locationId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const appointments = data?.appointments || data?.data || data || [];
      return { res: r, data: { appointments: Array.isArray(appointments) ? appointments : [] } };
    });
  } catch (err) {
    console.error('[GHL appointments] error', err);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// GET /api/ghl/contacts/:contactId/transactions – list transactions for contact (GHL Payments API)
router.get('/contacts/:contactId/transactions', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/payments/transactions?contactId=${encodeURIComponent(contactId)}&locationId=${encodeURIComponent(locationId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const transactions = data?.transactions || data?.data || data || [];
      return { res: r, data: { transactions: Array.isArray(transactions) ? transactions : [] } };
    });
  } catch (err) {
    console.error('[GHL transactions] error', err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// GET /api/ghl/custom-fields – list custom field definitions for the user's location (for contact custom fields)
router.get('/custom-fields', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/locations/${locationId}/customFields`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const list = data?.customFields ?? data?.customfields ?? data?.data ?? data;
      const customFields = Array.isArray(list) ? list : [];
      return { res: r, data: { customFields } };
    });
  } catch (err) {
    console.error('[GHL custom-fields] error', err);
    res.status(500).json({ error: 'Failed to fetch custom fields' });
  }
});

async function updateContactHandler(req, res) {
  try {
    const allowed = ['firstName', 'lastName', 'name', 'email', 'phone', 'companyName', 'company_name'];
    const body = {};
    for (const k of allowed) {
      let v = req.body[k];
      if (v === undefined) continue;
      const key = k === 'company_name' ? 'companyName' : k;
      if (typeof v === 'string') v = v.trim();
      if (v === '') continue;
      body[key] = v;
    }
    // Allow customFields: array of { id, value } for CRM custom fields
    if (Array.isArray(req.body.customFields)) {
      body.customFields = req.body.customFields
        .filter((f) => f && (f.id || f.fieldId))
        .map((f) => ({ id: f.id || f.fieldId, value: f.value != null ? String(f.value) : '' }));
    }
    if (Object.keys(body).length === 0) {
      return res.status(400).json({ error: 'At least one field is required to update' });
    }

    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const { contactId } = req.params;
      // GHL update contact: locationId as query param; body contains only contact fields
      const url = `https://services.leadconnectorhq.com/contacts/${contactId}?locationId=${encodeURIComponent(locationId)}`;
      const r = await ghlFetch(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      if (r.status === 422) {
        const msg = data?.message || data?.error || (Array.isArray(data?.errors) ? data.errors.map((e) => e.message || e.msg).filter(Boolean).join('; ') : null) || 'Validation failed';
        console.log('[GHL update contact] 422', msg, 'body keys:', Object.keys(body));
        return { res: r, data: { ...data, error: msg } };
      }
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL update contact] error', err);
    res.status(500).json({ error: 'Failed to update contact' });
  }
}
router.put('/contacts/:contactId', requireAuth, updateContactHandler);
router.patch('/contacts/:contactId', requireAuth, updateContactHandler);

// GET /api/ghl/tasks – list tasks for user's location (task search, or aggregate from contacts as fallback)
router.get('/tasks', requireAuth, async (req, res) => {
  const userId = req.user.id;
  let { accessToken: token, locationId } = await ghlTokenService.getValidToken(userId);
  if (!token || !locationId) {
    return res.status(200).json({ tasks: [] });
  }

  async function fetchTasksSearch(accessToken) {
    const r = await ghlFetch(
      `https://services.leadconnectorhq.com/locations/${locationId}/tasks/search`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({}),
      }
    );
    return { res: r, data: await r.json().catch(() => ({})) };
  }

  async function fetchTasksFromContacts(accessToken) {
    const searchRes = await ghlFetch('https://services.leadconnectorhq.com/contacts/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ locationId, pageLimit: 30 }),
    });
    const searchData = await searchRes.json().catch(() => ({}));
    const contacts = Array.isArray(searchData.contacts) ? searchData.contacts : [];
    const allTasks = [];
    for (const c of contacts.slice(0, 25)) {
      const cid = c.id || c.contactId;
      if (!cid) continue;
      const tr = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${cid}/tasks?locationId=${locationId}`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!tr.ok) continue;
      const tdata = await tr.json().catch(() => ({}));
      const list = Array.isArray(tdata.tasks) ? tdata.tasks : (Array.isArray(tdata) ? tdata : []);
      list.forEach((t) => allTasks.push({ ...t, contactId: t.contactId || cid }));
    }
    return allTasks;
  }

  try {
    let out = await fetchTasksSearch(token);
    if (isGhlUnauthorized(out.res, out.data)) {
      const refreshResult = await ghlTokenService.refreshIfNeeded(userId, { forceRefresh: true });
      const newToken = refreshResult?.accessToken ?? null;
      if (newToken) {
        token = newToken;
        out = await fetchTasksSearch(token);
      }
    }
    if (!isGhlUnauthorized(out.res, out.data) && out.res.ok) {
      const data = out.data;
      const tasks = Array.isArray(data.tasks) ? data.tasks : (Array.isArray(data) ? data : []);
      if (tasks.length > 0) return res.json({ tasks });
    }
    const fallbackTasks = await fetchTasksFromContacts(token);
    return res.json({ tasks: fallbackTasks });
  } catch (err) {
    console.error('[GHL list tasks] error', err);
    try {
      const fallbackTasks = await fetchTasksFromContacts(token);
      return res.json({ tasks: fallbackTasks });
    } catch (fallbackErr) {
      console.error('[GHL list tasks] fallback error', fallbackErr);
      return res.status(200).json({ tasks: [] });
    }
  }
});

router.post('/contacts', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const r = await ghlFetch('https://services.leadconnectorhq.com/contacts/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ locationId, ...req.body }),
      });
      return { res: r, data: await r.json() };
    });
  } catch (err) {
    console.error('[GHL create contact] error', err);
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

router.post('/tasks', requireAuth, async (req, res) => {
  try {
    const { contactId, title, dueDate, description } = req.body;
    if (!contactId || !title) {
      return res.status(400).json({ error: 'contactId and title are required' });
    }
    return await withGhlRetry(req, res, async (token) => {
      const body = { title, dueDate: dueDate || undefined, body: description || undefined, completed: false };
      const r = await ghlFetch(`https://services.leadconnectorhq.com/contacts/${contactId}/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      console.log('[GHL create task] status', r.status, 'response keys:', Object.keys(data));
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL create task] error', err);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

router.patch('/tasks/:taskId', requireAuth, async (req, res) => {
  try {
    const taskId = req.params.taskId;
    const contactId = req.body.contactId || req.query.contactId || lastContactIdByUser.get(req.user.id);
    const { status, completed } = req.body;
    if (!contactId) {
      console.log('[GHL update task] no contactId available (body, query, or cache)');
      return res.status(400).json({ error: 'Load the contact again and retry. contactId could not be determined.' });
    }
    console.log('[GHL update task] using contactId:', contactId, 'source:', req.body.contactId ? 'body' : req.query.contactId ? 'query' : 'cache');
    return await withGhlRetry(req, res, async (token) => {
      const body = { completed: completed ?? (status === 'completed') };
      const url = `https://services.leadconnectorhq.com/contacts/${contactId}/tasks/${taskId}`;
      const r = await ghlFetch(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      console.log('[GHL update task] status', r.status, 'contactId:', contactId, 'response keys:', Object.keys(data));
      return { res: r, data };
    });
  } catch (err) {
    console.error('[GHL update task] error', err);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

function logSyncAttempt(userId, gmailMessageId, ghlContactId, subject, errorMessage) {
  return db
    .query(
      'INSERT INTO sync_logs (user_id, gmail_message_id, ghl_contact_id, subject, error_message) VALUES (?, ?, ?, ?, ?)',
      [userId, gmailMessageId || null, ghlContactId || null, subject || null, errorMessage || null]
    )
    .catch((e) => console.error('[GHL sync-email] sync_logs insert failed', e.message));
}

// GET /api/ghl/templates – list email/SMS templates from CRM (GHL locations/templates)
router.get('/templates', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/locations/${locationId}/templates`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await r.json().catch(() => ({}));
      const list = data?.templates ?? data?.data ?? data;
      const templates = Array.isArray(list) ? list : [];
      return { res: r, data: { templates } };
    });
  } catch (err) {
    console.error('[GHL templates] error', err);
    res.status(500).json({ error: 'Failed to fetch templates' });
  }
});

// GET /api/ghl/snippets – list snippets/canned responses from CRM (GHL may not have endpoint; return empty if 404)
router.get('/snippets', requireAuth, async (req, res) => {
  try {
    const { accessToken: token, locationId } = await ghlTokenService.getValidToken(req.user.id).catch(() => ({}));
    if (!token || !locationId) return res.json({ snippets: [] });
    const r = await ghlFetch(
      `https://services.leadconnectorhq.com/locations/${locationId}/snippets`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (r.status === 404 || !r.ok) return res.json({ snippets: [] });
    const data = await r.json().catch(() => ({}));
    const list = data?.snippets ?? data?.data ?? data;
    return res.json({ snippets: Array.isArray(list) ? list : [] });
  } catch (_) {
    return res.json({ snippets: [] });
  }
});

// GET /api/ghl/meeting-link – default meeting/calendar link from CRM (if GHL exposes it)
router.get('/meeting-link', requireAuth, async (req, res) => {
  try {
    const { accessToken: token, locationId } = await ghlTokenService.getValidToken(req.user.id).catch(() => ({}));
    if (!token || !locationId) return res.json({ meetingLink: null });
    const r = await ghlFetch(
      `https://services.leadconnectorhq.com/locations/${locationId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!r.ok) return res.json({ meetingLink: null });
    const data = await r.json().catch(() => ({}));
    const loc = data?.location ?? data;
    const link = loc?.meetingLink ?? loc?.calendarLink ?? loc?.bookingUrl ?? loc?.defaultMeetingUrl ?? null;
    return res.json({ meetingLink: link || null });
  } catch (_) {
    return res.json({ meetingLink: null });
  }
});

// GET /api/ghl/documents – list CRM documents/files (GHL Media Storage API)
router.get('/documents', requireAuth, async (req, res) => {
  try {
    return await withGhlRetry(req, res, async (token) => {
      const { locationId } = await ghlTokenService.getValidToken(req.user.id);
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/medias/files?locationId=${encodeURIComponent(locationId)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!r.ok) return { res: r, data: { documents: [] } };
      const data = await r.json().catch(() => ({}));
      const list = data?.files ?? data?.medias ?? data?.data ?? data;
      const items = Array.isArray(list) ? list : [];
      const documents = items.map((f) => ({
        id: f.id ?? f._id,
        name: f.name ?? f.fileName ?? f.title ?? f.id,
        url: f.url ?? f.fileUrl ?? f.link ?? f.publicUrl ?? null,
      })).filter((d) => d.id || d.name);
      return { res: r, data: { documents } };
    });
  } catch (err) {
    console.error('[GHL documents] error', err);
    return res.json({ documents: [] });
  }
});

// Build note body for GHL (email subject, body, timestamp, direction) – used when syncing email to contact
function buildEmailNoteBody(subject, emailBody, direction = 'incoming') {
  const lines = [];
  if (subject) lines.push(`Subject: ${subject}`);
  lines.push(`Date: ${new Date().toISOString()}`);
  lines.push(`Direction: ${direction}`);
  lines.push('');
  lines.push(emailBody ? String(emailBody).trim() : '(No body)');
  return lines.join('\n');
}

router.post('/sync-email', requireAuth, async (req, res) => {
  const [user] = await db.query('SELECT credits_remaining FROM users WHERE id = ?', [req.user.id]);
  if (!user || user.credits_remaining < 1) return res.status(402).json({ error: 'Insufficient credits' });

  let {
    gmail_message_id,
    ghl_contact_id,
    subject,
    email_body,
    reply_only,
    contact_email,
    contact_name,
    contact_phone,
  } = req.body;

  if (!gmail_message_id) return res.status(400).json({ error: 'gmail_message_id required' });

  // High-level start log so we can trace every Save to CRM attempt end-to-end
  console.log('[GHL sync-email] START', {
    userId: req.user.id,
    gmail_message_id,
    contact_email: contact_email || null,
    reply_only: !!reply_only,
    subject_present: !!subject,
  });

  // Normalize email
  contact_email = (contact_email || '').trim().toLowerCase();

  // 1. Duplicate check: do not deduct or create note twice
  const existingRows = await db.query(
    'SELECT id FROM synced_emails WHERE user_id = ? AND gmail_message_id = ?',
    [req.user.id, gmail_message_id]
  );
  if (existingRows && existingRows.length > 0) {
    console.log('[GHL sync-email] DUPLICATE', {
      userId: req.user.id,
      gmail_message_id,
      existing_id: existingRows[0]?.id ?? null,
    });
    logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id || null, subject || null, 'Duplicate (already synced)');
    return res.json({ ok: true, credits_remaining: user.credits_remaining, message: 'Already synced this email.' });
  }

  const direction = reply_only ? 'outgoing' : 'incoming';

  // 2. Ensure we have a CRM contact ID. Never proceed without one.
  try {
    const { accessToken: token, locationId } = await ghlTokenService.getValidToken(req.user.id);
    if (!token || !locationId) {
      const reason = ghlTokenService.getDisconnectReason(req.user.id);
      console.error(
        '[GHL sync-email] FAILED missing token/location',
        'userId=',
        req.user.id,
        'disconnectReason=',
        reason || 'none',
        '| CRM row may have been deleted by another request (401/refresh-fail). Check logs above for [GHL] disconnected user.'
      );
      return res.status(502).json({ error: 'CRM connection is not available. Please reconnect and try again.' });
    }

    // If no contact id but we have an email, try to resolve from CRM
    if (!ghl_contact_id && contact_email) {
      try {
        const searchBody = { locationId, pageLimit: 50 };
        console.log('[GHL sync-email] CONTACT_LOOKUP_START', {
          userId: req.user.id,
          gmail_message_id,
          contact_email,
          locationId,
          url: 'https://services.leadconnectorhq.com/contacts/search',
          body: searchBody,
        });
        const r = await ghlFetch('https://services.leadconnectorhq.com/contacts/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(searchBody),
        });
        const data = await r.json().catch(() => ({}));
        const list = Array.isArray(data.contacts) ? data.contacts : [];
        const lower = contact_email;
        const match = list.find((c) => {
          const raw = c?.email ?? c?.contact?.email ?? c?.contact?.emails?.[0];
          const val =
            typeof raw === 'string'
              ? raw
              : raw && typeof raw === 'object'
              ? raw.value ?? raw.address ?? raw.email
              : null;
          return val && String(val).toLowerCase() === lower;
        });
        const foundId =
          match?.id ??
          match?.contactId ??
          match?.contact_id ??
          match?.contact?.id ??
          match?.contact?.contactId ??
          null;
        if (foundId) {
          ghl_contact_id = String(foundId);
          console.log('[GHL sync-email] CONTACT_LOOKUP_SUCCESS', {
            userId: req.user.id,
            gmail_message_id,
            contact_email,
            ghl_contact_id,
          });
        } else {
          console.log('[GHL sync-email] CONTACT_LOOKUP_EMPTY', {
            userId: req.user.id,
            gmail_message_id,
            contact_email,
            contacts_count: list.length,
          });
        }
      } catch (searchErr) {
        console.warn(
          '[GHL sync-email] CONTACT_LOOKUP_ERROR',
          'userId=',
          req.user.id,
          'email=',
          contact_email,
          searchErr.message || searchErr
        );
      }
    }

    // If still no contact, create one (best-effort) so every sync has a CRM contact
    if (!ghl_contact_id && contact_email) {
      try {
        const body = {
          locationId,
          email: contact_email,
          firstName: contact_name || undefined,
          phone: contact_phone || undefined,
        };
        console.log('[GHL sync-email] CONTACT_CREATE_START', {
          userId: req.user.id,
          gmail_message_id,
          contact_email,
          body,
          url: 'https://services.leadconnectorhq.com/contacts/',
        });
        const r = await ghlFetch('https://services.leadconnectorhq.com/contacts/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        const newId =
          data?.id ??
          data?.contact?.id ??
          data?.data?.id ??
          data?.data?.contact?.id ??
          null;
        if (!r.ok || !newId) {
          console.error(
            '[GHL sync-email] CONTACT_CREATE_FAILED',
            'userId=',
            req.user.id,
            'status=',
            r.status,
            'response=',
            JSON.stringify(data).slice(0, 300)
          );
          return res.status(502).json({ error: 'Could not create contact in CRM. Please try again.' });
        }
        ghl_contact_id = String(newId);
        console.log('[GHL sync-email] CONTACT_CREATE_SUCCESS', {
          userId: req.user.id,
          gmail_message_id,
          contact_email,
          ghl_contact_id,
        });
      } catch (createErr) {
        console.error(
          '[GHL sync-email] CONTACT_CREATE_ERROR',
          'userId=',
          req.user.id,
          'email=',
          contact_email,
          createErr.message || createErr
        );
        return res.status(502).json({ error: 'Could not create contact in CRM. Please try again.' });
      }
    }

    if (!ghl_contact_id) {
      console.error('[GHL sync-email] FAILED_NO_CONTACT_ID', {
        userId: req.user.id,
        gmail_message_id,
        contact_email,
      });
      return res.status(400).json({ error: 'Could not resolve CRM contact for this email.' });
    }

    // 3. Create a note in CRM. Do NOT deduct credits if this fails.
    try {
      const noteBody = buildEmailNoteBody(subject || '', email_body || '', direction);
      console.log('[GHL sync-email] NOTE_CREATE_START', {
        userId: req.user.id,
        gmail_message_id,
        ghl_contact_id,
        locationId,
        note_length: noteBody.length,
        endpoint: `https://services.leadconnectorhq.com/contacts/${ghl_contact_id}/notes?locationId=${encodeURIComponent(
          locationId
        )}`,
      });
      const r = await ghlFetch(
        `https://services.leadconnectorhq.com/contacts/${ghl_contact_id}/notes?locationId=${encodeURIComponent(locationId)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ body: noteBody }),
        }
      );
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        const msg = data?.message || data?.error || `CRM API ${r.status}`;
        console.error(
          '[GHL sync-email] NOTE_CREATE_FAILED',
          'userId=',
          req.user.id,
          'status=',
          r.status,
          'message=',
          msg,
          'responseKeys=',
          Object.keys(data || {})
        );
        logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id, subject, `CRM note failed: ${msg}`);
        return res.status(502).json({ error: 'Could not save email to CRM. Try again or check connection.' });
      }
      console.log('[GHL sync-email] NOTE_CREATE_SUCCESS', {
        userId: req.user.id,
        gmail_message_id,
        ghl_contact_id,
        status: 'ok',
      });
    } catch (noteErr) {
      console.error('[GHL sync-email] NOTE_CREATE_ERROR', 'userId=', req.user.id, noteErr.message || noteErr);
      logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id, subject, noteErr.message || 'CRM error');
      return res.status(502).json({ error: 'Could not save email to CRM. Try again later.' });
    }
  } catch (resolveErr) {
    console.error('[GHL sync-email] CONTACT_RESOLUTION_ERROR', 'userId=', req.user.id, resolveErr.message || resolveErr);
    return res.status(502).json({ error: 'Could not reach CRM. Try again later.' });
  }

  // 4. Save to M-Sync DB and deduct credit (only after CRM note succeeded)
  try {
    try {
      console.log('[GHL sync-email] DB_INSERT_START', {
        userId: req.user.id,
        gmail_message_id,
        ghl_contact_id,
      });
      await db.query(
        'INSERT INTO synced_emails (user_id, gmail_message_id, ghl_contact_id, subject, email_body) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, gmail_message_id, ghl_contact_id || null, subject || null, email_body || null]
      );
    } catch (insertErr) {
      if (insertErr.code === 'ER_BAD_FIELD_ERROR' && insertErr.message && insertErr.message.includes('email_body')) {
        await db.query(
          'INSERT INTO synced_emails (user_id, gmail_message_id, ghl_contact_id, subject) VALUES (?, ?, ?, ?)',
          [req.user.id, gmail_message_id, ghl_contact_id || null, subject || null]
        );
      } else {
        throw insertErr;
      }
    }
    await db.query('UPDATE users SET credits_remaining = credits_remaining - 1 WHERE id = ?', [req.user.id]);
    logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id, subject, null);
    const updatedRows = await db.query('SELECT credits_remaining FROM users WHERE id = ?', [req.user.id]);
    const creditsRemaining =
      updatedRows && updatedRows[0] ? updatedRows[0].credits_remaining : user.credits_remaining - 1;
    console.log('[GHL sync-email] SUCCESS', {
      userId: req.user.id,
      gmail_message_id,
      ghl_contact_id,
      credits_remaining: creditsRemaining,
    });
    res.json({ ok: true, credits_remaining: creditsRemaining });
  } catch (err) {
    const isDuplicate = err.code === 'ER_DUP_ENTRY' || (err.message && /duplicate|unique/i.test(err.message));
    if (isDuplicate) {
      logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id, subject, 'Duplicate (race)');
      return res.json({ ok: true, credits_remaining: user.credits_remaining, message: 'Already synced this email.' });
    }
    console.error('[GHL sync-email] FAILED_DB', 'userId=', req.user.id, err);
    logSyncAttempt(req.user.id, gmail_message_id, ghl_contact_id, subject, err.message || 'Sync failed');
    res.status(500).json({ error: err.message || 'Sync failed' });
  }
});

module.exports = router;
