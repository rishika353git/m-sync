/**
 * Shared GHL LeadConnector API helpers (used by auth callback and ghl routes).
 * All requests require Version header per GHL API.
 */

const GHL_VERSION = '2021-07-28';

function ghlFetch(url, options = {}) {
  const headers = { Version: GHL_VERSION, ...options.headers };
  return fetch(url, { ...options, headers });
}

/**
 * Try to extract first location ID from various API response shapes.
 */
function tryParseLocations(data) {
  const locations =
    data?.locations ??
    data?.location ??
    data?.data?.locations ??
    data?.data ??
    (Array.isArray(data) ? data : []);
  const list = Array.isArray(locations) ? locations : [locations].filter(Boolean);
  const first = list[0];
  if (!first) return null;
  const id = first?.id ?? first?.locationId ?? first?.location_id ?? first?.sub ?? null;
  return id != null ? String(id) : null;
}

/**
 * Get location ID when token response/JWT don't include it.
 * 1) GET /oauth/installedLocations (official "location where app is installed")
 * 2) GET /locations/search
 * Returns first location id or null.
 */
async function fetchLocationIdFromApi(accessToken) {
  if (!accessToken) return null;

  const authHeader = { Authorization: `Bearer ${accessToken}` };

  // 1. Official endpoint: get location(s) where app is installed
  let r = await ghlFetch('https://services.leadconnectorhq.com/oauth/installedLocations', {
    headers: authHeader,
  });
  let data = await r.json().catch(() => ({}));

  if (r.ok) {
    const id = tryParseLocations(data);
    if (id) {
      return id;
    }
    // Response might be { locationId: "..." } or { location: { id: "..." } }
    const single = data?.locationId ?? data?.location_id ?? data?.companyId ?? data?.id;
    if (single) return String(single);
    const loc = data?.location;
    if (loc) {
      const locId = loc?.id ?? loc?.locationId ?? loc?.location_id;
      if (locId) return String(locId);
    }
  } else {
    const errMsg = data?.message ?? data?.error ?? data?.error_description ?? '';
    console.warn('[GHL fetchLocationId] oauth/installedLocations failed', r.status, errMsg || '(no message)');
  }

  // 2. Fallback: GET /locations/search
  r = await ghlFetch('https://services.leadconnectorhq.com/locations/search', {
    headers: authHeader,
  });
  data = await r.json().catch(() => ({}));

  if (r.ok) {
    const id = tryParseLocations(data);
    if (id) return id;
    console.warn('[GHL fetchLocationId] locations/search 200 but no location in response. Top-level keys:', Object.keys(data));
    return null;
  }

  const errMsg = data?.message ?? data?.error ?? data?.error_description ?? (typeof data === 'object' ? JSON.stringify(data).slice(0, 200) : '');
  console.warn('[GHL fetchLocationId] locations/search failed', r.status, errMsg);

  return null;
}

module.exports = { ghlFetch, fetchLocationIdFromApi, GHL_VERSION };
