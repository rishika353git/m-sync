/**
 * Extract locationId from a GHL OAuth access token (JWT).
 * Used when the token exchange response omits locationId (e.g. some app types or legacy flows).
 * Decodes without verification (read-only); returns null if not present or invalid.
 */
const jwt = require('jsonwebtoken');

function getLocationIdFromGhlToken(accessToken) {
  if (!accessToken || typeof accessToken !== 'string') return null;
  try {
    const payload = jwt.decode(accessToken);
    if (!payload || typeof payload !== 'object') return null;
    // GHL JWT can use locationId, location_id, companyId, location, sub, or context.locationId
    const id =
      payload.locationId ??
      payload.location_id ??
      payload.companyId ??
      payload.location ??
      (payload.context && (payload.context.locationId ?? payload.context.location_id ?? payload.context.companyId)) ??
      payload.sub ??
      null;
    if (id == null) return null;
    return typeof id === 'string' ? id : String(id);
  } catch {
    return null;
  }
}

module.exports = { getLocationIdFromGhlToken };
