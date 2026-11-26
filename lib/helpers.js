'use strict';

// Pure helpers with no NodeBB dependency, so they can be unit-tested.

const crypto = require('node:crypto');

const DEFAULT_BASE_URL = 'https://one.th';

/** A OneID account id is a string of digits and nothing else. */
function isAccountID(id) {
  return typeof id === 'string' && /^\d{1,32}$/.test(id);
}

/**
 * Normalise the "Server" ACP setting to an origin such as `https://one.th`.
 * Anything that is not an https URL falls back to the production host.
 */
function normalizeBaseURL(value) {
  if (typeof value !== 'string' || !value.trim()) return DEFAULT_BASE_URL;
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== 'https:') return DEFAULT_BASE_URL;
    return parsed.origin;
  } catch {
    return DEFAULT_BASE_URL;
  }
}

/** URL that signs the user out of OneID and then sends them to `redirectTo`. */
function oneIDLogoutURL(baseURL, redirectTo) {
  return `${baseURL}/api/oauth/logout?redirect_url=${encodeURIComponent(redirectTo)}`;
}

/** Normalise ids (business ids, account ids) to trimmed, non-empty strings. */
function toIdList(values) {
  if (!Array.isArray(values)) return [];
  return values.map(v => (v === undefined || v === null ? '' : String(v).trim())).filter(Boolean);
}

/**
 * Parse the body of OneID's list-business call into a list of business ids.
 * Throws when the response is not the documented shape, so the caller can treat
 * membership as unknown.
 */
function parseBusinessIds(body) {
  const parsed = JSON.parse(body);
  if (!parsed || !Array.isArray(parsed.data)) {
    throw new Error('Unexpected list-business response');
  }
  return toIdList(parsed.data.map(b => b && b.id));
}

/**
 * Decide whether an account may log in under the configured business allowlist.
 * @param {string[]} allowed configured business ids (empty = no gate)
 * @param {string[]|null} memberOf the account's business ids, null when unknown
 * @returns {'allow'|'deny'|'unknown'}
 */
function businessAccess(allowed, memberOf) {
  const gate = toIdList(allowed);
  if (gate.length === 0) return 'allow';
  if (!Array.isArray(memberOf)) return 'unknown';
  const gateSet = new Set(gate);
  return toIdList(memberOf).some(id => gateSet.has(id)) ? 'allow' : 'deny';
}

/** Is the account id on the block list? Compared as strings. */
function isBlocked(blockList, accountID) {
  if (accountID === undefined || accountID === null) return false;
  return toIdList(blockList).includes(String(accountID).trim());
}

/** Build the passport profile from the OneID account response body. */
function parseProfile(body, provider) {
  const parsed = JSON.parse(body);
  const account = parsed && parsed.data;
  if (!account || account.id === undefined || account.id === null || account.id === '') {
    throw new Error('Unexpected account response');
  }
  const profile = {
    id: String(account.id),
    email: account.thai_email,
    displayName: `${account.account_title_th || ''}${account.first_name_th || ''} ${account.last_name_th || ''}`.trim(),
    provider,
    birthday: account.birth_date,
  };
  if (account.account_category !== 'Residential') {
    profile.displayName = `${account.account_title_eng || ''} ${account.first_name_eng || ''} ${account.last_name_eng || ''}`.trim();
  }
  return profile;
}

function getUsernameFromEmail(email) {
  if (typeof email !== 'string') return null;
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) return null;
  return email.substring(0, atIndex);
}

function generateState() {
  return crypto.randomBytes(32).toString('hex');
}

/** Constant-time comparison of the OAuth2 `state` value. */
function stateMatches(expected, actual) {
  if (typeof expected !== 'string' || typeof actual !== 'string' || !expected) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(actual);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Read the shared token from the query string or the body; null when absent or malformed. */
function readSharedToken(req) {
  const value = (req.query && req.query.sharedtoken) || (req.body && req.body.sharedtoken);
  if (typeof value !== 'string' || !value || value.length > 8192) return null;
  return value;
}

/**
 * Reconstruct the original URL of the request (protocol, host and path),
 * honouring X-Forwarded-* headers only when the app trusts its proxy.
 */
function originalURL(req, options) {
  options = options || {};
  const app = req.app;
  const trustProxy = options.proxy || (app && app.get && app.get('trust proxy'));

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  const tls = (req.socket && req.socket.encrypted) || (trustProxy && proto.split(/\s*,\s*/)[0] === 'https');
  const host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
  return `${tls ? 'https' : 'http'}://${host}${req.url || ''}`;
}

module.exports = {
  DEFAULT_BASE_URL,
  isAccountID,
  normalizeBaseURL,
  oneIDLogoutURL,
  toIdList,
  parseBusinessIds,
  businessAccess,
  isBlocked,
  parseProfile,
  getUsernameFromEmail,
  generateState,
  stateMatches,
  readSharedToken,
  originalURL,
};
