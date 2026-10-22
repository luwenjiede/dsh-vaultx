/**
 * Breach detection via haveibeenpwned's Pwned Passwords range API —
 * k-anonymity as designed by the service: only the first 5 hex characters of
 * the SHA-1 are ever transmitted; the suffix is compared locally.
 *
 * Fail-closed on privacy, fail-open on availability: any transport/HTTP error
 * returns `source: 'offline'` and never blocks the operation.
 *
 * @module vaultx/breach
 */
import { sha1Hex } from './crypto.js'

const RANGE_URL = 'https://api.pwnedpasswords.com/range/'
const TIMEOUT_MS = 12_000
const CACHE_TTL_MS = 60 * 60 * 1000

/** prefix → { at, suffixes:Set<string> } */
const rangeCache = new Map()

/** Offline weak list shared with the strength estimator's spirit. */
const OFFLINE_BREACHED = new Set([
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
  '1234567', 'dragon', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow',
  'master', '666666', 'qwertyuiop', '1234567890', 'superman', '000000', 'iloveyou',
])

/**
 * Query one k-anonymous range. Returns a Set of lowercase suffixes.
 * @param {string} prefix - 5 uppercase hex characters.
 */
async function queryRange(prefix, fetchImpl = fetch) {
  const res = await fetchImpl(`${RANGE_URL}${prefix}`, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { 'User-Agent': 'dsh-vaultx', 'Add-Padding': 'true' },
  })
  if (!res.ok) throw new Error(`Pwned Passwords HTTP ${res.status}`)
  const text = await res.text()
  const suffixes = new Set()
  for (const line of text.split('\n')) {
    const suffix = line.split(':')[0]
    if (suffix) suffixes.add(suffix.toLowerCase())
  }
  return suffixes
}

/**
 * Check a candidate password against HIBP (and an offline list).
 * @param {string} password
 * @param {{fetch?:typeof fetch,offline?:boolean}} [opts]
 * @returns {Promise<{breached:boolean, source:'hibp'|'offline'|'local', reason?:string}>}
 */
export async function checkBreached(password, { fetch: fetchImpl = fetch, offline = false } = {}) {
  const lower = String(password ?? '').toLowerCase()
  if (OFFLINE_BREACHED.has(lower)) return { breached: true, source: 'local', reason: 'known-common' }
  if (offline || !lower) return { breached: false, source: 'local' }

  const hash = sha1Hex(password)
  const prefix = hash.slice(0, 5)
  const suffix = hash.slice(5).toLowerCase()

  const cached = rangeCache.get(prefix)
  const now = Date.now()
  if (cached && now - cached.at < CACHE_TTL_MS) {
    return cached.suffixes.has(suffix)
      ? { breached: true, source: 'hibp', reason: 'pwned' }
      : { breached: false, source: 'hibp' }
  }

  try {
    const suffixes = await queryRange(prefix, fetchImpl)
    rangeCache.set(prefix, { at: now, suffixes })
    return suffixes.has(suffix)
      ? { breached: true, source: 'hibp', reason: 'pwned' }
      : { breached: false, source: 'hibp' }
  } catch {
    // Availability first: never fail the user's operation over a lookup.
    return { breached: false, source: 'offline' }
  }
}

/** Test hook: drop the in-memory range cache. */
export function clearBreachCache() {
  rangeCache.clear()
}
