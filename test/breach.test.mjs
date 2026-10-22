/**
 * Breach detection tests — the fetch layer is STUBBED; no real network calls.
 * Verifies k-anonymity (only the 5-char prefix leaves), caching, and the
 * fail-open contract (transport errors never report "breached", never throw).
 * Run: node --test test/breach.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkBreached, clearBreachCache } from '../lib/breach.js'

function fakeFetch(handler) {
  const calls = []
  return { calls, fetch: async (url, opts) => {
    calls.push({ url, opts })
    return handler(url, opts)
  } }
}

test('known-common passwords short-circuit offline (no fetch at all)', async () => {
  const { calls, fetch } = fakeFetch(() => { throw new Error('should not fetch') })
  const r = await checkBreached('password', { fetch })
  assert.equal(r.breached, true)
  assert.equal(r.source, 'local')
  assert.equal(calls.length, 0)
})

test('k-anonymity: only the 5-char SHA-1 prefix is requested; suffix compared locally', async () => {
  clearBreachCache()
  // sha1('not-a-real-pw-99') = ?
  const { createHash } = await import('node:crypto')
  const hash = createHash('sha1').update('not-a-real-pw-99').digest('hex').toUpperCase()
  const prefix = hash.slice(0, 5)
  const suffix = hash.slice(5).toLowerCase()
  const { calls, fetch } = fakeFetch(async () => ({
    ok: true,
    text: async () => 'DEAD0:9\n' + suffix + ':42\nBEEEF:1',
  }))
  const r = await checkBreached('not-a-real-pw-99', { fetch })
  assert.equal(r.breached, true)
  assert.equal(r.source, 'hibp')
  assert.equal(calls.length, 1)
  assert.ok(calls[0].url.endsWith(`/${prefix}`), `url ${calls[0].url} must carry ONLY the 5-char prefix`)
  assert.ok(!calls[0].url.includes(suffix), 'full hash must NEVER leave the process')
  assert.equal(calls[0].opts.headers['Add-Padding'], 'true')
})

test('non-breached: suffix absent from the range body', async () => {
  clearBreachCache()
  const { fetch } = fakeFetch(async () => ({ ok: true, text: async () => 'AAAAAA:1\nBBBBBB:2' }))
  const r = await checkBreached('unique-string-1234', { fetch })
  assert.equal(r.breached, false)
  assert.equal(r.source, 'hibp')
})

test('cache: repeating a lookup with the same prefix skips the network', async () => {
  clearBreachCache()
  let hits = 0
  const { fetch } = fakeFetch(async () => { hits++; return { ok: true, text: async () => 'NEVER:1' } })
  await checkBreached('cache-test-pw-A', { fetch })
  await checkBreached('cache-test-pw-A', { fetch }) // same password → same prefix
  assert.equal(hits, 1, 'range cache must serve the second call')
})

test('transport failure fails OPEN: source=offline, breached=false', async () => {
  clearBreachCache()
  const { fetch } = fakeFetch(async () => { throw new Error('ECONNREFUSED') })
  const r = await checkBreached('any-pw-123', { fetch })
  assert.equal(r.breached, false)
  assert.equal(r.source, 'offline')
})

test('HTTP error status fails open too', async () => {
  clearBreachCache()
  const { fetch } = fakeFetch(async () => ({ ok: false, status: 503, text: async () => '' }))
  const r = await checkBreached('any-pw-456', { fetch })
  assert.equal(r.breached, false)
  assert.equal(r.source, 'offline')
})

test('offline:true never touches the network', async () => {
  const { calls, fetch } = fakeFetch(() => { throw new Error('must not fetch') })
  const r = await checkBreached('some-pw', { fetch, offline: true })
  assert.equal(r.source, 'local')
  assert.equal(calls.length, 0)
})
