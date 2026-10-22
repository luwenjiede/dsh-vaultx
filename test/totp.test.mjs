/**
 * TOTP tests against the RFC 6238 Appendix B vectors and RFC 4226 HOTP vectors.
 * RFC 6238 secret: ASCII "12345678901234567890" (4232423434424447494A4B4E505152525455)
 * Run: node --test test/totp.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { hotp, totp, verifyTotp, base32Decode, base32Encode, totpUri } from '../lib/totp.js'

const RFC_BYTES = Buffer.from('12345678901234567890', 'utf8')
// base32 of the RFC secret, uppercase, unpadded
const RFC_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

test('base32 decode/encode round-trip + RFC secret', () => {
  assert.deepEqual(base32Decode(RFC_B32), RFC_BYTES)
  assert.equal(base32Encode(RFC_BYTES), RFC_B32)
  assert.deepEqual(base32Decode('MFRGG==='), Buffer.from('abc'))
})

test('base32 rejects invalid characters', () => {
  assert.throws(() => base32Decode('0189!@#'), /invalid base32/)
})

test('HOTP RFC 4226 Appendix D vectors (counter 0..9)', () => {
  // Table 2 of RFC 4226 itself (fetched 2026-10-23): the truncated decimal.
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  expected.forEach((code, counter) => {
    assert.equal(hotp(RFC_B32, counter), code, `counter ${counter}`)
  })
})

test('TOTP RFC 6238 Appendix B vectors (SHA1, 8 digits)', () => {
  const vectors = [
    [59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130'],
  ]
  for (const [time, expected] of vectors) {
    assert.equal(totp(RFC_B32, time, { digits: 8 }), expected, `t=${time}`)
  }
})

test('TOTP default is 6 digits (truncation keeps the LAST six: 94287082 → 287082)', () => {
  assert.equal(totp(RFC_B32, 59).length, 6)
  assert.equal(totp(RFC_B32, 59), '287082')
})

test('TOTP SHA256 vector (RFC 6238 B, t=59)', () => {
  const key256 = Buffer.from('12345678901234567890123456789012', 'utf8')
  assert.equal(totp(key256, 59, { digits: 8, algo: 'sha256' }), '46119246')
})

test('TOTP SHA512 vector (RFC 6238 B, t=59)', () => {
  const key512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'utf8')
  assert.equal(totp(key512, 59, { digits: 8, algo: 'sha512' }), '90693936')
})

test('verifyTotp accepts window ±1 and rejects bad codes', () => {
  const t = 1111111111
  assert.equal(verifyTotp(RFC_B32, totp(RFC_B32, t), { timeSeconds: t + 30, window: 1 }), true)
  assert.equal(verifyTotp(RFC_B32, totp(RFC_B32, t), { timeSeconds: t - 30, window: 1 }), true)
  assert.equal(verifyTotp(RFC_B32, totp(RFC_B32, t), { timeSeconds: t + 61, window: 1 }), false)
  assert.equal(verifyTotp(RFC_B32, '0000000', { timeSeconds: t }), false) // wrong length
  assert.equal(verifyTotp(RFC_B32, 'abcdef', { timeSeconds: t }), false)
})

test('totpUri builds otpauth URL', () => {
  const uri = totpUri({ secret: RFC_B32, label: 'Acme:jane', issuer: 'Acme' })
  assert.match(uri, /^otpauth:\/\/totp\/Acme%3Ajane\?/)
  assert.match(uri, /secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ/)
  assert.match(uri, /issuer=Acme/)
})
