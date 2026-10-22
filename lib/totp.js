/**
 * RFC 4226 (HOTP) / RFC 6238 (TOTP) + RFC 4648 base32 — zero dependencies.
 *
 * Kept deliberately small and testable; vectors from the RFCs run in
 * test/totp.test.mjs.
 *
 * @module vaultx/totp
 */
import { randomBytes } from 'node:crypto'
import { hmac } from './crypto.js'

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decode RFC 4648 base32 (unpadded). Throws on invalid characters.
 * @param {string} input
 * @returns {Buffer}
 */
export function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '')
  if (!clean) return Buffer.alloc(0)
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error('vaultx: invalid base32 input')
  let bits = 0
  let value = 0
  const out = []
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch)
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** Encode a buffer as unpadded uppercase base32. */
export function base32Encode(buf) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

/** Generate a fresh random base32 secret (default 160 bits, per RFC 4226 guidance). */
export function generateSecret(bytes = 20) {
  return base32Encode(randomBytes(bytes))
}

/**
 * HOTP per RFC 4226 §5.4 (dynamic truncation).
 * @param {Buffer|string} key - raw secret bytes or base32 string.
 * @param {number} counter
 * @param {{digits?:number,algo?:'sha1'|'sha256'|'sha512'}} [opts]
 */
export function hotp(key, counter, { digits = 6, algo = 'sha1' } = {}) {
  const keyBuf = typeof key === 'string' ? base32Decode(key) : key
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt.asUintN(64, BigInt(counter)))
  const digest = hmac(algo, keyBuf, buf)
  const offset = digest[digest.length - 1] & 0x0f
  const code = ((digest[offset] & 0x7f) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3]) % 10 ** digits
  return String(code).padStart(digits, '0')
}

/**
 * TOTP per RFC 6238 §5.
 * @param {Buffer|string} key
 * @param {number} [timeSeconds] - unix seconds; defaults to now.
 * @param {{digits?:number,period?:number,algo?:'sha1'|'sha256'|'sha512'}} [opts]
 */
export function totp(key, timeSeconds = Math.floor(Date.now() / 1000), { period = 30, ...rest } = {}) {
  return hotp(key, Math.floor(timeSeconds / period), rest)
}

/** Seconds remaining in the current TOTP window (for UI countdowns). */
export function totpRemaining(period = 30, timeSeconds = Math.floor(Date.now() / 1000)) {
  return period - (timeSeconds % period)
}

/**
 * Constant-time-ish verification with an acceptable drift window.
 * @param {Buffer|string} key
 * @param {string} code - the digits to check.
 * @param {{window?:number,period?:number,digits?:number,algo?:string,timeSeconds?:number}} [opts]
 */
export function verifyTotp(key, code, { window = 1, period = 30, digits = 6, algo = 'sha1', timeSeconds = Math.floor(Date.now() / 1000) } = {}) {
  if (typeof code !== 'string' || !new RegExp(`^\\d{${digits}}$`).test(code)) return false
  const counter = Math.floor(timeSeconds / period)
  for (let i = -window; i <= window; i++) {
    if (hotp(key, counter + i, { digits, algo }) === code) return true
  }
  return false
}

/**
 * Build an `otpauth://` URI (RFC draft / Keyex URL scheme) for QR provisioning.
 */
export function totpUri({ secret, label, issuer, period = 30, digits = 6, algo = 'SHA1' }) {
  const enc = encodeURIComponent
  const params = new URLSearchParams({ secret: String(secret).toUpperCase(), algorithm: algo, digits: String(digits), period: String(period) })
  if (issuer) params.set('issuer', issuer)
  return `otpauth://totp/${enc(label ?? issuer ?? 'vaultx')}?${params.toString()}`
}
