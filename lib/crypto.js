/**
 * VaultX crypto core — dependency-free, node:crypto only.
 *
 * Envelope design (see docs/ARCHITECTURE.md):
 *   - A random 256-bit Vault Key (VK) encrypts every credential field with
 *     AES-256-GCM. Each field gets a fresh 96-bit nonce and its AAD binds
 *     `entryId|fieldName|formatVersion`, so ciphertext cannot be spliced
 *     between entries or fields without detection.
 *   - The operator's master password never encrypts data directly. It derives
 *     a Master Key (MK) via scrypt(N=2^15, r=8, p=1, 16-byte random salt)
 *     which only wraps VK. Rotating the master password re-wraps VK; the
 *     entries are untouched.
 *   - A fixed plaintext "check token" encrypted under VK lets an unlock
 *     attempt validate itself (GCM tag failure = wrong password) and powers
 *     the brute-force lockout counter.
 *
 * @module vaultx/crypto
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
  createHmac,
  timingSafeEqual,
  scrypt as scryptCb,
} from 'node:crypto'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCb)

/** AES-256 key length in bytes. */
export const KEY_BYTES = 32
/** GCM recommended nonce length. */
export const NONCE_BYTES = 12
/** scrypt cost parameters baked into new vaults. */
export const SCRYPT = Object.freeze({ n: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
/** Format version bound into every AAD. */
export const FORMAT_VERSION = 1

/** Generate a fresh random vault key (32 bytes). */
export function newVaultKey() {
  return randomBytes(KEY_BYTES)
}

/** Fresh KDF parameter set with a random salt. */
export function newKdfParams() {
  return {
    algo: 'scrypt',
    n: SCRYPT.n,
    r: SCRYPT.r,
    p: SCRYPT.p,
    saltHex: randomBytes(16).toString('hex'),
  }
}

/**
 * Derive the Master Key from the operator's master password.
 * @param {string} masterPassword
 * @param {{n:number,r:number,p:number,saltHex:string}} params - from the vault header.
 * @returns {Promise<Buffer>} 32-byte key.
 */
export async function deriveMasterKey(masterPassword, params) {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new Error('vaultx: master password must be a non-empty string')
  }
  return scrypt(Buffer.from(masterPassword, 'utf8'), Buffer.from(params.saltHex, 'hex'), KEY_BYTES, {
    N: params.n,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT.maxmem,
  })
}

/**
 * AES-256-GCM seal.
 * @param {Buffer} plaintext
 * @param {Buffer} key - 32 bytes.
 * @param {Buffer|string} aad - additional authenticated data (string or Buffer).
 * @returns {{ivHex:string,tagHex:string,dataHex:string}}
 */
export function seal(plaintext, key, aad = '') {
  const iv = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const aadBuf = typeof aad === 'string' ? Buffer.from(aad, 'utf8') : aad
  if (aadBuf.length) cipher.setAAD(aadBuf)
  const data = Buffer.concat([cipher.update(toBuffer(plaintext)), cipher.final()])
  return { ivHex: iv.toString('hex'), tagHex: cipher.getAuthTag().toString('hex'), dataHex: data.toString('hex') }
}

/**
 * AES-256-GCM open. Throws on any tampering or wrong key (never returns garbage).
 * @param {{ivHex:string,tagHex:string,dataHex:string}} blob
 * @param {Buffer} key
 * @param {Buffer|string} aad
 * @returns {Buffer} plaintext.
 */
export function unseal(blob, key, aad = '') {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(blob.ivHex, 'hex'))
  const aadBuf = typeof aad === 'string' ? Buffer.from(aad, 'utf8') : aad
  if (aadBuf.length) decipher.setAAD(aadBuf)
  decipher.setAuthTag(Buffer.from(blob.tagHex, 'hex'))
  return Buffer.concat([decipher.update(Buffer.from(blob.dataHex, 'hex')), decipher.final()])
}

/** The fixed plaintext every vault encrypts under VK to validate an unlock. */
const CHECK_PLAINTEXT = 'vaultx-check-v1'

/** Wrap the vault key under the master key. */
export function wrapKey(vaultKey, masterKey) {
  return seal(vaultKey, masterKey, 'vaultx-wrapped-key-v1')
}

/** Unwrap the vault key; throws if the master key is wrong. */
export function unwrapKey(wrapped, masterKey) {
  return unseal(wrapped, masterKey, 'vaultx-wrapped-key-v1')
}

/** Encrypt the check token under VK. */
export function makeCheck(vaultKey) {
  return seal(CHECK_PLAINTEXT, vaultKey, 'vaultx-check-v1')
}

/** True iff the blob decrypts as the expected check plaintext. */
export function verifyCheck(check, vaultKey) {
  try {
    return unseal(check, vaultKey, 'vaultx-check-v1').toString('utf8') === CHECK_PLAINTEXT
  } catch {
    return false
  }
}

/** AAD for one entry field: binds the id and field name into the ciphertext. */
export function fieldAad(entryId, fieldName) {
  return `${entryId}|${fieldName}|${FORMAT_VERSION}`
}

/** Constant-time equality over equal-length buffers; safe for tokens. */
export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a), 'utf8')
  const bufB = Buffer.from(String(b), 'utf8')
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB)
}

/** Random id: 24 hex chars. */
export function newId() {
  return randomBytes(12).toString('hex')
}

/**
 * SHA-1 hex (uppercase) for the HIBP k-anonymity protocol. SHA-1 here is a
 * lookup index, never a security decision.
 */
export function sha1Hex(text) {
  return createHash('sha1').update(text, 'utf8').digest('hex').toUpperCase()
}

/** HMAC helper for TOTP and the audit hash chain. */
export function hmac(algo, key, data) {
  return createHmac(algo, key).update(data).digest()
}

/** SHA-256 hex digest. */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex')
}

/** Accept string|Buffer everywhere crypto receives plaintext. */
function toBuffer(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
}
