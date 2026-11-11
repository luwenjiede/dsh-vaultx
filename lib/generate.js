/**
 * Cryptographically secure password / passphrase / secret generation.
 *
 * Uses rejection sampling on random bytes so output is unbiased (the usual
 * `rand % len` bug gives some characters more weight — here the distribution
 * is exactly uniform).
 *
 * @module vaultx/generate
 */
import { randomBytes, randomInt } from 'node:crypto'
import { base32Encode } from './totp.js'
import { EFF_SHORT_WORDS } from './wordlist.js'

const SETS = {
  lower: 'abcdefghjkmnpqrstuvwxyz',        // i/l/o excluded for reading aloud
  upper: 'ABCDEFGHJKMNPQRSTUVWXYZ',        // I/L/O excluded
  digits: '23456789',                      // 0/1 excluded
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
  ambiguous: 'il1Lo0',
}

/** Wordlist: the full EFF short list 1 — 1296 unique words, CC-BY-3.0 (EFF).
 *  Review P0-4: the previous inline list had 698 entries incl. a duplicate,
 *  inflating the advertised per-word entropy. See lib/wordlist.js. */
const WORDS = EFF_SHORT_WORDS
/** True generation entropy of one passphrase word: log2(1296) ≈ 10.34 bits. */
export const PASSPHRASE_WORD_BITS = Math.log2(WORDS.length)

/** Draw one uniform index below `len` by rejection sampling on random bytes. */
function uniformIndex(len) {
  // Accept bytes < the largest multiple of len that fits in a byte, then
  // reduce: this yields a perfectly uniform index over [0, len).
  const limit = 256 - (256 % len)
  let byte
  do { byte = randomBytes(1)[0] } while (byte >= limit)
  return byte % len
}

/** True if char ch is present in at least one active set of the mask. */
function pickFrom(charsets) {
  const all = charsets.join('')
  return all[uniformIndex(all.length)]
}

/**
 * Generate a random password. Guarantees at least one char from each
 * enabled set when length permits.
 * @param {{length?:number,lower?:boolean,upper?:boolean,digits?:boolean,symbols?:boolean,noAmbiguous?:boolean}} [opts]
 */
export function generatePassword(opts = {}) {
  const {
    length = 24,
    lower = true,
    upper = true,
    digits = true,
    symbols = true,
    noAmbiguous = true,
  } = opts
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new Error('vaultx: password length must be an integer in [8, 128]')
  }
  const charsets = []
  if (lower) charsets.push(noAmbiguous ? SETS.lower : SETS.lower + 'ilo')
  if (upper) charsets.push(noAmbiguous ? SETS.upper : SETS.upper + 'ILO')
  if (digits) charsets.push(noAmbiguous ? SETS.digits : SETS.digits + '01')
  if (symbols) charsets.push(SETS.symbols)
  if (!charsets.length) throw new Error('vaultx: at least one character set must be enabled')

  const out = []
  // one guaranteed sample per set (length >= sets count enforced: sets <= 4 <= 8 <= length)
  for (const cs of charsets) {
    out.push(cs[uniformIndex(cs.length)])
  }
  while (out.length < length) out.push(pickFrom(charsets))
  // Fisher-Yates over the pool so guaranteed chars aren't positional.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out.join('')
}

/**
 * Generate a diceware-style passphrase: random words separated by a symbol.
 * @param {{words?:number,separator?:string,capitalize?:boolean,appendDigits?:boolean}} [opts]
 */
export function generatePassphrase(opts = {}) {
  const { words = 4, separator = '-', capitalize = false, appendDigits = true } = opts
  if (!Number.isInteger(words) || words < 3 || words > 10) {
    throw new Error('vaultx: word count must be an integer in [3, 10]')
  }
  const chosen = []
  for (let i = 0; i < words; i++) chosen.push(WORDS[randomInt(WORDS.length)])
  let out = chosen.map(w => (capitalize ? w[0].toUpperCase() + w.slice(1) : w)).join(separator)
  if (appendDigits) out += String(randomInt(10, 100))
  return out
}

/** Generate a fresh base32 TOTP secret (160-bit). */
export function generateTotpSecret() {
  return base32Encode(randomBytes(20))
}

/** Generate an API-key-like token: URL-safe, 256-bit entropy. */
export function generateToken({ prefix = '' } = {}) {
  return `${prefix}${randomBytes(32).toString('base64url')}`
}

/**
 * TRUE generation entropy for a generated secret (review P0-4). The charset
 * estimator in strength.js overestimates passphrases (it prices characters,
 * not the word draws); callers reporting strengthBits for freshly generated
 * values must use this instead.
 * @param {'password'|'passphrase'|'token'|'totp'} style
 * @param {{words?:number,length?:number}} [opts] - generation options used.
 */
export function generationBits(style, { words = 4 } = {}) {
  switch (style) {
    case 'passphrase': return Math.round(words * PASSPHRASE_WORD_BITS + Math.log2(90)) // +2 digits
    case 'token': return 256
    case 'totp': return 160
    default: return null // charset passwords: estimator is close enough
  }
}
