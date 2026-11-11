/**
 * Generator tests — wordlist integrity, true generation entropy (P0-4),
 * distribution sanity. Run: node --test test/generate.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EFF_SHORT_WORDS } from '../lib/wordlist.js'
import { generatePassphrase, generatePassword, generateToken, generateTotpSecret, generationBits, PASSPHRASE_WORD_BITS } from '../lib/generate.js'

test('wordlist is the full EFF short list: 1296 unique lowercase words', () => {
  assert.equal(EFF_SHORT_WORDS.length, 1296)
  assert.equal(new Set(EFF_SHORT_WORDS).size, 1296, 'no duplicates (the old inline list had 698 + 1 dup)')
  assert.ok(EFF_SHORT_WORDS.every(w => typeof w === 'string' && /^[a-z][a-z-]{2,8}$/.test(w)), 'all words lowercase alpha (EFF allows hyphenated tokens like yo-yo)')
})

test('per-word entropy is log2(1296) ≈ 10.34 bits, not the old ~9.44', () => {
  assert.ok(Math.abs(PASSPHRASE_WORD_BITS - Math.log2(1296)) < 1e-9)
  assert.ok(PASSPHRASE_WORD_BITS > 10.3 && PASSPHRASE_WORD_BITS < 10.4)
})

test('generationBits reports TRUE generation entropy (P0-4)', () => {
  assert.equal(generationBits('passphrase', { words: 4 }), Math.round(4 * Math.log2(1296) + Math.log2(90)))
  assert.equal(generationBits('token'), 256)
  assert.equal(generationBits('totp'), 160)
  assert.equal(generationBits('password'), null, 'charset passwords keep the estimator')
})

test('passphrase samples stay inside the wordlist, digits appended once', () => {
  for (let i = 0; i < 60; i++) {
    const p = generatePassphrase({ words: 5 })
    const parts = p.split('-')
    assert.equal(parts.length, 5)
    for (const w of parts.slice(0, 4)) assert.ok(EFF_SHORT_WORDS.includes(w), `word not in list: ${w}`)
    assert.match(parts[4], /^[a-z]{3,8}\d{2}$/, 'last word carries the 2-digit suffix')
  }
})

test('passphrase 4-word entropy is >= 44 bits (old list claimed ~40)', () => {
  const bits = generationBits('passphrase', { words: 4 })
  assert.ok(bits >= 44, `expected >=44, got ${bits}`)
})

test('password generator: charset rules + uniformity sanity', () => {
  for (let i = 0; i < 30; i++) {
    const p = generatePassword({ length: 24 })
    assert.equal(p.length, 24)
    assert.match(p, /[a-z]/), assert.match(p, /[A-Z]/), assert.match(p, /[0-9]/), assert.match(p, /[^a-zA-Z0-9]/)
    assert.ok(!/^(.)\\1+$/.test(p), 'not a single repeated char')
  }
  // noAmbiguous excludes i/l/o/I/L/O/0/1 — and the pools must actually agree
  // with the comment (they didn't before the fix: lower kept i/o, upper kept L)
  const clean = generatePassword({ length: 128, noAmbiguous: true })
  assert.ok(!/[iloILO01]/.test(clean), `noAmbiguous pool leaked: ${clean.match(/[iloILO01]/)?.[0]}`)
  const full = generatePassword({ length: 128, noAmbiguous: false })
  // P(any single ambiguous char absent from 128 draws) ≈ (1-1/88)^128 ≈ 23%,
  // so per-char assertions flake. Assert on the GROUP instead: P(no i/l/o at
  // all) ≈ (85/88)^128 ≈ 1.2%, and loop the whole check to push the flake
  // probability to negligible (3 independent 128-char samples).
  let groupSeen = false
  for (let i = 0; i < 3 && !groupSeen; i++) {
    const s = i === 0 ? full : generatePassword({ length: 128, noAmbiguous: false })
    if (/[ilo]/.test(s) && /[ILO]/.test(s) && /[01]/.test(s)) groupSeen = true
  }
  assert.ok(groupSeen, 'noAmbiguous=false must restore the full pools')
  assert.throws(() => generatePassword({ length: 7 }), /\[8, 128\]/)
  assert.throws(() => generatePassword({ length: 129 }), /\[8, 128\]/)
})

test('token / totp secret shapes', () => {
  assert.match(generateToken(), /^[A-Za-z0-9_-]{43}$/, '256-bit base64url, no prefix')
  assert.match(generateToken({ prefix: 'sk-' }), /^sk-[A-Za-z0-9_-]{43}$/)
  const secret = generateTotpSecret()
  assert.match(secret, /^[A-Z2-7]{32}$/, '160-bit base32, unpadded')
})
