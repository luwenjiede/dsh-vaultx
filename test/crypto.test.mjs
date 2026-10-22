/**
 * Crypto core tests: round-trips, AAD binding, tamper detection, KDF sanity.
 * Run: node --test test/crypto.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  newVaultKey, newKdfParams, deriveMasterKey, seal, unseal, wrapKey, unwrapKey,
  makeCheck, verifyCheck, fieldAad, safeEqual, sha1Hex,
} from '../lib/crypto.js'

test('deriveMasterKey is deterministic and 32 bytes', async () => {
  const params = newKdfParams()
  const a = await deriveMasterKey('correct horse battery staple', params)
  const b = await deriveMasterKey('correct horse battery staple', params)
  assert.equal(a.length, 32)
  assert.deepEqual(a, b)
  const c = await deriveMasterKey('Correct horse battery staple', params)
  assert.notDeepEqual(a, c)
})

test('deriveMasterKey rejects empty password', async () => {
  await assert.rejects(() => deriveMasterKey('', newKdfParams()), /non-empty/)
})

test('salt is random per KDF params', () => {
  const set = new Set(Array.from({ length: 8 }, () => newKdfParams().saltHex))
  assert.equal(set.size, 8)
})

test('seal/unseal round-trip with AAD', () => {
  const key = newVaultKey()
  const aad = fieldAad('entry1', 'password')
  const blob = seal('s3cr3t-ünicode', key, aad)
  assert.equal(unseal(blob, key, aad).toString('utf8'), 's3cr3t-ünicode')
})

test('same plaintext twice yields different ciphertext (fresh nonce)', () => {
  const key = newVaultKey()
  const a = seal('x', key, 'aad')
  const b = seal('x', key, 'aad')
  assert.notEqual(a.dataHex, b.dataHex)
  assert.notEqual(a.ivHex, b.ivHex)
})

test('wrong key fails to unseal (GCM auth)', () => {
  const blob = seal('x', newVaultKey(), 'aad')
  assert.throws(() => unseal(blob, newVaultKey(), 'aad'))
})

test('tampered ciphertext fails to unseal', () => {
  const key = newVaultKey()
  const blob = seal('hello', key, 'aad')
  const flipped = { ...blob, dataHex: blob.dataHex.slice(0, -2) + (blob.dataHex.slice(-2) === 'ff' ? '00' : 'ff') }
  assert.throws(() => unseal(flipped, key, 'aad'))
})

test('AAD is bound: wrong field name for same entry decrypts to nothing', () => {
  const key = newVaultKey()
  const blob = seal('pw', key, fieldAad('e1', 'password'))
  assert.throws(() => unseal(blob, key, fieldAad('e1', 'apiKey')), /(unable to decrypt|bad decrypt|auth)/i)
  assert.throws(() => unseal(blob, key, fieldAad('e2', 'password')), /(unable|bad|auth)/i)
})

test('wrap/unwrap key round-trip and wrong-MK rejection', async () => {
  const vk = newVaultKey()
  const mk1 = await deriveMasterKey('password-one', newKdfParams())
  const mk2 = await deriveMasterKey('password-two', newKdfParams())
  const wrapped = wrapKey(vk, mk1)
  assert.deepEqual(unwrapKey(wrapped, mk1), vk)
  assert.throws(() => unwrapKey(wrapped, mk2))
})

test('check token validates only the right VK', async () => {
  const vk = newVaultKey()
  const check = makeCheck(vk)
  assert.equal(verifyCheck(check, vk), true)
  assert.equal(verifyCheck(check, newVaultKey()), false)
})

test('full unlock path: header round-trip', async () => {
  const vk = newVaultKey()
  const kdf = newKdfParams()
  const mk = await deriveMasterKey('master-pw-123', kdf)
  const header = { kdf, wrappedKey: wrapKey(vk, mk), check: makeCheck(vk) }
  // wrong password -> unwrap throws
  const badMk = await deriveMasterKey('not-the-master', kdf)
  assert.throws(() => unwrapKey(header.wrappedKey, badMk))
  // right password -> unwrap then verify check
  assert.equal(verifyCheck(header.check, unwrapKey(header.wrappedKey, mk)), true)
})

test('safeEqual', () => {
  assert.equal(safeEqual('abc', 'abc'), true)
  assert.equal(safeEqual('abc', 'abd'), false)
  assert.equal(safeEqual('abc', 'abcd'), false)
})

test('sha1Hex matches node reference for the HIBP prefix protocol', () => {
  // known digests: sha1("password") / sha1("Hello World!")
  assert.equal(sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8')
  assert.equal(sha1Hex('Hello World!'), '2EF7BDE608CE5404E97D5F042F95F89F1C232871')
  const hash = sha1Hex('anything')
  assert.equal(hash.slice(0, 5).toUpperCase(), hash.slice(0, 5))
  assert.equal(hash.length, 40)
})
