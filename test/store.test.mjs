/**
 * Encrypted store tests — round-trips, wrong password, tamper, atomicity.
 * Run: node --test test/store.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { VaultStore } from '../lib/store.js'

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-test-'))
}

test('create → save → fromFile → unlock round-trip keeps secrets off disk', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const store = await VaultStore.createNew({ path: p, masterPassword: 'a-perfectly-good-1' })
  store.add({ title: 'GitHub', kind: 'login', fields: { username: 'me', password: 'hunter2!secret' }, tags: ['work'] })
  await store.save()

  // at-rest: secret VALUES never appear in the file; titles are clear metadata
  // (intentional, like every mainstream vault — enables search while locked).
  const raw = fs.readFileSync(p, 'utf8')
  assert.ok(!raw.includes('hunter2'), 'password leaked to disk!')
  assert.ok(raw.includes('GitHub'), 'title should remain searchable metadata')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('unlock with wrong password fails; right password decrypts fields', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const s1 = await VaultStore.createNew({ path: p, masterPassword: 'master-one-abc' })
  s1.add({ title: 'T', fields: { apiKey: 'sk-test-1234567890abcdef', username: 'u' } })
  await s1.save()

  const s2 = VaultStore.fromFile({ path: p })
  assert.equal(s2.unlocked, false)
  assert.equal(s2.entries().length, 1) // structural reads work while locked
  await assert.rejects(() => s2.unlock('wrong-password'), /check token|auth/)

  const s3 = VaultStore.fromFile({ path: p })
  await s3.unlock('master-one-abc')
  assert.equal(s3.entries()[0].field('apiKey'), 'sk-test-1234567890abcdef')
  assert.equal(s3.entries()[0].field('username'), 'u')
  assert.equal(s3.entries()[0].field('nope'), undefined)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('locked store throws on secret reads with a clear message', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const s1 = await VaultStore.createNew({ path: p, masterPassword: 'master-one-abc' })
  s1.add({ title: 'T', fields: { password: 'x' } })
  await s1.save()
  const s2 = VaultStore.fromFile({ path: p })
  const e = s2.entries()[0]
  assert.throws(() => e.field('password'), TypeError) // vk null → unseal fails
  assert.throws(() => s2.add({ title: 'Y' }), /locked/)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('lock() zeroes the key; prior Entry objects can no longer decrypt', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: 'master-one-abc' })
  store.add({ title: 'T', fields: { password: 'sekret' } })
  const entry = store.entries()[0]
  assert.equal(entry.field('password'), 'sekret')
  store.lock()
  assert.equal(store.unlocked, false)
  assert.throws(() => entry.field('password'))
  fs.rmSync(dir, { recursive: true, force: true })
})

test('tampered ciphertext is rejected by GCM', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const s1 = await VaultStore.createNew({ path: p, masterPassword: 'master-one-abc' })
  s1.add({ title: 'T', fields: { password: 'original' } })
  await s1.save()
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'))
  const d = doc.entries[0].fields.password.dataHex
  doc.entries[0].fields.password.dataHex = (d.slice(0, -2) + (d.slice(-2) === 'ff' ? '00' : 'ff'))
  fs.writeFileSync(p, JSON.stringify(doc))
  const s2 = VaultStore.fromFile({ path: p })
  await s2.unlock('master-one-abc')
  assert.throws(() => s2.entries()[0].field('password'))
  fs.rmSync(dir, { recursive: true, force: true })
})

test('field AAD cross-entry splice fails', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: 'master-one-abc' })
  const a = store.add({ title: 'A', fields: { password: 'aaa-secret' } })
  const b = store.add({ title: 'B', fields: { password: 'bbb-secret' } })
  // swap the encrypted password blobs between entries
  const tmp = store.doc.entries[0].fields.password
  store.doc.entries[0].fields.password = store.doc.entries[1].fields.password
  store.doc.entries[1].fields.password = tmp
  assert.throws(() => store.get(a.id).field('password'))
  assert.throws(() => store.get(b.id).field('password'))
  fs.rmSync(dir, { recursive: true, force: true })
})

test('env validation + high-sensitivity env refusal', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: 'master-one-abc' })
  assert.throws(() => store.add({ title: 'A', env: 'lowercase', fields: { password: 'x' } }), /DSH_/)
  assert.throws(() => store.add({ title: 'B', env: 'DSH_BET', sensitivity: 'high', fields: { password: 'x' } }), /high-sensitivity/)
  const ok = store.add({ title: 'C', env: 'DSH_CEE', fields: { password: 'x' } })
  assert.equal(ok.env, 'DSH_CEE')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('envEntries + search + summary shapes', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: 'master-one-abc' })
  store.add({ title: 'Alpha', tags: ['x'], fields: { password: 'p1' } })
  store.add({ title: 'Beta', env: 'DSH_BETA', fields: { apiKey: 'k' } })
  store.add({ title: 'Gamma', sensitivity: 'high', fields: { password: 'g' } })
  assert.deepEqual(store.envEntries().map(c => c.env), ['DSH_BETA'])
  assert.equal(store.search('alpha').length, 1)
  assert.equal(store.search('gamma')[0].fields.length >= 1, true)
  const summary = store.search('beta')[0]
  assert.ok(!JSON.stringify(summary).includes('"k"'), 'summary must not contain values')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('rotate master password re-wraps VK without re-encrypting fields', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const s1 = await VaultStore.createNew({ path: p, masterPassword: 'old-master-xyz' })
  s1.add({ title: 'T', fields: { password: 'stable-secret' } })
  await s1.save()
  const dataHexBefore = JSON.parse(fs.readFileSync(p, 'utf8')).entries[0].fields.password.dataHex

  const s2 = VaultStore.fromFile({ path: p })
  await s2.unlock('old-master-xyz')
  await s2.changeMasterPassword('old-master-xyz', 'brand-new-master')
  await s2.save()
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'))
  assert.equal(doc.entries[0].fields.password.dataHex, dataHexBefore) // untouched!
  const s3 = VaultStore.fromFile({ path: p })
  await s3.unlock('brand-new-master')
  assert.equal(s3.entries()[0].field('password'), 'stable-secret')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('file modes are pinned 0600/0700', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const s = await VaultStore.createNew({ path: p, masterPassword: 'master-one-abc' })
  await s.save()
  assert.equal(fs.statSync(p).mode & 0o777, 0o600)
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('notes ride encrypted under __notes__', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: 'master-one-abc' })
  store.add({ title: 'T', fields: { password: 'p' }, notes: 'top secret memo' })
  assert.equal(store.entries()[0].field('__notes__'), 'top secret memo')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('corrupt document fails to parse (no silent empty vault)', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  fs.writeFileSync(p, '{"nonsense": true}')
  assert.throws(() => VaultStore.fromFile({ path: p }), /not a recognized/)
  fs.rmSync(dir, { recursive: true, force: true })
})
