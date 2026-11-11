/**
 * Hardening regression tests — one test per REVIEW.md finding.
 * Run: node --test test/hardening.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { VaultStore, sanitizeDocument } from '../lib/store.js'
import { registerModelTools, ConfirmationLedger } from '../lib/tools.js'
import { PolicyStore, DEFAULT_POLICY } from '../lib/policy.js'
import { AuditLog } from '../lib/audit.js'
import { maskValue } from '../lib/mask.js'

const PW = 'hardening-master-1'
const HERE = path.dirname(fileURLToPath(import.meta.url))
const CLIENT_SRC = fs.readFileSync(path.join(HERE, '..', 'lib', 'client.js'), 'utf8')

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-hard-')) }

async function makeTools(dir) {
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const registered = new Map()
  const ctx = { tools: { register: d => { registered.set(d.name, d); return () => registered.delete(d.name) } } }
  const policy = new PolicyStore(path.join(dir, 'policy.json')); policy.load()
  registerModelTools({ ctx, store: () => store, policy: () => policy.get(), ledger: new ConfirmationLedger(), audit: async () => {} })
  return { store, registered }
}

// ── P0-1: update() validates with the same rules as add() ──────────────────
test('P0-1 update() rejects invalid env, duplicate env, bad envField', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const a = store.add({ title: 'A', env: 'DSH_ONE', fields: { password: 'x' } })
  const b = store.add({ title: 'B', fields: { password: 'y' } })
  assert.throws(() => store.update(b.id, { env: 'PATH' }), /DSH_/, 'invalid env name must be rejected')
  assert.throws(() => store.update(b.id, { env: 'DSH_ONE' }), /unique|already/, 'duplicate env must be rejected')
  assert.throws(() => store.update(b.id, { env: 'DSH_TWO', envField: 'nope' }), /envField/, 'envField must exist')
  // legitimate re-targeting still works
  store.update(b.id, { env: 'DSH_TWO' })
  assert.equal(store.get(b.id).env, 'DSH_TWO')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('P0-1 upgrading to high strips the env export instead of keeping it', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const a = store.add({ title: 'A', env: 'DSH_HIGH', fields: { password: 'x' } })
  store.update(a.id, { sensitivity: 'high' })
  const after = store.get(a.id)
  assert.equal(after.sensitivity, 'high')
  assert.equal(after.env, undefined, 'high entry must not keep an env export')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('P0-1 update() rejects reserved field names (prototype safety)', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const a = store.add({ title: 'A', fields: { password: 'x' } })
  // JSON.parse (the tool wire path) creates an OWN __proto__ key — the real
  // attack vector; object literals would silently set the prototype instead.
  const evil = JSON.parse('{"__proto__": "evil"}')
  assert.throws(() => store.update(a.id, { fields: evil }), /reserved|prototype/)
  assert.throws(() => store.add({ title: 'B', fields: evil }), /reserved|prototype/)
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P0-2: model cannot create high entries ─────────────────────────────────
test('P0-2 vaultx_add refuses sensitivity=high with guidance', async () => {
  const dir = tmpDir()
  const { store, registered } = await makeTools(dir)
  const r = await registered.get('vaultx_add').execute({ title: 'H', sensitivity: 'high', fields: { password: 'x' } })
  assert.equal(r.ok, false)
  assert.match(r.note, /high|operator/i)
  assert.equal(store.entries().length, 0, 'nothing may have been stored')
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P0-5: clipboard hygiene + reveal re-confirm are real ───────────────────
test('P0-5 client bundle implements clipboard TTL and reveal re-confirm', () => {
  assert.ok(CLIENT_SRC.includes('copySecret'), 'client must use copySecret()')
  assert.ok(CLIENT_SRC.includes('CLIPBOARD_TTL_MS'), 'clipboard TTL constant must exist')
  assert.ok(CLIENT_SRC.includes('revealConfirm'), 'panel must re-confirm plaintext reveal')
  assert.ok(CLIENT_SRC.includes('revealRequiresConfirm'), 'panel must read the policy dial')
  assert.ok(CLIENT_SRC.includes('console.log("vaultx: client plugin loaded")'), 'D-4: client boot line')
  // zh/en dictionaries both carry the new keys (locale test locks key-set parity)
  const zh = CLIENT_SRC.match(/revealConfirm: "确认要明文显示字段/), en = CLIENT_SRC.match(/revealConfirm: "Show field/)
  assert.ok(zh && en, 'revealConfirm must exist in both dictionaries')
})

test('P0-5 revealRequiresConfirm defaults ON and persists through setPolicy', async () => {
  assert.equal(DEFAULT_POLICY.revealRequiresConfirm, true)
  const dir = tmpDir()
  const p = new PolicyStore(path.join(dir, 'policy.json')); p.load()
  assert.equal(p.get().revealRequiresConfirm, true)
  await p.set({ revealRequiresConfirm: false })
  assert.equal(p.get().revealRequiresConfirm, false)
  const p2 = new PolicyStore(path.join(dir, 'policy.json')); p2.load()
  assert.equal(p2.get().revealRequiresConfirm, false, 'must survive restart')
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P1-1: auto-lock window is operator-only ────────────────────────────────
test('P1-1 model activity does not extend the auto-lock window; operator activity does', async () => {
  const dir = tmpDir()
  process.env.VAULTX_LOCK_PW = PW
  const { default: plugin } = await import('../lib/index.js')
  const tools = {}
  const provided = {}
  const ctx = {
    tools: { register: d => { tools[d.name] = d; return () => {} } },
    shellEnv: { register: () => () => {} },
    systemPrompt: { section() {} },
    on() { return () => {} },
    effect() {},
    logger: { info() {}, warn() {} },
    reflect: { provide: (n, s) => { provided[n] = s } },
  }
  plugin.apply(ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_LOCK_PW', autoLockMinutes: 15 })
  const gw = provided.vaultx ?? Object.values(provided)[0]
  await gw.create(PW)
  await gw.add('A', 'login', 'normal', '', '', [], { password: 'x' }, '')
  const t0 = gw.status().lastActivity
  await new Promise(r => setTimeout(r, 25))
  await tools.vaultx_list.execute({})          // model activity
  await tools.vaultx_intent.execute({ purpose: 'p' })
  assert.equal(gw.status().lastActivity, t0, 'model tool calls must NOT touch the idle window')
  gw.list()                                     // operator activity
  assert.ok(gw.status().lastActivity > t0, 'operator panel reads DO touch the window')
  delete process.env.VAULTX_LOCK_PW
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P1-2: metadata MAC ─────────────────────────────────────────────────────
test('P1-2 metadata MAC detects hand-edited titles and survives legit updates', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const e = store.add({ title: 'T', fields: { password: 'v' } })
  assert.equal(store.verifyMetadata().ok, true)
  store.doc.entries[0].title = 'Evil'           // hand-edit: no valid MAC
  const v1 = store.verifyMetadata()
  assert.equal(v1.ok, false)
  assert.equal(v1.broken[0].id, e.id)
  store.update(e.id, { title: 'Fine' })          // legit update re-MACs
  assert.equal(store.verifyMetadata().ok, true)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('P1-2 legacy entries are backfilled with a MAC on save', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'vault.json')
  const store = await VaultStore.createNew({ path: p, masterPassword: PW })
  store.add({ title: 'T', fields: { password: 'v' } })
  delete store.doc.entries[0].metaMac            // simulate a pre-MAC document
  await store.save()
  assert.ok(store.doc.entries[0].metaMac, 'save backfills missing MAC')
  const s2 = VaultStore.fromFile({ path: p })
  await s2.unlock(PW)
  const m = s2.verifyMetadata()
  assert.equal(m.ok, true)
  assert.equal(m.unsigned, 0)
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P1-3: sanitizeDocument rejects hostile imports ─────────────────────────
const BLOB = { ivHex: '00'.repeat(12), tagHex: '00'.repeat(16), dataHex: '00'.repeat(32) }
const baseDoc = () => ({
  version: 1,
  header: { kdf: { algo: 'scrypt', n: 32768, r: 8, p: 1, saltHex: '00'.repeat(16) }, wrappedKey: BLOB, check: BLOB },
  entries: [],
})
const entry = (over = {}) => ({ id: 'a'.repeat(24), title: 't', fields: { password: BLOB }, ...over })

test('P1-3 sanitizeDocument rejects malformed documents', () => {
  assert.throws(() => sanitizeDocument(null), /recognized/)
  assert.throws(() => sanitizeDocument({ ...baseDoc(), header: null }), /recognized|malformed/)
  assert.throws(() => sanitizeDocument({ ...baseDoc(), header: { kdf: {}, wrappedKey: BLOB, check: BLOB } }), /malformed/)
  // prototype-pollution field name
  const evil = JSON.parse('{"id":"' + 'a'.repeat(24) + '","title":"t","fields":{"__proto__":{"ivHex":"' + '0'.repeat(24) + '","tagHex":"' + '0'.repeat(32) + '","dataHex":"' + '0'.repeat(32) + '"}}}')
  assert.throws(() => sanitizeDocument({ ...baseDoc(), entries: [evil] }), /forbidden|reserved/)
  // duplicate ids
  assert.throws(() => sanitizeDocument({ ...baseDoc(), entries: [entry(), entry()] }), /duplicate entry id/)
  // invalid env name
  assert.throws(() => sanitizeDocument({ ...baseDoc(), entries: [entry({ env: 'PATH' })] }), /env name/)
  // duplicate env
  assert.throws(() => sanitizeDocument({ ...baseDoc(), entries: [entry({ env: 'DSH_AAA' }), entry({ id: 'b'.repeat(24), env: 'DSH_AAA' })] }), /duplicate env/)
  // bad blob shape
  assert.throws(() => sanitizeDocument({ ...baseDoc(), entries: [entry({ fields: { password: { ivHex: 'zz' } } })] }), /blob/)
  // valid document passes round-trip
  const clean = { ...baseDoc(), entries: [entry({ env: 'DSH_OKK', envField: 'password' })] }
  const out = sanitizeDocument(clean)
  assert.equal(out.entries[0].env, 'DSH_OKK')
  assert.equal(Object.getPrototypeOf(out.entries[0].fields), null, 'field map must be null-prototype')
})

test('P1-3 importVault gateway rejects a foreign/undecryptable document', async () => {
  const dir = tmpDir()
  process.env.VAULTX_IMP_PW = PW
  const { default: plugin } = await import('../lib/index.js')
  const provided = {}
  const ctx = {
    tools: { register: () => () => {} },
    shellEnv: { register: () => () => {} },
    systemPrompt: { section() {} },
    on() { return () => {} },
    effect() {},
    logger: { info() {}, warn() {} },
    reflect: { provide: (n, s) => { provided[n] = s } },
  }
  plugin.apply(ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_IMP_PW', autoLockMinutes: 0 })
  const gw = provided.vaultx ?? Object.values(provided)[0]
  await gw.create(PW)
  // wrong password on a structurally valid doc → rejected, vault untouched
  const r = await gw.importVault(baseDoc(), 'not-the-password')
  assert.equal(r.ok, false)
  assert.match(r.error, /check token|auth|decrypt/i)
  delete process.env.VAULTX_IMP_PW
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P1-4: cross-process audit lock ─────────────────────────────────────────
test('P1-4 interleaved writers from two AuditLog instances keep one chain', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'audit.log')
  const a = new AuditLog(p)
  const b = new AuditLog(p)
  const jobs = []
  for (let i = 0; i < 40; i++) jobs.push((i % 2 ? a : b).append({ actor: 'proc', action: 'op' + i }))
  await Promise.all(jobs)
  const res = await a.verify()
  assert.equal(res.valid, true, `chain broken at ${res.brokenAt}`)
  assert.equal(res.count, 40)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('D-7 oversized detail is truncated before hashing (no false chain break)', async () => {
  const dir = tmpDir()
  const log = new AuditLog(path.join(dir, 'audit.log'))
  await log.append({ actor: 'model', action: 'big', detail: 'x'.repeat(70_000) })
  await log.append({ actor: 'model', action: 'after' })
  const res = await log.verify()
  assert.equal(res.valid, true)
  const lines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').trim().split('\n')
  assert.ok(lines[0].length < 30_000, 'record must be bounded')
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── Real-host verification: status poll must not wipe panel policy ─────────
test('panel status() includes policy; Root polling merges instead of replacing snapshot', async () => {
  // client-side: the poll must merge (setSnapshot(s => ...)), never replace
  assert.ok(CLIENT_SRC.includes('setSnapshot(s => ({ ...(s ?? {}), ...st }))'), 'status poll must merge snapshot to keep policy')
  // host-side: status() must carry the policy object
  const dir = tmpDir()
  process.env.VAULTX_STATUS_PW = PW
  const { default: plugin } = await import('../lib/index.js')
  const provided = {}
  const ctx = {
    tools: { register: () => () => {} },
    shellEnv: { register: () => () => {} },
    systemPrompt: { section() {} },
    on() { return () => {} },
    effect() {},
    logger: { info() {}, warn() {} },
    reflect: { provide: (n, s) => { provided[n] = s } },
  }
  plugin.apply(ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_STATUS_PW', autoLockMinutes: 0 })
  const gw = provided.vaultx ?? Object.values(provided)[0]
  await gw.create(PW)
  await gw.setPolicy('edit', null, null, null, 'allow', true)
  const st = gw.status()
  assert.ok(st.policy, 'status() must include policy for the panel')
  assert.equal(st.policy.accessMode, 'edit')
  assert.equal(st.policy.modelReveal, 'allow')
  assert.equal(st.policy.revealRequiresConfirm, true)
  delete process.env.VAULTX_STATUS_PW
  fs.rmSync(dir, { recursive: true, force: true })
})

// ── P1-5: masking tightened ────────────────────────────────────────────────
test('P1-5 short values are fully masked; long values leak at most 3+3', () => {
  assert.equal(maskValue(''), '')
  assert.equal(maskValue('abc'), '•••')
  assert.equal(maskValue('1234567890123456'), '•'.repeat(16), '≤16 chars fully masked')
  const v = 'sk-abcdef0123456789XYZ' // 22 → budget 5 → head 3 + tail 2
  assert.equal(maskValue(v), 'sk-' + '•'.repeat(17) + 'YZ')
  const long = maskValue('a'.repeat(100) + 'ZQ') // 102 chars → budget 6 → head 3 + tail 3
  assert.equal(long.slice(0, 3), 'aaa', 'head exposes at most 3 chars')
  assert.ok(long.endsWith('aZQ'), 'tail exposes at most 3 chars')
  assert.ok(!long.includes('a'.repeat(10)), 'no long plaintext run in mask')
})
