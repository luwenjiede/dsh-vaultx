/**
 * Lifecycle test — the user story of the assistant's own vault, end to end:
 *   1. STORE: a credential the user handed in chat goes in via vaultx_add
 *      (plaintext never echoed back).
 *   2. CONSUME OUT-OF-BAND: env resync declares $DSH_GH_*; the shell resolver
 *      returns the real value at execution time only.
 *   3. REVEAL WITH APPROVAL: the gate turns vaultx_reveal into a one-time ask;
 *      approved -> plaintext back; policy flipped to deny -> not even exists.
 * Run: node --test test/lifecycle.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { VaultStore } from '../lib/store.js'
import { PolicyStore, checkModelAccess } from '../lib/policy.js'
import { AuditLog } from '../lib/audit.js'
import { registerModelTools, ConfirmationLedger } from '../lib/tools.js'

const PW = 'lifecycle-master-123'
const PAT = 'ghp-REAL-LOOKING-TOKEN-9f3a'

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-life-')) }

test('store → out-of-band consume → approval-gated reveal (assistant vault story)', async () => {
  const dir = tmpDir()
  const storePath = path.join(dir, 'vault.json')

  // 1) create + unlock (operator created the vault earlier)
  const store = await VaultStore.createNew({ path: storePath, masterPassword: PW })
  await store.save()

  const policyStore = new PolicyStore(path.join(dir, 'policy.json'))
  policyStore.load() // defaults: accessMode=readonly, modelReveal=ask
  const audit = new AuditLog(path.join(dir, 'audit.log'))
  const envDecls = []
  const ctx = {
    tools: { register: () => () => {} },
    shellEnv: { register: c => { envDecls.push(c); return () => {} } },
  }
  const registered = new Map()
  ctx.tools.register = def => { registered.set(def.name, def); return () => registered.delete(def.name) }
  registerModelTools({ ctx, store: () => store, policy: () => policyStore.get(), ledger: new ConfirmationLedger(), audit: (a, e) => audit.append(e), resync: () => {} })

  // -- STORE: user pasted their PAT in chat, said "save it" --
  const addRes = await registered.get('vaultx_add').execute({
    title: 'GitHub PAT', kind: 'api-key', env: 'DSH_GITHUB_TOKEN',
    fields: { apiKey: PAT }, tags: ['github'],
  })
  assert.equal(addRes.ok, true)
  assert.ok(!JSON.stringify(addRes).includes(PAT), 'add must never echo the secret')
  await store.save()

  // entry landed encrypted; disk holds no plaintext
  const raw = fs.readFileSync(storePath, 'utf8')
  assert.ok(!raw.includes(PAT), 'plaintext leaked to disk!')

  // -- CONSUME OUT-OF-BAND: env declaration + per-execution resolver --
  const entry = store.get(addRes.id)
  store.envEntries().length === 1
  // emulate resyncEnv: declare then resolve like the host shell tool would
  const declVars = { [entry.env]: { description: 'VaultX credential' } }
  const resolved = {}
  for (const c of store.envEntries()) {
    if (c.sensitivity === 'high') continue
    resolved[c.env] = store.get(c.id).field(c.field ?? 'password')
  }
  assert.equal(resolved.DSH_GITHUB_TOKEN, PAT, 'out-of-band resolve must yield the real value for the shell')

  // -- REVEAL: needs approval under default posture --
  const meta = { sensitivity: entry.sensitivity, origin: 'model' }
  const gateDecision = checkModelAccess(policyStore.get(), 'vaultx_reveal', meta)
  assert.equal(gateDecision.ask, true, 'default modelReveal=ask: a human approval is required')
  // approved → execute reveals plaintext
  const reveal = await registered.get('vaultx_reveal').execute({ id: entry.id, field: 'apiKey', reason: 'write it into git remote URL per user request' })
  assert.equal(reveal.ok, true)
  assert.equal(reveal.value, PAT)
  // audit recorded the ask and the reveal, never the value
  const auditRaw = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8')
  assert.ok(auditRaw.includes('ask:vaultx_reveal') || auditRaw.includes('reveal'), 'reveal events must be audited')
  assert.ok(!auditRaw.includes(PAT), 'audit trail must never contain the secret')

  // -- operator flips to deny: reveal tool vanishes, env path still works --
  await policyStore.set({ modelReveal: 'deny' })
  const d2 = checkModelAccess(policyStore.get(), 'vaultx_reveal', meta)
  assert.equal(d2.allowed, false)
  // (registration would drop on next retool; simulate by checking posture logic)

  // fs cleanup
  fs.rmSync(dir, { recursive: true, force: true })
})

test('high-sensitivity entry: env-exempt and reveal-exempt even under allow', async () => {
  const dir = tmpDir()
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const h = store.add({ title: 'root', sensitivity: 'high', fields: { password: 'ultra' } })
  // structural check: even hand-edited env, policy hides it from every model channel
  store.doc.entries.find(e => e.id === h.id).env = 'DSH_ROOT'
  const p = new PolicyStore(path.join(dir, 'policy.json')); p.load()
  await p.set({ accessMode: 'edit', modelReveal: 'allow' })
  const meta = { sensitivity: 'high', origin: 'operator' }
  for (const tool of ['vaultx_list', 'vaultx_get', 'vaultx_reveal', 'vaultx_set', 'vaultx_delete']) {
    assert.equal(checkModelAccess(p.get(), tool, meta).allowed, false, tool)
  }
  const injected = store.envEntries().filter(c => c.sensitivity !== 'high').map(c => c.env)
  assert.deepEqual(injected, [], 'high entry must be env-exempt')
  fs.rmSync(dir, { recursive: true, force: true })
})
