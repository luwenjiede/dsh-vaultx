/**
 * Model-tool behavior tests — registerModelTools against a mocked ctx.
 * These lock the fusion's hard invariants at the tool level, not just the
 * policy function: NO tool result may contain a plaintext secret value.
 * Run: node --test test/tools.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { VaultStore } from '../lib/store.js'
import { PolicyStore } from '../lib/policy.js'
import { registerModelTools, ConfirmationLedger } from '../lib/tools.js'

const PW = 'tool-master-123456'

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-tools-')) }

function makeEnv({ accessMode = 'readonly', totpViaModel = false } = {}) {
  const dir = tmpDir()
  const store = VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  const registered = new Map()
  const audits = []
  const ctx = { tools: { register: def => { registered.set(def.name, def); return () => registered.delete(def.name) } } }
  const policyStore = new PolicyStore(path.join(dir, 'policy.json'))
  policyStore.load()
  return {
    dir,
    register: async () => {
      const s = await store
      await s.add({ title: 'OpenAI', kind: 'api-key', sensitivity: 'normal', env: 'DSH_OPENAI', fields: { apiKey: 'sk-REAL-SECRET-999' } })
      await s.add({ title: 'GitHub', kind: 'login', sensitivity: 'high', fields: { password: 'high-value-123' } })
      await s.add({ title: 'Vault', kind: 'totp', sensitivity: 'normal', fields: { totp: 'JBSWY3DPEHPK3PXP' } })
      const policy = new PolicyStore(path.join(dir, 'policy.json'))
      policy.load(); await policy.set({ accessMode, totpViaModel })
      const disposer = registerModelTools({
        ctx, store: () => s, policy: () => policy.get(),
        ledger: new ConfirmationLedger(),
        audit: async (_a, e) => { audits.push(e) },
      })
      return { s, policy, disposer, registered }
    },
    audits, registered, ctx,
  }
}

async function ready(env) { return env.register() }

test('readonly registers read tools and no mutating ones', async () => {
  const { registered } = await ready(makeEnv({ accessMode: 'readonly' }))
  assert.ok(registered.has('vaultx_list') && registered.has('vaultx_get') && registered.has('vaultx_intent'))
  assert.ok(!registered.has('vaultx_generate'))
  assert.ok(!registered.has('vaultx_set'))
  assert.ok(!registered.has('vaultx_delete'))
})

test('sealed registers NOTHING', async () => {
  const { registered } = await ready(makeEnv({ accessMode: 'sealed' }))
  assert.equal(registered.size, 0)
})

test('vaultx_list output contains NO plaintext secret of any entry', async () => {
  const { registered } = await ready(makeEnv())
  const result = await registered.get('vaultx_list').execute({})
  const dump = JSON.stringify(result)
  assert.ok(!dump.includes('sk-REAL-SECRET-999'), 'apiKey leaked to model tool result!')
  assert.ok(!dump.includes('high-value-123'), 'high entry leaked!')
  assert.ok(!dump.includes('JBSWY3DPEHPK3PXP'), 'totp secret leaked!')
  assert.ok(dump.includes('OpenAI'), 'titles are fine to show')
  // high entry invisible entirely
  assert.ok(!dump.includes('GitHub'))
})

test('vaultx_get is masked — mask present, plaintext absent', async () => {
  const { registered } = await ready(makeEnv())
  const entries = (await registered.get('vaultx_list').execute({})).entries
  const openai = entries.find(e => e.title === 'OpenAI')
  const r = await registered.get('vaultx_get').execute({ id: openai.id })
  const dump = JSON.stringify(r)
  assert.ok(!dump.includes('sk-REAL-SECRET-999'), 'get leaked plaintext!')
  assert.ok(r.entry.fields.apiKey.mask.includes('•'), 'expected a masked value')
})

test('totp tool is registered ONLY when policy allows it (withheld otherwise)', async () => {
  const off = await ready(makeEnv({ totpViaModel: false }))
  assert.ok(!off.registered.has('vaultx_totp'), 'totp must not exist when withheld')
  const on = await ready(makeEnv({ totpViaModel: true }))
  assert.ok(on.registered.has('vaultx_totp'))
  const v2 = (await on.registered.get('vaultx_list').execute({})).entries.find(e => e.kind === 'totp')
  const ok = await on.registered.get('vaultx_totp').execute({ id: v2.id })
  assert.equal(ok.ok, true)
  assert.match(ok.code, /^\d{6}$/)
})

test('vaultx_generate stores silently — result carries id+strength, no value', async () => {
  const { registered, s } = await ready(makeEnv({ accessMode: 'write' }))
  const r = await registered.get('vaultx_generate').execute({ title: 'Fresh', style: 'password', length: 20 })
  assert.equal(r.ok, true)
  assert.equal(typeof r.strengthBits, 'number')
  const dump = JSON.stringify(r)
  // the generated value must not appear anywhere in the result
  const entry = s.get(r.id)
  const value = entry.field('password')
  assert.ok(value.length >= 20)
  assert.ok(!dump.includes(value), 'generated secret leaked into tool result!')
})

test('model cannot touch operator-owned entries (set/delete) even in edit mode', async () => {
  const { registered, s } = await ready(makeEnv({ accessMode: 'edit' }))
  const openai = (await registered.get('vaultx_list').execute({})).entries.find(e => e.title === 'OpenAI')
  const setR = await registered.get('vaultx_set').execute({ id: openai.id, fields: { apiKey: 'hijack' } })
  assert.equal(setR.ok, false, 'operator entry must be immune to model set')
  assert.ok(/operator-owned/.test(setR.note))

  // a model-created entry: delete needs the two-phase confirm
  const gen = await registered.get('vaultx_generate').execute({ title: 'Mine', style: 'token' })
  assert.equal(gen.ok, true)
  const del1 = await registered.get('vaultx_delete').execute({ id: gen.id })
  assert.equal(del1.ok, false)
  assert.ok(del1.confirmToken, 'first delete call must mint a confirmation token')
  const del2 = await registered.get('vaultx_delete').execute({ id: gen.id, confirm: del1.confirmToken })
  assert.equal(del2.ok, true)
  assert.equal(s.get(gen.id), undefined, 'confirmed delete must remove')
})

test('confirm token is single-use and id-bound', async () => {
  const { registered, s } = await ready(makeEnv({ accessMode: 'edit' }))
  const a = await registered.get('vaultx_generate').execute({ title: 'A', style: 'token' })
  const b = await registered.get('vaultx_generate').execute({ title: 'B', style: 'token' })
  const t1 = (await registered.get('vaultx_delete').execute({ id: a.id })).confirmToken
  // re-issue supersedes
  const t1b = (await registered.get('vaultx_delete').execute({ id: a.id })).confirmToken
  assert.notEqual(t1, t1b)
  // token for A must not work on B
  assert.equal((await registered.get('vaultx_delete').execute({ id: b.id, confirm: t1b })).ok, false)
  // consuming works, second consume fails
  assert.equal((await registered.get('vaultx_delete').execute({ id: a.id, confirm: t1b })).ok, true)
  assert.equal((await registered.get('vaultx_delete').execute({ id: b.id, confirm: t1b })).ok, false)
})

test('intent records audit and is always registered', async () => {
  const env = makeEnv({ accessMode: 'readonly' })
  const { registered } = await ready(env)
  assert.ok(registered.has('vaultx_intent'))
  const r = await registered.get('vaultx_intent').execute({ purpose: 'deploy' })
  assert.equal(r.ok, true)
  assert.equal(env.audits.length, 1)
  assert.equal(env.audits[0].action, 'intent')
  assert.equal(env.audits[0].detail, 'deploy')
})

test('locked vault: every tool answers with guidance, never throws', async () => {
  const dir = tmpDir()
  const { VaultStore: VS } = await import('../lib/store.js')
  const created = await VS.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  await created.add({ title: 'X', fields: { password: 'p' } })
  await created.save()
  created.lock()
  const registered = new Map()
  const ctx = { tools: { register: d => { registered.set(d.name, d); return () => {} } } }
  registerModelTools({ ctx, store: () => created, policy: () => ({ accessMode: 'readonly' }), ledger: new ConfirmationLedger() })
  for (const [name, def] of registered) {
    const r = await def.execute({ id: 'x', purpose: 'p' })
    // intent is legitimately ok:true while locked (it records only metadata)
    if (name === 'vaultx_intent') { assert.equal(r.ok, true); continue }
    assert.ok(r.locked === true || r.ok === false || r.found === false, `${name} must fail soft when locked`)
  }
})
