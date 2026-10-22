/**
 * Integration contracts — index.js apply() against a faithful mock of the
 * host services (shellEnv/tools/systemPrompt/typert). This is the file that
 * would catch "the plugin loads but the channels are wired wrong" regressions.
 * Run: node --test test/contracts.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

process.env.DSH_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-contract-'))
const { default: plugin, Config } = await import('../lib/index.js')

/** Minimal but faithful cordis-ish context mock. */
function makeCtx() {
  const registered = { tools: [], slots: [] }
  const promptSections = []
  const events = []
  const shellEnv = {
    registered: [],
    register(contrib) {
      shellEnv.registered.push(contrib)
      return () => { const i = shellEnv.registered.indexOf(contrib); if (i >= 0) shellEnv.registered.splice(i, 1) }
    },
  }
  const ctx = {
    // cordis Service registration surface: the gateway calls super(ctx, key)
    // which does ctx.reflect.provide(name, service). Stub it and keep the
    // service so tests can invoke gateway methods directly.
    provided: {},
    reflect: { provide(name, service) { ctx.provided[name] = service } },
    tools: { register: def => { registered.tools.push(def.name); return () => { registered.tools.splice(registered.tools.indexOf(def.name), 1) } } },
    shellEnv,
    systemPrompt: { section(def) { promptSections.push(def) } },
    on(event, fn) { events.push({ event, fn }); return () => {} },
    effect(fn) { fn() },
    logger: { info() {}, warn() {}, error() {} },
  }
  return { ctx, registered, envReg: shellEnv, promptSections, events }
}

const PW = 'integration-master-9'

async function freshVault(name, extra = {}) {
  const made = makeCtx()
  const dir = path.join(process.env.DSH_HOME, name)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  plugin.apply(made.ctx, { storePath: path.join(dir, 'vault.json'), autoLockMinutes: 0, ...extra })
  return { ...made, dir }
}

/** Poll a predicate until true or timeout (async auto-unlock runs scrypt). */
async function until(fn, ms = 5000) {
  const t0 = Date.now()
  for (;;) {
    if (fn()) return
    if (Date.now() - t0 > ms) throw new Error('until: timed out waiting for condition')
    await new Promise(r => setTimeout(r, 25))
  }
}

test('Config schema is a Standard Schema with the documented fields', () => {
  assert.equal(typeof Config, 'function')
  assert.ok(Config['~standard'], 'schemastery exposes the standard-schema interface')
  const fields = Object.keys(Config.dict ?? {})
  for (const f of ['storePath', 'masterPasswordEnv', 'masterPassword', 'autoLockMinutes', 'disableEnvExport']) {
    assert.ok(fields.includes(f), `missing config field: ${f}`)
  }
})

test('apply() does not throw on a missing vault (fail-open boot)', async () => {
  await freshVault('missing')
  assert.ok(true)
})

test('no master password → prompt registered, no env declarations, tools present', async () => {
  const { registered, envReg, promptSections } = await freshVault('nopw')
  await new Promise(r => setTimeout(r, 80))
  assert.ok(promptSections.some(s => s.name === 'vaultx'))
  assert.equal(envReg.registered.length, 0, 'locked vault must not declare any $DSH_* variables')
  assert.ok(registered.tools.includes('vaultx_list'))
})

test('create → add env entry → auto-unlock declares exactly one DSH_* var', async () => {
  const { dir } = await freshVault('envflow')
  const { VaultStore } = await import('../lib/store.js')
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  store.add({ title: 'OpenAI', kind: 'api-key', env: 'DSH_OPENAI_KEY', fields: { apiKey: 'sk-abcdef0123456789' } })
  await store.save()

  // re-boot the plugin against the now-existing vault with a password env
  process.env.VAULTX_PW_TEST = PW
  const made = makeCtx()
  plugin.apply(made.ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_PW_TEST', autoLockMinutes: 0 })
  await until(() => made.envReg.registered.length > 0)
  const contrib = made.envReg.registered[0]
  assert.deepEqual(Object.keys(contrib.variables), ['DSH_OPENAI_KEY'])
  // description must not contain the secret
  assert.ok(!JSON.stringify(contrib.variables).includes('sk-abcdef'))
  // resolve returns the plaintext value for the shell only
  const resolved = contrib.resolve({})
  assert.equal(resolved.DSH_OPENAI_KEY, 'sk-abcdef0123456789')
})

test('high-sensitivity env entries never resolve', async () => {
  const dir = path.join(process.env.DSH_HOME, 'highenv')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const { VaultStore } = await import('../lib/store.js')
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  store.add({ title: 'root', kind: 'ssh', fields: { password: 'super-secret' } })
  store.add({ title: 'ok', env: 'DSH_LOW_OK', fields: { apiKey: 'fine' } })
  // high + env is rejected at add() — simulate a hand-edited file instead:
  const high = store.add({ title: 'bank', sensitivity: 'high', fields: { password: 'nope' } })
  store.doc.entries.find(e => e.id === high.id).env = 'DSH_BANK'
  await store.save()

  process.env.VAULTX_PW_HIGH = PW
  const made = makeCtx()
  plugin.apply(made.ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_PW_HIGH', autoLockMinutes: 0 })
  await until(() => made.envReg.registered.length > 0)
  const contrib = made.envReg.registered[0]
  assert.deepEqual(Object.keys(contrib.variables), ['DSH_LOW_OK'], 'only the low entry is declared')
  assert.ok(!('DSH_BANK' in contrib.variables), 'hand-edited high env var must not be declared')
  const resolved = contrib.resolve({})
  assert.equal(resolved.DSH_BANK, undefined, 'high-sensitivity value must NEVER be injected')
  assert.equal(resolved.DSH_LOW_OK, 'fine')
})

test('pre-execute gate denies vaultx_reveal; lets readonly list pass through', async () => {
  const { events } = await freshVault('gate')
  const gate = events.find(e => e.event === 'tools/pre-execute').fn
  const next = () => Promise.resolve('NEXT')

  const pass = await gate({ name: 'other_tool' }, next)
  assert.equal(pass, 'NEXT')

  const reveal = await gate({ name: 'vaultx_reveal', arguments: { id: 'x' } }, next)
  assert.equal(reveal.kind, 'deny')
  assert.match(reveal.reason, /never to the model/)

  const list = await gate({ name: 'vaultx_list', arguments: {} }, next)
  assert.equal(list, 'NEXT') // readonly default: list is allowed through to next()
})

test('policy file persists across plugin restarts', async () => {
  const dir = path.join(process.env.DSH_HOME, 'persist')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const { PolicyStore } = await import('../lib/policy.js')
  const p1 = new PolicyStore(path.join(dir, 'policy.json'))
  p1.load()
  await p1.set({ accessMode: 'edit' })
  const p2 = new PolicyStore(path.join(dir, 'policy.json'))
  assert.equal(p2.load().accessMode, 'edit')
  await p2.set({ accessMode: 'bogus' })
  assert.equal(p2.get().accessMode, 'readonly', 'invalid values normalise back')
})

test('shellEnv resolver survives the vault file vanishing mid-flight', async () => {
  const dir = path.join(process.env.DSH_HOME, 'lockrace')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const { VaultStore } = await import('../lib/store.js')
  const store = await VaultStore.createNew({ path: path.join(dir, 'vault.json'), masterPassword: PW })
  store.add({ title: 'X', env: 'DSH_X_ONE', fields: { password: 'v' } })
  await store.save()
  process.env.VAULTX_PW_LR = PW
  const made = makeCtx()
  plugin.apply(made.ctx, { storePath: path.join(dir, 'vault.json'), masterPasswordEnv: 'VAULTX_PW_LR', autoLockMinutes: 0 })
  await until(() => made.envReg.registered.length > 0)
  const contrib = made.envReg.registered[0]
  fs.rmSync(path.join(dir, 'vault.json'))
  assert.doesNotThrow(() => contrib.resolve({}))
})
