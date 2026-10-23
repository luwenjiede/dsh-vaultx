/**
 * Client-bundle smoke tests — run the browser factory in a vm with stubbed
 * requires, verify registration shape, dictionary flattening, and that the
 * RPC surface mirrors the gateway's parameter names (wire contract).
 * Run: node --test test/client.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const src = fs.readFileSync(path.join(HERE, '..', 'lib', 'client.js'), 'utf8')

// ── minimal react stub: just enough for the factory + registration flow ──
const reactStub = {
  useState(init) { return [typeof init === 'function' ? init() : init, () => {}] },
  useEffect() {}, useCallback(fn) { return fn }, useMemo(fn) { return fn() },
  useRef(init) { return { current: init } },
}
const jsxStub = (type, props) => ({ type, props })
const primitives = Object.fromEntries(['Button', 'Input', 'Tag', 'StateDot', 'Modal', 'Toast'].map(n => [n, () => null]))
function requireStub(id) {
  if (id === 'react') return reactStub
  if (id === 'react/jsx-runtime') return { jsx: jsxStub, jsxs: jsxStub, Fragment: 'Fragment' }
  if (id === '@deepseek-ai/dsh-client-ui-primitives') return primitives
  throw new Error('unexpected require: ' + id)
}

function loadBundle() {
  let captured = null
  const sandbox = { window: { __ModuleLoader__: { load(def) { captured = def } } }, console }
  vm.createContext(sandbox)
  vm.runInContext(src, sandbox)
  const mod = captured.factory(requireStub)
  return { mod, id: captured.id }
}

// ── gateway parity: read the host module, extract markRemoteMethods list ──
const gatewaySrc = fs.readFileSync(path.join(HERE, '..', 'lib', 'index.js'), 'utf8')
const remoteList = gatewaySrc.match(/markRemoteMethods\(VaultXGateway,\s*\[([\s\S]*?)\]\)/)?.[1]
  .match(/'([^']+)'/g).map(s => s.replace(/'/g, ''))

test('bundle registers under the exact package name', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'package.json'), 'utf8'))
  const { id, mod } = loadBundle()
  assert.equal(id, pkg.name)
  assert.equal(mod.apply.name, 'apply')
  assert.equal(JSON.stringify(mod.inject), JSON.stringify(["slots","locale","connection"]))
})

test('dictionaries flatten cleanly and zh/en key sets match', () => {
  const { mod } = loadBundle()
  // extract the register payload by invoking a fake locale service
  let registered = null
  const ctx = {
    locale: { register(ns, dicts) { registered = { ns, dicts }; return () => {} }, bind() { return k => k } },
    slots: { inject: () => {}, register: () => {} },
    get() { return { rpc: { call: async () => ({ ok: true, value: {} }) } } },
    effect(fn) { fn() },
  }
  mod.apply(ctx)
  assert.ok(registered, 'locale dictionary was not registered')
  assert.equal(registered.ns, 'settings.vaultx')
  const zhKeys = Object.keys(registered.dicts.zh).sort()
  const enKeys = Object.keys(registered.dicts.en).sort()
  assert.deepEqual(zhKeys, enKeys, 'zh/en key sets must be identical')
  // dotted keys prove the flattening happened
  assert.ok(zhKeys.includes('kinds.api-key'))
  assert.ok(zhKeys.includes('status.entries'))
  assert.ok(zhKeys.includes('sens.high'))
  // every value is a string (locale templates)
  for (const v of Object.values(registered.dicts.zh)) assert.equal(typeof v, 'string', 'non-string dictionary value: ' + JSON.stringify(v).slice(0, 60))
})

test('every RPC method the client calls exists on the gateway with matching parameter names', () => {
  // client side: grep the `call("method", { named args })` shape
  const clientCalls = [...src.matchAll(/call\("(\w+)",\s*(?:\{([^}]*)\})?/g)]
  assert.ok(clientCalls.length >= remoteList.length, 'client covers every remote method')
  const methodArgs = {}
  for (const [, method, argObj] of clientCalls) {
    const keys = (argObj ?? '').split(',').map(s => s.split(':')[0].trim()).filter(Boolean)
    methodArgs[method] = keys
  }
  // gateway side: parameter names per method
  for (const m of remoteList) {
    const sig = gatewaySrc.match(new RegExp(`(?:async\\s+)?\\b${m}\\(([^)]*)\\)\\s*\\{`))
    if (!sig) continue
    const params = (sig[1] ?? sig[2] ?? '').split(',').map(s => s.split('=')[0].trim()).filter(Boolean)
    const sent = methodArgs[m]
    if (!sent) continue // status/list style zero-arg calls
    for (const key of sent) {
      assert.ok(params.includes(key), `client sends "${m}.${key}" but the gateway parameter is (${params.join(',')}) — Typert rejects unknown keys`)
    }
  }
})

test('locked and unlocked renders use an identical hook sequence (Rules of Hooks regression)', () => {
  // Real bug: the locked branch returned BEFORE useMemo ran, so unlocking made
  // React see one more hook than the previous render registered →
  // "Rendered more hooks than during the previous render" → white section.
  const seq = []
  const countingReact = {
    useState(init) { seq.push('S'); return [typeof init === 'function' ? init() : init, () => {}] },
    useEffect() { seq.push('E') },
    useCallback(fn) { seq.push('C'); return fn },
    useMemo(fn) { seq.push('M'); return fn() },
    useRef(i) { seq.push('R'); return { current: i } },
  }
  let captured = null
  const sandbox = { window: { __ModuleLoader__: { load(d) { captured = d } } }, console }
  vm.createContext(sandbox)
  vm.runInContext(src, sandbox)
  const mod = captured.factory(id => (id === 'react' ? countingReact : requireStub(id)))
  const api = new Proxy({}, { get: () => async () => [] })
  const t = k => String(k)
  const render = snapshot => {
    seq.length = 0
    mod.VaultXSection({ t, api, snapshot, setSnapshot() { }, reload() { } })
    return seq.join('')
  }
  const locked = render({ exists: true, locked: true })
  const unlocked = render({ exists: true, locked: false, entries: 0 })
  assert.ok(locked.length > 0, 'locked render ran no hooks (stub not wired?)')
  assert.equal(unlocked, locked, 'hook sequence changed between locked and unlocked renders')
})

test('wire argument names equal gateway parameter names exactly (strict, hand-curated table)', () => {
  // The generic scan above can miss spread/renaming; this table is the contract.
  const expected = {
    unlock: ['password'], create: ['password'], lock: [], list: [],
    reveal: ['id', 'field'], masked: ['id', 'field'],
    add: ['title', 'kind', 'sensitivity', 'env', 'envField', 'tags', 'fields', 'notes'],
    update: ['id', 'patch'], remove: ['id'],
    generate: ['style', 'length', 'words', 'symbols'],
    strength: ['value', 'personal'], totpCode: ['id'],
    rotate: ['oldPassword', 'newPassword'],
    exportVault: ['targetPassword'], importVault: ['doc', 'password'],
    getPolicy: [], setPolicy: ['accessMode', 'autoCapture', 'totpViaModel', 'envExport', 'modelReveal'],
    recentAudit: ['limit'], verifyAudit: [], verifyVault: [], status: [],
  }
  for (const m of remoteList) {
    assert.ok(m in expected, `method "${m}" missing from the wire contract table`)
  }
  for (const [m, want] of Object.entries(expected)) {
    if (!remoteList.includes(m)) continue
    // Dedicated parser: match `async? method(params) {` at class-member depth.
    const cls = gatewaySrc.slice(gatewaySrc.indexOf('class VaultXGateway'))
    const sig = cls.match(new RegExp('(?:async\\s+)?\\b' + m + '\\s*\\(([^)]*)\\)\\s*\\{'))
    assert.ok(sig, `cannot locate gateway signature for ${m}`)
    const params = sig[1].split(',').map(s => s.split('=')[0].trim()).filter(Boolean)
    assert.deepEqual(params, want, `gateway ${m} parameter names drifted`)
  }
})
