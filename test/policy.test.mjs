/**
 * Policy matrix tests — the fusion's core invariants, exhaustively.
 * Run: node --test test/policy.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkModelAccess, normalise, DEFAULT_POLICY, ACCESS_MODES } from '../lib/policy.js'

const P = (over = {}) => normalise(over)

test('normalise: unknown fields dropped, bad modes fall to default', () => {
  const n = normalise({ accessMode: 'superuser', evil: 1 })
  assert.equal(n.accessMode, DEFAULT_POLICY.accessMode)
  assert.ok(!('evil' in n))
  assert.equal(n.autoCapture, false)
  assert.equal(n.totpViaModel, false)
  assert.equal(n.envExport, true)
})

test('normalise accepts each legal mode', () => {
  for (const m of ACCESS_MODES) assert.equal(normalise({ accessMode: m }).accessMode, m)
})

test('SEALED denies everything, even intent', () => {
  for (const fam of ['list', 'get', 'totp', 'generate', 'set', 'delete', 'intent', 'reveal']) {
    const d = checkModelAccess(P({ accessMode: 'sealed' }), `vaultx_${fam}`)
    assert.equal(d.allowed, false, fam)
  }
})

test('invariant #1: reveal is denied in EVERY non-sealed mode (no plaintext to the model)', () => {
  for (const m of ['readonly', 'write', 'edit']) {
    const d = checkModelAccess(P({ accessMode: m }), 'vaultx_reveal')
    assert.equal(d.allowed, false)
    assert.match(d.reason, /never to the model/)
  }
})

test('invariant #2: high-sensitivity is human-only in every mode', () => {
  for (const m of ['readonly', 'write', 'edit']) {
    for (const fam of ['list', 'get', 'totp', 'set', 'delete']) {
      const d = checkModelAccess(P({ accessMode: m }), `vaultx_${fam}`, { sensitivity: 'high' })
      assert.equal(d.allowed, false, `${m}/${fam}`)
      assert.match(d.reason, /human-only/)
    }
  }
})

test('intent is always allowed (non-mutating)', () => {
  for (const m of ['readonly', 'write', 'edit']) {
    assert.equal(checkModelAccess(P({ accessMode: m }), 'vaultx_intent').allowed, true)
  }
})

test('readonly: reads yes, writes/deletes no', () => {
  const pol = P({ accessMode: 'readonly' })
  assert.equal(checkModelAccess(pol, 'vaultx_list').allowed, true)
  assert.equal(checkModelAccess(pol, 'vaultx_get').allowed, true)
  assert.equal(checkModelAccess(pol, 'vaultx_generate').allowed, false)
  assert.equal(checkModelAccess(pol, 'vaultx_set').allowed, false)
  assert.equal(checkModelAccess(pol, 'vaultx_delete').allowed, false)
})

test('write: model-owned creates/updates; operator-owned immutable', () => {
  const pol = P({ accessMode: 'write' })
  assert.equal(checkModelAccess(pol, 'vaultx_generate', { origin: 'model' }).allowed, true)
  assert.equal(checkModelAccess(pol, 'vaultx_set', { origin: 'model' }).allowed, true)
  assert.equal(checkModelAccess(pol, 'vaultx_set', { origin: 'operator' }).allowed, false)
  assert.equal(checkModelAccess(pol, 'vaultx_delete', { origin: 'model' }).allowed, false) // delete needs edit
})

test('edit: delete allowed only for model-owned, still gated by confirm elsewhere', () => {
  const pol = P({ accessMode: 'edit' })
  assert.equal(checkModelAccess(pol, 'vaultx_delete', { origin: 'model' }).allowed, true)
  assert.equal(checkModelAccess(pol, 'vaultx_delete', { origin: 'operator' }).allowed, false)
})

test('TOTP is withheld unless totpViaModel', () => {
  assert.equal(checkModelAccess(P({ accessMode: 'readonly' }), 'vaultx_totp').allowed, false)
  assert.equal(checkModelAccess(P({ accessMode: 'readonly', totpViaModel: true }), 'vaultx_totp').allowed, true)
  // and even enabled, high entries stay locked
  assert.equal(checkModelAccess(P({ accessMode: 'readonly', totpViaModel: true }), 'vaultx_totp', { sensitivity: 'high' }).allowed, false)
})

test('unknown family denies with reason', () => {
  const d = checkModelAccess(P({ accessMode: 'edit' }), 'vaultx_launch_missiles')
  assert.equal(d.allowed, false)
})
