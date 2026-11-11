/**
 * Masking tests — tightened policy (P1-5). Run: node --test test/mask.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { maskValue, looksMasked } from '../lib/mask.js'

test('empty and short values never expose characters', () => {
  assert.equal(maskValue(''), '')
  assert.equal(maskValue('abc'), '•••')
  assert.equal(maskValue('1234567890123456'), '•'.repeat(16), '16 chars → fully masked')
})

test('17+ chars expose at most 3 head + 3 tail, ≤ 1/4 of length', () => {
  const v = 'sk-abcdef0123456789XYZ' // 22 → budget 5 → head 3 + tail 2
  assert.equal(maskValue(v), 'sk-' + '•'.repeat(17) + 'YZ')
  const long = maskValue('a'.repeat(100) + 'ZQ') // 102 → budget 6 → head 3 + tail 3
  assert.equal(long.slice(0, 3), 'aaa')
  assert.ok(long.endsWith('aZQ'))
  const exposed = (long.match(/[^•]/g) ?? []).length
  assert.ok(exposed <= Math.ceil(long.length / 4), 'exposed ≤ 1/4 of length')
})

test('looksMasked recognizes existing masks', () => {
  assert.equal(looksMasked('••••'), true)
  assert.equal(looksMasked('****'), true)
  assert.equal(looksMasked('[已加密]'), true)
  assert.equal(looksMasked('real-value'), false)
})
