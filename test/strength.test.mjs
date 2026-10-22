/**
 * Strength estimator tests — monotonicity + common pitfalls.
 * Run: node --test test/strength.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assess, label } from '../lib/strength.js'

test('empty and common passwords score 0', () => {
  assert.equal(assess('').score, 0)
  assert.equal(assess('password').score, 0)
  assert.equal(assess('123456').score, 0)
  assert.equal(assess('aaaaaaaa').score, 0)
})

test('leet substitution of a common word is punished', () => {
  const r = assess('P@ssw0rd')
  assert.ok(r.score <= 1, `expected ≤1, got ${r.score}`)
  assert.ok(r.feedback.some(f => /leet/i.test(f)))
})

test('strong passphrases beat symbol soup', () => {
  const phrase = assess('correct horse battery staple nine')
  const soup = assess('Xq9!aK2#')
  assert.ok(phrase.bits > soup.bits, `${phrase.bits} !> ${soup.bits}`)
  assert.ok(phrase.score >= 3)
})

test('personal terms reduce entropy', () => {
  const base = assess('Tr0ub4d0ur&Gr33n')
  const withName = assess('Tr0ub4d0ur&Gr33n', ['alice'])
  assert.ok(withName.bits >= base.bits) // name not contained → no penalty
  const contained = assess('Alice123!bob', ['alice'])
  assert.ok(contained.bits < assess('Zephyr123!bob', ['alice']).bits)
})

test('sequences get flagged', () => {
  const r = assess('abcdefghijklmnop')
  assert.ok(r.feedback.some(f => /sequential|连续/i.test(f)))
})

test('label maps 0..4 and clamps', () => {
  assert.ok(label(0).length > 0)
  assert.ok(label(9).length > 0)
})

test('score is monotonic in length for a fixed charset', () => {
  const a = assess('Ab1!xxxxxxxx')
  const b = assess('Ab1!xxxxxxxxxxxxxxxxxxxxxxxx')
  assert.ok(b.bits > a.bits)
  assert.ok(b.score >= a.score)
})
