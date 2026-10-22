/**
 * Audit hash-chain tests: append order, tamper detection, tail reader.
 * Run: node --test test/audit.test.mjs
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { AuditLog } from '../lib/audit.js'

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-audit-')) }

test('empty log verifies as valid with 0 records', async () => {
  const log = new AuditLog(path.join(tmp(), 'audit.log'))
  assert.deepEqual(await log.verify(), { valid: true, count: 0 })
})

test('append + verify chain across many records', async () => {
  const dir = tmp()
  const log = new AuditLog(path.join(dir, 'audit.log'))
  for (let i = 0; i < 25; i++) await log.append({ actor: 'model', action: `op${i}`, entryId: `id${i}` })
  const res = await log.verify()
  assert.equal(res.valid, true)
  assert.equal(res.count, 25)
})

test('middle-line edit breaks the chain at that line', async () => {
  const dir = tmp()
  const p = path.join(dir, 'audit.log')
  const log = new AuditLog(p)
  for (let i = 0; i < 5; i++) await log.append({ actor: 'operator', action: `a${i}` })
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)
  const tampered = JSON.parse(lines[2])
  tampered.action = 'evil'
  lines[2] = JSON.stringify(tampered)
  fs.writeFileSync(p, lines.join('\n') + '\n')
  const res = await log.verify()
  assert.equal(res.valid, false)
  assert.equal(res.brokenAt, 2)
})

test('line deletion breaks the chain at the splice point', async () => {
  const dir = tmp()
  const p = path.join(dir, 'audit.log')
  const log = new AuditLog(p)
  for (let i = 0; i < 6; i++) await log.append({ actor: 'model', action: `x${i}` })
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean)
  lines.splice(1, 1)
  fs.writeFileSync(p, lines.join('\n') + '\n')
  const res = await log.verify()
  assert.equal(res.valid, false)
  assert.equal(res.brokenAt, 1)
})

test('recent() returns newest first, capped', async () => {
  const dir = tmp()
  const log = new AuditLog(path.join(dir, 'audit.log'))
  for (let i = 0; i < 8; i++) await log.append({ actor: 'model', action: `r${i}` })
  const rows = await log.recent(3)
  assert.equal(rows.length, 3)
  assert.equal(rows[0].action, 'r7')
  assert.equal(rows[2].action, 'r5')
})

test('records never contain a "value" key (secrets must not be logged)', async () => {
  const dir = tmp()
  const p = path.join(dir, 'audit.log')
  const log = new AuditLog(p)
  await log.append({ actor: 'operator', action: 'reveal', entryId: 'e1', title: 'GitHub', fields: ['password'] })
  const raw = fs.readFileSync(p, 'utf8')
  assert.ok(!raw.includes('hunter'), 'no plaintext should ever land in the audit trail')
  assert.ok(raw.includes('password'), 'field NAMES may be recorded')
})

test('long tails: readTailLine handles multi-KB records', async () => {
  const dir = tmp()
  const p = path.join(dir, 'audit.log')
  const log = new AuditLog(p)
  await log.append({ actor: 'model', action: 'a', detail: 'x'.repeat(1200) })
  await log.append({ actor: 'model', action: 'b', detail: 'y'.repeat(900) })
  assert.equal((await log.verify()).valid, true)
})
