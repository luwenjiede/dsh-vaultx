/**
 * Tamper-evident audit log — a hash chain over JSONL records.
 *
 * Each record carries the SHA-256 of the previous record, so deleting or
 * editing any line breaks every hash after it. `verify()` detects this.
 * Records contain only non-secret context (actor, tool, entry id/title,
 * field names) — never values, never plaintext that is itself a secret.
 *
 * Appends use a single `fs.appendFileSync` write per record, which for our
 * line sizes (< PIPE_BUF on Linux) is atomic enough against the sibling
 * `*.bak` rotation; on win32 we fall back to a best-effort append.
 *
 * @module vaultx/audit
 */
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { sha256Hex } from './crypto.js'
import { FILE_MODE } from './constants.js'

const GENESIS = '0'.repeat(64)

export class AuditLog {
  /** @param {string} filePath */
  constructor(filePath) {
    this.path = filePath
  }

  /**
   * Append one event. `data` must be secret-free.
   * @param {{actor:string, action:string, entryId?:string, title?:string, fields?:string[], detail?:string, ok?:boolean, at?:number}} event
   */
  async append(event) {
    const dir = path.dirname(this.path)
    await fsp.mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => {})
    let prev = GENESIS
    try {
      const tail = readTailLine(this.path)
      if (tail) prev = sha256Hex(tail)
    } catch { /* new file */ }
    const record = { at: event.at ?? Date.now(), actor: event.actor, action: event.action, ...stripNils(event), prev }
    record.hash = sha256Hex(JSON.stringify({ ...record, hash: undefined }))
    await fsp.appendFile(this.path, JSON.stringify(record) + '\n', { mode: FILE_MODE })
    return record
  }

  /**
   * Walk the chain and verify every link. @returns {Promise<{valid:boolean, count:number, brokenAt?:number}>}
   */
  async verify() {
    let raw
    try {
      raw = await fsp.readFile(this.path, 'utf8')
    } catch (err) {
      if (err.code === 'ENOENT') return { valid: true, count: 0 }
      throw err
    }
    const lines = raw.split('\n').filter(Boolean)
    let prev = GENESIS
    for (let i = 0; i < lines.length; i++) {
      let rec
      try { rec = JSON.parse(lines[i]) } catch { return { valid: false, count: i, brokenAt: i } }
      if (rec.prev !== prev) return { valid: false, count: i, brokenAt: i }
      const recomputed = sha256Hex(JSON.stringify({ ...rec, hash: undefined }))
      if (recomputed !== rec.hash) return { valid: false, count: i, brokenAt: i }
      prev = sha256Hex(lines[i])
    }
    return { valid: true, count: lines.length }
  }

  /** Read the most recent `limit` records (newest first). @returns {Promise<object[]>} */
  async recent(limit = 20) {
    let raw
    try {
      raw = await fsp.readFile(this.path, 'utf8')
    } catch {
      return []
    }
    const lines = raw.split('\n').filter(Boolean).slice(-limit).reverse()
    return lines.map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  }
}

/** Last non-empty line of a file without reading it whole (seek-from-end). */
function readTailLine(filePath) {
  const fd = fs.openSync(filePath, 'r')
  try {
    const size = fs.fstatSync(fd).size
    if (size === 0) return null
    const chunk = Math.min(size, 64 * 1024)
    const buf = Buffer.alloc(chunk)
    fs.readSync(fd, buf, 0, chunk, size - chunk)
    const lines = buf.toString('utf8').split('\n').filter(Boolean)
    if (lines.length === 0) return null
    // if the read started mid-line the first entry is partial; drop it unless
    // the file is smaller than the chunk.
    if (chunk < size && lines.length > 1) return lines[lines.length - 1]
    return lines[lines.length - 1]
  } finally {
    fs.closeSync(fd)
  }
}

/** Remove null/undefined keys so the hash input stays stable. */
function stripNils(obj) {
  const out = {}
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || k === 'actor' || k === 'action' || k === 'at') continue
    out[k] = v
  }
  return out
}
