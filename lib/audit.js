/**
 * Tamper-evident audit log — a hash chain over JSONL records.
 *
 * Each record carries the SHA-256 of the previous record, so deleting or
 * editing any line breaks every hash after it. `verify()` detects this.
 * Records contain only non-secret context (actor, tool, entry id/title,
 * field names) — never values, never plaintext that is itself a secret.
 *
 * Appends are serialized by an in-process promise queue AND a cross-process
 * lockfile (`audit.log.lock`, mkdir-atomic, stale-takeover) so the CLI and the
 * host never fork the chain by reading the same tail (review P1-4).
 *
 * @module vaultx/audit
 */
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { sha256Hex } from './crypto.js'
import { FILE_MODE } from './constants.js'

const GENESIS = '0'.repeat(64)
/** Cap untrusted text so one record stays well under the 64KiB tail window. */
const MAX_DETAIL = 2000
const MAX_TITLE = 300

/**
 * Cross-process lock for one append (review P1-4): the in-process queue only
 * serializes THIS process; the CLI writes the same file from another process.
 * A `mkdir`-based lockfile (atomic on every POSIX fs and win32) with staleness
 * takeover keeps the read-tail → append window exclusive across processes.
 */
async function withFileLock(filePath, fn, { timeoutMs = 3000, staleMs = 10_000 } = {}) {
  const lockPath = `${filePath}.lock`
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 })
      break
    } catch (err) {
      if (err.code !== 'EEXIST') throw err
      // Steal a stale lock (crashed writer): older than staleMs.
      try {
        const st = fs.statSync(lockPath)
        if (Date.now() - st.mtimeMs > staleMs) { fs.rmSync(lockPath, { recursive: true, force: true }); continue }
      } catch { /* vanished between checks — retry immediately */ continue }
      if (Date.now() > deadline) throw new Error(`vaultx: audit lock busy (${lockPath})`)
      await new Promise(r => setTimeout(r, 15))
    }
  }
  try { return await fn() } finally { try { fs.rmSync(lockPath, { recursive: true, force: true }) } catch { /* best effort */ } }
}

export class AuditLog {
  /** @param {string} filePath */
  constructor(filePath) {
    this.path = filePath
    // Serial queue: appends must never interleave, or two writers read the
    // same tail line and fork the chain at the same prev (observed in the
    // real host when retool's fire-and-forget raced a user create-vault).
    // One AuditLog instance == one process == one chain of custody.
    this._queue = Promise.resolve()
  }

  /**
   * Queue one event append; resolves with the written record.
   * `data` must be secret-free.
   * @param {{actor:string, action:string, entryId?:string, title?:string, fields?:string[], detail?:string, ok?:boolean, at?:number}} event
   */
  append(event) {
    const write = this._queue.then(() => this._appendNow(event))
    // The queue itself must survive a failed write (a broken disk shouldn't
    // wedge every later audit call; the caller sees this rejection).
    this._queue = write.then(() => {}, () => {})
    return write
  }

  async _appendNow(event) {
    const dir = path.dirname(this.path)
    await fsp.mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => {})
    // Bound untrusted strings (review D-7): a giant title/detail could exceed
    // the tail-read window and forge a false chain break.
    const bounded = { ...event }
    if (typeof bounded.detail === 'string') bounded.detail = bounded.detail.slice(0, MAX_DETAIL)
    if (typeof bounded.title === 'string') bounded.title = bounded.title.slice(0, MAX_TITLE)
    return withFileLock(this.path, async () => {
      let prev = GENESIS
      try {
        const tail = readTailLine(this.path)
        if (tail) prev = sha256Hex(tail)
      } catch { /* new file */ }
      const record = { at: bounded.at ?? Date.now(), actor: bounded.actor, action: bounded.action, ...stripNils(bounded), prev }
      record.hash = sha256Hex(JSON.stringify({ ...record, hash: undefined }))
      await fsp.appendFile(this.path, JSON.stringify(record) + '\n', { mode: FILE_MODE })
      return record
    })
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
