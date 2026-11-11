/**
 * VaultX encrypted store — the single JSON document on disk.
 *
 * Layout (everything except `header` is ciphertext at rest):
 * {
 *   "version": 1,
 *   "header": { "kdf": {...}, "wrappedKey": {iv,tag,data}, "check": {iv,tag,data} },
 *   "entries": [ { id, title, kind, sensitivity, env?, tags, createdAt, updatedAt,
 *                  fields: { <name>: {iv,tag,data} } } ]
 * }
 *
 * Secrets never appear in this file except as AES-GCM blobs. A wrong key is
 * detected by the `check` blob before entries are ever touched.
 *
 * Atomic writes: tmp file in the same directory → fsync → rename → dir fsync.
 * File/dir modes pinned to 0600/0700. A legacy `*.bak` copy of the previous
 * file is kept during the rename window so a crash mid-write can't lose data.
 *
 * @module vaultx/store
 */
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import {
  newVaultKey, newKdfParams, deriveMasterKey, wrapKey, unwrapKey, makeCheck, verifyCheck,
  seal, unseal, fieldAad, newId, hmac, safeEqual,
} from './crypto.js'
import { DIR_MODE, FILE_MODE, MAX_ENTRIES, SENSITIVITIES } from './constants.js'

/** Reserved (non-user) field names: never listed in summaries. */
const RESERVED_FIELDS = new Set(['__notes__', 'envField'])
/** Field names that must never be accepted from untrusted input (prototype chain). */
const FORBIDDEN_FIELDS = new Set(['__proto__', 'constructor', 'prototype'])
/** The env namespace pattern; single source of truth for add/update/envEntries. */
export const ENV_NAME_RE = /^DSH_[A-Z0-9_]{3,}$/
/** A GCM envelope blob must have exactly these three hex strings. */
function isBlob(v) {
  return v && typeof v === 'object'
    && typeof v.ivHex === 'string' && /^[0-9a-f]{24}$/.test(v.ivHex)
    && typeof v.tagHex === 'string' && /^[0-9a-f]{32}$/.test(v.tagHex)
    && typeof v.dataHex === 'string' && /^[0-9a-f]*$/.test(v.dataHex)
}

/**
 * Structural validation for documents arriving from DISK or IMPORT (review
 * P1-3). Rebuilds every entry with whitelisted keys on a null-prototype field
 * map so a hostile `__proto__` key can never reach a prototype setter.
 * Throws on the first malformed entry; returns a sanitized doc.
 */
export function sanitizeDocument(doc) {
  if (!doc || typeof doc !== 'object' || !doc.header || !Array.isArray(doc.entries)) {
    throw new Error('vaultx: vault file is not a recognized VaultX document')
  }
  const h = doc.header
  if (!h.kdf || h.kdf.algo !== 'scrypt' || typeof h.kdf.saltHex !== 'string'
    || !Number.isInteger(h.kdf.n) || h.kdf.n < 2 || (h.kdf.n & (h.kdf.n - 1)) !== 0
    || !Number.isInteger(h.kdf.r) || !Number.isInteger(h.kdf.p)
    || !isBlob(h.wrappedKey) || !isBlob(h.check)) {
    throw new Error('vaultx: vault header is malformed (kdf/wrappedKey/check)')
  }
  const ids = new Set()
  const envs = new Set()
  const entries = doc.entries.map((e, i) => {
    if (!e || typeof e !== 'object' || typeof e.id !== 'string' || !/^[0-9a-f]{24}$/.test(e.id)
      || typeof e.title !== 'string' || !e.title
      || !e.fields || typeof e.fields !== 'object' || Array.isArray(e.fields)) {
      throw new Error(`vaultx: entry #${i} is malformed (id/title/fields)`)
    }
    if (ids.has(e.id)) throw new Error(`vaultx: duplicate entry id ${e.id}`)
    ids.add(e.id)
    const sensitivity = SENSITIVITIES.includes(e.sensitivity) ? e.sensitivity : 'normal'
    const fields = Object.create(null)
    for (const [name, blob] of Object.entries(e.fields)) {
      if (FORBIDDEN_FIELDS.has(name)) throw new Error(`vaultx: entry ${e.id} has forbidden field name "${name}"`)
      if (!isBlob(blob)) throw new Error(`vaultx: entry ${e.id} field "${name}" is not a valid encrypted blob`)
      fields[name] = { ivHex: blob.ivHex, tagHex: blob.tagHex, dataHex: blob.dataHex }
    }
    const out = {
      id: e.id, title: e.title,
      kind: typeof e.kind === 'string' ? e.kind : 'secret',
      sensitivity,
      tags: Array.isArray(e.tags) ? e.tags.filter(t => typeof t === 'string') : [],
      fields,
      createdAt: Number.isFinite(e.createdAt) ? e.createdAt : 0,
      updatedAt: Number.isFinite(e.updatedAt) ? e.updatedAt : 0,
    }
    if (typeof e.env === 'string' && e.env) {
      if (!ENV_NAME_RE.test(e.env)) throw new Error(`vaultx: entry ${e.id} has invalid env name "${e.env}"`)
      if (envs.has(e.env)) throw new Error(`vaultx: duplicate env name ${e.env}`)
      envs.add(e.env)
      out.env = e.env
      out.envField = typeof e.envField === 'string' ? e.envField : 'password'
    }
    if (typeof e.metaMac === 'string' && /^[0-9a-f]{64}$/.test(e.metaMac)) out.metaMac = e.metaMac
    return out
  })
  return { version: 1, header: { kdf: { algo: 'scrypt', n: h.kdf.n, r: h.kdf.r, p: h.kdf.p, saltHex: h.kdf.saltHex }, wrappedKey: { ...h.wrappedKey }, check: { ...h.check } }, entries }
}

/**
 * Canonical metadata projection for the per-entry integrity MAC (review
 * P1-2). Fixed key order + JSON.stringify gives a stable byte string; the MAC
 * key is HMAC(VK, domain-separator), never VK itself.
 */
function metaProjection(raw) {
  return JSON.stringify([
    raw.id, raw.title, raw.kind ?? 'secret', raw.sensitivity ?? 'normal',
    raw.env ?? '', raw.envField ?? '', [...(raw.tags ?? [])].sort(),
    Object.keys(raw.fields).sort(), raw.createdAt ?? 0,
  ])
}
function metaMacFor(raw, vk) {
  const macKey = hmac('sha256', vk, 'vaultx-meta-mac-v1')
  return hmac('sha256', macKey, metaProjection(raw)).toString('hex')
}

/**
 * Shared entry-metadata validation for add() AND update() (review P0-1/P0-3).
 * Mutates nothing; throws with actionable messages.
 * @param {{env?:string|null, envField?:string, sensitivity?:string, fieldNames:string[], excludeId?:string}} meta
 * @param {object[]} entries - current raw entries (for env-collision checks).
 */
export function validateEntryMeta({ env, envField, sensitivity, fieldNames }, entries) {
  for (const name of fieldNames) {
    if (FORBIDDEN_FIELDS.has(name)) throw new Error(`vaultx: field name "${name}" is reserved (prototype safety)`)
  }
  if (env === undefined || env === null || env === '') return
  if (!ENV_NAME_RE.test(String(env))) {
    throw new Error('vaultx: env name must match /^DSH_[A-Z0-9_]{3,}$/')
  }
  if (sensitivity === 'high') {
    throw new Error('vaultx: high-sensitivity entries cannot be exported to $DSH_* (human-only channel)')
  }
  if (envField !== undefined && !fieldNames.includes(envField)) {
    throw new Error(`vaultx: envField "${envField}" does not exist on the entry (fields: ${fieldNames.join(', ') || 'none'})`)
  }
  const clash = entries.find(e => e.env === env)
  if (clash) {
    throw new Error(`vaultx: env name ${env} is already used by entry "${clash.title}" (${clash.id}); env names must be unique`)
  }
}

/** In-memory representation of one entry (secrets as plaintext fields). */
export class Entry {
  constructor(raw) {
    // Whitelist-copy known keys: a hand-edited/imported `__proto__` key must
    // never reach Object.assign's prototype setter (review P1-3).
    this.raw = raw.raw ?? raw
    if (raw.vk !== undefined) this.vk = raw.vk
  }
  get id() { return this.raw.id }
  get title() { return this.raw.title }
  get kind() { return this.raw.kind }
  get sensitivity() { return this.raw.sensitivity }
  get env() { return this.raw.env }
  get tags() { return this.raw.tags }
  get createdAt() { return this.raw.createdAt }
  get updatedAt() { return this.raw.updatedAt }
  get notes() { return this.raw.notes }

  /**
   * @param {string} name
   * @returns {string|undefined} plaintext field value (undefined if absent).
   */
  field(name) {
    const blob = this.raw.fields[name]
    if (!blob) return undefined
    return unseal(blob, this.vk, fieldAad(this.raw.id, name)).toString('utf8')
  }

  /** True if a field name exists (without decrypting). */
  has(name) {
    return Object.prototype.hasOwnProperty.call(this.raw.fields, name)
  }

  /** Field names without their values. */
  fieldNames() {
    return Object.keys(this.raw.fields)
  }

  /** Non-secret summary safe for model/CLI/UI list rendering. */
  summary({ includeEnv = true } = {}) {
    return {
      id: this.raw.id,
      title: this.raw.title,
      kind: this.raw.kind,
      sensitivity: this.raw.sensitivity,
      ...(includeEnv && this.raw.env ? { env: this.raw.env } : {}),
      tags: this.raw.tags ?? [],
      // Reserved fields are filtered at the SOURCE so every consumer (panel,
      // CLI, search, tools) sees the same list (review P1-6).
      fields: this.fieldNames().filter(f => !RESERVED_FIELDS.has(f)),
      createdAt: this.raw.createdAt,
      updatedAt: this.raw.updatedAt,
    }
  }
}

/**
 * A VaultX document bound to a decrypted vault key. A *locked* store is a
 * valid state: structural reads (summaries) work, field decryption throws.
 */
export class VaultStore {
  /**
   * @param {{path:string, doc:object|null, vaultKey:Buffer|null}} state
   */
  constructor({ path: filePath, doc, vaultKey }) {
    this.path = filePath
    this.doc = doc ?? { version: 1, header: null, entries: [] }
    this.vk = vaultKey ?? null
    this._dirty = false
  }

  /** True when a vault key is loaded (secrets can be decrypted). */
  get unlocked() { return this.vk !== null }

  /** @returns {boolean} */
  get empty() { return (this.doc.entries ?? []).length === 0 }

  get size() { return (this.doc.entries ?? []).length }

  /** Create a brand-new encrypted document and unlock it. */
  static async createNew({ path: filePath, masterPassword }) {
    const vk = newVaultKey()
    const kdf = newKdfParams()
    const mk = await deriveMasterKey(masterPassword, kdf)
    const doc = {
      version: 1,
      header: { kdf, wrappedKey: wrapKey(vk, mk), check: makeCheck(vk) },
      entries: [],
    }
    return new VaultStore({ path: filePath, doc, vaultKey: vk })
  }

  /** Load a document from disk (structural metadata only — stays locked). */
  static fromFile({ path: filePath }) {
    const raw = fs.readFileSync(filePath, 'utf8')
    return new VaultStore({ path: filePath, doc: sanitizeDocument(JSON.parse(raw)), vaultKey: null })
  }

  /** Decrypt the vault key with the master password and unlock. */
  async unlock(masterPassword) {
    const mk = await deriveMasterKey(masterPassword, this.doc.header.kdf)
    const vk = unwrapKey(this.doc.header.wrappedKey, mk)
    if (!verifyCheck(this.doc.header.check, vk)) {
      mk.fill(0)
      throw Object.assign(new Error('vaultx: wrong master password (check token failed)'), { code: 'auth' })
    }
    mk.fill(0)
    this.vk = vk
    // Backfill metadata MACs for legacy entries on the next save; existing
    // MACs are NOT trusted silently — verifyMetadata() reports mismatches.
    return this
  }

  /** Drop the vault key; structural metadata stays readable, fields do not. */
  lock() {
    if (!this.vk) return this
    // Zero the in-memory key material before dropping the reference.
    this.vk.fill(0)
    this.vk = null
    return this
  }

  /** Change the master password (re-wraps VK; entries untouched). */
  async changeMasterPassword(oldPassword, newPassword) {
    // Verify old first (the check token doubles as the password proof).
    const oldMk = await deriveMasterKey(oldPassword, this.doc.header.kdf)
    const vk = unwrapKey(this.doc.header.wrappedKey, oldMk)
    oldMk.fill(0)
    if (!verifyCheck(this.doc.header.check, vk)) {
      vk.fill(0)
      throw Object.assign(new Error('vaultx: old master password incorrect'), { code: 'auth' })
    }
    const kdf = newKdfParams()
    const newMk = await deriveMasterKey(newPassword, kdf)
    this.doc.header = { kdf, wrappedKey: wrapKey(vk, newMk), check: makeCheck(vk) }
    newMk.fill(0)
    // Same key bytes as the current VK (unwrap produced a fresh buffer); zero
    // the old in-memory copy before swapping (review D-5).
    if (this.vk && this.vk !== vk) this.vk.fill(0)
    this.vk = vk
    this._dirty = true
  }

  /**
   * Verify per-entry metadata MACs (review P1-2). Entries without a MAC are
   * reported as `unsigned` (legacy docs, backfilled on next save), not broken.
   * @returns {{ok:boolean, unsigned:number, broken:Array<{id:string,title:string}>}}
   */
  verifyMetadata() {
    this.#requireUnlocked()
    let unsigned = 0
    const broken = []
    for (const raw of this.doc.entries ?? []) {
      if (!raw.metaMac) { unsigned += 1; continue }
      if (!safeEqual(raw.metaMac, metaMacFor(raw, this.vk))) broken.push({ id: raw.id, title: raw.title })
    }
    return { ok: broken.length === 0, unsigned, broken }
  }

  /** Wrap the current vault key for export under a *different* password. */
  async exportWrapped(targetPassword) {
    if (!this.unlocked) throw new Error('vaultx: store must be unlocked to export')
    const kdf = newKdfParams()
    const mk = await deriveMasterKey(targetPassword, kdf)
    const wrapped = { version: 1, header: { kdf, wrappedKey: wrapKey(this.vk, mk), check: makeCheck(this.vk) } }
    mk.fill(0)
    return wrapped
  }

  // ------------------------------------------------------------------ reads

  /** @returns {Entry[]} all entries, decrypted lazily per field access. */
  entries() {
    return (this.doc.entries ?? []).map(raw => new Entry({ raw, vk: this.vk }))
  }

  /** @param {string} id @returns {Entry|undefined} */
  get(id) {
    const raw = (this.doc.entries ?? []).find(e => e.id === id)
    return raw ? new Entry({ raw, vk: this.vk }) : undefined
  }

  /**
   * Non-secret search across title / tags / env / field names.
   * @param {string} query - case-insensitive substring.
   * @param {{limit?:number}} [opts]
   */
  search(query, { limit = 50 } = {}) {
    const q = String(query ?? '').toLowerCase().trim()
    const out = []
    for (const raw of this.doc.entries ?? []) {
      const hay = [raw.title, ...(raw.tags ?? []), raw.env ?? '', raw.kind ?? ''].join(' ').toLowerCase()
      if (!q || hay.includes(q)) {
        out.push(new Entry({ raw, vk: this.vk }).summary())
        if (out.length >= limit) break
      }
    }
    return out
  }

  /** Entries with a usable `env` name (candidates for shellEnv injection). */
  envEntries() {
    return (this.doc.entries ?? [])
      .filter(raw => typeof raw.env === 'string' && ENV_NAME_RE.test(raw.env))
      .map(raw => ({ env: raw.env, id: raw.id, title: raw.title, sensitivity: raw.sensitivity, field: raw.envField ?? 'password' }))
  }

  // ----------------------------------------------------------------- writes

  /**
   * Insert one entry. `secrets` maps field name → plaintext; they are
   * encrypted per-field before storage.
   * @returns {Entry}
   */
  add({ title, kind = 'login', sensitivity = 'normal', env, envField, tags = [], fields = {}, notes = '', createdAt, updatedAt }) {
    this.#requireUnlocked()
    if (this.size >= MAX_ENTRIES) throw new Error(`vaultx: entry limit (${MAX_ENTRIES}) reached`)
    if (!title || typeof title !== 'string') throw new Error('vaultx: entry requires a non-empty title')
    if (!SENSITIVITIES.includes(sensitivity)) sensitivity = 'normal'
    const cleanedFields = Object.fromEntries(
      Object.entries(fields).filter(([name, value]) => name !== 'envField' && value !== undefined && value !== null && value !== ''),
    )
    const resolvedEnvField = envField ?? (env ? firstSecretField(cleanedFields) : undefined)
    if (env !== undefined && env !== null && env !== '') {
      if (!cleanedFields[resolvedEnvField]) throw new Error(`vaultx: env entry has no recognizable secret field (checked: ${Object.keys(cleanedFields).join(', ') || 'none'}); pass envField or name one apiKey/password/secret/token`)
    }
    validateEntryMeta({ env, envField: resolvedEnvField, sensitivity, fieldNames: Object.keys(cleanedFields) }, this.doc.entries ?? [])
    const id = newId()
    const now = Date.now()
    const encFields = {}
    for (const [name, value] of Object.entries(cleanedFields)) {
      encFields[name] = seal(String(value), this.vk, fieldAad(id, name))
    }
    const raw = {
      id, title, kind, sensitivity,
      ...(env ? { env, envField: resolvedEnvField } : {}),
      tags: Array.isArray(tags) ? tags : [String(tags)],
      fields: encFields,
      createdAt: createdAt ?? now,
      updatedAt: updatedAt ?? now,
    }
    // Notes ride in the field map under a reserved name, same AAD discipline.
    if (notes) raw.fields.__notes__ = seal(String(notes), this.vk, fieldAad(id, '__notes__'))
    raw.metaMac = metaMacFor(raw, this.vk)
    this.doc.entries.push(raw)
    this._dirty = true
    return new Entry({ raw, vk: this.vk })
  }

  /** Remove one entry by id. @returns {boolean} */
  remove(id) {
    const before = this.doc.entries.length
    this.doc.entries = this.doc.entries.filter(e => e.id !== id)
    if (this.doc.entries.length !== before) {
      this._dirty = true
      return true
    }
    return false
  }

  /**
   * Replace/patch field secrets of an existing entry.
   * @param {string} id
   * @param {{fields?:object, title?:string, sensitivity?:string, tags?:string[], env?:string}} patch
   * @returns {Entry}
   */
  update(id, patch) {
    this.#requireUnlocked()
    const raw = this.doc.entries.find(e => e.id === id)
    if (!raw) throw Object.assign(new Error('vaultx: entry not found'), { code: 'not-found' })

    // Compute the POST-patch shape first, validate it with the SAME rules as
    // add() (review P0-1), then apply. Nothing mutates before validation.
    const nextSensitivity = patch.sensitivity !== undefined && SENSITIVITIES.includes(patch.sensitivity) ? patch.sensitivity : raw.sensitivity
    const nextFieldNames = new Set(Object.keys(raw.fields))
    for (const [name, value] of Object.entries(patch.fields ?? {})) {
      if (FORBIDDEN_FIELDS.has(name)) throw new Error(`vaultx: field name "${name}" is reserved (prototype safety)`)
      if (value === null || value === '') nextFieldNames.delete(name)
      else nextFieldNames.add(name)
    }
    let nextEnv = patch.env !== undefined ? (patch.env === null || patch.env === '' ? undefined : String(patch.env)) : raw.env
    let nextEnvField = patch.envField ?? raw.envField
    // Hard invariant: high entries are human-only — upgrading to high strips
    // the env export instead of silently keeping it (review P0-1).
    if (nextSensitivity === 'high' && nextEnv) { nextEnv = undefined; nextEnvField = undefined }
    validateEntryMeta(
      { env: nextEnv, envField: nextEnvField, sensitivity: nextSensitivity, fieldNames: [...nextFieldNames] },
      (this.doc.entries ?? []).filter(e => e.id !== id),
    )

    if (patch.title !== undefined) raw.title = String(patch.title)
    if (patch.kind !== undefined) raw.kind = String(patch.kind)
    raw.sensitivity = nextSensitivity
    if (patch.tags !== undefined) raw.tags = Array.isArray(patch.tags) ? patch.tags : [String(patch.tags)]
    if (nextEnv) { raw.env = nextEnv; raw.envField = nextEnvField ?? 'password' }
    else { delete raw.env; delete raw.envField }
    for (const [name, value] of Object.entries(patch.fields ?? {})) {
      if (value === null || value === '') { delete raw.fields[name]; continue }
      raw.fields[name] = seal(String(value), this.vk, fieldAad(raw.id, name))
    }
    raw.updatedAt = Date.now()
    raw.metaMac = metaMacFor(raw, this.vk)
    this._dirty = true
    return new Entry({ raw, vk: this.vk })
  }

  /** Persist atomically. If `masterPassword` is omitted the store must already be unlocked. */
  async save() {
    if (!this._dirty && !this.doc.header) throw new Error('vaultx: nothing to save (locked or unchanged)')
    if (!this.doc.header) throw new Error('vaultx: header missing — cannot save')
    // Backfill metadata MACs for legacy entries whenever we hold the key
    // (review P1-2). Never re-MAC blindly over a MISMATCH — that would bless
    // tampered metadata; only entries with no MAC at all are backfilled.
    if (this.unlocked) {
      for (const raw of this.doc.entries ?? []) {
        if (!raw.metaMac) raw.metaMac = metaMacFor(raw, this.vk)
      }
    }
    const dir = path.dirname(this.path)
    await fsp.mkdir(dir, { recursive: true, mode: DIR_MODE }).catch(() => {})
    await fsp.chmod(dir, DIR_MODE).catch(() => {})
    const tmp = `${this.path}.${process.pid}.${Date.now()}.tmp`
    const payload = JSON.stringify(this.doc, null, 2)
    const handle = await fsp.open(tmp, 'w', FILE_MODE)
    try {
      await handle.writeFile(payload, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    try {
      await fsp.copyFile(this.path, `${this.path}.bak`).catch(() => {})
      await fsp.rename(tmp, this.path)
    } finally {
      await fsp.rm(tmp, { force: true }).catch(() => {})
    }
    try {
      const dh = await fsp.open(dir, 'r')
      try { await dh.sync() } finally { await dh.close() }
    } catch { /* some filesystems do not allow opening dirs */ }
    this._dirty = false
  }

  /** Throw when an operation needs the vault key but it is absent. */
  #requireUnlocked() {
    if (!this.vk) throw Object.assign(new Error('vaultx: vault is locked — unlock with the master password first'), { code: 'locked' })
  }
}

/** First plausible secret field name for env injection. */
function firstSecretField(fields) {
  const priority = ['apiKey', 'password', 'secret', 'token', 'accessToken', 'privateKey']
  for (const p of priority) if (fields[p]) return p
  return Object.keys(fields).find(k => !['username', 'host', 'url', 'notes', 'envField'].includes(k)) ?? 'password'
}

/** Re-export of the default file resolver helper (used by index/cli). */
export function defaultVaultPath(dshHome) {
  return path.join(dshHome ?? '~/.dsh', 'vaultx', 'vault.json')
}
