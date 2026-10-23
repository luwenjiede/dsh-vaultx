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
  seal, unseal, fieldAad, newId,
} from './crypto.js'
import { DIR_MODE, FILE_MODE, MAX_ENTRIES, SENSITIVITIES } from './constants.js'

/** In-memory representation of one entry (secrets as plaintext fields). */
export class Entry {
  constructor(raw) {
    Object.assign(this, raw)
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
      fields: this.fieldNames(),
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
    const doc = JSON.parse(raw)
    if (!doc || typeof doc !== 'object' || !doc.header || !Array.isArray(doc.entries)) {
      throw new Error('vaultx: vault file is not a recognized VaultX document')
    }
    return new VaultStore({ path: filePath, doc, vaultKey: null })
  }

  /** Decrypt the vault key with the master password and unlock. */
  async unlock(masterPassword) {
    const mk = await deriveMasterKey(masterPassword, this.doc.header.kdf)
    const vk = unwrapKey(this.doc.header.wrappedKey, mk)
    if (!verifyCheck(this.doc.header.check, vk)) {
      throw Object.assign(new Error('vaultx: wrong master password (check token failed)'), { code: 'auth' })
    }
    this.vk = vk
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
    if (!verifyCheck(this.doc.header.check, vk)) {
      throw Object.assign(new Error('vaultx: old master password incorrect'), { code: 'auth' })
    }
    const kdf = newKdfParams()
    const newMk = await deriveMasterKey(newPassword, kdf)
    this.doc.header = { kdf, wrappedKey: wrapKey(vk, newMk), check: makeCheck(vk) }
    this.vk = vk
    this._dirty = true
  }

  /** Wrap the current vault key for export under a *different* password. */
  async exportWrapped(targetPassword) {
    if (!this.unlocked) throw new Error('vaultx: store must be unlocked to export')
    const kdf = newKdfParams()
    const mk = await deriveMasterKey(targetPassword, kdf)
    return { version: 1, header: { kdf, wrappedKey: wrapKey(this.vk, mk), check: makeCheck(this.vk) } }
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
      .filter(raw => typeof raw.env === 'string' && /^DSH_[A-Z0-9_]{3,}$/.test(raw.env))
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
    if (env !== undefined && env !== null && env !== '') {
      if (!/^DSH_[A-Z0-9_]{3,}$/.test(String(env))) {
        throw new Error('vaultx: env name must match /^DSH_[A-Z0-9_]{3,}$/')
      }
      const resolved = envField ?? firstSecretField(fields)
      if (!fields[resolved]) throw new Error(`vaultx: env entry has no recognizable secret field (checked: ${Object.keys(fields).join(', ') || 'none'}); pass envField or name one apiKey/password/secret/token`)
      if (sensitivity === 'high') {
        throw new Error('vaultx: high-sensitivity entries cannot be exported to $DSH_* (human-only channel)')
      }
    }
    const id = newId()
    const now = Date.now()
    const encFields = {}
    for (const [name, value] of Object.entries(fields)) {
      if (name === 'envField') continue // metadata, not a secret
      if (value === undefined || value === null || value === '') continue
      encFields[name] = seal(String(value), this.vk, fieldAad(id, name))
    }
    const raw = {
      id, title, kind, sensitivity,
      ...(env ? { env, envField: envField ?? firstSecretField(encFields) } : {}),
      tags: Array.isArray(tags) ? tags : [String(tags)],
      fields: encFields,
      createdAt: createdAt ?? now,
      updatedAt: updatedAt ?? now,
    }
    // Notes ride in the field map under a reserved name, same AAD discipline.
    if (notes) raw.fields.__notes__ = seal(String(notes), this.vk, fieldAad(id, '__notes__'))
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
    if (patch.title !== undefined) raw.title = String(patch.title)
    if (patch.kind !== undefined) raw.kind = String(patch.kind)
    if (patch.sensitivity !== undefined && SENSITIVITIES.includes(patch.sensitivity)) raw.sensitivity = patch.sensitivity
    if (patch.tags !== undefined) raw.tags = Array.isArray(patch.tags) ? patch.tags : [String(patch.tags)]
    if (patch.env !== undefined) {
      if (patch.env === null || patch.env === '') { delete raw.env; delete raw.envField }
      else { raw.env = String(patch.env); raw.envField = patch.envField ?? raw.envField ?? 'password' }
    }
    for (const [name, value] of Object.entries(patch.fields ?? {})) {
      if (value === null || value === '') { delete raw.fields[name]; continue }
      raw.fields[name] = seal(String(value), this.vk, fieldAad(raw.id, name))
    }
    raw.updatedAt = Date.now()
    this._dirty = true
    return new Entry({ raw, vk: this.vk })
  }

  /** Persist atomically. If `masterPassword` is omitted the store must already be unlocked. */
  async save() {
    if (!this._dirty && !this.doc.header) throw new Error('vaultx: nothing to save (locked or unchanged)')
    if (!this.doc.header) throw new Error('vaultx: header missing — cannot save')
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
