/**
 * Operator policy — the single source of truth for what the model may do.
 *
 * Lives OUTSIDE the encrypted document (plain JSON at vaultx/policy.json,
 * mode 0600) for two reasons:
 *   1. the shellEnv resolver and the tools/pre-execute gate must read it while
 *      the vault is still locked, and
 *   2. it must survive a locked vault — policy is about control, not secrets.
 *
 * Modes (ascending capability):
 *   - 'sealed'   : model gets no tools and no $DSH_* values at all.
 *   - 'readonly' : read-only model tools (masked); $DSH_* injection active.
 *   - 'write'    : + add/update for origin='model' entries only.
 *   - 'edit'     : + delete (still requires the two-phase confirm round-trip).
 *
 * High-sensitivity entries are exempt from every model channel by design:
 * they are human-only (policy hard-codes this; the operator cannot widen it).
 *
 * @module vaultx/policy
 */
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { FILE_MODE } from './constants.js'

export const ACCESS_MODES = ['sealed', 'readonly', 'write', 'edit']

/** Defaults: the most conservative useful posture. */
export const DEFAULT_POLICY = Object.freeze({
  version: 1,
  accessMode: 'readonly',
  autoCapture: false,          // never auto-save secrets seen in conversation
  revealRequiresConfirm: true,  // plaintext reveal in UI asks for a re-confirm
  totpViaModel: false,          // TOTP codes are NOT handed to the model
  envExport: true,              // $DSH_* injection enabled (per-entry opt-in via `env`)
})

/** Normalize/validate an untrusted policy object. Unknown fields are dropped. */
export function normalise(raw) {
  const p = raw && typeof raw === 'object' ? raw : {}
  return {
    version: 1,
    accessMode: ACCESS_MODES.includes(p.accessMode) ? p.accessMode : DEFAULT_POLICY.accessMode,
    autoCapture: typeof p.autoCapture === 'boolean' ? p.autoCapture : DEFAULT_POLICY.autoCapture,
    revealRequiresConfirm: p.revealRequiresConfirm !== false,
    totpViaModel: p.totpViaModel === true,
    envExport: p.envExport !== false,
  }
}

/**
 * File-backed policy with a cached snapshot and atomic save.
 */
export class PolicyStore {
  /** @param {string} filePath */
  constructor(filePath) {
    this.path = filePath
    this.cache = { ...DEFAULT_POLICY }
  }

  /** Load from disk (missing file → defaults; corrupt file → defaults + error surfaced to caller). */
  load() {
    try {
      const raw = fs.readFileSync(this.path, 'utf8')
      this.cache = normalise(JSON.parse(raw))
    } catch (err) {
      if (err.code !== 'ENOENT') this.lastError = err
      this.cache = { ...DEFAULT_POLICY }
    }
    return this.cache
  }

  /** @returns {object} current policy snapshot. */
  get() { return this.cache }

  /** Persist a new policy. Only the settings-page gateway calls this. */
  async set(patch) {
    const next = normalise({ ...this.cache, ...patch })
    const dir = path.dirname(this.path)
    await fsp.mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => {})
    const tmp = `${this.path}.${process.pid}.tmp`
    const handle = await fsp.open(tmp, 'w', FILE_MODE)
    try {
      await handle.writeFile(JSON.stringify(next, null, 2), 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await fsp.rename(tmp, this.path)
    this.cache = next
    return next
  }
}

/**
 * Pure decision function: given a policy + a model tool call, allow or deny?
 * Returns {allowed, reason}. Used by both registration (which tools exist at
 * all) and the pre-execute gate (defense in depth: policy can change between
 * registration and the call).
 *
 * @param {object} policy
 * @param {string} toolName - e.g. 'vaultx_list'
 * @param {{sensitivity?:'low'|'normal'|'high', origin?:'model'|'operator'}} [context]
 */
export function checkModelAccess(policy, toolName, context = {}) {
  const mode = policy.accessMode
  const family = toolName.replace(/^vaultx_/, '')

  if (mode === 'sealed') {
    return { allowed: false, reason: 'vaultx: model access is sealed by operator policy' }
  }

  // intent is a non-mutating declaration; always allowed when tools exist.
  if (family === 'intent') return { allowed: true }

  // Hard rule #1: the model NEVER reads plaintext secret values. Masked views
  // only. This is the whole point of the fusion; no mode loosens it.
  if (family === 'reveal') {
    return { allowed: false, reason: 'vaultx: plaintext values are only available to the operator via $DSH_* substitution or the settings panel — never to the model' }
  }

  // Hard rule #2: high-sensitivity entries are invisible to model tools.
  if (context.sensitivity === 'high') {
    return { allowed: false, reason: 'vaultx: entry is marked high-sensitivity (human-only channel)' }
  }

  // TOTP codes: off unless explicitly enabled (they are short-lived secrets;
  // default posture keeps them out of the transcript). When enabled, allowed.
  if (family === 'totp') {
    return policy.totpViaModel
      ? { allowed: true }
      : { allowed: false, reason: 'vaultx: TOTP codes are withheld from the model (operator can enable totpViaModel)' }
  }

  const READ = new Set(['list', 'search', 'get', 'describe', 'field_names'])
  const WRITE = new Set(['add', 'update', 'set', 'generate'])
  const DELETE = new Set(['delete'])

  if (READ.has(family)) return { allowed: true }

  if (WRITE.has(family)) {
    if (mode === 'readonly') return { allowed: false, reason: 'vaultx: read-only mode' }
    // write/edit: model may create its own entries; it may only modify entries
    // it created (origin='model') — operator-owned data is immutable to it.
    if (context.origin === 'operator') {
      return { allowed: false, reason: 'vaultx: entry is operator-owned; the model may not modify it' }
    }
    return { allowed: true }
  }

  if (DELETE.has(family)) {
    if (mode !== 'edit') return { allowed: false, reason: 'vaultx: delete requires edit mode' }
    if (context.origin === 'operator') {
      return { allowed: false, reason: 'vaultx: entry is operator-owned; the model may not delete it' }
    }
    return { allowed: true } // still requires the confirm round-trip in tools.js
  }

  return { allowed: false, reason: `vaultx: unknown tool family "${family}"` }
}
