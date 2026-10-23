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

/** Reveal postures (the "how do you take secrets OUT" dial). */
export const REVEAL_MODES = ['deny', 'ask', 'allow']

/** Defaults: assistant-first vault — store is open, plaintext out is gated. */
export const DEFAULT_POLICY = Object.freeze({
  version: 1,
  accessMode: 'readonly',
  autoCapture: false,          // never auto-save secrets seen in conversation
  revealRequiresConfirm: true,  // plaintext reveal in UI asks for a re-confirm
  totpViaModel: false,          // TOTP codes are NOT handed to the model
  envExport: true,              // $DSH_* injection enabled (per-entry opt-in via `env`)
  modelReveal: 'ask',           // vaultx_reveal needs a human approval per call
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
    modelReveal: REVEAL_MODES.includes(p.modelReveal) ? p.modelReveal : DEFAULT_POLICY.modelReveal,
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
 * Pure decision function: given a policy + a model tool call, what happens?
 * Returns `{allowed, ask?, reason?}`. `ask:true` means "run it only after a
 * human approves this specific call" — the caller (pre-execute gate) turns it
 * into a `kind:'ask'` waterfall decision. Used by both registration (which
 * tools exist at all) and the gate (defense in depth: policy can change
 * between registration and the call).
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

  // Reveal (plaintext value out to the model) is governed by `modelReveal`,
  // NOT by accessMode — it is a separate "how do secrets leave the box" dial.
  // This is the assistant's own vault: taking a secret back is a first-class
  // operation, gated per call by default. high entries stay human-only even
  // under `allow`, so the operator always keeps one hard escape hatch.
  if (family === 'reveal') {
    if (context.sensitivity === 'high') {
      return { allowed: false, reason: 'vaultx: entry is high-sensitivity (human-only channel, never revealed to the model)' }
    }
    const posture = policy.modelReveal
    if (posture === 'deny') return { allowed: false, reason: 'vaultx: plaintext reveal to the model is disabled (use $DSH_* or lower the modelReveal dial)' }
    if (posture === 'allow') return { allowed: true }
    return { allowed: true, ask: true, reason: 'vaultx: assistant is reading a plaintext credential — approve this one time' }
  }

  // Hard rule: high-sensitivity entries are invisible to every OTHER model
  // tool regardless of posture (list/get/totp/set/delete all hide them).
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
  // CREATE (store something new) is the assistant's core capability — allowed
  // in every non-sealed mode. The user hands the assistant a credential, it
  // puts it in its own box. This is NOT gated by readonly.
  const CREATE = new Set(['add', 'generate'])
  // MUTATE (change/delete what exists) is what `accessMode` actually guards.
  const MUTATE = new Set(['update', 'set'])
  const DELETE = new Set(['delete'])

  if (READ.has(family)) return { allowed: true }

  if (CREATE.has(family)) {
    return { allowed: true } // mode!=='sealed' already returned above
  }

  if (MUTATE.has(family)) {
    if (mode === 'readonly') return { allowed: false, reason: 'vaultx: read-only mode (the assistant may store new entries but not change existing ones)' }
    // write/edit: only entries the model created (origin=model) are mutable;
    // operator-owned data stays immutable to the assistant.
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
