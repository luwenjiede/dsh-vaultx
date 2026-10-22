/**
 * Model-facing tools for VaultX.
 *
 * Invariants that hold in EVERY mode (the fusion's backbone):
 *
 *  1. **No tool ever returns a plaintext secret value.** The model sees ids,
 *     titles, field NAMES, masked values and strength scores. The only channels
 *     that carry values are $DSH_* shell substitution (host-side, per call)
 *     and the operator's settings panel. A hallucinated or injected prompt
 *     cannot exfiltrate the vault through the transcript.
 *
 *  2. **vaultx_generate stores instead of printing.** Fresh secrets go into an
 *     entry; the transcript only ever sees the id + strength stats.
 *
 *  3. **Deletion is two-phase** (single-use confirm tokens, in-memory only).
 *
 *  4. **Policy is re-checked at call time** (registerModelTools decides which
 *     tools EXIST; the pre-execute gate in index.js decides what they may DO
 *     against the live policy + entry metadata — origin/sensitivity).
 *
 * @module vaultx/tools
 */
import { randomBytes } from 'node:crypto'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { assess, label } from './strength.js'
import { generatePassword, generatePassphrase, generateToken, generateTotpSecret } from './generate.js'
import { totp, totpRemaining } from './totp.js'
import { checkModelAccess } from './policy.js'
import { maskValue } from './mask.js'

/** Delete-confirmation tokens: random, single-use, memory-only, 5 min TTL. */
export class ConfirmationLedger {
  constructor(ttlMs = 5 * 60_000) {
    this.ttlMs = ttlMs
    /** @type {Map<string,{id:string,expiresAt:number}>} */
    this.pending = new Map()
  }

  issue(id) {
    this.#sweep()
    for (const [token, entry] of this.pending) {
      if (entry.id === id) this.pending.delete(token) // one token per target
    }
    const token = randomBytes(16).toString('hex')
    this.pending.set(token, { id, expiresAt: Date.now() + this.ttlMs })
    return token
  }

  /** Consume a token; returns the bound id iff valid (single use). */
  consume(token, id) {
    this.#sweep()
    const entry = token ? this.pending.get(token) : undefined
    if (!entry || entry.id !== id) return false
    this.pending.delete(token)
    return true
  }

  #sweep() {
    const now = Date.now()
    for (const [token, entry] of this.pending) {
      if (entry.expiresAt <= now) this.pending.delete(token)
    }
  }
}

/**
 * Register every model tool allowed by the CURRENT access mode. Returns a
 * disposer that unregisters all of them (call again after policy changes).
 *
 * @param {{ctx:object, store:()=>import('./store.js').VaultStore, policy:()=>object,
 *          ledger:ConfirmationLedger, audit:(kind:string, data:object)=>Promise<void>,
 *          resync:()=>void}} deps
 */
export function registerModelTools({ ctx, store, policy, ledger, audit = async () => {}, resync = () => {} }) {
  const disposers = []
  const mode = policy().accessMode
  const add = def => disposers.push(ctx.tools.register(def))
  const denyMsg = 'vaultx: not available under the current access mode'

  // ---- always present (except sealed): declare intent; pure metadata ------
  if (mode !== 'sealed') {
    add(defineTool({
      name: 'vaultx_intent',
      description: 'Declare what you intend to do with a vault credential before using it. Creates an audit annotation only; changes nothing. Always allowed.',
      parameters: {
        env: { type: 'string', description: 'The $DSH_* variable you plan to reference, if any.' },
        purpose: { type: 'string', required: true, description: 'One short sentence: what the credential is used for in this task.' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, note: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.ok ? 'intent recorded' : (v.note ?? 'rejected') }],
      },
      async execute(args) {
        await audit('model', { actor: 'model', action: 'intent', entryId: args.env ?? null, title: args.env ?? null, detail: String(args.purpose).slice(0, 500) })
        return { ok: true }
      },
    }))

    // ---- discovery: names + field names only, never values ---------------
    add(defineTool({
      name: 'vaultx_list',
      description: 'List vault entries: id, title, kind, sensitivity, field names, env variable name. Values are NEVER returned. To USE a secret, reference its $DSH_* name in a shell command — the host substitutes the value without it entering this conversation.',
      parameters: { query: { type: 'string', description: 'Case-insensitive substring over title/tags/kind.' } },
      output: {
        schema: {
          type: 'object', additionalProperties: false,
          properties: { entries: { type: 'array', required: true, items: { type: 'json' } }, locked: { type: 'boolean', required: true } },
        },
        render: (_a, v) => [{ type: 'text', text: v.locked
          ? 'VaultX is LOCKED: no entries can be read until the operator unlocks it in Settings → VaultX.'
          : v.entries.length === 0
            ? 'VaultX: no entries (or none matching).'
            : v.entries.map(e => `- ${e.id}  ${e.title}  [${e.kind}/${e.sensitivity}]${e.env ? ` $${e.env}` : ''}  fields: ${e.fields.join(', ') || '-'}`).join('\n') }],
      },
      async execute(args) {
        const s = store()
        const entries = (s.search(args.query ?? '') ?? []).map(sum => ({
          id: sum.id, title: sum.title, kind: sum.kind, sensitivity: sum.sensitivity,
          fields: sum.fields.filter(f => f !== '__notes__'), env: sum.env ?? undefined,
        })).filter(e => e.sensitivity !== 'high') // hard rule: human-only entries are invisible
        return { entries, locked: !s.unlocked }
      },
    }))

    // ---- masked detail ----------------------------------------------------
    add(defineTool({
      name: 'vaultx_get',
      description: 'Read one entry in MASKED form: field names, character classes, head/tail masks and strength scores — never plaintext. Use env references to actually use secrets.',
      parameters: { id: { type: 'string', required: true, description: 'Entry id from vaultx_list.' } },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, entry: { type: 'json' }, error: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.found ? JSON.stringify(v.entry) : (v.error ?? 'entry not found') }],
      },
      async execute(args) {
        const s = store()
        if (!s.unlocked) return { found: false, error: 'vault is locked' }
        const entry = s.get(args.id)
        if (!entry || entry.sensitivity === 'high') return { found: false, error: 'entry not found' }
        const masked = { id: entry.id, title: entry.title, kind: entry.kind, sensitivity: entry.sensitivity, env: entry.env ?? null, fields: {} }
        for (const name of entry.fieldNames()) {
          if (name === '__notes__') continue
          let value
          try { value = entry.field(name) } catch { return { found: false, error: 'field decrypt failed' } }
          masked.fields[name] = { mask: maskValue(value), length: value.length, strength: assess(value).score }
        }
        return { found: true, entry: masked }
      },
    }))

    // ---- totp: registered ONLY when policy allows; the pre-execute gate
    //      stays as second defense if the tool ever reaches execution. ----
    if (policy().totpViaModel) {
      add(defineTool({
        name: 'vaultx_totp',
        description: 'Compute the current TOTP code for an entry.',
        parameters: { id: { type: 'string', required: true, description: 'Entry id whose secret field totp holds the base32 secret.' } },
        output: {
          schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, code: { type: 'string' }, secondsRemaining: { type: 'number' }, error: { type: 'string' } } },
          render: (_a, v) => [{ type: 'text', text: v.ok ? `${v.code} (window ${v.secondsRemaining}s)` : (v.error ?? 'failed') }],
        },
        async execute(args) {
          const s = store()
          if (!s.unlocked) return { ok: false, error: 'vault is locked' }
          const entry = s.get(args.id)
          if (!entry || entry.sensitivity === 'high') return { ok: false, error: 'entry not found' }
          const secret = entry.field('totp')
          if (!secret) return { ok: false, error: 'entry has no totp secret field' }
          try {
            return { ok: true, code: totp(secret), secondsRemaining: totpRemaining() }
          } catch {
            return { ok: false, error: 'invalid base32 totp secret' }
          }
        },
      }))
    }
  }

  // ---- generation: value goes TO the vault, not the transcript -----------
  if (mode === 'write' || mode === 'edit') {
    add(defineTool({
      name: 'vaultx_generate',
      description: 'Generate a strong secret and STORE it in a new (or existing, origin=model) entry. The plaintext value is NOT returned to you — afterwards reference it via $ENV or ask the operator. Strength feedback is returned.',
      parameters: {
        title: { type: 'string', required: true, description: 'Human title for the new entry.' },
        kind: { type: 'string', description: 'login | api-key | ssh | secret | totp | custom', enum: ['login', 'api-key', 'ssh', 'secret', 'totp', 'custom'] },
        style: { type: 'string', description: 'password (charset) | passphrase (diceware) | token (base64url) | totp (base32 secret)', enum: ['password', 'passphrase', 'token', 'totp'] },
        field: { type: 'string', description: 'Field name to store the secret under (default apiKey for api-key, password otherwise).' },
        env: { type: 'string', description: 'Optional DSH_* variable name to expose this secret as.' },
        username: { type: 'string', description: 'Optional non-secret username/label stored alongside.' },
        length: { type: 'number', description: 'password length 8-128 (default 24).' },
        words: { type: 'number', description: 'passphrase word count 3-10 (default 4).' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, id: { type: 'string' }, env: { type: 'string' }, strengthBits: { type: 'number' }, strengthLabel: { type: 'string' }, note: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.ok ? `stored ${v.id} (${v.strengthLabel}, ${v.strengthBits} bits)${v.env ? ` — use $${v.env}` : ''} — value not shown by design` : (v.note ?? 'failed') }],
      },
      async execute(args) {
        const s = store()
        if (!s.unlocked) return { ok: false, note: 'vault is locked' }
        const { title, kind = 'secret', style = 'password', field, env, username, length, words } = args
        let value
        switch (style) {
          case 'passphrase': value = generatePassphrase({ words: words ?? 4 }); break
          case 'token': value = generateToken({}); break
          case 'totp': value = generateTotpSecret(); break
          default: value = generatePassword({ length: length ?? 24 })
        }
        const fieldName = field ?? (kind === 'api-key' ? 'apiKey' : style === 'totp' ? 'totp' : 'password')
        try {
          const fields = { [fieldName]: value, ...(username ? { username } : {}) }
          const created = s.add({ title, kind, sensitivity: 'normal', env, fields, tags: ['model'] })
          await audit('model', { actor: 'model', action: 'generate', entryId: created.id, title, fields: [fieldName] })
          if (env) resync()
          const stats = assess(value)
          return { ok: true, id: created.id, env: env ?? undefined, strengthBits: stats.bits, strengthLabel: label(stats.score) }
        } catch (err) {
          return { ok: false, note: err.message }
        }
      },
    }))

    add(defineTool({
      name: 'vaultx_set',
      description: 'Add or update NON-SECRET metadata and secrets on an entry the model created (origin=model). Operator-owned entries cannot be modified. Never echoes values.',
      parameters: {
        id: { type: 'string', required: true },
        title: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        fields: { type: 'json', description: 'Field name → plaintext value object (null removes a field).' },
        notes: { type: 'string' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, note: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.ok ? 'updated' : (v.note ?? 'rejected') }],
      },
      async execute(args) {
        const s = store()
        if (!s.unlocked) return { ok: false, note: 'vault is locked' }
        const entry = s.get(args.id)
        if (!entry) return { ok: false, note: 'entry not found' }
        if (entry.sensitivity === 'high') return { ok: false, note: 'high-sensitivity entries are human-only' }
        if (!entry.tags?.includes('model')) return { ok: false, note: 'entry is operator-owned; the model may not modify it' }
        try {
          s.update(args.id, { title: args.title, tags: args.tags, fields: args.fields ?? {}, ...(args.notes !== undefined ? { fields: { ...(args.fields ?? {}), __notes__: args.notes } } : {}) })
          await audit('model', { actor: 'model', action: 'update', entryId: entry.id, title: entry.title, fields: Object.keys(args.fields ?? {}) })
          return { ok: true }
        } catch (err) { return { ok: false, note: err.message } }
      },
    }))

    add(defineTool({
      name: 'vaultx_delete',
      description: 'Delete an entry the model created. Two-phase: the first call returns a one-use confirm token, the second call with that token performs the deletion.',
      parameters: {
        id: { type: 'string', required: true },
        confirm: { type: 'string', description: 'Token from the first call, to confirm deletion.' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, confirmToken: { type: 'string' }, note: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.ok ? 'deleted' : (v.confirmToken ? `confirmation required — call again with confirm=${v.confirmToken}` : (v.note ?? 'failed')) }],
      },
      async execute(args) {
        const s = store()
        if (!s.unlocked) return { ok: false, note: 'vault is locked' }
        const entry = s.get(args.id)
        if (!entry) return { ok: false, note: 'entry not found' }
        if (entry.sensitivity === 'high' || !entry.tags?.includes('model')) {
          return { ok: false, note: 'entry is operator-owned; the model may not delete it' }
        }
        if (!args.confirm) {
          return { ok: false, confirmToken: ledger.issue(entry.id), note: `deleting "${entry.title}" requires confirmation` }
        }
        if (!ledger.consume(args.confirm, entry.id)) return { ok: false, note: 'confirmation token invalid or expired' }
        s.remove(entry.id)
        await audit('model', { actor: 'model', action: 'delete', entryId: entry.id, title: entry.title })
        resync()
        return { ok: true }
      },
    }))
  }

  return () => { for (const d of disposers) { try { d() } catch { /* already gone */ } } }
}

/** Re-export so index.js can gate with the same pure function the tests pin. */
export { checkModelAccess }
