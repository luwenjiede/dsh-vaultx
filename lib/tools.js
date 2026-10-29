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

/** Hosts may deliver `json` tool params as an object OR a JSON string — accept both. */
function coerceFields(f) {
  if (f && typeof f === 'object') return f
  if (typeof f === 'string') { try { const p = JSON.parse(f); return p && typeof p === 'object' && !Array.isArray(p) ? p : {} } catch { return {} } }
  return {}
}
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
          fields: sum.fields.filter(f => f !== '__notes__'), ...(sum.env ? { env: sum.env } : {}),
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

    // ---- add: the assistant stores a credential it was just given ----------
    // Plaintext VALUES travel IN (through this call's arguments), get encrypted
    // on the spot, and are NEVER echoed back — the result is id + field names
    // only. Registerd in every non-sealed mode: putting secrets INTO the box is
    // the assistant's own capability, not a privileged mutation.
    add(defineTool({
      name: 'vaultx_add',
      description: 'Store a new credential in the vault (encrypted at rest). Pass the plaintext secret in `fields`; it is encrypted immediately and NEVER returned — you get back the id and non-secret summary only. Use its $DSH_* env reference (if you set one) to consume it without the value entering the conversation, or vaultx_reveal to read the plaintext back through an approval-gated path. This is how you save a password/API key the user just handed you.',
      parameters: {
        title: { type: 'string', required: true, description: 'Human title for the new entry.' },
        kind: { type: 'string', description: 'login | api-key | ssh | secret | totp | custom', enum: ['login', 'api-key', 'ssh', 'secret', 'totp', 'custom'] },
        sensitivity: { type: 'string', description: 'low | normal | high (default normal).', enum: ['low', 'normal', 'high'] },
        env: { type: 'string', description: 'Optional DSH_* variable name to expose the secret as (for shell $-substitution).' },
        envField: { type: 'string', description: 'Which field the env var should carry (default: the primary secret field).' },
        fields: { type: 'json', required: true, description: 'Field name → plaintext value, e.g. {"apiKey":"sk-...","username":"me"}.' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Labels; "model" is added automatically to mark assistant ownership.' },
        notes: { type: 'string', description: 'Optional plaintext note (stored encrypted; not returned by list).' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, id: { type: 'string' }, env: { type: 'string' }, fields: { type: 'array', items: { type: 'string' } }, note: { type: 'string' } } },
        render: (_a, v) => [{ type: 'text', text: v.ok
          ? `stored ${v.id} — fields ${v.fields.join(', ')}${v.env ? `, use $${v.env}` : ''} (value encrypted, not shown)`
          : (v.note ?? 'failed') }],
      },
      async execute(args) {
        const s = store()
        if (!s.unlocked) return { ok: false, note: 'vault is locked' }
        const rawFields = coerceFields(args.fields)
        if (Object.keys(rawFields).length === 0) return { ok: false, note: 'fields must be a non-empty object of name → plaintext value' }
        const tags = Array.from(new Set([...(Array.isArray(args.tags) ? args.tags : []), 'model']))
        try {
          const created = s.add({
            title: args.title, kind: args.kind ?? 'secret', sensitivity: args.sensitivity ?? 'normal',
            env: args.env, envField: args.envField, tags, fields: rawFields, notes: args.notes,
          })
          await s.save()
          await audit('model', { actor: 'model', action: 'add', entryId: created.id, title: args.title, fields: Object.keys(rawFields) })
          if (args.env) resync()
          return { ok: true, id: created.id, ...(created.env ? { env: created.env } : {}), fields: Object.keys(rawFields) }
        } catch (err) {
          return { ok: false, note: err.message }
        }
      },
    }))

    // ---- reveal: plaintext OUT, gated by modelReveal (default: per-call ask) --
    // The assistant's own vault means it can read its secrets back. The value
    // enters the transcript ONLY after the operator approves this one call
    // (the pre-execute gate turns modelReveal:'ask' into a human approval).
    // Under 'deny' this tool is not registered; under 'allow' it runs silently.
    if (policy().modelReveal !== 'deny') {
      add(defineTool({
        name: 'vaultx_reveal',
        description: 'Read back the PLAINTEXT value of one credential field. Prefer $DSH_* env references for mere execution (no plaintext); use this only when you must see or emit the value (e.g. write it into a config file the user asked for). Each call is subject to the operator\'s reveal approval.',
        parameters: {
          id: { type: 'string', required: true, description: 'Entry id.' },
          field: { type: 'string', description: 'Field to reveal (default: the primary secret field).' },
          reason: { type: 'string', required: true, description: 'Why you need the plaintext — shown to the approver.' },
        },
        output: {
          schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, value: { type: 'string' }, field: { type: 'string' }, error: { type: 'string' } } },
          render: (_a, v) => [{ type: 'text', text: v.ok ? `${v.field}=${v.value}` : (v.error ?? 'failed') }],
        },
        async execute(args) {
          const s = store()
          if (!s.unlocked) return { ok: false, error: 'vault is locked' }
          const entry = s.get(args.id)
          if (!entry || entry.sensitivity === 'high') return { ok: false, error: 'entry not found' }
          const field = args.field ?? entry.fieldNames().find(f => ['apiKey', 'password', 'secret', 'token', 'accessToken', 'privateKey'].includes(f)) ?? entry.fieldNames()[0]
          let value
          try { value = entry.field(field) } catch { return { ok: false, error: 'field decrypt failed' } }
          if (value === undefined) return { ok: false, error: `entry has no field "${field}"` }
          await audit('model', { actor: 'model', action: 'reveal', entryId: entry.id, title: entry.title, fields: [field], detail: String(args.reason ?? '').slice(0, 500) })
          return { ok: true, value, field }
        },
      }))
    }

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

  // ---- generate: creates a NEW entry (CREATE), so available in every
  //      non-sealed mode; value goes TO the vault, not the transcript --------
  if (mode !== 'sealed') {
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
          // 2026-10-29 修复：这里原本漏了 save —— 生成的值只在内存里，宿主重启即丢，
          // 而工具早已回报 "stored"，属于最坏的一种静默失败。
          await s.save()
          await audit('model', { actor: 'model', action: 'generate', entryId: created.id, title, fields: [fieldName] })
          if (env) resync()
          const stats = assess(value)
          return { ok: true, id: created.id, ...(env ? { env } : {}), strengthBits: stats.bits, strengthLabel: label(stats.score) }
        } catch (err) {
          return { ok: false, note: err.message }
        }
      },
    }))
  }

  // ---- mutation: changing/deleting EXISTING entries is privileged ---------
  // generate/add (CREATE) are open in every non-sealed mode; set/delete
  // require write/edit so "readonly" still lets the assistant store, just not
  // rewrite what already exists.
  if (mode === 'write' || mode === 'edit') {
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
          const patchFields = coerceFields(args.fields)
          if (args.notes !== undefined) patchFields.__notes__ = args.notes
          s.update(args.id, { title: args.title, tags: args.tags, fields: patchFields })
          await s.save()   // 2026-10-29 修复：原缺 save，改完重启即回滚
          await audit('model', { actor: 'model', action: 'update', entryId: entry.id, title: entry.title, fields: Object.keys(patchFields) })
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
        await s.save()   // 2026-10-29 修复：原缺 save，删除不落盘 → 重启后条目复活
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
