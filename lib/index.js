/**
 * VaultX — host plugin entry.
 *
 * Fusion design (docs/ARCHITECTURE.md), in one paragraph: an encrypted vault
 * (scrypt + AES-256-GCM envelopes, from dsh-vault's school) whose secrets are
 * NEVER readable by the model through tools — the only value channel is the
 * per-execution $DSH_* shell substitution and the operator's settings panel
 * (from dsh-key-panel's school) — while fixing both originals' flaws: the
 * vault boots LOCKED instead of throwing when the master password is absent,
 * plaintext is never the storage format, high-sensitivity entries are a
 * human-only hard channel, and every access leaves a hash-chained audit trail.
 *
 * Loading is fail-open for the rest of the app: apply() must never throw.
 * A missing/corrupt vault or absent password yields a locked store whose
 * tools answer with guidance.
 *
 * @module vaultx
 */
import path from 'node:path'
import Schema from '@deepseek-ai/schemastery'
import { TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'

import { VaultStore, defaultVaultPath } from './store.js'
import { PolicyStore, ACCESS_MODES, REVEAL_MODES, checkModelAccess } from './policy.js'
import { AuditLog } from './audit.js'
import { registerModelTools, ConfirmationLedger } from './tools.js'
import { assess, label } from './strength.js'
import { generatePassword, generatePassphrase, generateToken, generateTotpSecret } from './generate.js'
import { totp, totpRemaining, totpUri } from './totp.js'
import { checkBreached } from './breach.js'
import { maskValue } from './mask.js'
import { PLUGIN_NAME, VAULT_FILE, AUDIT_FILE, POLICY_FILE, MAX_ATTEMPTS, LOCKOUT_MS, DEFAULT_AUTO_LOCK_MINUTES } from './constants.js'

export const name = PLUGIN_NAME
export const inject = ['shellEnv', 'tools', 'systemPrompt']

/** Runtime configuration (all optional; zero secrets belong in here except
 *  the env-var NAME that points at the master password). */
export const Config = Schema.object({
  /** Where the vault document lives. Default: <dshHome>/vaultx/vault.json */
  storePath: Schema.string().default(''),
  /** Env var holding the master password for auto-unlock (recommended). */
  masterPasswordEnv: Schema.string().default(''),
  /** Literal master password — kept ONLY for CLI/test parity; the settings UI
   * never reads it back. Prefer masterPasswordEnv. */
  masterPassword: Schema.string().role('secret').default(''),
  /** Auto-lock after N minutes idle; 0 disables; default 15. */
  autoLockMinutes: Schema.natural().default(DEFAULT_AUTO_LOCK_MINUTES),
  /** Skip $DSH_* injection entirely (belt mode). */
  disableEnvExport: Schema.boolean().default(false),
})

// ------------------------------------------------------------------ lockout
/** In-memory failed-unlock bookkeeping: MAX_ATTEMPTS → LOCKOUT_MS cooldown. */
class AttemptTracker {
  constructor() { this.failures = 0; this.lockedUntil = 0 }
  noteFailure() {
    this.failures += 1
    if (this.failures >= MAX_ATTEMPTS) this.lockedUntil = Date.now() + LOCKOUT_MS
  }
  noteSuccess() { this.failures = 0; this.lockedUntil = 0 }
  get blocked() { return Date.now() < this.lockedUntil }
  get remainingLockSeconds() { return Math.max(0, Math.ceil((this.lockedUntil - Date.now()) / 1000)) }
}

// ------------------------------------------------------------ shell-env glue
const REMOTE_METHOD_DESCRIPTOR = '@deepseek-ai/dsh-typert-protocol/remote-methods'

/** Hand-written @Remote markers (same sugar key-panel uses; no build step). */
function markRemoteMethods(ctor, methods) {
  const existing = ctor.prototype[REMOTE_METHOD_DESCRIPTOR]
  const markers = methods.map(method => Object.freeze({ method, invocation: Object.freeze({ kind: 'direct' }) }))
  Object.defineProperty(ctor.prototype, REMOTE_METHOD_DESCRIPTOR, {
    configurable: true,
    value: Object.freeze({ version: 1, methods: Object.freeze([...existing?.methods ?? [], ...markers]) }),
  })
}

// -------------------------------------------------------------------- plugin
const plugin = {
  name,
  Config,
  inject,

  apply(ctx, config = {}) {
    const dshHome = resolveDshHome()
    const storePath = config.storePath || defaultVaultPath(dshHome)
    const audit = new AuditLog(path.join(dshHome, AUDIT_FILE))
    const policyStore = new PolicyStore(path.join(dshHome, POLICY_FILE))
    policyStore.load()
    const attempts = new AttemptTracker()
    const ledger = new ConfirmationLedger()

    /** @type {VaultStore|null} */
    let store = null
    /** @type {null|(()=>void)} */
    let toolDisposer = null
    /** @type {null|(()=>void)} */
    let envRegistration = null
    let lastActivity = Date.now()
    let autoLockTimer = null

    // ---- lazy, fail-open load --------------------------------------------
    function loadStore() {
      if (store) return store
      try {
        store = VaultStore.fromFile({ path: storePath })
      } catch (err) {
        if (err.code === 'ENOENT') {
          store = new VaultStore({ path: storePath, doc: null, vaultKey: null })
        } else {
          ctx.logger?.warn?.(`vaultx: cannot read vault document (${err.message}); running locked`)
          store = new VaultStore({ path: storePath, doc: { version: 1, header: null, entries: [] }, vaultKey: null })
        }
      }
      return store
    }

    function masterPassword() {
      if (config.masterPasswordEnv) {
        const fromEnv = process.env[config.masterPasswordEnv]
        if (typeof fromEnv === 'string' && fromEnv) return fromEnv
      }
      if (config.masterPassword) return config.masterPassword
      return null
    }

    /** Try env/config unlock. Safe to call repeatedly; never throws. */
    async function tryAutoUnlock() {
      const s = loadStore()
      if (!s.doc.header) return { state: 'empty' }          // fresh vault: nothing to unlock
      if (s.unlocked) return { state: 'unlocked' }
      if (attempts.blocked) return { state: 'locked-out', seconds: attempts.remainingLockSeconds }
      const pw = masterPassword()
      if (!pw) return { state: 'awaiting-password' }
      try {
        await s.unlock(pw)
        attempts.noteSuccess(); touch(); resyncEnv()
        return { state: 'unlocked' }
      } catch {
        attempts.noteFailure()
        return { state: 'wrong-password' }
      }
    }

    // ---- activity / auto-lock --------------------------------------------
    function touch() {
      lastActivity = Date.now()
      if (autoLockTimer) { clearTimeout(autoLockTimer); autoLockTimer = null }
      const mins = config.autoLockMinutes ?? DEFAULT_AUTO_LOCK_MINUTES
      if (mins > 0 && loadStore().unlocked) {
        autoLockTimer = setTimeout(() => { lock('auto-lock timeout') }, mins * 60_000)
        autoLockTimer.unref?.()
      }
    }

    function lock(reason) {
      const s = loadStore()
      if (!s.unlocked) return
      s.lock()
      resyncEnv()
      ctx.logger?.info?.(`vaultx: vault locked (${reason})`)
    }

    // ---- env resync (the zero-exposure channel) --------------------------
    /**
     * Declare exactly the DSH_* names currently injectable: unlocked, policy
     * allows env, entries opted in, NOT high sensitivity. Values are resolved
     * per shell execution — they never enter the transcript or the registry.
     */
    function resyncEnv() {
      if (envRegistration) { envRegistration(); envRegistration = null }
      const s = loadStore()
      const pol = policyStore.get()
      if (!s.unlocked || pol.envExport === false || config.disableEnvExport) return
      const candidates = s.envEntries().filter(c => c.sensitivity !== 'high')
      if (candidates.length === 0) return
      const variables = {}
      for (const c of candidates) variables[c.env] = { description: `VaultX credential for ${c.title}` }
      envRegistration = ctx.shellEnv.register({
        name: 'vaultx',
        variables,
        resolve() {
          const cur = loadStore()
          if (!cur.unlocked) return {}
          const out = {}
          for (const c of cur.envEntries()) {
            if (c.sensitivity === 'high' || !variables[c.env]) continue
            try {
              const value = cur.get(c.id)?.field(c.field ?? 'password')
              if (value !== undefined) out[c.env] = value
            } catch { /* skip one broken field; others still resolve */ }
          }
          touch()
          return out
        },
      })
    }

    // ---- tool (re)registration -------------------------------------------
    function retool() {
      if (toolDisposer) { try { toolDisposer() } catch { /* noop */ } toolDisposer = null }
      const policy = policyStore.get()
      const liveStore = () => loadStore()
      toolDisposer = registerModelTools({
        ctx,
        store: liveStore,
        policy: () => policyStore.get(),
        ledger,
        audit: (actor, data) => audit.append({ ...data, actor }),
        resync: resyncEnv,
      })
      void audit.append({ actor: 'system', action: 'retool', detail: `accessMode=${policy.accessMode}` })
    }

    // ---- defense in depth: live policy gate ------------------------------
    // Tools EXIST per mode; this gate re-checks the live policy + the target
    // entry's metadata at CALL time (mode could have changed after register).
    ctx.on('tools/pre-execute', (exec, next) => {
      if (exec?.name && exec.name.startsWith('vaultx_')) {
        const s = loadStore()
        const args = exec.arguments ?? {}
        let meta = {}
        if (typeof args.id === 'string') {
          const entry = s.get(args.id)
          if (entry) meta = { sensitivity: entry.sensitivity, origin: entry.tags?.includes('model') ? 'model' : 'operator' }
        }
        const decision = checkModelAccess(policyStore.get(), exec.name, meta)
        if (!decision.allowed) {
          void audit.append({ actor: 'model', action: `denied:${exec.name}`, entryId: args.id ?? args.env ?? null, detail: decision.reason })
          return { kind: 'deny', reason: decision.reason }
        }
        // modelReveal:'ask' -> one-time human approval before a plaintext read
        // dispatches. The host runs its approval flow and only continues on
        // allowed-once; a denial never reaches vaultx_reveal.execute().
        if (decision.ask) {
          void audit.append({ actor: 'model', action: `ask:${exec.name}`, entryId: args.id ?? null, detail: decision.reason })
          return {
            kind: 'ask',
            reason: decision.reason,
            displayReason: {
              en: `VaultX: the assistant wants to read the plaintext value of entry ${args.id ?? '?'} (field: ${args.field ?? 'primary secret'}). Reason given: ${String(args.reason ?? '(none)')}`,
              zh: `VaultX：助手请求读取条目 ${args.id ?? '?'} 的明文值（字段：${args.field ?? '主密钥字段'}）。给出的理由：${String(args.reason ?? '（未给出）')}`,
            },
          }
        }
        touch()
      }
      return next()
    })

    // ---- system prompt: teach the model the rules of the game ------------
    ctx.systemPrompt?.section({
      name: 'vaultx',
      order: 140,
      text: () => {
        const pol = policyStore.get()
        const lines = [
          '## VaultX credential vault (this is YOUR assistant vault; encrypted at rest)',
          `- Access mode: ${pol.accessMode.toUpperCase()}${pol.accessMode === 'sealed' ? ' — vault tools are not registered.' : '.'}`,
          `- Plaintext reveal posture: ${String(pol.modelReveal).toUpperCase()}${pol.modelReveal === 'ask' ? ' — every vaultx_reveal call needs a one-time human approval.' : pol.modelReveal === 'allow' ? ' — reveals run unattended; still prefer env refs.' : ' — no plaintext ever reaches you; $DSH_* env refs are the only consumption path.'}`,
          'Storing: when the user hands you a credential and confirms it works (or you validate it), call vaultx_add with the plaintext in fields — it is encrypted immediately and never echoed back. You own what you store (tagged model).',
          'Consuming — choose the form by usability: if the secret is only needed to RUN something, prefer the out-of-band path: reference its $DSH_* variable in a shell command (the host substitutes at execution; value never enters the transcript). If you genuinely must SEE the plaintext (e.g. to write it into a config file the user requested), call vaultx_reveal with a clear one-line reason.',
          'Discover names via vaultx_list; check metadata via vaultx_get (masked, plus which fields exist); declare intent via vaultx_intent before first use of an env var.',
          'High-sensitivity entries are human-only: invisible to you, never injected, never revealable to you. Do not attempt to reconstruct them.',
          'Generated secrets (vaultx_generate) are stored and never shown; strength stats are returned instead.',
          'Never ask the user for the vault master password.',
        ]
        if (pol.autoCapture) {
          lines.push('autoCapture is ON: if a credential appears in the conversation and the user wants it kept, store it via vaultx_add without being asked each time.')
        } else {
          lines.push('autoCapture is OFF: store credentials when the user asks or clearly intends persistence, not merely from observing them.')
        }
        return lines.join('\n')
      },
    })

    // ---- settings-page gateway (Typert remote; operator-only surface) ----
    class VaultXGateway extends TypertRemoteService {
      constructor(context) {
        super(context, 'vaultx')
      }

      /** Dashboard state for the panel. */
      status() {
        const s = loadStore()
        const pol = policyStore.get()
        return {
          exists: Boolean(s.doc.header),
          locked: !s.unlocked,
          entries: s.size,
          accessMode: pol.accessMode,
          modelReveal: pol.modelReveal,
          autoLockMinutes: config.autoLockMinutes ?? DEFAULT_AUTO_LOCK_MINUTES,
          lastActivity,
          lockoutSeconds: attempts.blocked ? attempts.remainingLockSeconds : 0,
          envVariables: (() => {
            try { return s.envEntries().filter(c => c.sensitivity !== 'high').map(c => c.env) } catch { return [] }
          })(),
          breachEnabled: true,
        }
      }

      /** Unlock from the panel (password crosses RPC once, loopback-trusted). */
      async unlock(password) {
        if (attempts.blocked) return { ok: false, error: `locked out for ${attempts.remainingLockSeconds}s` }
        const s = loadStore()
        if (!s.doc.header) return { ok: false, error: 'vault has not been created yet' }
        try {
          await s.unlock(String(password ?? ''))
          attempts.noteSuccess(); touch(); resyncEnv()
          await audit.append({ actor: 'operator', action: 'unlock' })
          return { ok: true }
        } catch {
          attempts.noteFailure()
          return { ok: false, error: attempts.blocked ? `too many failures; locked ${Math.ceil(LOCKOUT_MS / 1000)}s` : 'wrong master password' }
        }
      }

      /** Create (or reset-and-create) the vault document. */
      async create(password) {
        const s = loadStore()
        if (s.doc.header) return { ok: false, error: 'vault already exists' }
        const pw = String(password ?? '')
        if (pw.length < 10) return { ok: false, error: 'master password too short (min 10 chars)' }
        const fresh = await VaultStore.createNew({ path: storePath, masterPassword: pw })
        await fresh.save()
        store = fresh
        touch(); resyncEnv(); retool()
        await audit.append({ actor: 'operator', action: 'create-vault' })
        return { ok: true }
      }

      async lock() {
        lock('operator')
        await audit.append({ actor: 'operator', action: 'lock' })
        return { ok: true }
      }

      /** Full list with masked previews (operator view; high entries visible here). */
      list() {
        const s = loadStore()
        return s.entries().map(e => ({
          ...e.summary(),
          notes: (() => { try { return e.field('__notes__') } catch { return undefined } })(),
        }))
      }

      /** Reveal one field to the operator ONLY (panel, after confirm in UI). */
      reveal(id, field) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        const e = s.get(id)
        if (!e) return { ok: false, error: 'not found' }
        const value = e.field(field)
        void audit.append({ actor: 'operator', action: 'reveal', entryId: id, title: e.title, fields: [field] })
        touch()
        return { ok: true, value }
      }

      /** Copy-safe: masked copy for chat contexts. */
      masked(id, field) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        const value = s.get(id)?.field(field)
        return { ok: true, mask: maskValue(value ?? '') }
      }

      /** Operator CRUD. `secrets` values are encrypted immediately. */
      async add(title, kind, sensitivity, env, envField, tags, fields, notes) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        try {
          const created = s.add({ title, kind, sensitivity, env: env || undefined, envField, tags: tags ?? [], fields: fields ?? {}, notes })
          await s.save()
          resyncEnv(); touch()
          await audit.append({ actor: 'operator', action: 'add', entryId: created.id, title, fields: Object.keys(fields ?? {}) })
          return { ok: true, id: created.id }
        } catch (err) { return { ok: false, error: err.message } }
      }

      async update(id, patch) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        try {
          const merged = { ...(patch ?? {}) }
          // Notes ride the encrypted field map under the reserved name.
          if (merged.notes !== undefined) {
            merged.fields = { ...(merged.fields ?? {}), __notes__: merged.notes }
            delete merged.notes
          }
          const patched = s.update(id, merged)
          await s.save(); resyncEnv(); touch()
          await audit.append({ actor: 'operator', action: 'update', entryId: id, title: patched.title, fields: Object.keys(merged.fields ?? {}) })
          return { ok: true }
        } catch (err) { return { ok: false, error: err.message } }
      }

      async remove(id) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        const e = s.get(id)
        if (!e) return { ok: false, error: 'not found' }
        s.remove(id)
        await s.save(); resyncEnv()
        await audit.append({ actor: 'operator', action: 'delete', entryId: id, title: e.title })
        return { ok: true }
      }

      /** Generate + return value to the PANEL only (operator action). */
      async generate(style, length, words, symbols) {
        let value
        if (style === 'passphrase') value = generatePassphrase({ words: words ?? 4 })
        else if (style === 'token') value = generateToken({})
        else if (style === 'totp') value = generateTotpSecret()
        else value = generatePassword({ length: length ?? 24, symbols: symbols !== false })
        const stats = assess(value)
        return { value, strengthBits: stats.bits, strengthLabel: label(stats.score), feedback: stats.feedback }
      }

      /** Strength analysis of a typed value (panel only). */
      async strength(value, personal) {
        const stats = assess(value, Array.isArray(personal) ? personal : [])
        const breach = await checkBreached(String(value ?? ''))
        return { ...stats, label: label(stats.score), breached: breach.breached, breachSource: breach.source }
      }

      /** Current TOTP for an entry (panel countdown). */
      totpCode(id) {
        const s = loadStore()
        const e = s.get(id)
        const secret = e?.field('totp')
        if (!secret) return { ok: false, error: 'no totp secret' }
        try {
          return { ok: true, code: totp(secret), secondsRemaining: totpRemaining(), uri: totpUri({ secret, label: e.title }) }
        } catch (err) { return { ok: false, error: err.message } }
      }

      /** Re-key: rotate master password (safe: re-wrap VK only). */
      async rotate(oldPassword, newPassword) {
        const s = loadStore()
        try {
          await s.changeMasterPassword(String(oldPassword ?? ''), String(newPassword ?? ''))
          await s.save()
          await audit.append({ actor: 'operator', action: 'rotate-master-password' })
          return { ok: true }
        } catch (err) { return { ok: false, error: err.message } }
      }

      /** Export the vault document (envelope stays; wrapped under targetPassword). */
      async exportVault(targetPassword) {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        if (!targetPassword || String(targetPassword).length < 10) return { ok: false, error: 'target password too short' }
        const wrapped = await s.exportWrapped(String(targetPassword))
        // Entries keep their per-field ciphertext: they are under VK, unchanged.
        return { ok: true, doc: { version: 1, header: wrapped.header, entries: s.doc.entries } }
      }

      /** Import: replace the local document wholesale (operator-confirmed in UI). */
      async importVault(doc, password) {
        try {
          if (!doc?.header || !Array.isArray(doc.entries)) throw new Error('not a VaultX export document')
          const incoming = new VaultStore({ path: storePath, doc, vaultKey: null })
          await incoming.unlock(String(password ?? ''))
          await incoming.save()
          store = incoming
          resyncEnv(); retool()
          await audit.append({ actor: 'operator', action: 'import-vault', entryId: null, detail: `${incoming.size} entries` })
          return { ok: true, entries: incoming.size }
        } catch (err) { return { ok: false, error: err.message } }
      }

      /** Policy get/set (operator-only; the model has no path to this).
       *  Null/undefined params keep their current value — partial updates. */
      getPolicy() { return policyStore.get() }
      async setPolicy(accessMode, autoCapture, totpViaModel, envExport, modelReveal) {
        const patch = {}
        if (ACCESS_MODES.includes(accessMode)) patch.accessMode = accessMode
        if (typeof autoCapture === 'boolean') patch.autoCapture = autoCapture
        if (typeof totpViaModel === 'boolean') patch.totpViaModel = totpViaModel
        if (typeof envExport === 'boolean') patch.envExport = envExport
        if (REVEAL_MODES.includes(modelReveal)) patch.modelReveal = modelReveal
        const next = await policyStore.set(patch)
        retool(); resyncEnv()
        await audit.append({ actor: 'operator', action: 'set-policy', detail: Object.keys(patch).join(',') })
        return next
      }

      /** Audit: recent events + chain verification. */
      async recentAudit(limit = 30) { return await audit.recent(Math.min(Number(limit) || 30, 200)) }
      async verifyAudit() { return await audit.verify() }

      /** Integrity self-check: decrypt a probe field of every entry (no values out). */
      async verifyVault() {
        const s = loadStore()
        if (!s.unlocked) return { ok: false, error: 'vault is locked' }
        const results = []
        for (const e of s.entries()) {
          for (const f of e.fieldNames()) {
            try { e.field(f) } catch (err) { results.push({ id: e.id, title: e.title, field: f, error: err.message }) }
          }
        }
        return { ok: results.length === 0, broken: results, total: s.size }
      }
    }
    markRemoteMethods(VaultXGateway, [
      'status', 'unlock', 'create', 'lock', 'list', 'reveal', 'masked', 'add', 'update', 'remove',
      'generate', 'strength', 'totpCode', 'rotate', 'exportVault', 'importVault',
      'getPolicy', 'setPolicy', 'recentAudit', 'verifyAudit', 'verifyVault',
    ])
    // Constructing the Service registers it (ctx.reflect.provide) and binds the
    // same key to the Typert gateway — the settings panel reaches it as `vaultx/*`.
    const gateway = new VaultXGateway(ctx)

    // ---- boot: never throw; auto-unlock if we can -------------------------
    // Self-owned console line (mirrors the mobile-gateway log convention):
    // the plugin's presence in the host log must not depend on ctx.logger.
    const note = line => console.log(`vaultx: [${new Date().toISOString()}] ${line}`)
    note('plugin loaded')
    void tryAutoUnlock().then(state => {
      if (state.state === 'unlocked') note('vault unlocked from configured source')
      else if (state.state === 'awaiting-password') note('locked — set masterPasswordEnv or unlock in Settings → VaultX')
      else if (state.state === 'empty') note('ready — no vault yet; create one in Settings → VaultX')
      else if (state.state === 'locked-out') note(`locked out for ${state.seconds}s after repeated failed unlocks`)
    }).catch(err => note(`boot check failed: ${err?.message ?? err}`))
    resyncEnv()
    retool()

    // ---- disposal ----------------------------------------------------------
    ctx.effect(() => () => {
      if (autoLockTimer) clearTimeout(autoLockTimer)
      if (toolDisposer) { try { toolDisposer() } catch { /* noop */ } }
      if (envRegistration) { try { envRegistration() } catch { /* noop */ } }
    }, 'vaultx teardown')
  },
}

export default plugin
