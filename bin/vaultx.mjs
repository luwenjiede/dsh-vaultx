#!/usr/bin/env node
/**
 * VaultX CLI — the OUT-OF-BAND secret channel.
 *
 * The model never calls this to smuggle values into a transcript: the point
 * is the opposite. A skill's child process (or the operator) reads a secret
 * straight from the encrypted vault; the plaintext flows into the process
 * environment/stdout, never into the conversation history.
 *
 * Usage:
 *   vaultx status
 *   vaultx list [query]
 *   vaultx get  <id|title|ENV> [--field <name>] [--mask]
 *   vaultx env  [--mask] [--prefix APP_]
 *   vaultx create <password>
 *   vaultx add <title> [--kind k] [--field name=value ...] [--env DSH_X]
 *   vaultx gen  [--style password|passphrase|token|totp] [--length n] [--words n] [--store <title>]
 *   vaultx strength <value|stdin> [--check]
 *   vaultx totp <id|title> [--uri]
 *   vaultx verify          # audit hash chain + vault decryptability
 *   vaultx export <target-password> [outfile]
 *   vaultx import <file> <password>
 *   vaultx rotate <old> <new>
 *   vaultx lock-keep
 *
 * The master password is taken from DSH_VAULTX_PASSWORD (or --password-env
 * <NAME>) so it never appears in shell history via argv; passing a literal
 * password via argv is supported for scripts but loudly discouraged.
 *
 * @module vaultx/cli
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import process from 'node:process'
import { VaultStore } from '../lib/store.js'
import { AuditLog } from '../lib/audit.js'
import { assess, label } from '../lib/strength.js'
import { generatePassword, generatePassphrase, generateToken, generateTotpSecret } from '../lib/generate.js'
import { totp, totpUri } from '../lib/totp.js'
import { checkBreached } from '../lib/breach.js'
import { maskValue } from '../lib/mask.js'

const DSH_HOME = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
const VAULT_PATH = process.env.VAULTX_PATH || path.join(DSH_HOME, 'vaultx', 'vault.json')
const auditLog = new AuditLog(path.join(DSH_HOME, 'vaultx', 'audit.log'))

/** CLI reads/writes land in the same hash-chained audit trail as the panel. */
function audited(event) {
  return auditLog.append({ actor: 'cli', ...event }).catch(() => {})
}

function fail(msg, code = 1) {
  process.stderr.write(`vaultx: ${msg}\n`)
  process.exit(code)
}

function parseFlags(argv) {
  const flags = {}
  const rest = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--mask') flags.mask = true
    else if (a === '--check') flags.check = true
    else if (a === '--offline') flags.offline = true
    else if (a === '--uri') flags.uri = true
    else if (a.startsWith('--')) {
      const key = a.slice(2)
      const value = argv[++i]
      // repeated keys accumulate into an array (e.g. --field a=1 --field b=2)
      if (key in flags) flags[key] = Array.isArray(flags[key]) ? [...flags[key], value] : [flags[key], value]
      else flags[key] = value
    }
    else rest.push(a)
  }
  return { flags, rest }
}

/** Normalize a flag that may appear once or many times into a string array. */
function many(value) {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function readPassword(flags) {
  const envName = flags['password-env'] ?? 'DSH_VAULTX_PASSWORD'
  if (process.env[envName]) return process.env[envName]
  if (flags.password) return flags.password
  return null
}

async function open(flags) {
  let store
  try {
    store = VaultStore.fromFile({ path: VAULT_PATH })
  } catch (err) {
    if (err.code === 'ENOENT') fail(`no vault at ${VAULT_PATH} (run: vaultx create <password>)`)
    fail(`cannot read vault: ${err.message}`)
  }
  const pw = readPassword(flags)
  if (!pw) fail('master password required: export DSH_VAULTX_PASSWORD (or --password / --password-env NAME)')
  try {
    await store.unlock(pw)
  } catch {
    fail('wrong master password', 2)
  }
  return store
}

/** Find entry by exact id, exact title, or exact env var name (in that order). */
function findEntry(store, ref) {
  const entries = store.entries()
  return entries.find(e => e.id === ref)
    ?? entries.find(e => e.title === ref)
    ?? entries.find(e => (e.env ?? '').toUpperCase() === String(ref).toUpperCase())
}

function firstSecretFieldName(entry) {
  const names = entry.fieldNames().filter(n => n !== '__notes__')
  return entry.raw.envField ?? names.find(n => ['apiKey', 'password', 'secret', 'token', 'accessToken', 'privateKey'].includes(n)) ?? names[0]
}

function printJson(obj) { process.stdout.write(JSON.stringify(obj, null, 2) + '\n') }

// ----------------------------------------------------------------- commands
const commands = {
  async status(flags) {
    let store = null
    try { store = VaultStore.fromFile({ path: VAULT_PATH }) } catch (err) {
      if (err.code === 'ENOENT') { printJson({ exists: false, path: VAULT_PATH }); return }
      throw err
    }
    printJson({ exists: Boolean(store.doc.header), path: VAULT_PATH, locked: !store.unlocked, entries: store.size })
  },

  async list({ flags, rest }) {
    const store = await open(flags)
    const q = rest[0] ?? ''
    const rows = store.entries()
      .filter(e => !q || [e.title, ...(e.tags ?? []), e.kind, e.env ?? ''].join(' ').toLowerCase().includes(q.toLowerCase()))
      .map(e => ({ id: e.id, title: e.title, kind: e.kind, sensitivity: e.sensitivity, env: e.env ?? null, fields: e.fieldNames().filter(f => f !== '__notes__') }))
    printJson(rows)
  },

  async get({ flags, rest }) {
    const store = await open(flags)
    if (!rest[0]) fail('usage: vaultx get <id|title|ENV> [--field name] [--mask]')
    const entry = findEntry(store, rest[0])
    if (!entry) fail(`entry not found: ${rest[0]}`, 3)
    const field = flags.field ?? firstSecretFieldName(entry)
    let value
    try { value = entry.field(field) } catch (err) { fail(`cannot decrypt field "${field}": ${err.message}`, 4) }
    if (value === undefined) fail(`entry "${entry.title}" has no field "${field}"`, 4)
    await audited({ action: 'cli-get', entryId: entry.id, title: entry.title, fields: [field], detail: flags.mask ? 'masked' : 'plaintext' })
    if (flags.mask) process.stdout.write(maskValue(value) + '\n')
    else process.stdout.write(value + '\n')
  },

  async env({ flags }) {
    const store = await open(flags)
    const out = []
    for (const c of store.envEntries()) {
      if (c.sensitivity === 'high') continue
      const e = store.get(c.id)
      let value
      try { value = e?.field(c.field ?? 'password') } catch { continue }
      if (value === undefined) continue
      const name = flags.prefix ? `${flags.prefix}${c.env.replace(/^DSH_/, '')}` : c.env
      out.push(flags.mask ? `${name}=${maskValue(value)}` : `${name}=${value}`)
    }
    process.stdout.write(out.join('\n') + (out.length ? '\n' : ''))
  },

  async create({ flags, rest }) {
    if (fs.existsSync(VAULT_PATH)) fail(`vault already exists at ${VAULT_PATH}; use rotate or delete the file deliberately`)
    const pw = rest[0] ?? readPassword(flags)
    if (!pw || pw.length < 10) fail('master password required (min 10 chars); never passes via argv in shared machines')
    const store = await VaultStore.createNew({ path: VAULT_PATH, masterPassword: pw })
    await store.save()
    printJson({ ok: true, path: VAULT_PATH })
  },

  async add({ flags, rest }) {
    const store = await open(flags)
    const title = rest[0]
    if (!title) fail('usage: vaultx add <title> [--kind login] [--sensitivity normal] [--field name=value ...] [--env DSH_X] [--tags a,b] [--notes text]')
    const fields = {}
    for (const spec of many(flags.field)) {
      const eq = String(spec).indexOf('=')
      if (eq > 0) fields[spec.slice(0, eq)] = spec.slice(eq + 1)
    }
    if (flags.notes) fields.__notes__ = String(flags.notes)
    try {
      const created = store.add({
        title,
        kind: flags.kind ?? 'login',
        sensitivity: flags.sensitivity ?? 'normal',
        env: flags.env,
        envField: flags['env-field'],
        tags: flags.tags ? String(flags.tags).split(',').map(s => s.trim()).filter(Boolean) : [],
        fields,
      })
      await store.save()
      await audited({ action: 'cli-add', entryId: created.id, title, fields: Object.keys(fields) })
      printJson({ ok: true, id: created.id })
    } catch (err) { fail(err.message) }
  },

  async gen({ flags }) {
    const style = flags.style ?? 'password'
    let value
    if (style === 'passphrase') value = generatePassphrase({ words: Number(flags.words ?? 4) })
    else if (style === 'token') value = generateToken({})
    else if (style === 'totp') value = generateTotpSecret()
    else value = generatePassword({ length: Number(flags.length ?? 24) })
    if (flags.store) {
      const store = await open(flags)
      const field = style === 'totp' ? 'totp' : style === 'token' ? 'apiKey' : 'password'
      const created = store.add({ title: flags.store, kind: style === 'token' ? 'api-key' : 'login', fields: { [field]: value }, ...(flags.env ? { env: flags.env } : {}) })
      await store.save()
      const stats = assess(value)
      printJson({ ok: true, id: created.id, strengthBits: stats.bits, strengthLabel: label(stats.score) })
      return
    }
    process.stdout.write(value + '\n')
  },

  async strength({ flags, rest }) {
    let value = rest[0]
    if (!value) {
      // read from stdin without tripping on TTY-less environments
      value = fs.readFileSync(0, 'utf8').trim()
    }
    if (!value) fail('usage: vaultx strength <value>  (or pipe via stdin; note: argv values may land in shell history — prefer stdin)')
    const stats = assess(value)
    let breach = null
    if (flags.check) breach = await checkBreached(value, { offline: flags.offline })
    printJson({ bits: stats.bits, score: stats.score, label: label(stats.score), feedback: stats.feedback, breach })
  },

  async totp({ flags, rest }) {
    const store = await open(flags)
    if (!rest[0]) fail('usage: vaultx totp <id|title> [--uri]')
    const entry = findEntry(store, rest[0])
    if (!entry) fail('entry not found', 3)
    const secret = entry.field('totp')
    if (!secret) fail('entry has no totp field', 4)
    if (flags.uri) process.stdout.write(totpUri({ secret, label: entry.title }) + '\n')
    else process.stdout.write(totp(secret) + '\n')
  },

  async verify({ flags }) {
    const { AuditLog } = await import('../lib/audit.js')
    const audit = new AuditLog(path.join(DSH_HOME, 'vaultx', 'audit.log'))
    const chain = await audit.verify()
    let vault = { ok: true, total: 0, broken: [] }
    try {
      const store = await open(flags)
      for (const e of store.entries()) for (const f of e.fieldNames()) {
        try { e.field(f) } catch (err) { vault.broken.push({ id: e.id, field: f, error: err.message }) }
      }
      vault.total = store.size
      vault.ok = vault.broken.length === 0
    } catch { /* no password provided: chain-only verify */ }
    printJson({ chain, vault })
  },

  async export({ flags, rest }) {
    const store = await open(flags)
    const target = rest[0] ?? readPassword({ ...flags, 'password-env': undefined })
    if (!target || target.length < 10) fail('usage: vaultx export <target-password> [outfile]')
    const wrapped = await store.exportWrapped(target)
    const doc = { version: 1, header: wrapped.header, entries: store.doc.entries }
    await audited({ action: 'cli-export', detail: rest[1] ?? 'stdout' })
    if (rest[1]) { fs.writeFileSync(rest[1], JSON.stringify(doc, null, 2), { mode: 0o600 }); printJson({ ok: true, file: rest[1] }) }
    else process.stdout.write(JSON.stringify(doc))
  },

  async import({ flags, rest }) {
    const [file, password] = rest
    if (!file || !password) fail('usage: vaultx import <file> <password>')
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'))
    const store = new VaultStore({ path: VAULT_PATH, doc, vaultKey: null })
    await store.unlock(password)
    await store.save()
    await audited({ action: 'cli-import', detail: `${store.size} entries from ${file}` })
    printJson({ ok: true, entries: store.size })
  },

  async rotate({ flags, rest }) {
    const [oldPw, newPw] = rest
    const cur = readPassword(flags) ?? oldPw
    if (!cur || !newPw) fail('usage: vaultx rotate <old> <new>   (old may come from the env var)')
    const store = await open({ ...flags, password: cur })
    await store.changeMasterPassword(cur, newPw)
    await store.save()
    await audited({ action: 'cli-rotate' })
    printJson({ ok: true })
  },
}

async function main() {
  const [, , cmd, ...argv] = process.argv
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(fs.readFileSync(new URL(import.meta.url), 'utf8').match(/Usage:\n(?:^ \*.*\n)+/)?.[0].replace(/^ \* /gm, '  ') ?? 'vaultx — see docs\n')
    return
  }
  const handler = commands[cmd]
  if (!handler) fail(`unknown command: ${cmd}`)
  const { flags, rest } = parseFlags(argv)
  try {
    await handler({ flags, rest })
  } catch (err) {
    fail(err?.message ?? String(err))
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  main()
}

export { main, commands }
