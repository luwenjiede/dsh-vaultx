#!/usr/bin/env node
/**
 * Link host-provided peer packages into node_modules so `pnpm test` works on
 * a fresh clone without installing the harness itself (review D-1).
 *
 * Peers (@deepseek-ai/*) ship inside the DSH installation, not on npm. This
 * script symlinks them from the first root that has them:
 *   1. $VAULTX_PEER_ROOT (absolute path to a node_modules dir containing @deepseek-ai/*)
 *   2. /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules
 *   3. ~/.dsh/node_modules
 *
 * Idempotent: existing links are left alone; missing peers are reported.
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const PEERS = [
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-home-paths',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/dsh-typert-protocol',
  '@deepseek-ai/schemastery',
]

const roots = [
  process.env.VAULTX_PEER_ROOT,
  '/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules',
  path.join(os.homedir(), '.dsh', 'node_modules'),
].filter(Boolean)

const nm = path.resolve('node_modules/@deepseek-ai')
fs.mkdirSync(nm, { recursive: true })

let linked = 0
let missing = []
for (const root of roots) {
  if (!fs.existsSync(root)) continue
  for (const p of PEERS) {
    const src = path.join(root, p)
    const dst = path.join(nm, p.replace('@deepseek-ai/', ''))
    if (fs.existsSync(dst)) { linked++; continue }
    if (fs.existsSync(src)) {
      fs.symlinkSync(src, dst, 'dir')
      linked++
      console.log(`linked ${p} -> ${src}`)
    } else {
      missing.push(p)
    }
  }
  if (linked) break
}

if (!linked) {
  console.error('vaultx peers: no host node_modules found. Set VAULTX_PEER_ROOT to a dir containing @deepseek-ai/* and re-run.')
  process.exit(1)
}
console.log(`vaultx peers: ${linked}/${PEERS.length} linked` + (missing.length ? ` (missing: ${missing.join(', ')})` : ''))
