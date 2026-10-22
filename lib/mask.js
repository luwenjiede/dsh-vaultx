/**
 * Value masking for logs, UI listings and (nowhere the model can use it to
 * reconstruct). Keeps a short head/tail so the operator can recognize WHICH
 * key is which without printing it.
 *
 * @module vaultx/mask
 */

/**
 * @param {string} value
 * @returns {string} e.g. "sk-a……………………3f9"
 */
export function maskValue(value) {
  const s = String(value ?? '')
  if (s.length === 0) return ''
  if (s.length <= 12) return '•'.repeat(s.length)
  const tail = Math.min(4, Math.floor((s.length - 8) / 2))
  const head = Math.min(4, s.length - 8 - tail)
  const dots = '•'.repeat(Math.min(24, Math.max(0, s.length - head - tail)))
  return `${s.slice(0, head)}${dots}${s.slice(s.length - tail)}`
}

/** True if a string already looks masked (contains • or is a known placeholder). */
export function looksMasked(value) {
  const s = String(value ?? '')
  return s.includes('•') || /^\*+$/.test(s) || s === '[已加密]'
}
