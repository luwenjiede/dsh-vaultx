/**
 * Value masking for logs, UI listings and (nowhere the model can use it to
 * reconstruct). Keeps a short head/tail so the operator can recognize WHICH
 * key is which without printing it.
 *
 * @module vaultx/mask
 */

/**
 * @param {string} value
 * @returns {string} e.g. "sk-……………………3f9"
 */
export function maskValue(value) {
  const s = String(value ?? '')
  if (s.length === 0) return ''
  // Review P1-5: short secrets stay fully masked; longer ones expose at most
  // 3+3 chars AND never more than a quarter of the value.
  if (s.length <= 16) return '•'.repeat(Math.min(24, s.length))
  const budget = Math.min(6, Math.floor(s.length / 4))
  const tail = Math.min(3, Math.floor(budget / 2))
  const head = Math.min(3, budget - tail)
  const dots = '•'.repeat(Math.min(24, Math.max(0, s.length - head - tail)))
  return `${s.slice(0, head)}${dots}${s.slice(s.length - tail)}`
}

/** True if a string already looks masked (contains • or is a known placeholder). */
export function looksMasked(value) {
  const s = String(value ?? '')
  return s.includes('•') || /^\*+$/.test(s) || s === '[已加密]'
}
