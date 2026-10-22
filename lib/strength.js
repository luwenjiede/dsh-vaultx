/**
 * Password strength estimation — a compact, dependency-free approximation of
 * the zxcvbn idea: character-space guess entropy minus common-pattern penalties.
 *
 * Never a security decision by itself; it is UI guidance. The authoritative
 * "is it leaked?" check lives in breach.js.
 *
 * @module vaultx/strength
 */

/** Head of the rockyou-style common list (a deliberately small, offline set). */
const COMMON = new Set([
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
  '1234567', 'dragon', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow',
  'master', '666666', 'qwertyuiop', 'mustang', '1234567890', 'michael', '654321', 'jordan',
  'superman', '1qaz2wsx', '7777777', '000000', 'killer', 'trustno1', 'batman', 'access',
  'hello', 'charlie', 'donald', 'password1', 'qwerty123', 'iloveyou', 'admin', 'welcome',
])

const PEEKABLE_LAYOUTS = ['qwerty', 'azerty', 'qwertz', 'dvorak', 'colemak']

/** Count distinct character classes present. */
function classes(pw) {
  let mask = 0
  if (/[a-z]/.test(pw)) mask |= 1
  if (/[A-Z]/.test(pw)) mask |= 2
  if (/[0-9]/.test(pw)) mask |= 4
  if (/[^a-zA-Z0-9]/.test(pw)) mask |= 8
  return mask
}

/**
 * Estimate bits of guessing entropy and a 0-4 score (0 weakest).
 * @param {string} password
 * @param {string[]} [userInputs] - names/titles/emails the attacker would try first.
 */
export function assess(password, userInputs = []) {
  const pw = String(password ?? '')
  if (!pw) return { bits: 0, score: 0, feedback: ['空密码', 'Empty password'] }

  let pool = 0
  const mask = classes(pw)
  if (mask & 1) pool += 26
  if (mask & 2) pool += 26
  if (mask & 4) pool += 10
  if (mask & 8) pool += 33

  let bits = pw.length * Math.log2(pool || 1)

  const lower = pw.toLowerCase()
  const feedback = []

  if (COMMON.has(lower)) {
    bits = Math.min(bits, 4)
    feedback.push('极常见密码 / Extremely common password')
  } else if (/^(.)\1+$/.test(pw)) {
    bits = Math.min(bits, 3)
    feedback.push('重复单字符 / Repeated single character')
  }

  // Sequential (abcd, 4321) and keyboard-row penalties.
  if (hasRun(pw, 4)) {
    bits -= pw.length * 0.5
    feedback.push('连续字符序列 / Sequential characters')
  }
  if (PEEKABLE_LAYOUTS.some(layout => leaksKeyboardRow(lower, layout))) {
    bits -= pw.length * 1.0
    feedback.push('键盘行走模式 / Keyboard row pattern')
  }

  // Leet-ish substitution of a common word: "P@ssw0rd"
  const deleet = lower.replace(/[@4]/g, 'a').replace(/[0]/g, 'o').replace(/[1!|]/g, 'i').replace(/[3]/g, 'e').replace(/[$5]/g, 's').replace(/[7]/g, 't')
  if (COMMON.has(deleet)) {
    bits -= 16
    feedback.push('常见词替换 / Leet-substituted common word')
  }

  // Personal terms the model/attacker would try first.
  for (const term of userInputs.map(t => String(t).toLowerCase())) {
    if (term.length >= 3 && lower.includes(term)) {
      bits -= 10
      feedback.push(`含个人词汇「${term}」 / Contains personal term "${term}"`)
      break
    }
  }

  // Entropy cap: a long passphrase beats symbols.
  bits = Math.max(0, bits)
  const score = bits >= 80 ? 4 : bits >= 60 ? 3 : bits >= 40 ? 2 : bits >= 25 ? 1 : 0
  if (score >= 4) feedback.length = 0
  return { bits: Math.round(bits), score, feedback }
}

/** True if a strictly ascending/descending run of `min` chars exists. */
function hasRun(pw, min) {
  let asc = 1
  let desc = 1
  for (let i = 1; i < pw.length; i++) {
    const d = pw.charCodeAt(i) - pw.charCodeAt(i - 1)
    asc = d === 1 ? asc + 1 : 1
    desc = d === -1 ? desc + 1 : 1
    if (asc >= min || desc >= min) return true
  }
  return false
}

const ROWS = {
  qwerty: ['`1234567890-=', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'],
  azerty: ['&é"\'(-_)=', 'azertyuiop', 'qsdfghjklm', 'wxcvbn'],
  qwertz: ['1234567890', 'qwertzuiop', 'asdfghjkl', 'yxcvbnm'],
  dvorak: ['1234567890', '\'，.pyfgcrl', 'aoeuidhtns', 'qjkxbmwvz'],
  colemak: ['1234567890', 'qwfpgjluy', 'arstdhneio', 'zxcvbkm'],
}

/** True if ≥4 chars of the password are consecutive keys on one row. */
function leaksKeyboardRow(lower, layout) {
  const rows = ROWS[layout] ?? []
  for (const row of rows) {
    for (let i = 0; i + 4 <= row.length; i++) {
      const window = row.slice(i, i + 4)
      for (let j = 0; j + 4 <= lower.length; j++) {
        const slice = lower.slice(j, j + 4)
        if ([...window].every(ch => slice.includes(ch)) && slice.length === 4 && new Set(slice).size >= 3) {
          // crude: 4 chars of the slice all live in the same 4-key window
          let order = true
          for (let k = 1; k < 4; k++) {
            if (window.indexOf(slice[k]) !== window.indexOf(slice[k - 1]) + 1) order = false
          }
          if (order) return true
        }
      }
    }
  }
  return false
}

/** Strength label used in UI output. */
export function label(score) {
  return ['很弱', '弱', '一般', '强', '极强'][Math.max(0, Math.min(4, score))]
}
