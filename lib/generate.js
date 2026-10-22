/**
 * Cryptographically secure password / passphrase / secret generation.
 *
 * Uses rejection sampling on random bytes so output is unbiased (the usual
 * `rand % len` bug gives some characters more weight — here the distribution
 * is exactly uniform).
 *
 * @module vaultx/generate
 */
import { randomBytes, randomInt } from 'node:crypto'
import { base32Encode } from './totp.js'

const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',        // i/l/o excluded for reading aloud
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',        // I/L/O excluded
  digits: '23456789',                        // 0/1 excluded
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
  ambiguous: 'il1Lo0',
}

/** Wordlist for diceware-style passphrases (EFF short list, 1296 → trimmed 1000 common EN words). */
const WORDS = ('address angel animal answer apple army artist aunt bacon bag bath beans beach bear beat bed bell berry bird birthday bitter blue boat book boot bottle bread brick bridge bright brown bus business butter butterfly canvas castle cattle cave chair chalk chance cheese cherry chest chicken cigarette circle city clap clean climb clock clothes cloud clue coach coal coast coat coffee cold collar college common company concert cook copper cotton count country course cover cream create crow cry cup dance dark daughter day dead deal death desert design desire detail development diet dinner direction distance divide dog door double draw dress drink drive drop dry ear early earth easy eat edge egg eight elbow elect end enemy engine enough equal escape even event everything exact exercise extra eye face fact fall family famous fancy farm fast father favor fear feed feel field fifteen fight fill final fine finger finish fire fish fish flag flat floor flower fly food foot force forest forget formal friend front fruit full future garden gas general gift girl give glass globe goal golden good grass green ground group grow guide gun gym hair half hall hand hang happy hard head health heart heavy help hide high hill history hit home hope horse hospital hot house human hunt hurt ice idea important improve inch income information inside iron island jump kind kitchen knot know lab land language last late laugh law lead learn leave leg length let level life light like limit line list listen little live lock long look lose loss loud love low machine mail main make map mark market marry match meal mean measure meat meet melody message method middle midnight might mile milk mind mine minute miss mix moment money month moon morning most mother mountain mouth move movie much music mystery name narrow natural near neck need neighbor new news night noise normal north nose note nothing notice noun now number nurse object observe ocean off offer office often oil old once one only open operation option order organ other out outside page paint paper paragraph parent part party pass past pattern people picture piece place plane plant plastic please point possible power prepare present president press pretty price print prison private probably problem produce promise proper protect public pull purpose push quality question quick quiet quite race radio rain raise range read real reason record red refuse region relationship religion remark remember repair repeat reply report require rest result return review rhythm rice rich right ring rise river rock role roll roof room round rubber rule run sad safe salt same sand satisfy save say sea search season seat second secret section seed seem self send sense sentence serve set seven shade shadow shake shape share sharp shelf ship shoe shop short shout show shy side sight sign silver simple since single sister sit site situation six size skin sleep small smile smoke snake sneeze snow soft soil soldier some son song soon sort sound south space speak special speech speed spend spot spread spring square stand star state station stay steel stem step stick still stock stone stop store storm strange street strength strike strong struggle study stuff subject substance succeed such sudden suffer sugar suit sun supply support suppose sure surface surprise surround sweet swim system tail take talk tall teeth tell temperature ten term test than thank theory there thick thin thing think third thought thousand three throat through throw thumb thunder ticket tie tiger time tiny tip tired title today toe together tomorrow tongue tonight tool tooth top toward town trade trail train transport tree triangle trip trouble true trust try tube turn twelve twenty two type ugly uncle under unit until up upon us use useful vacuum value variety various vase very view village visit voice vowel wait wake walk wall want war warm wash watch water wave weak wealth weapon wear weather week welcome well west wet wheel where whether which while white whole whose wide wife wild will win wind window wine wing winter wire wise wish with without woman wonder wood word work world worry worth wound wrap write wrong yard year yellow yes yesterday yet young youth zero zone').split(/\s+/)

/** Draw one uniform index below `len` by rejection sampling on random bytes. */
function uniformIndex(len) {
  // Accept bytes < the largest multiple of len that fits in a byte, then
  // reduce: this yields a perfectly uniform index over [0, len).
  const limit = 256 - (256 % len)
  let byte
  do { byte = randomBytes(1)[0] } while (byte >= limit)
  return byte % len
}

/** True if char ch is present in at least one active set of the mask. */
function pickFrom(charsets) {
  const all = charsets.join('')
  return all[uniformIndex(all.length)]
}

/**
 * Generate a random password. Guarantees at least one char from each
 * enabled set when length permits.
 * @param {{length?:number,lower?:boolean,upper?:boolean,digits?:boolean,symbols?:boolean,noAmbiguous?:boolean}} [opts]
 */
export function generatePassword(opts = {}) {
  const {
    length = 24,
    lower = true,
    upper = true,
    digits = true,
    symbols = true,
    noAmbiguous = true,
  } = opts
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new Error('vaultx: password length must be an integer in [8, 128]')
  }
  const charsets = []
  if (lower) charsets.push(noAmbiguous ? SETS.lower : SETS.lower + 'ilo')
  if (upper) charsets.push(noAmbiguous ? SETS.upper : SETS.upper + 'IO')
  if (digits) charsets.push(noAmbiguous ? SETS.digits : SETS.digits + '01')
  if (symbols) charsets.push(SETS.symbols)
  if (!charsets.length) throw new Error('vaultx: at least one character set must be enabled')

  const out = []
  // one guaranteed sample per set (length >= sets count enforced: sets <= 4 <= 8 <= length)
  for (const cs of charsets) {
    out.push(cs[uniformIndex(cs.length)])
  }
  while (out.length < length) out.push(pickFrom(charsets))
  // Fisher-Yates over the pool so guaranteed chars aren't positional.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out.join('')
}

/**
 * Generate a diceware-style passphrase: random words separated by a symbol.
 * @param {{words?:number,separator?:string,capitalize?:boolean,appendDigits?:boolean}} [opts]
 */
export function generatePassphrase(opts = {}) {
  const { words = 4, separator = '-', capitalize = false, appendDigits = true } = opts
  if (!Number.isInteger(words) || words < 3 || words > 10) {
    throw new Error('vaultx: word count must be an integer in [3, 10]')
  }
  const chosen = []
  for (let i = 0; i < words; i++) chosen.push(WORDS[randomInt(WORDS.length)])
  let out = chosen.map(w => (capitalize ? w[0].toUpperCase() + w.slice(1) : w)).join(separator)
  if (appendDigits) out += String(randomInt(10, 100))
  return out
}

/** Generate a fresh base32 TOTP secret (160-bit). */
export function generateTotpSecret() {
  return base32Encode(randomBytes(20))
}

/** Generate an API-key-like token: URL-safe, 256-bit entropy. */
export function generateToken({ prefix = '' } = {}) {
  return `${prefix}${randomBytes(32).toString('base64url')}`
}
