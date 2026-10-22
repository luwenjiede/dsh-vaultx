/**
 * Shared constants for VaultX.
 *
 * Kept dependency-free so the CLI, tests and the host plugin all read the
 * same truth. Nothing in here is secret.
 *
 * @module vaultx/constants
 */
/** On-disk format version stamped into every vault header. */
export const VAULT_VERSION = 1
/** Name of the plugin, used in service keys, RPC namespaces and env prefixes. */
export const PLUGIN_NAME = 'vaultx'
/** Default vault file location, relative to the DSH home. */
export const VAULT_FILE = 'vaultx/vault.json'
/** Default audit log location, relative to the DSH home. */
export const AUDIT_FILE = 'vaultx/audit.log'
/** Default policy location, relative to the DSH home. */
export const POLICY_FILE = 'vaultx/policy.json'
/** Directory mode for everything VaultX creates. */
export const DIR_MODE = 0o700
/** File mode for the vault, policy and audit artifacts. */
export const FILE_MODE = 0o600
/** Environment namespace the host substitutes per shell execution. */
export const ENV_PREFIX = 'DSH_'
/** Maximum entries accepted in one page of results. */
export const MAX_PAGE = 200
/** Hard ceiling on entry count; beyond this the vault refuses writes. */
export const MAX_ENTRIES = 5000
/** Master-password attempts before lockout. */
export const MAX_ATTEMPTS = 5
/** Lockout window after MAX_ATTEMPTS failures, in milliseconds. */
export const LOCKOUT_MS = 5 * 60_000
/** How long an unlocked vault stays usable without operator touch, in minutes. 0 = until explicit lock. */
export const DEFAULT_AUTO_LOCK_MINUTES = 15
/** Sensitivity levels recorded on every entry; drives approval gates. */
export const SENSITIVITIES = ['low', 'normal', 'high']
