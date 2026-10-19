#!/usr/bin/env node
/**
 * Local secrets broker for DeepSeek Harness / codex / hermes.
 *
 * Vault backend: any Bitwarden-compatible server (NodeWarden, Vaultwarden, Bitwarden) via
 * the Bitwarden CLI. The master password is entered only in the local page; the
 * decrypted session lives in memory and is never written to disk. Agents call
 * the HTTP API with per-agent tokens; reading an item opens an approval request
 * where the user can allow once, or for 1h / 24h / 7d / forever.
 *
 * Admin page (localhost only): unlock, add/rotate/delete secrets, add/rotate/
 * delete agents, revoke grants, approve pending requests.
 *
 * Env:
 *   SECRETS_BROKER_HOME  data directory (default ~/.secrets-broker)
 *   SECRETS_BROKER_PORT  listen port (default 8788)
 *   SECRETS_BROKER_MOCK  "1" swaps the vault for a fixed dummy value (tests)
 *   SECRETS_BROKER_BW    path to @bitwarden/cli build/bw.js
 */
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'

const ROOT = process.env.SECRETS_BROKER_HOME ?? path.join(os.homedir(), '.secrets-broker')
const CONFIG_PATH = path.join(ROOT, 'config.json')
const GRANTS_PATH = path.join(ROOT, 'grants.json')
const AUDIT_PATH = path.join(ROOT, 'audit.log')
const MASTER_PASSWORD_FILE = path.join(ROOT, 'master-password')
const AGENT_TOKENS_PATH = path.join(ROOT, 'agent-tokens.json')
const ENCRYPTION_KEY_PATH = process.env.SECRETS_BROKER_KEY_FILE ?? path.join(ROOT, 'encryption.key')
const MOCK = process.env.SECRETS_BROKER_MOCK === '1'
const DEFAULT_BW_JS = process.env.SECRETS_BROKER_BW ?? 'bw'
const BW_JS = process.env.SECRETS_BROKER_BW ?? DEFAULT_BW_JS

fs.mkdirSync(ROOT, { recursive: true })

function randomToken() {
  return crypto.randomBytes(24).toString('base64url')
}

// ---- at-rest encryption (AES-256-GCM) ----
let encryptionKey
function loadEncryptionKey() {
  if (encryptionKey !== undefined) return encryptionKey
  const fromEnv = process.env.SECRETS_BROKER_ENCRYPTION_KEY
  if (fromEnv) {
    encryptionKey = Buffer.from(fromEnv, 'base64')
    if (encryptionKey.length !== 32) throw new Error('SECRETS_BROKER_ENCRYPTION_KEY must be 32 bytes base64')
    return encryptionKey
  }
  if (fs.existsSync(ENCRYPTION_KEY_PATH)) {
    encryptionKey = Buffer.from(fs.readFileSync(ENCRYPTION_KEY_PATH, 'utf8').trim(), 'base64')
    if (encryptionKey.length !== 32) throw new Error(`invalid encryption key in ${ENCRYPTION_KEY_PATH}`)
    return encryptionKey
  }
  encryptionKey = crypto.randomBytes(32)
  fs.writeFileSync(ENCRYPTION_KEY_PATH, `${encryptionKey.toString('base64')}\n`, { mode: 0o600 })
  return encryptionKey
}
function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith('enc:v1:')
}
function encryptString(plain) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', loadEncryptionKey(), iv)
  const ciphertext = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()])
  return `enc:v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${ciphertext.toString('base64')}`
}
function decryptString(value) {
  if (!isEncrypted(value)) return value
  const parts = value.split(':')
  if (parts.length !== 5) throw new Error('malformed encrypted value')
  const iv = Buffer.from(parts[2], 'base64')
  const tag = Buffer.from(parts[3], 'base64')
  const ciphertext = Buffer.from(parts[4], 'base64')
  const decipher = crypto.createDecipheriv('aes-256-gcm', loadEncryptionKey(), iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}
function maskToken(token) {
  if (typeof token !== 'string' || token.length === 0) return ''
  if (token.length <= 10) return '••••••'
  return `${token.slice(0, 4)}…${token.slice(-4)}`
}
function encryptionFingerprint() {
  return crypto.createHash('sha256').update(loadEncryptionKey()).digest('hex').slice(0, 12)
}

function hashToken(token) {
  return `sha256:${crypto.createHash('sha256').update(String(token)).digest('hex')}`
}

/** Plaintext tokens are only kept locally for copy/rotate; config.json stores hashes. */
function loadAgentTokens() {
  if (!fs.existsSync(AGENT_TOKENS_PATH)) return {}
  try {
    const parsed = JSON.parse(fs.readFileSync(AGENT_TOKENS_PATH, 'utf8'))
    const tokens = {}
    for (const [name, value] of Object.entries(parsed)) {
      tokens[name] = isEncrypted(value) ? decryptString(value) : value
    }
    return tokens
  } catch {
    return {}
  }
}
function saveAgentTokens(tokens) {
  const encrypted = {}
  for (const [name, value] of Object.entries(tokens)) {
    encrypted[name] = isEncrypted(value) ? value : encryptString(value)
  }
  fs.writeFileSync(AGENT_TOKENS_PATH, JSON.stringify(encrypted, null, 2), { mode: 0o600 })
}
function migrateAgentTokens() {
  const tokens = loadAgentTokens()
  let changed = false
  for (const [name, value] of Object.entries(config.agents ?? {})) {
    if (typeof value === 'string' && !value.startsWith('sha256:') && value.length > 0) {
      tokens[name] = value
      config.agents[name] = hashToken(value)
      changed = true
    }
  }
  if (changed) {
    saveAgentTokens(tokens)
    saveConfig()
    console.log('[secrets-broker] migrated agent tokens to sha256 hashes')
  }
}

/** Read + decrypt the optional auto-unlock password; migrate plaintext files in place. */
function readAutoUnlockPassword() {
  const fromEnv = process.env.SECRETS_BROKER_MASTER_PASSWORD
  if (fromEnv) return fromEnv
  if (!fs.existsSync(MASTER_PASSWORD_FILE)) return undefined
  const raw = fs.readFileSync(MASTER_PASSWORD_FILE, 'utf8').trim()
  if (raw.length === 0) return undefined
  if (isEncrypted(raw)) {
    try {
      return decryptString(raw)
    } catch {
      return undefined
    }
  }
  try {
    fs.writeFileSync(MASTER_PASSWORD_FILE, `${encryptString(raw)}\n`, { mode: 0o600 })
  } catch {}
  return raw
}

function loginThrottle(req) {
  const ip = req.socket?.remoteAddress ?? 'unknown'
  const entry = loginFailures.get(ip)
  if (entry === undefined) return { ip, blocked: false, count: 0 }
  if (entry.blockedUntil && entry.blockedUntil > Date.now()) return { ip, blocked: true, count: entry.count }
  if (entry.firstAt < Date.now() - 10 * 60 * 1000) {
    loginFailures.delete(ip)
    return { ip, blocked: false, count: 0 }
  }
  return { ip, blocked: false, count: entry.count }
}
function recordLoginFailure(ip) {
  const entry = loginFailures.get(ip) ?? { count: 0, firstAt: Date.now(), blockedUntil: 0 }
  entry.count += 1
  if (entry.count >= 5) entry.blockedUntil = Date.now() + 5 * 60 * 1000
  loginFailures.set(ip, entry)
}

function loadConfig() {
  if (fs.existsSync(CONFIG_PATH)) {
    const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
    parsed.agents ??= { dsh: randomToken(), codex: randomToken(), hermes: randomToken() }
    parsed.agentAccess ??= {}
    parsed.agentWrite ??= {}
    parsed.itemGroups ??= {}
    parsed.profile ??= { name: '', email: '', phone: '', avatarUrl: '', oidcSub: '', oidcEmail: '', totpSecret: '', totpEnabled: false }
    parsed.telegram ??= {}
    parsed.gotify ??= {}
    parsed.wxpush ??= {}
    parsed.oauthClients ??= {}
    parsed.oauthTokens ??= {}
    parsed.port ??= 8788
    parsed.bwJs ??= BW_JS
    parsed.autoImport ??= true
    if (parsed.oidc?.clientSecret && isEncrypted(parsed.oidc.clientSecret)) {
      parsed.oidc.clientSecret = decryptString(parsed.oidc.clientSecret)
    }
    if (parsed.telegram?.token && isEncrypted(parsed.telegram.token)) {
      parsed.telegram.token = decryptString(parsed.telegram.token)
    }
    if (parsed.gotify?.token && isEncrypted(parsed.gotify.token)) {
      parsed.gotify.token = decryptString(parsed.gotify.token)
    }
    if (parsed.wxpush?.token && isEncrypted(parsed.wxpush.token)) {
      parsed.wxpush.token = decryptString(parsed.wxpush.token)
    }
    return parsed
  }
  const config = {
    port: Number(process.env.SECRETS_BROKER_PORT ?? 8788),
    serverUrl: 'https://vault.example.com',
    bwJs: BW_JS,
    autoImport: true,
    agents: { dsh: randomToken(), codex: randomToken(), hermes: randomToken() },
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8')
  return config
}

function saveConfig() {
  const serializable = JSON.parse(JSON.stringify(config))
  if (serializable.oidc?.clientSecret && !isEncrypted(serializable.oidc.clientSecret)) {
    serializable.oidc.clientSecret = encryptString(serializable.oidc.clientSecret)
  }
  if (serializable.telegram?.token && !isEncrypted(serializable.telegram.token)) {
    serializable.telegram.token = encryptString(serializable.telegram.token)
  }
  if (serializable.gotify?.token && !isEncrypted(serializable.gotify.token)) {
    serializable.gotify.token = encryptString(serializable.gotify.token)
  }
  if (serializable.wxpush?.token && !isEncrypted(serializable.wxpush.token)) {
    serializable.wxpush.token = encryptString(serializable.wxpush.token)
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(serializable, null, 2), 'utf8')
}

function loadGrants() {
  if (!fs.existsSync(GRANTS_PATH)) return []
  try {
    const parsed = JSON.parse(fs.readFileSync(GRANTS_PATH, 'utf8'))
    if (!Array.isArray(parsed.grants)) return []
    return parsed.grants.map((grant) => ({
      ...grant,
      reads: Number.isInteger(grant.reads) ? grant.reads : 0,
      maxReads: Number.isInteger(grant.maxReads) ? grant.maxReads : null,
      revokedAt: grant.revokedAt ?? null,
    }))
  } catch {
    return []
  }
}

function saveGrants() {
  fs.writeFileSync(GRANTS_PATH, JSON.stringify({ grants }, null, 2), 'utf8')
}

function audit(entry) {
  fs.appendFileSync(AUDIT_PATH, `${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`, 'utf8')
}

const config = loadConfig()
if (process.env.SECRETS_BROKER_PORT) config.port = Number(process.env.SECRETS_BROKER_PORT)
migrateAgentTokens()
if (config.oidc?.clientSecret && !isEncrypted(config.oidc.clientSecret)) saveConfig()
const ADMIN_PASSWORD = process.env.SECRETS_BROKER_ADMIN_PASSWORD ?? config.adminPassword ?? ''
const BIND = process.env.SECRETS_BROKER_BIND ?? config.bind ?? '127.0.0.1'
const SESSION_SECRET = config.adminSessionSecret ?? crypto.randomBytes(32).toString('hex')
const AUTH_REQUIRED = ADMIN_PASSWORD.length > 0
let PUBLIC_URL = (config.publicUrl ?? process.env.BROKER_PUBLIC_URL ?? 'http://127.0.0.1:8788').replace(/\/+$/, '')
let NTFY_URL = config.ntfyUrl ?? process.env.NTFY_URL ?? ''
let OIDC_ISSUER = (config.oidc?.issuer ?? process.env.OIDC_ISSUER ?? '').replace(/\/+$/, '')
let OIDC_CLIENT_ID = config.oidc?.clientId ?? process.env.OIDC_CLIENT_ID ?? ''
let OIDC_CLIENT_SECRET = config.oidc?.clientSecret ?? process.env.OIDC_CLIENT_SECRET ?? ''
let OIDC_REDIRECT_URI = config.oidc?.redirectUri ?? process.env.OIDC_REDIRECT_URI ?? `${PUBLIC_URL}/oidc/callback`
let OIDC_SCOPE = config.oidc?.scope ?? process.env.OIDC_SCOPE ?? 'openid profile email'
let OIDC_ENABLED = OIDC_ISSUER.length > 0 && OIDC_CLIENT_ID.length > 0
function refreshRuntimeSettings() {
  PUBLIC_URL = (config.publicUrl ?? process.env.BROKER_PUBLIC_URL ?? 'http://127.0.0.1:8788').replace(/\/+$/, '')
  NTFY_URL = config.ntfyUrl ?? process.env.NTFY_URL ?? ''
  OIDC_ISSUER = (config.oidc?.issuer ?? process.env.OIDC_ISSUER ?? '').replace(/\/+$/, '')
  OIDC_CLIENT_ID = config.oidc?.clientId ?? process.env.OIDC_CLIENT_ID ?? ''
  OIDC_CLIENT_SECRET = config.oidc?.clientSecret ?? process.env.OIDC_CLIENT_SECRET ?? ''
  OIDC_REDIRECT_URI = config.oidc?.redirectUri ?? process.env.OIDC_REDIRECT_URI ?? `${PUBLIC_URL}/oidc/callback`
  OIDC_SCOPE = config.oidc?.scope ?? process.env.OIDC_SCOPE ?? 'openid profile email'
  OIDC_ENABLED = OIDC_ISSUER.length > 0 && OIDC_CLIENT_ID.length > 0
  oidcDiscoveryCache = undefined
}
let grants = loadGrants()
const loginFailures = new Map()

const state = {
  unlocked: false,
  session: undefined,
  pending: new Map(), // requestId -> { id, agent, name, createdAt, status }
  lastImport: undefined,
}

function validName(name) {
  return (
    typeof name === 'string' &&
    name.length > 0 &&
    name.length <= 160 &&
    name.trim() === name &&
    !name.startsWith('-') &&
    !/[\u0000-\u001f\u007f]/.test(name)
  )
}

function runBw(args, { env = {}, input } = {}) {
  const bwEntry = process.env.SECRETS_BROKER_BW ?? config.bwJs ?? BW_JS
  const isNodeScript = typeof bwEntry === 'string' && bwEntry.endsWith('.js')
  const command = isNodeScript ? process.execPath : bwEntry
  const commandArgs = isNodeScript ? [bwEntry, ...args] : args
  return new Promise((resolve) => {
    const child = spawn(command, commandArgs, {
      env: { ...process.env, BW_SESSION: state.session ?? '', ...env },
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => (stdout += d.toString()))
    child.stderr.on('data', (d) => (stderr += d.toString()))
    child.on('error', (error) => resolve({ code: -1, stdout, stderr: String(error) }))
    if (input !== undefined) child.stdin.end(input)
    else child.stdin.end()
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

async function unlock(password) {
  if (MOCK) {
    state.unlocked = true
    state.session = 'mock-session'
    audit({ event: 'unlock', mode: 'mock' })
    if (config.autoImport !== false) {
      state.lastImport = { created: [], skipped: ['导入进行中…'] }
      importLocalSecrets()
        .then((result) => {
          state.lastImport = result
          invalidateItems()
        })
        .catch(() => {})
    }
    return { ok: true }
  }
  const result = await runBw(['unlock', '--raw', '--passwordenv', 'BW_MASTER_PASSWORD'], {
    env: { BW_MASTER_PASSWORD: password },
  })
  const session = result.stdout.trim()
  if (result.code !== 0 || session.length === 0) {
    return { ok: false, error: (result.stderr || result.stdout || 'unlock failed').trim().slice(0, 500) }
  }
  state.session = session
  state.unlocked = true
  audit({ event: 'unlock' })
  // Auto-import runs in the background so unlock returns immediately.
  if (config.autoImport !== false) {
    state.lastImport = { created: [], skipped: ['导入进行中…'] }
    importLocalSecrets()
      .then((imported) => {
        state.lastImport = imported
        invalidateItems()
        audit({ event: 'import.auto', created: imported.created, skipped: imported.skipped.length })
      })
      .catch(() => {})
  }
  return { ok: true }
}

function lock() {
  state.unlocked = false
  state.session = undefined
  audit({ event: 'lock' })
}

async function listItems() {
  if (MOCK) return [{ id: 'mock-id', name: 'mock-item', login: { password: 'mock' } }]
  const result = await runBw(['list', 'items'])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout).trim().slice(0, 500))
  return JSON.parse(result.stdout || '[]')
}

// Small TTL cache: the bw CLI is the slow part, and the dashboard polls often.
let itemsCache = { at: 0, list: [] }
function invalidateItems() {
  itemsCache = { at: 0, list: [] }
}
async function listItemsCached(force = false) {
  if (!force && Date.now() - itemsCache.at < 3000) return itemsCache.list
  const list = await listItems()
  itemsCache = { at: Date.now(), list }
  return list
}

/** Keep the bw CLI's local cache in sync with NodeWarden after mutations. */
function backgroundSync() {
  runBw(['sync'])
    .then(() => invalidateItems())
    .catch(() => {})
}

async function saveItem(name, value, notes, url) {
  if (!validName(name)) throw new Error('invalid item name')
  if (value !== undefined && (typeof value !== 'string' || value.length === 0)) throw new Error('empty value')
  if (MOCK) return { name, updated: false }
  const uris = typeof url === 'string' && url.trim().length > 0 ? [{ uri: url.trim() }] : undefined
  const items = await listItems()
  const existing = items.find((item) => item.name?.toLowerCase() === name.toLowerCase())
  if (existing !== undefined) {
    const got = await runBw(['get', 'item', existing.id])
    if (got.code !== 0) throw new Error((got.stderr || got.stdout).trim().slice(0, 500))
    const item = JSON.parse(got.stdout)
    item.name = name
    item.login ??= { username: '', password: '', uris: [] }
    if (value !== undefined) item.login.password = value
    if (notes !== undefined) item.notes = notes
    if (uris !== undefined) item.login.uris = uris
    const encoded = await runBw(['encode'], { input: JSON.stringify(item) })
    if (encoded.code !== 0) throw new Error((encoded.stderr || encoded.stdout).trim().slice(0, 500))
    const edited = await runBw(['edit', 'item', existing.id, encoded.stdout.trim()])
    if (edited.code !== 0) throw new Error((edited.stderr || edited.stdout).trim().slice(0, 500))
    audit({ event: 'item.update', name })
    backgroundSync()
    return { name, updated: true }
  }
  const tmpl = await runBw(['get', 'template', 'item'])
  if (tmpl.code !== 0) throw new Error((tmpl.stderr || tmpl.stdout).trim().slice(0, 500))
  const item = JSON.parse(tmpl.stdout)
  item.type = 1
  item.name = name
  item.notes = notes ?? null
  item.login = { username: '', password: value ?? '', uris: uris ?? [] }
  const encoded = await runBw(['encode'], { input: JSON.stringify(item) })
  if (encoded.code !== 0) throw new Error((encoded.stderr || encoded.stdout).trim().slice(0, 500))
  const created = await runBw(['create', 'item', encoded.stdout.trim()])
  if (created.code !== 0) throw new Error((created.stderr || created.stdout).trim().slice(0, 500))
  audit({ event: 'item.create', name })
  backgroundSync()
  return { name, updated: false }
}

function itemUrl(item) {
  const uri = item.login?.uris?.[0]?.uri
  return typeof uri === 'string' ? uri : ''
}
function urlHost(url) {
  if (typeof url !== 'string' || url.length === 0) return ''
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).host.toLowerCase()
  } catch {
    return ''
  }
}
function itemMatchesUrl(item, targetUrl) {
  const target = urlHost(targetUrl)
  if (!target) return false
  const uri = itemUrl(item)
  if (!uri) return false
  const host = urlHost(uri)
  return host === target || host.endsWith(`.${target}`) || target.endsWith(`.${host}`)
}

async function deleteItem(name) {
  if (!validName(name)) throw new Error('invalid item name')
  if (MOCK) return
  const items = await listItems()
  const existing = items.find((item) => item.name?.toLowerCase() === name.toLowerCase())
  if (existing === undefined) throw new Error(`item "${name}" not found`)
  const result = await runBw(['delete', 'item', existing.id])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout).trim().slice(0, 500))
  audit({ event: 'item.delete', name })
  backgroundSync()
}

async function readItemValue(name) {
  if (MOCK) return `MOCK-SECRET-FOR-${name}`
  const items = await listItems()
  const item = items.find((candidate) => candidate.name?.toLowerCase() === name.toLowerCase())
  if (item === undefined) throw new Error(`item "${name}" not found in the vault`)
  if (typeof item.login?.password === 'string' && item.login.password.length > 0) return item.login.password
  if (typeof item.notes === 'string' && item.notes.length > 0) return item.notes
  const field = (item.fields ?? []).find((candidate) => typeof candidate.value === 'string' && candidate.value.length > 0)
  if (field !== undefined) return field.value
  throw new Error(`item "${name}" has no password, note, or custom field to return`)
}

// ---- local secret import (runs after unlock) ----
function readCredentialsRefs() {
  const file = path.join(process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh-home'), '.credentials.yaml')
  if (!fs.existsSync(file)) return {}
  const refs = {}
  let inRefs = false
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (/^refs:\s*$/.test(line)) {
      inRefs = true
      continue
    }
    if (inRefs && /^\S/.test(line)) inRefs = false
    if (inRefs) {
      const match = line.match(/^\s+([A-Za-z0-9_-]+):\s*(.+?)\s*$/)
      if (match) refs[match[1]] = match[2]
    }
  }
  return refs
}

function readDotEnv() {
  const file = path.join(process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh-home'), '.env')
  if (!fs.existsSync(file)) return {}
  const out = {}
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z0-9_]+)=(.*)$/)
    if (match) out[match[1]] = match[2]
  }
  return out
}

async function importLocalSecrets() {
  if (!state.unlocked) return { created: [], skipped: ['vault locked'] }
  const created = []
  const skipped = []
  const candidates = []
  const refs = readCredentialsRefs()
  const env = readDotEnv()
  if (typeof refs.DEEPSEEK_API_KEY === 'string' && refs.DEEPSEEK_API_KEY.startsWith('tvly-')) {
    candidates.push({ name: 'tavily-api-key', value: refs.DEEPSEEK_API_KEY, notes: 'Tavily API key (imported from DSH credentials)' })
  }
  if (typeof env.DEEPSEEK_API_KEY === 'string' && env.DEEPSEEK_API_KEY.startsWith('sk-') && env.DEEPSEEK_API_KEY.length > 20) {
    candidates.push({ name: 'deepseek-api-key', value: env.DEEPSEEK_API_KEY, notes: 'DeepSeek API key (imported from DSH .env)' })
  }
  const tokenFile = path.join(process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh-home'), 'mcp-auth', 'mcp-token.json')
  if (fs.existsSync(tokenFile)) {
    try {
      const token = JSON.parse(fs.readFileSync(tokenFile, 'utf8'))
      if (token.access_token) {
        candidates.push({ name: 'mcp-oauth-token', value: undefined, notes: JSON.stringify(token), notesOnly: true })
      }
    } catch {
      skipped.push('mcp token file unreadable')
    }
  }
  if (candidates.length === 0) return { created, skipped }
  let existingNames = []
  try {
    existingNames = (await listItems()).map((item) => item.name.toLowerCase())
  } catch (error) {
    return { created, skipped: [`cannot list vault items: ${String(error.message ?? error)}`] }
  }
  for (const candidate of candidates) {
    if (existingNames.includes(candidate.name.toLowerCase())) {
      skipped.push(`${candidate.name} (already exists)`)
      continue
    }
    try {
      await saveItem(candidate.name, candidate.value, candidate.notes)
      created.push(candidate.name)
    } catch (error) {
      skipped.push(`${candidate.name}: ${String(error.message ?? error)}`)
    }
  }
  if (created.length > 0) audit({ event: 'import.local', created })
  return { created, skipped }
}

// ---- grants ----
function grantActive(grant) {
  if (grant.revokedAt) return false
  const now = Date.now()
  if (grant.expiresAt !== null && grant.expiresAt !== undefined && grant.expiresAt <= now) return false
  if (grant.maxReads !== null && grant.maxReads !== undefined && (grant.reads ?? 0) >= grant.maxReads) return false
  return true
}

function validGrant(agent, name) {
  return grants.find((grant) => grant.agent === agent && grant.name === name && grantActive(grant))
}

function findGrant(agent, name) {
  return grants.find((grant) => grant.agent === agent && grant.name === name)
}

function addGrant(agent, name, mode, ttlMs, maxReads = null) {
  grants = grants.filter((grant) => !(grant.agent === agent && grant.name === name))
  grants.push({
    agent,
    name,
    mode,
    expiresAt: ttlMs === undefined || ttlMs === null ? null : Date.now() + ttlMs,
    createdAt: new Date().toISOString(),
    reads: 0,
    maxReads: Number.isInteger(maxReads) && maxReads > 0 ? maxReads : null,
    revokedAt: null,
  })
  saveGrants()
  return findGrant(agent, name)
}

function extendGrant(agent, name, seconds) {
  const grant = findGrant(agent, name)
  if (grant === undefined) return undefined
  const base = grant.expiresAt !== null && grant.expiresAt !== undefined && grant.expiresAt > Date.now() ? grant.expiresAt : Date.now()
  grant.expiresAt = base + Number(seconds) * 1000
  grant.revokedAt = null
  saveGrants()
  audit({ event: 'grant.extend', agent, name, seconds: Number(seconds) })
  return grant
}

function setGrantExpiry(agent, name, expiresAt) {
  const grant = findGrant(agent, name)
  if (grant === undefined) return undefined
  grant.expiresAt = Number.isFinite(expiresAt) ? expiresAt : null
  grant.revokedAt = null
  saveGrants()
  audit({ event: 'grant.set-expiry', agent, name, expiresAt: grant.expiresAt })
  return grant
}

function revokeGrant(agent, name) {
  const grant = findGrant(agent, name)
  if (grant === undefined) return undefined
  grant.revokedAt = new Date().toISOString()
  saveGrants()
  audit({ event: 'grant.revoke', agent, name })
  return grant
}

function restoreGrant(agent, name) {
  const grant = findGrant(agent, name)
  if (grant === undefined) return undefined
  grant.revokedAt = null
  if (grant.expiresAt !== null && grant.expiresAt !== undefined && grant.expiresAt <= Date.now()) {
    grant.expiresAt = null
  }
  grant.reads = 0
  saveGrants()
  audit({ event: 'grant.restore', agent, name })
  return grant
}

function deleteGrant(agent, name) {
  grants = grants.filter((grant) => !(grant.agent === agent && grant.name === name))
  saveGrants()
  audit({ event: 'grant.delete', agent, name })
}

// ---- HTTP helpers ----
function json(res, code, payload) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(payload))
}
function html(res, body) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(body)
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
      if (data.length > 2_000_000) req.destroy()
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

function wantsJson(req) {
  return req.headers['x-broker-json'] === '1' || String(req.headers.accept ?? '').includes('application/json')
}

function form(data) {
  return new URLSearchParams(data)
}

async function parseBody(req) {
  const raw = await readBody(req)
  if (String(req.headers['content-type'] ?? '').includes('application/json')) {
    try {
      return JSON.parse(raw)
    } catch {
      return {}
    }
  }
  return Object.fromEntries(new URLSearchParams(raw))
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

function adminCookieValue() {
  return crypto.createHmac('sha256', SESSION_SECRET).update('admin-session').digest('base64url')
}

function cookies(req) {
  const out = {}
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    const index = part.indexOf('=')
    if (index > 0) out[part.slice(0, index).trim()] = part.slice(index + 1).trim()
  }
  return out
}

function isAdmin(req) {
  if (!AUTH_REQUIRED) return true
  const value = cookies(req).broker_admin
  return typeof value === 'string' && value === adminCookieValue()
}

function loginPage(message) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>Secrets Broker 登录</title>
<style>body{font-family:system-ui;max-width:420px;margin:80px auto;padding:0 16px;background:#0e1119;color:#e7ebf3}input{padding:7px;width:100%;background:#0b0f17;border:1px solid #263041;color:#e7ebf3;border-radius:8px}button{margin-top:10px;padding:8px 14px;border-radius:8px;border:1px solid #263041;background:#5b8cff;color:#fff;cursor:pointer;width:100%}a.btn{display:block;text-align:center;margin-top:10px;padding:8px;border:1px solid #263041;border-radius:8px;color:#e7ebf3;text-decoration:none;background:#1d2635}code{background:#0b0f17;padding:1px 4px}.muted{color:#93a0b5;font-size:12px}</style></head><body>
<h2>Secrets Broker</h2>${message ? `<p style="color:#ff9b9b">${esc(message)}</p>` : ''}
${OIDC_ENABLED ? '<a class="btn" href="/oidc/login">使用 OIDC / Passkey 登录</a>' : ''}
<form method="post" action="/login"><label class="muted">管理密码：</label><input type="password" name="password" autocomplete="current-password" required>${config.profile?.totpEnabled ? '<label class="muted">两步验证码：</label><input name="code" inputmode="numeric" placeholder="6 位验证码" autocomplete="one-time-code" required>' : ''}<button>用管理密码登录</button></form>
<p class="muted">Agent API（<code>/secret</code>）使用各自的 Bearer token，不需要此登录。</p>
</body></html>`
}

// ---- OIDC (xid) admin login ----
let oidcDiscoveryCache
async function oidcDiscovery() {
  if (oidcDiscoveryCache !== undefined) return oidcDiscoveryCache
  let discovered = {}
  try {
    const response = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`)
    if (response.ok) discovered = await response.json()
  } catch {}
  const overrides = config.oidc ?? {}
  const metadata = {
    ...discovered,
    authorization_endpoint: overrides.authorizationEndpoint || discovered.authorization_endpoint || `${OIDC_ISSUER}/authorize`,
    token_endpoint: overrides.tokenEndpoint || discovered.token_endpoint || `${OIDC_ISSUER}/token`,
    userinfo_endpoint: overrides.userinfoEndpoint || discovered.userinfo_endpoint || `${OIDC_ISSUER}/userinfo`,
    jwks_uri: overrides.jwksUri || discovered.jwks_uri || `${OIDC_ISSUER}/jwks`,
  }
  if (!metadata.authorization_endpoint || !metadata.token_endpoint) throw new Error('OIDC endpoints are not configured')
  oidcDiscoveryCache = metadata
  return oidcDiscoveryCache
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url')
}

function randomUrlSafe(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url')
}

async function verifyIdToken(idToken, expectedNonce) {
  const discovery = await oidcDiscovery()
  const parts = String(idToken).split('.')
  if (parts.length !== 3) throw new Error('malformed id_token')
  const [headerB64, payloadB64, signatureB64] = parts
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'))
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'))
  if (header.alg !== 'ES256') throw new Error(`unsupported id_token alg ${header.alg}`)
  const jwks = await (await fetch(discovery.jwks_uri)).json()
  const jwk = (jwks.keys ?? []).find((key) => key.kid === header.kid) ?? (jwks.keys ?? [])[0]
  if (jwk === undefined) throw new Error('no JWKS key for id_token')
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' })
  const valid = crypto.verify(
    'sha256',
    Buffer.from(`${headerB64}.${payloadB64}`),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signatureB64, 'base64url'),
  )
  if (!valid) throw new Error('id_token signature invalid')
  const now = Math.floor(Date.now() / 1000)
  if (typeof payload.exp === 'number' && payload.exp < now) throw new Error('id_token expired')
  if (payload.aud !== OIDC_CLIENT_ID && !(Array.isArray(payload.aud) && payload.aud.includes(OIDC_CLIENT_ID))) {
    throw new Error('id_token audience mismatch')
  }
  if (payload.iss !== OIDC_ISSUER) throw new Error('id_token issuer mismatch')
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) throw new Error('id_token nonce mismatch')
  return payload
}
function dashboardShell() {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title>
<style>
:root{--bg:#0e1119;--card:#161b26;--line:#263041;--text:#e7ebf3;--muted:#93a0b5;--accent:#5b8cff;--ok:#2ecc71;--warn:#f5a623;--danger:#ff5c5c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 18px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:22px}
h1{font-size:20px;margin:0}.badge{padding:2px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.badge.on{color:var(--ok);border-color:#1f5134;background:#10241a}.badge.off{color:var(--warn);border-color:#513f1f;background:#241d10}
.sub{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px}
.card h2{font-size:15px;margin:0 0 12px;color:#cdd6e6;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}th{color:var(--muted);font-weight:500;text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid #1d2532;vertical-align:middle}tr:last-child td{border-bottom:0}
code{background:#0b0f17;border:1px solid #1d2532;padding:1px 6px;border-radius:6px;font-size:12px}
button{cursor:pointer;border:1px solid var(--line);background:#1d2635;color:var(--text);border-radius:8px;padding:5px 10px;font-size:12px;margin:2px}
button:hover{background:#243049}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.primary:hover{filter:brightness(1.1)}
button.danger{color:#ffb4b4;border-color:#4a2222;background:#2a1616}
input,select{background:#0b0f17;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 9px;font-size:13px;margin:2px}
form.inline{display:inline}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.hint{color:var(--muted);font-size:12px;margin-top:8px}.empty{color:var(--muted);font-size:13px}
.chk{display:inline-flex;align-items:center;gap:6px;margin:4px 10px 4px 0;font-size:13px}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);align-items:center;justify-content:center;z-index:50;padding:18px}
.modal-card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;max-width:560px;width:100%;max-height:85vh;overflow:auto}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);background:#1d2635;border:1px solid var(--line);padding:10px 16px;border-radius:10px;opacity:0;transition:.2s;z-index:60;pointer-events:none;max-width:90vw}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}.toast.err{border-color:#5a2626;color:#ffb4b4}
</style></head><body><div class="wrap">
<header><h1>Secrets Broker</h1><span id="status-badge" class="badge">加载中</span><span class="sub">Vault: <code id="vault-url">…</code></span><span id="auth-actions"></span></header>
<div class="card"><h2>待批准请求</h2><div id="pending-box" class="empty">加载中…</div></div>
<div class="card"><h2>授权与到期</h2>
<div class="row"><label class="hint">排序 <select id="g-sort"><option value="expiry">到期时间</option><option value="created">授权时间</option><option value="agent">Agent</option><option value="name">密钥名</option></select></label>
<label class="hint">分组 <select id="g-group"><option value="none">不分组</option><option value="agent">按 agent</option></select></label>
<button data-act="refresh">刷新</button></div>
<div id="grants-box" class="empty">加载中…</div></div>
<div class="card"><h2>密钥条目</h2>
<div class="row"><input id="item-search" placeholder="搜索名称或网址…" style="width:220px"><select id="group-filter"><option value="">全部分组</option></select><button data-act="sync-items">同步服务器</button>
<form id="item-form" class="inline"><input name="name" placeholder="条目名" required><input name="url" placeholder="网址（可选，如 https://example.com）"><input name="group" placeholder="分组（可选）"><input type="password" name="value" placeholder="密钥值（留空不改）"><input name="notes" placeholder="备注"><button class="primary">新增 / 更新</button></form></div>
<div id="items-box" class="empty">加载中…</div></div>
<div class="card"><h2>Agents</h2>
<div class="row"><form id="agent-form" class="inline"><input name="name" placeholder="新 agent 名（如 codex-office）" required><button class="primary">添加</button></form></div>
<div id="agents-box" class="empty">加载中…</div></div>
<div class="card"><h2>导入与说明</h2><button data-act="import">从本机导入明文密钥</button>
<div class="hint">Agent API：<code>GET /secret?name=条目名</code>（Bearer token）· CLI：<code>node wh.mjs get 条目名</code> · 注入进程：<code>node wh.mjs run --var NAME=条目名 -- 命令</code><br>条目名支持 <code>项目/环境/名称</code> 分类；agent 可读条目可在 Agents 里逐条勾选。</div></div>
<section id="view-profile" class="view"><div class="card"><h2>个人资料</h2>
<form id="profile-form"><div class="row"><input name="name" placeholder="用户名"><input name="email" placeholder="邮箱"><input name="phone" placeholder="手机号"></div>
<div class="row"><input name="avatarUrl" placeholder="头像 URL" style="width:100%"></div>
<button class="primary" data-act="profile-save">保存资料</button></form><div class="hint" id="profile-info"></div></div>
<div class="card"><h2>两步验证（TOTP）</h2><div class="hint" id="totp-info"></div><div class="row"><button data-act="totp-setup">生成 2FA 密钥</button><button class="danger" data-act="totp-disable">关闭 2FA</button></div><div id="totp-setup-box"></div></div>
<div class="card"><h2>账号绑定</h2><div class="hint" id="oidc-bind-info"></div><div class="row" style="margin-top:8px"><a class="btn" id="oidc-bind-link" href="/oidc/login?bind=1" style="display:none;padding:6px 10px;border:1px solid var(--line);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px">绑定 OIDC 账号</a><button class="danger" data-act="oidc-unbind">解绑 OIDC</button></div></div></section>
<div id="modal" class="modal"><div class="modal-card"><div class="row" style="justify-content:space-between"><b id="modal-title"></b><button data-act="modal-close">关闭</button></div><div id="modal-body"></div></div></div>
<div id="toast" class="toast"></div>
<script>
const $=function(id){return document.getElementById(id)};
let state={items:[],agents:[],grants:[],pending:[],status:null,shareItem:null};
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]})}
function toast(msg,err){var t=$('toast');t.textContent=msg;t.className='toast show'+(err?' err':'');clearTimeout(t._timer);t._timer=setTimeout(function(){t.className='toast'},3200)}
async function api(path,opts){const r=await fetch(path,opts||{});const j=await r.json().catch(function(){return {}});if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
function post(path,data){return api(path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','x-broker-json':'1'},body:new URLSearchParams(data)})}
function fmt(ms){return ms?new Date(ms).toLocaleString('zh-CN',{hour12:false}):'永久'}
function active(g){if(g.revokedAt)return false;if(g.expiresAt&&g.expiresAt<=Date.now())return false;if(g.maxReads&&(g.reads||0)>=g.maxReads)return false;return true}
function openModal(title,html){$('modal-title').textContent=title;$('modal-body').innerHTML=html;$('modal').style.display='flex'}
function closeModal(){$('modal').style.display='none';$('modal-body').innerHTML=''}
async function loadAll(){
  try{
    const results=await Promise.all([api('/api/status'),api('/api/items').catch(function(e){return {error:e.message}}),api('/api/agents'),api('/api/pending'),api('/api/grants-list')]);
    state.status=results[0];state.items=results[1].items||[];state.agents=results[2].agents||[];state.pending=results[3].requests||[];state.grants=results[4].grants||[];
    renderStatus();renderPending();renderItems();renderAgents();renderGrants();
  }catch(e){toast('加载失败：'+e.message,true)}
}
function renderStatus(){var unlocked=state.status&&state.status.unlocked;var b=$('status-badge');b.textContent=unlocked?'已解锁':'未解锁';b.className='badge '+(unlocked?'on':'off');
  var a=$('auth-actions');
  if(unlocked){a.innerHTML='<button data-act="lock">锁定</button><button data-act="logout">退出</button>'}
  else{a.innerHTML='<form id="unlock-form" class="inline"><input type="password" name="password" placeholder="NodeWarden 主密码" required><button class="primary">解锁</button></form><button data-act="logout">退出</button>'}
}
function renderPending(){var box=$('pending-box');var rows=state.pending;if(!rows.length){box.innerHTML='<div class="empty">暂无待批准请求</div>';return}
  box.innerHTML='<table><tr><th>Agent</th><th>条目</th><th>时间</th><th>授权</th></tr>'+rows.map(function(r){var btns=[['once','仅本次'],['1h','1 小时'],['24h','24 小时'],['7d','7 天'],['always','永久']].map(function(d){return '<button class="primary" data-act="decide" data-id="'+esc(r.id)+'" data-decision="'+d[0]+'">'+d[1]+'</button>'}).join('');return '<tr><td>'+esc(r.agent)+'</td><td><code>'+esc(r.name)+'</code></td><td>'+esc(new Date(r.createdAt).toLocaleTimeString())+'</td><td>'+btns+'<button class="danger" data-act="decide" data-id="'+esc(r.id)+'" data-decision="deny">拒绝</button></td></tr>'}).join('')+'</table>'}
function renderItems(){var box=$('items-box');var q=($('item-search').value||'').toLowerCase();var gf=$('group-filter')?$('group-filter').value:'';
  var items=state.items.filter(function(i){var hay=(String(i.name)+' '+String(i.url||'')).toLowerCase();return (!q||hay.indexOf(q)>=0)&&(!gf||(i.group||'')===gf)});
  if(state.status&&!state.status.unlocked){box.innerHTML='<div class="empty">解锁后显示条目</div>';return}
  if(!items.length){box.innerHTML='<div class="empty">'+(q||gf?'没有匹配的条目':'暂无条目')+'</div>';return}
  box.innerHTML='<table><tr><th>名称</th><th>网址</th><th>分组</th><th>类型</th><th>操作</th></tr>'+items.map(function(i){return '<tr><td><code>'+esc(i.name)+'</code></td><td class="hint">'+esc(i.url||'')+'</td><td class="hint">'+esc(i.group||'')+'</td><td>'+esc(i.type)+'</td><td><button data-act="share" data-name="'+esc(i.name)+'">分享</button><button data-act="edit-item" data-name="'+esc(i.name)+'">编辑</button><button class="danger" data-act="item-delete" data-name="'+esc(i.name)+'">删除</button></td></tr>'}).join('')+'</table>';
  var gsel=$('group-filter');if(gsel){var current=gsel.value;var groups=Array.from(new Set(state.items.map(function(i){return i.group||''}))).filter(Boolean).sort();gsel.innerHTML='<option value="">全部分组</option>'+groups.map(function(g){return '<option value="'+esc(g)+'">'+esc(g)+'</option>'}).join('');gsel.value=current}}
function renderAgents(){var box=$('agents-box');if(!state.agents.length){box.innerHTML='<div class="empty">暂无 agent</div>';return}
  box.innerHTML='<table><tr><th>Agent</th><th>Token</th><th>可读条目</th><th>操作</th></tr>'+state.agents.map(function(a){var allow=a.allow&&a.allow.length?a.allow.join(', '):'全部';return '<tr><td>'+esc(a.name)+'</td><td><code>'+esc(a.tokenPreview||'')+'</code> <button data-act="copy" data-agent="'+esc(a.name)+'">复制</button></td><td class="hint">'+esc(allow)+'</td><td><button data-act="access" data-agent="'+esc(a.name)+'">设置可读</button><button data-act="agent-write" data-agent="'+esc(a.name)+'" data-allow="'+((state.agentWrite&&state.agentWrite[a.name])?'0':'1')+'">写入:'+((state.agentWrite&&state.agentWrite[a.name])?'开':'关')+'</button><button data-act="rotate" data-agent="'+esc(a.name)+'">轮换</button><button class="danger" data-act="agent-delete" data-agent="'+esc(a.name)+'">删除</button></td></tr>'}).join('')+'</table>'}
function renderGrants(){var box=$('grants-box');var rows=state.grants;if(!rows.length){box.innerHTML='<div class="empty">暂无授权</div>';return}
  var sort=$('g-sort').value,group=$('g-group').value;var list=rows.slice();var key=sort==='created'?function(g){return g.createdAt?Date.parse(g.createdAt):0}:sort==='agent'?function(g){return String(g.agent).toLowerCase()}:sort==='name'?function(g){return String(g.name).toLowerCase()}:function(g){return g.expiresAt==null?Number.MAX_SAFE_INTEGER:g.expiresAt};
  list.sort(function(x,y){var a=key(x),b=key(y);return a<b?-1:a>b?1:0});
  function row(g){var st=g.revokedAt?'<span style="color:#ff9b9b">已撤销</span>':(g.expiresAt&&g.expiresAt<=Date.now())?'<span style="color:#f5a623">已过期</span>':(g.maxReads&&(g.reads||0)>=g.maxReads)?'<span style="color:#f5a623">次数用尽</span>':'<span style="color:#6ee7a8">生效中</span>';
    var btn=function(act,label,extra,cls){return '<button data-act="'+act+'" data-agent="'+esc(g.agent)+'" data-name="'+esc(g.name)+'"'+(extra||'')+(cls?' class="'+cls+'"':'')+'>'+label+'</button>'};
    return '<tr><td>'+esc(g.agent)+'</td><td><code>'+esc(g.name)+'</code></td><td>'+st+'</td><td>'+fmt(g.expiresAt)+'</td><td>'+(g.reads||0)+'/'+(g.maxReads||'∞')+'</td><td>'+btn('g-extend','+1h',' data-s="3600"')+btn('g-extend','+24h',' data-s="86400"')+btn('g-extend','+7d',' data-s="604800"')+btn('g-set','改期')+(g.revokedAt?btn('g-restore','恢复'):btn('g-revoke','撤销','','danger'))+btn('g-delete','删除','','danger')+'</td></tr>'}
  var head='<table><tr><th>Agent</th><th>条目</th><th>状态</th><th>到期</th><th>读取</th><th>操作</th></tr>';
  if(group==='agent'){var groups={};list.forEach(function(g){(groups[g.agent]=groups[g.agent]||[]).push(g)});box.innerHTML=Object.keys(groups).sort().map(function(n){return '<h3 style="font-size:13px;color:#9aa3b8;margin:10px 0 4px">'+esc(n)+'</h3>'+head+groups[n].map(row).join('')+'</table>'}).join('');return}
  box.innerHTML=head+list.map(row).join('')+'</table>'}
function openShare(name){state.shareItem=name;var agents=state.agents.map(function(a){return '<label class="chk"><input type="checkbox" class="share-agent" value="'+esc(a.name)+'">'+esc(a.name)+'</label>'}).join('');openModal('分享「'+name+'」','<div>'+agents+'</div><div class="row" style="margin-top:10px"><label class="hint">有效时间 <select id="share-ttl"><option value="1">1 小时</option><option value="24">24 小时</option><option value="168">7 天</option><option value="0">永久</option></select></label><label class="hint">可读次数 <input id="share-reads" type="number" min="1" placeholder="不限" style="width:90px"></label><button class="primary" data-act="share-go">分享</button></div>')}
function openAccess(agent){var a=state.agents.find(function(x){return x.name===agent});if(!a)return;if(!state.items.length){toast('解锁并加载条目后再设置',true);return}
  var all=(a.allow||[]).length===0;var boxes=state.items.map(function(i){var checked=all||(a.allow||[]).indexOf(i.name)>=0;return '<label class="chk"><input type="checkbox" class="access-item" value="'+esc(i.name)+'"'+(checked?' checked':'')+'>'+esc(i.name)+'</label>'}).join('');
  openModal('「'+agent+'」可读条目','<label class="chk"><input type="checkbox" id="access-all"'+(all?' checked':'')+'> 全部条目</label><div>'+boxes+'</div><div class="row"><button class="primary" data-act="access-save" data-agent="'+esc(agent)+'">保存</button></div>')}
async function doShare(){var agents=[].slice.call(document.querySelectorAll('.share-agent:checked')).map(function(x){return x.value});if(!agents.length){toast('至少选一个 agent',true);return}var ttl=Number($('share-ttl').value);var reads=Number($('share-reads').value||0);for(var i=0;i<agents.length;i++){await post('/api/grants/create',{agent:agents[i],name:state.shareItem,ttlHours:ttl,maxReads:reads})}toast('已分享给 '+agents.join(', '));closeModal();loadAll()}
async function doAccess(agent){var all=$('access-all').checked;var names=all?'':[].slice.call(document.querySelectorAll('.access-item:checked')).map(function(x){return x.value}).join(',');await post('/api/agents/access',{name:agent,allow:names});toast('已保存');closeModal();loadAll()}
document.addEventListener('submit',async function(e){var f=e.target;try{
  if(f.id==='unlock-form'){e.preventDefault();toast('解锁中…');var r=await post('/api/unlock',{password:f.password.value});f.password.value='';toast(r.ok?'已解锁':'解锁失败');await loadAll()}
  else if(f.id==='item-form'){e.preventDefault();var d=new FormData(f);var body={name:d.get('name'),value:d.get('value')||'',notes:d.get('notes')||''};await post('/api/items/save',body);f.reset();toast('已保存');await loadAll()}
  else if(f.id==='agent-form'){e.preventDefault();await post('/api/agents/add',{name:f.name.value});f.reset();toast('已添加');await loadAll()}
  else if(f.id==='item-edit-form'){e.preventDefault();var ed=new FormData(f);await post('/api/items/save',{name:ed.get('name'),url:ed.get('url')||'',group:ed.get('group')||'',value:ed.get('value')||'',notes:ed.get('notes')||''});toast('已更新');closeModal();await loadAll()}
}catch(err){toast(err.message,true)}});
document.addEventListener('click',async function(e){var b=e.target.closest('[data-act]');if(!b)return;var act=b.getAttribute('data-act');
  try{
    if(act==='refresh'){await loadAll();toast('已刷新')}
    else if(act==='lock'){await post('/api/lock',{});await loadAll();toast('已锁定')}
    else if(act==='logout'){await post('/api/logout',{});location.href='/login'}
    else if(act==='decide'){await post('/api/requests/'+encodeURIComponent(b.getAttribute('data-id'))+'/decide',{decision:b.getAttribute('data-decision')});await loadAll()}
    else if(act==='share'){openShare(b.getAttribute('data-name'))}
    else if(act==='edit-item'){var it=state.items.find(function(x){return x.name===b.getAttribute('data-name')});if(it)openModal('编辑「'+it.name+'」','<form id="item-edit-form"><input type="hidden" name="name" value="'+esc(it.name)+'"><label class="hint">网址<input name="url" value="'+esc(it.url||'')+'" style="width:100%"></label><label class="hint">分组<input name="group" value="'+esc(it.group||'')+'" style="width:100%"></label><label class="hint">新密钥值（留空不改）<input type="password" name="value" style="width:100%"></label><label class="hint">备注<input name="notes" style="width:100%"></label><button class="primary">保存</button></form>')}
    else if(act==='share-go'){await doShare()}
    else if(act==='item-delete'){if(!confirm('删除条目「'+b.getAttribute('data-name')+'」？'))return;await post('/api/items/delete',{name:b.getAttribute('data-name')});await loadAll();toast('已删除')}
    else if(act==='access'){openAccess(b.getAttribute('data-agent'))}
    else if(act==='access-save'){await doAccess(b.getAttribute('data-agent'))}
    else if(act==='rotate'){if(!confirm('轮换 agent「'+b.getAttribute('data-agent')+'」的 token？'))return;await post('/api/agents/rotate',{name:b.getAttribute('data-agent')});toast('已轮换 token，点“复制”获取新值');await loadAll()}
    else if(act==='agent-delete'){if(!confirm('删除 agent「'+b.getAttribute('data-agent')+'」及其授权？'))return;await post('/api/agents/delete',{name:b.getAttribute('data-agent')});await loadAll()}
    else if(act==='copy'){try{var t=await post('/api/agents/token',{name:b.getAttribute('data-agent')});await navigator.clipboard.writeText(t.token);toast('已复制到剪贴板')}catch(err){toast('复制失败',true)}}
    else if(act==='g-extend'){await post('/api/grants/extend',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name'),seconds:b.getAttribute('data-s')});await loadAll()}
    else if(act==='g-set'){var v=prompt('新的到期时间（YYYY-MM-DD HH:MM，留空=永久）','');if(v===null)return;var iso='';if(v.trim()!==''){var dt=new Date(v.trim().replace(' ','T'));if(isNaN(dt.getTime())){toast('时间格式不对',true);return}iso=dt.toISOString()}await post('/api/grants/set-expiry',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name'),expiresAt:iso});await loadAll()}
    else if(act==='g-revoke'){await post('/api/grants/revoke',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='g-restore'){await post('/api/grants/restore',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='g-delete'){if(!confirm('删除这条授权记录？'))return;await post('/api/grants/delete',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='import'){var r=await post('/api/import',{});toast('导入完成：新增 '+(r.created||[]).length+'，跳过 '+(r.skipped||[]).length);await loadAll()}
    else if(act==='sync-items'){toast('正在从 NodeWarden 同步…');var r=await api('/api/items?sync=1');state.items=r.items||[];renderItems();toast('已同步')}
    else if(act==='modal-close'){closeModal()}
  }catch(err){toast(err.message,true)}});
$('item-search').addEventListener('input',renderItems);
if($('group-filter'))$('group-filter').addEventListener('change',renderItems);
$('g-sort').addEventListener('change',renderGrants);
$('g-group').addEventListener('change',renderGrants);
loadAll();
setInterval(function(){if(document.visibilityState==='visible')loadAll()},12000);
</script>
</div></body></html>`
}

function dashboardShellV2() {
  return `<!doctype html><html lang="zh" data-theme="auto"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title>
<style>
:root{--bg:#f5f7fb;--card:#ffffff;--line:#d9e0ea;--text:#16202f;--muted:#5d6a7c;--accent:#3b6ef5;--ok:#1f9d55;--warn:#b7791f;--danger:#c0392b;--btn:#eef1f6;--code:#eef1f6;--hover:#e6ebf3}
html[data-theme="dark"]{--bg:#0e1119;--card:#161b26;--line:#263041;--text:#e7ebf3;--muted:#93a0b5;--accent:#5b8cff;--ok:#2ecc71;--warn:#f5a623;--danger:#ff5c5c;--btn:#1d2635;--code:#0b0f17;--hover:#243049}
@media (prefers-color-scheme: dark){html[data-theme="auto"]{--bg:#0e1119;--card:#161b26;--line:#263041;--text:#e7ebf3;--muted:#93a0b5;--accent:#5b8cff;--ok:#2ecc71;--warn:#f5a623;--danger:#ff5c5c;--btn:#1d2635;--code:#0b0f17;--hover:#243049}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;transition:background .15s,color .15s}
.wrap{max-width:1120px;margin:0 auto;padding:22px 18px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:19px;margin:0}.badge{padding:2px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.badge.on{color:var(--ok);border-color:var(--ok)}.badge.off{color:var(--warn);border-color:var(--warn)}
nav{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto}
nav a{padding:6px 12px;border-radius:9px;color:var(--muted);text-decoration:none;font-size:13px}
nav a:hover{background:var(--btn);color:var(--text)}nav a.active{background:var(--accent);color:#fff}
.view{display:none}.view.active{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;margin:0 0 10px;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}th{color:var(--muted);font-weight:500;text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:middle}tr:last-child td{border-bottom:0}
code{background:var(--code);border:1px solid var(--line);padding:1px 6px;border-radius:6px;font-size:12px}
button{cursor:pointer;border:1px solid var(--line);background:var(--btn);color:var(--text);border-radius:8px;padding:5px 10px;font-size:12px;margin:2px}
button:hover{background:var(--hover)}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--danger);border-color:var(--danger);background:transparent}
input,select{background:var(--card);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 9px;font-size:13px;margin:2px}
form.inline{display:inline}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.hint{color:var(--muted);font-size:12px;margin-top:6px}.empty{color:var(--muted);font-size:13px}
.chk{display:inline-flex;align-items:center;gap:6px;margin:4px 10px 4px 0;font-size:13px}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);align-items:center;justify-content:center;z-index:50;padding:18px}
.modal-card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;max-width:600px;width:100%;max-height:85vh;overflow:auto}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);background:var(--card);border:1px solid var(--line);padding:10px 16px;border-radius:10px;opacity:0;transition:.2s;z-index:60;pointer-events:none;max-width:90vw;box-shadow:0 8px 30px rgba(0,0,0,.15)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}.toast.err{border-color:var(--danger);color:var(--danger)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:12px 0}
.kpi{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:linear-gradient(180deg,var(--card),var(--bg))}
.kpi .label{color:var(--muted);font-size:12px}.kpi .value{font-size:24px;font-weight:600;margin-top:2px}
.chart{margin:14px 0;min-height:160px}.chart svg{width:100%;height:180px;display:block}
.top-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-top:6px}
.top-item{font-size:12px}.bar-track{height:7px;background:var(--btn);border-radius:99px;overflow:hidden;margin-top:4px}.bar-fill{height:100%;background:var(--accent);border-radius:99px}
.charts{display:grid;grid-template-columns:minmax(0,2fr) minmax(240px,1fr);gap:12px;margin:8px 0}
@media(max-width:760px){.charts{grid-template-columns:1fr}}
.donut-wrap{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.donut-legend{font-size:12px}.dot{display:inline-block;width:8px;height:8px;border-radius:99px;margin-right:6px}
.recent{font-size:12px}.recent div{padding:4px 0;border-bottom:1px solid var(--line)}.recent div:last-child{border-bottom:0}
</style></head><body><div class="wrap">
<header><h1>Secrets Broker</h1><span id="status-badge" class="badge">加载中</span>
<nav><a href="#/overview">概览</a><a href="#/items">密钥</a><a href="#/agents">Agents</a><a href="#/grants">授权</a><a href="#/logs">日志</a><a href="#/profile">个人</a><a href="#/settings">设置</a></nav>
<span id="auth-actions"></span></header>
<section id="view-overview" class="view active"><div class="card"><h2>实时概览</h2>
<div class="row" id="range-row"><button class="primary" data-act="stats-range" data-range="24h">24 小时</button><button data-act="stats-range" data-range="3d">3 天</button><button data-act="stats-range" data-range="7d">7 天</button><button data-act="stats-range" data-range="30d">30 天</button></div>
<div id="kpis" class="kpis"></div>
<div class="card" style="padding:12px"><div class="row" style="justify-content:space-between;margin:0 0 6px"><b style="font-size:13px">读取趋势</b><span class="hint">每根点可悬停查看数值</span></div><div id="chart-box" class="chart"></div></div>
<div class="charts"><div><h3 style="font-size:13px;color:var(--muted);margin:0 0 8px">条目读取排行</h3><div id="top-box"></div></div><div><h3 style="font-size:13px;color:var(--muted);margin:0 0 8px">Agent 读取占比</h3><div id="donut-box" class="donut-wrap"></div></div></div>
<div class="hint" id="overview-info"></div></div>
<div class="card"><h2>待批准请求</h2><div id="pending-box" class="empty">加载中…</div><div class="hint">点按钮即授权；ntfy 已推送时也可以在手机点链接。</div></div></section>
<section id="view-items" class="view"><div class="card"><h2>密钥条目</h2>
<div class="row"><input id="item-search" placeholder="搜索名称或网址…" style="width:220px"><select id="group-filter"><option value="">全部分组</option></select><button data-act="sync-items">同步服务器</button>
<form id="item-form" class="inline"><input name="name" placeholder="条目名" required><input name="url" placeholder="网址（可选，如 https://example.com）"><input name="group" placeholder="分组（可选）"><input type="password" name="value" placeholder="密钥值（留空不改）"><input name="notes" placeholder="备注"><button class="primary">新增 / 更新</button></form></div>
<div id="items-box" class="empty">加载中…</div></div></section>
<section id="view-agents" class="view"><div class="card"><h2>Agents</h2>
<div class="row"><form id="agent-form" class="inline"><input name="name" placeholder="新 agent 名（如 codex-office）" required><button class="primary">添加</button></form></div>
<div id="agents-box" class="empty">加载中…</div></div></section>
<section id="view-grants" class="view"><div class="card"><h2>授权与到期</h2>
<div class="row"><label class="hint">排序 <select id="g-sort"><option value="expiry">到期时间</option><option value="created">授权时间</option><option value="agent">Agent</option><option value="name">密钥名</option></select></label>
<label class="hint">分组 <select id="g-group"><option value="none">不分组</option><option value="agent">按 agent</option></select></label>
<button data-act="refresh">刷新</button></div><div id="grants-box" class="empty">加载中…</div></div></section>
<section id="view-logs" class="view"><div class="card"><h2>读取 / 授权日志</h2>
<div class="row"><select id="log-agent"><option value="">全部 agent</option></select><input id="log-event" placeholder="事件（如 secret.read）" style="width:180px"><input id="log-name" placeholder="密钥名包含…" style="width:160px"><button data-act="logs-refresh">刷新</button></div>
<div id="logs-box" class="empty">加载中…</div><div class="row" style="margin-top:10px"><button data-act="logs-more">加载更多</button><span id="logs-count" class="hint"></span></div></div></section>
<section id="view-settings" class="view"><div class="card"><h2>外观</h2><label class="hint">主题 <select id="theme-select"><option value="auto">自动（跟随系统）</option><option value="light">白天</option><option value="dark">夜间</option></select></label></div>
<div class="card"><h2>连接设置</h2>
<form id="settings-form">
<label class="hint">公开地址 Public URL<br><input name="publicUrl" placeholder="https://broker.example.com" style="width:100%"></label>
<label class="hint">Vault 地址（NodeWarden/Bitwarden，修改后需重启并重新登录 bw）<br><input name="serverUrl" placeholder="https://vault.example.com" style="width:100%"></label>
<div class="hint">修改后点保存即生效（部分字段重启后生效）。</div>
</form></div>
<div class="card"><h2>OIDC 登录</h2>
<form id="oidc-form">
<label class="hint">Issuer（如 https://auth.example.com）<br><input name="oidcIssuer" style="width:100%"></label>
<label class="hint">Client ID<br><input name="oidcClientId" style="width:100%"></label>
<label class="hint">Client Secret（public client 可留空）<br><input name="oidcClientSecret" type="password" style="width:100%"></label>
<label class="hint">Redirect URI<br><input name="oidcRedirectUri" style="width:100%"></label>
<details style="margin-top:8px"><summary class="hint" style="cursor:pointer">高级设置（端点覆盖 / claim 映射）</summary>
<label class="hint">Authorization Endpoint（留空自动发现）<br><input name="oidcAuthorizationEndpoint" style="width:100%"></label>
<label class="hint">Token Endpoint<br><input name="oidcTokenEndpoint" style="width:100%"></label>
<label class="hint">Userinfo Endpoint<br><input name="oidcUserinfoEndpoint" style="width:100%"></label>
<label class="hint">JWKS URI<br><input name="oidcJwksUri" style="width:100%"></label>
<label class="hint">Scope<br><input name="oidcScope" placeholder="openid profile email" style="width:100%"></label>
<div class="row"><input name="oidcClaimIdentifier" placeholder="identifier claim (sub)" style="width:180px"><input name="oidcClaimName" placeholder="name claim (name)" style="width:180px"><input name="oidcClaimEmail" placeholder="email claim (email)" style="width:180px"><input name="oidcClaimAvatar" placeholder="avatar claim (picture)" style="width:180px"></div>
<div class="hint">端点留空时使用 OIDC Discovery；claim 映射用于把 id_token 字段写入个人资料。</div>
</details>
<button class="primary" data-act="settings-save">保存设置</button>
<button data-act="settings-restart">保存并重启容器</button>
</form>
<div class="hint">OIDC 通过标准 Discovery 自动发现端点；xid/Keycloak/Authentik/Auth0 等都可。</div></div>
<div class="card"><h2>通知</h2>
<label class="hint">ntfy URL（如 https://ntfy.example.com/topic 或 http://172.17.0.1:2586/topic）<br><input id="ntfy-input" style="width:100%"></label>
<div class="row"><button data-act="settings-save">保存设置</button><button data-act="ntfy-test">发送测试通知</button></div>
<div class="hint" id="notify-info"></div></div>
<div class="card"><h2>Telegram 通知</h2><label class="hint">Bot Token<br><input name="telegramToken" type="password" style="width:100%"></label><label class="hint">Chat ID<br><input name="telegramChatId" style="width:100%"></label><div class="row"><button data-act="settings-save">保存设置</button></div><div class="hint" id="telegram-info"></div></div>
<div class="card"><h2>Gotify 通知</h2><label class="hint">Gotify URL<br><input name="gotifyUrl" placeholder="https://gotify.example.com" style="width:100%"></label><label class="hint">App Token<br><input name="gotifyToken" type="password" style="width:100%"></label><div class="row"><button data-act="settings-save">保存设置</button></div><div class="hint" id="gotify-info"></div></div>
<div class="card"><h2>wxpush 微信通知</h2><label class="hint">wxpush URL<br><input name="wxpushUrl" placeholder="https://wxpush.example.com" style="width:100%"></label><label class="hint">API Token<br><input name="wxpushToken" type="password" style="width:100%"></label><div class="row"><button data-act="settings-save">保存设置</button></div><div class="hint" id="wxpush-info"></div></div>
<div class="card"><h2>服务与安全</h2><div class="hint" id="settings-info"></div><div class="hint" id="security-info"></div>
<div class="row" style="margin-top:8px"><button data-act="disable-auto" class="danger">删除自动解锁密码文件</button><button data-act="settings-restart">重启服务</button></div></div></section>
<section id="view-profile" class="view"><div class="card"><h2>个人资料</h2>
<form id="profile-form"><div class="row"><input name="name" placeholder="用户名"><input name="email" placeholder="邮箱"><input name="phone" placeholder="手机号"></div>
<div class="row"><input name="avatarUrl" placeholder="头像 URL" style="width:100%"></div>
<button class="primary" data-act="profile-save">保存资料</button></form><div class="hint" id="profile-info"></div></div>
<div class="card"><h2>两步验证（TOTP）</h2><div class="hint" id="totp-info"></div><div class="row"><button data-act="totp-setup">生成 2FA 密钥</button><button class="danger" data-act="totp-disable">关闭 2FA</button></div><div id="totp-setup-box"></div></div>
<div class="card"><h2>账号绑定</h2><div class="hint" id="oidc-bind-info"></div><div class="row" style="margin-top:8px"><a class="btn" id="oidc-bind-link" href="/oidc/login?bind=1" style="display:none;padding:6px 10px;border:1px solid var(--line);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px">绑定 OIDC 账号</a><button class="danger" data-act="oidc-unbind">解绑 OIDC</button></div></div></section>
<div id="modal" class="modal"><div class="modal-card"><div class="row" style="justify-content:space-between"><b id="modal-title"></b><button data-act="modal-close">关闭</button></div><div id="modal-body"></div></div></div>
<div id="toast" class="toast"></div>
<script data-cfasync="false">
const $=function(id){return document.getElementById(id)};
let state={items:[],agents:[],grants:[],pending:[],status:null,shareItem:null,logs:[],logsTotal:0,logsOffset:0,agentWrite:{}};
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]})}
function toast(msg,err){var t=$('toast');t.textContent=msg;t.className='toast show'+(err?' err':'');clearTimeout(t._timer);t._timer=setTimeout(function(){t.className='toast'},3200)}
async function api(path,opts){const r=await fetch(path,opts||{});const j=await r.json().catch(function(){return {}});if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
function post(path,data){return api(path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','x-broker-json':'1'},body:new URLSearchParams(data||{})})}
function fmt(ms){return ms?new Date(ms).toLocaleString('zh-CN',{hour12:false}):'永久'}
function applyTheme(theme){document.documentElement.setAttribute('data-theme',theme);localStorage.setItem('broker-theme',theme)}
function initTheme(){var t=localStorage.getItem('broker-theme')||'auto';applyTheme(t);if($('theme-select'))$('theme-select').value=t}
function openModal(title,html){$('modal-title').textContent=title;$('modal-body').innerHTML=html;$('modal').style.display='flex'}
function closeModal(){$('modal').style.display='none';$('modal-body').innerHTML=''}
function route(){var name=(location.hash||'#/overview').replace(/^#\\//,'')||'overview';document.querySelectorAll('.view').forEach(function(v){v.classList.toggle('active',v.id==='view-'+name)});document.querySelectorAll('nav a').forEach(function(a){a.classList.toggle('active',a.getAttribute('href')==='#/'+name)});if(name==='logs')loadLogs(true)}
window.addEventListener('hashchange',route);
async function loadAll(){
  try{
    var results=await Promise.all([api('/api/status'),api('/api/items').catch(function(e){return {error:e.message}}),api('/api/agents'),api('/api/pending'),api('/api/grants-list')]);
    state.status=results[0];state.items=results[1].items||[];state.agents=results[2].agents||[];state.pending=results[3].requests||[];state.grants=results[4].grants||[];
    renderStatus();renderPending();renderItems();renderAgents();renderGrants();renderInfo();loadStats(statsRange);loadSettings();loadProfile();
  }catch(e){toast('加载失败：'+e.message,true)}
}
function renderStatus(){var unlocked=state.status&&state.status.unlocked;var b=$('status-badge');b.textContent=unlocked?'已解锁':'未解锁';b.className='badge '+(unlocked?'on':'off');
  var a=$('auth-actions');
  if(unlocked){a.innerHTML='<button data-act="lock">锁定</button><button data-act="logout">退出</button>'}
  else{a.innerHTML='<form id="unlock-form" class="inline"><input type="password" name="password" placeholder="NodeWarden 主密码" required><button class="primary">解锁</button></form><button data-act="logout">退出</button>'}
}
let statsRange='24h';
function renderStats(s){
  var k=$('kpis');if(!k)return;
  var cards=[['读取次数',s.totalReads],['活跃 Agent',s.activeAgents],['待批准',s.pending],['有效授权',s.activeGrants]];
  k.innerHTML=cards.map(function(c){return '<div class="kpi"><div class="label">'+c[0]+'</div><div class="value">'+c[1]+'</div></div>'}).join('');
  var buckets=s.buckets||[];var max=Math.max(1,...buckets.map(function(b){return b.count}));var W=600,H=180,px=38,py=18,iw=W-2*px,ih=H-2*py;var step=buckets.length>1?iw/(buckets.length-1):0;
  var pts=buckets.map(function(b,i){return [px+i*step,H-py-(b.count/max)*ih]});
  function smooth(points){if(points.length<2)return '';var d='M'+points[0][0].toFixed(1)+','+points[0][1].toFixed(1);for(var i=0;i<points.length-1;i++){var p0=points[i-1]||points[i],p1=points[i],p2=points[i+1],p3=points[i+2]||p2;var c1x=p1[0]+(p2[0]-p0[0])/6,c1y=p1[1]+(p2[1]-p0[1])/6;var c2x=p2[0]-(p3[0]-p1[0])/6,c2y=p2[1]-(p3[1]-p1[1])/6;d+=' C'+c1x.toFixed(1)+','+c1y.toFixed(1)+' '+c2x.toFixed(1)+','+c2y.toFixed(1)+' '+p2[0].toFixed(1)+','+p2[1].toFixed(1)}return d}
  var line=smooth(pts);
  var area=line+' L'+(px+(buckets.length-1)*step)+','+(H-py)+' L'+px+','+(H-py)+' Z';
  var grid='';for(var g=0;g<=4;g++){var y=py+ih*g/4;grid+='<line x1="'+px+'" y1="'+y+'" x2="'+(W-px)+'" y2="'+y+'" stroke="currentColor" stroke-opacity=".10"/>';grid+='<text x="4" y="'+(y+3)+'" fill="currentColor" font-size="9" opacity=".5">'+Math.round(max*(4-g)/4)+'</text>'}
  var labelIdx=[];for(var k=0;k<6;k++){var idx=Math.round(k*(buckets.length-1)/5);if(idx>=0&&labelIdx.indexOf(idx)<0)labelIdx.push(idx)}
  var labels=labelIdx.map(function(i){return '<text x="'+pts[i][0].toFixed(1)+'" y="'+(H-4)+'" text-anchor="middle" fill="currentColor" font-size="9" opacity=".55">'+buckets[i].label+'</text>'}).join('');
  var dots=pts.map(function(p,i){return '<circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="2.6" fill="#0e9f8a"/><circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="10" fill="transparent"><title>'+esc(buckets[i].label)+'：'+buckets[i].count+' 次读取</title></circle>'}).join('');
  $('chart-box').innerHTML='<div class="hint" style="margin:0 0 4px"><span style="color:#0e9f8a">●</span> 读取次数</div><svg viewBox="0 0 '+W+' '+H+'"><defs><linearGradient id="gfill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#0e9f8a" stop-opacity=".28"/><stop offset="100%" stop-color="#0e9f8a" stop-opacity=".02"/></linearGradient></defs>'+grid+'<path d="'+area+'" fill="url(#gfill)"/><path d="'+line+'" fill="none" stroke="#0e9f8a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'+dots+labels+'</svg>';
  var top=s.topItems||[];var totalTop=top.reduce(function(sum,t){return sum+t.count},0)||1;
  $('top-box').innerHTML=top.length?'<table><tr><th>#</th><th>条目</th><th>读取</th><th>占比</th></tr>'+top.map(function(t,i){return '<tr><td>'+(i+1)+'</td><td><code>'+esc(t.name)+'</code></td><td>'+t.count+'</td><td>'+Math.round(t.count/totalTop*100)+'%</td></tr>'}).join('')+'</table>':'<div class="hint">该区间暂无读取记录</div>';
  var colors=['#5b8cff','#2ecc71','#f5a623','#ff5c5c','#a78bfa','#14b8a6'];var ag=s.topAgents||[];var agTotal=ag.reduce(function(sum,a){return sum+a.count},0)||1;var cursor=0;var gradientParts=ag.map(function(a,i){var from=cursor;cursor+=a.count/agTotal*360;return colors[i%colors.length]+' '+from.toFixed(1)+'deg '+cursor.toFixed(1)+'deg'});if(!gradientParts.length)gradientParts=['var(--btn) 0deg 360deg'];
  $('donut-box').innerHTML='<div style="width:120px;height:120px;border-radius:50%;background:conic-gradient('+gradientParts.join(',')+');flex:0 0 auto"></div><div class="donut-legend">'+ag.map(function(a,i){return '<div><span class="dot" style="background:'+colors[i%colors.length]+'"></span>'+esc(a.agent)+' · '+a.count+' 次</div>'}).join('')+'</div>';
  var agents=(s.topAgents||[]).map(function(a){return esc(a.agent)+' '+a.count+' 次'}).join(' · ');
  var info=$('overview-info');if(info)info.innerHTML='区间 '+esc(s.range)+' · agent 读取排行：'+(agents||'暂无');
}
async function loadRecent(){try{var r=await api('/api/audit?limit=8');var box=$('recent-box');if(box)box.innerHTML=r.entries.map(function(e){return '<div><b>'+esc(e.event||'')+'</b> '+(e.agent?esc(e.agent):'')+(e.name?' <code>'+esc(e.name)+'</code>':'')+' <span class="hint">'+esc(e.time?new Date(e.time).toLocaleTimeString('zh-CN',{hour12:false}):'')+'</span></div>'}).join('')}catch(e){}}
async function loadStats(range){try{statsRange=range||statsRange;var s=await api('/api/stats?range='+encodeURIComponent(statsRange));renderStats(s);loadRecent();document.querySelectorAll('[data-act="stats-range"]').forEach(function(b){b.className=b.getAttribute('data-range')===statsRange?'primary':''})}catch(e){toast('统计加载失败：'+e.message,true)}}
function settingsField(name){var el=document.querySelector('[name="'+name+'"]');return el?el.value:''}
async function loadProfile(){try{var p=await api('/api/profile');var f=$('profile-form');if(f){f.name.value=p.name||'';f.email.value=p.email||'';f.phone.value=p.phone||'';f.avatarUrl.value=p.avatarUrl||''}var ti=$('totp-info');if(ti)ti.innerHTML=p.totpEnabled?'已启用 TOTP 两步验证':'未启用';var bi=$('oidc-bind-info');if(bi)bi.innerHTML=p.oidcEnabled?(p.oidcBound?'已绑定 <code>'+esc(p.oidcIssuer||'OIDC')+'</code> · 外部标识 <code>'+esc(p.oidcSubMasked||'')+'</code>'+(p.oidcEmail?' · '+esc(p.oidcEmail):''):'未绑定。配置好 OIDC 后，点“绑定 OIDC 账号”完成关联。'):'未配置 OIDC（Settings → OIDC）';var bl=$('oidc-bind-link');if(bl)bl.style.display=p.oidcEnabled?'inline-block':'none';}catch(e){}}
async function saveProfile(){var f=$('profile-form');try{await post('/api/profile',{name:f.name.value,email:f.email.value,phone:f.phone.value,avatarUrl:f.avatarUrl.value});toast('资料已保存');loadProfile()}catch(e){toast(e.message,true)}}
async function loadSettings(){try{var s=await api('/api/settings');state.agentWrite=s.agentWrite||{};document.querySelectorAll('[name="publicUrl"]').forEach(function(el){el.value=s.publicUrl||''});document.querySelectorAll('[name="serverUrl"]').forEach(function(el){el.value=s.serverUrl||''});document.querySelectorAll('[name="oidcIssuer"]').forEach(function(el){el.value=s.oidc.issuer||''});document.querySelectorAll('[name="oidcClientId"]').forEach(function(el){el.value=s.oidc.clientId||''});document.querySelectorAll('[name="oidcRedirectUri"]').forEach(function(el){el.value=s.oidc.redirectUri||''});document.querySelectorAll('[name="oidcAuthorizationEndpoint"]').forEach(function(el){el.value=s.oidc.authorizationEndpoint||''});document.querySelectorAll('[name="oidcTokenEndpoint"]').forEach(function(el){el.value=s.oidc.tokenEndpoint||''});document.querySelectorAll('[name="oidcUserinfoEndpoint"]').forEach(function(el){el.value=s.oidc.userinfoEndpoint||''});document.querySelectorAll('[name="oidcJwksUri"]').forEach(function(el){el.value=s.oidc.jwksUri||''});document.querySelectorAll('[name="oidcScope"]').forEach(function(el){el.value=s.oidc.scope||''});document.querySelectorAll('[name="oidcClaimIdentifier"]').forEach(function(el){el.value=(s.oidc.claims&&s.oidc.claims.identifier)||''});document.querySelectorAll('[name="oidcClaimName"]').forEach(function(el){el.value=(s.oidc.claims&&s.oidc.claims.name)||''});document.querySelectorAll('[name="oidcClaimEmail"]').forEach(function(el){el.value=(s.oidc.claims&&s.oidc.claims.email)||''});document.querySelectorAll('[name="oidcClaimAvatar"]').forEach(function(el){el.value=(s.oidc.claims&&s.oidc.claims.avatar)||''});document.querySelectorAll('[name="telegramChatId"]').forEach(function(el){el.value=s.telegram?String(s.telegram.chatId||''):''});if(s.gotify){document.querySelectorAll('[name="gotifyUrl"]').forEach(function(el){el.value=s.gotify.url||''})}if(s.wxpush){document.querySelectorAll('[name="wxpushUrl"]').forEach(function(el){el.value=s.wxpush.url||''})}if($('ntfy-input'))$('ntfy-input').value=s.ntfyUrl||'';var si=$('settings-info');if(si)si.innerHTML='Vault：<code>'+esc(s.serverUrl||'')+'</code> · 端口 '+esc(s.port)+' · 绑定 '+esc(s.bind)+' · 自动解锁：'+(s.autoUnlock?'已启用':'未启用');var sec=$('security-info');if(sec)sec.innerHTML=s.autoUnlock?'主密码加密保存在容器卷（AES-GCM）。':'未启用自动解锁，重启后需手动输入主密码。';var nt=$('notify-info');if(nt)nt.innerHTML=s.ntfyUrl?'当前回调：<code>'+esc(s.ntfyUrl)+'</code>':'未配置 ntfy。';var tg=$('telegram-info');if(tg)tg.innerHTML=s.telegram&&s.telegram.configured?'Telegram 已配置（Chat '+esc(String(s.telegram.chatId||''))+'）':'未配置 Telegram；保存后需重启生效。';var gf=$('gotify-info');if(gf)gf.innerHTML=s.gotify&&s.gotify.configured?'Gotify 已配置：<code>'+esc(s.gotify.url||'')+'</code>':'未配置 Gotify。';var wx=$('wxpush-info');if(wx)wx.innerHTML=s.wxpush&&s.wxpush.configured?'wxpush 已配置：<code>'+esc(s.wxpush.url||'')+'</code>':'未配置 wxpush。';var si2=$('settings-info');if(si2&&s.encryptionKeyFingerprint)si2.innerHTML+='<br>加密密钥指纹：<code>'+esc(s.encryptionKeyFingerprint)+'</code>（AES-256-GCM）';}catch(e){}}
async function saveSettings(){try{var data={publicUrl:settingsField('publicUrl'),serverUrl:settingsField('serverUrl'),oidcIssuer:settingsField('oidcIssuer'),oidcClientId:settingsField('oidcClientId'),oidcClientSecret:settingsField('oidcClientSecret'),oidcRedirectUri:settingsField('oidcRedirectUri'),oidcScope:settingsField('oidcScope'),oidcAuthorizationEndpoint:settingsField('oidcAuthorizationEndpoint'),oidcTokenEndpoint:settingsField('oidcTokenEndpoint'),oidcUserinfoEndpoint:settingsField('oidcUserinfoEndpoint'),oidcJwksUri:settingsField('oidcJwksUri'),oidcClaimIdentifier:settingsField('oidcClaimIdentifier'),oidcClaimName:settingsField('oidcClaimName'),oidcClaimEmail:settingsField('oidcClaimEmail'),oidcClaimAvatar:settingsField('oidcClaimAvatar'),ntfyUrl:$('ntfy-input')?$('ntfy-input').value:'',telegramToken:settingsField('telegramToken'),telegramChatId:settingsField('telegramChatId'),gotifyUrl:settingsField('gotifyUrl'),gotifyToken:settingsField('gotifyToken'),wxpushUrl:settingsField('wxpushUrl'),wxpushToken:settingsField('wxpushToken')};await post('/api/settings',data);toast('设置已保存');await loadSettings();await loadAll()}catch(e){toast(e.message,true)}}
function renderInfo(){var s=state.status||{};var info=$('overview-info');if(info)info.innerHTML='Vault: <code>'+esc(s.publicUrl||'')+'</code> · OIDC 登录：'+(s.oidc?'已启用':'未启用')+' · ntfy 通知：'+(s.ntfy?'已启用':'未启用')+' · 自动解锁：'+(s.autoUnlock?'已启用':'未启用');
  var si=$('settings-info');if(si)si.innerHTML='公开地址：<code>'+esc(s.publicUrl||'')+'</code><br>OIDC：'+(s.oidc?'已启用':'未启用')+'<br>ntfy：'+(s.ntfy?'已启用':'未启用')+'<br>自动解锁：'+(s.autoUnlock?'已启用':'未启用')+'<br>Agents：'+esc((state.agents||[]).map(function(a){return a.name}).join(', '));
  var sec=$('security-info');if(sec)sec.innerHTML=s.autoUnlock?'主密码明文保存在容器卷的 <code>master-password</code> 文件中（600 权限）。删除后需手动解锁。':'未启用自动解锁，每次重启需要手动输入主密码。';
  var nt=$('notify-info');if(nt)nt.innerHTML=s.ntfy?'已配置 ntfy 推送。':'未配置 ntfy。可在部署 .env 中设置 <code>NTFY_URL</code>。';
  var opts=(state.agents||[]).map(function(a){return '<option value="'+esc(a.name)+'">'+esc(a.name)+'</option>'}).join('');var la=$('log-agent');if(la&&la.options.length<=1)la.innerHTML='<option value="">全部 agent</option>'+opts;
}
function renderPending(){var box=$('pending-box');var rows=state.pending;if(!rows.length){box.innerHTML='<div class="empty">暂无待批准请求</div>';return}
  box.innerHTML='<table><tr><th>Agent</th><th>条目</th><th>时间</th><th>授权</th></tr>'+rows.map(function(r){var btns=[['once','仅本次'],['1h','1 小时'],['24h','24 小时'],['7d','7 天'],['always','永久']].map(function(d){return '<button class="primary" data-act="decide" data-id="'+esc(r.id)+'" data-decision="'+d[0]+'">'+d[1]+'</button>'}).join('');return '<tr><td>'+esc(r.agent)+'</td><td><code>'+esc(r.name)+'</code></td><td>'+esc(new Date(r.createdAt).toLocaleTimeString())+'</td><td>'+btns+'<button class="danger" data-act="decide" data-id="'+esc(r.id)+'" data-decision="deny">拒绝</button></td></tr>'}).join('')+'</table>'}
function renderItems(){var box=$('items-box');var q=($('item-search').value||'').toLowerCase();var gf=$('group-filter')?$('group-filter').value:'';
  var items=state.items.filter(function(i){var hay=(String(i.name)+' '+String(i.url||'')).toLowerCase();return (!q||hay.indexOf(q)>=0)&&(!gf||(i.group||'')===gf)});
  if(state.status&&!state.status.unlocked){box.innerHTML='<div class="empty">解锁后显示条目</div>';return}
  if(!items.length){box.innerHTML='<div class="empty">'+(q||gf?'没有匹配的条目':'暂无条目')+'</div>';return}
  box.innerHTML='<table><tr><th>名称</th><th>网址</th><th>分组</th><th>类型</th><th>操作</th></tr>'+items.map(function(i){return '<tr><td><code>'+esc(i.name)+'</code></td><td class="hint">'+esc(i.url||'')+'</td><td class="hint">'+esc(i.group||'')+'</td><td>'+esc(i.type)+'</td><td><button data-act="share" data-name="'+esc(i.name)+'">分享</button><button data-act="edit-item" data-name="'+esc(i.name)+'">编辑</button><button class="danger" data-act="item-delete" data-name="'+esc(i.name)+'">删除</button></td></tr>'}).join('')+'</table>';
  var gsel=$('group-filter');if(gsel){var current=gsel.value;var groups=Array.from(new Set(state.items.map(function(i){return i.group||''}))).filter(Boolean).sort();gsel.innerHTML='<option value="">全部分组</option>'+groups.map(function(g){return '<option value="'+esc(g)+'">'+esc(g)+'</option>'}).join('');gsel.value=current}}
function renderAgents(){var box=$('agents-box');if(!state.agents.length){box.innerHTML='<div class="empty">暂无 agent</div>';return}
  box.innerHTML='<table><tr><th>Agent</th><th>Token</th><th>可读条目</th><th>操作</th></tr>'+state.agents.map(function(a){var allow=a.allow&&a.allow.length?a.allow.join(', '):'全部';return '<tr><td>'+esc(a.name)+'</td><td><code>'+esc(a.tokenPreview||'')+'</code> <button data-act="copy" data-agent="'+esc(a.name)+'">复制</button></td><td class="hint">'+esc(allow)+'</td><td><button data-act="access" data-agent="'+esc(a.name)+'">设置可读</button><button data-act="agent-write" data-agent="'+esc(a.name)+'" data-allow="'+((state.agentWrite&&state.agentWrite[a.name])?'0':'1')+'">写入:'+((state.agentWrite&&state.agentWrite[a.name])?'开':'关')+'</button><button data-act="rotate" data-agent="'+esc(a.name)+'">轮换</button><button class="danger" data-act="agent-delete" data-agent="'+esc(a.name)+'">删除</button></td></tr>'}).join('')+'</table>'}
function renderGrants(){var box=$('grants-box');var rows=state.grants;if(!rows.length){box.innerHTML='<div class="empty">暂无授权</div>';return}
  var sort=$('g-sort').value,group=$('g-group').value;var list=rows.slice();var key=sort==='created'?function(g){return g.createdAt?Date.parse(g.createdAt):0}:sort==='agent'?function(g){return String(g.agent).toLowerCase()}:sort==='name'?function(g){return String(g.name).toLowerCase()}:function(g){return g.expiresAt==null?Number.MAX_SAFE_INTEGER:g.expiresAt};
  list.sort(function(x,y){var a=key(x),b=key(y);return a<b?-1:a>b?1:0});
  function row(g){var st=g.revokedAt?'<span style="color:var(--danger)">已撤销</span>':(g.expiresAt&&g.expiresAt<=Date.now())?'<span style="color:var(--warn)">已过期</span>':(g.maxReads&&(g.reads||0)>=g.maxReads)?'<span style="color:var(--warn)">次数用尽</span>':'<span style="color:var(--ok)">生效中</span>';
    var btn=function(act,label,extra,cls){return '<button data-act="'+act+'" data-agent="'+esc(g.agent)+'" data-name="'+esc(g.name)+'"'+(extra||'')+(cls?' class="'+cls+'"':'')+'>'+label+'</button>'};
    return '<tr><td>'+esc(g.agent)+'</td><td><code>'+esc(g.name)+'</code></td><td>'+st+'</td><td>'+fmt(g.expiresAt)+'</td><td>'+(g.reads||0)+'/'+(g.maxReads||'∞')+'</td><td>'+btn('g-extend','+1h',' data-s="3600"')+btn('g-extend','+24h',' data-s="86400"')+btn('g-extend','+7d',' data-s="604800"')+btn('g-set','改期')+(g.revokedAt?btn('g-restore','恢复'):btn('g-revoke','撤销','','danger'))+btn('g-delete','删除','','danger')+'</td></tr>'}
  var head='<table><tr><th>Agent</th><th>条目</th><th>状态</th><th>到期</th><th>读取</th><th>操作</th></tr>';
  if(group==='agent'){var groups={};list.forEach(function(g){(groups[g.agent]=groups[g.agent]||[]).push(g)});box.innerHTML=Object.keys(groups).sort().map(function(n){return '<h3 style="font-size:13px;color:var(--muted);margin:10px 0 4px">'+esc(n)+'</h3>'+head+groups[n].map(row).join('')+'</table>'}).join('');return}
  box.innerHTML=head+list.map(row).join('')+'</table>'}
function logRow(e){var event=esc(e.event||'');var agent=esc(e.agent||'');var name=e.name?('<code>'+esc(e.name)+'</code>'):'';var extra='';if(e.mode)extra+=' mode='+esc(e.mode);if(e.reads!==undefined)extra+=' reads='+esc(e.reads);if(e.maxReads)extra+=' max='+esc(e.maxReads);return '<tr><td>'+esc(e.time?new Date(e.time).toLocaleString('zh-CN',{hour12:false}):'')+'</td><td>'+agent+'</td><td>'+event+'</td><td>'+name+'</td><td class="hint">'+esc(extra.trim())+'</td></tr>'}
async function loadLogs(reset){try{
  var offset=reset?0:state.logs.length;var qs='?limit=100&offset='+offset+'&agent='+encodeURIComponent($('log-agent').value||'')+'&event='+encodeURIComponent($('log-event').value||'')+'&name='+encodeURIComponent($('log-name').value||'');
  var r=await api('/api/audit'+qs);state.logsTotal=r.total;state.logs=reset?r.entries:state.logs.concat(r.entries);
  $('logs-box').innerHTML=state.logs.length?'<table><tr><th>时间</th><th>Agent</th><th>事件</th><th>密钥</th><th>详情</th></tr>'+state.logs.map(logRow).join('')+'</table>':'<div class="empty">暂无日志</div>';
  $('logs-count').textContent='共 '+r.total+' 条，已显示 '+state.logs.length+' 条';
}catch(e){toast('日志加载失败：'+e.message,true)}}
function openShare(name){state.shareItem=name;var agents=state.agents.map(function(a){return '<label class="chk"><input type="checkbox" class="share-agent" value="'+esc(a.name)+'">'+esc(a.name)+'</label>'}).join('');openModal('分享「'+name+'」','<div>'+agents+'</div><div class="row" style="margin-top:10px"><label class="hint">有效时间 <select id="share-ttl"><option value="1">1 小时</option><option value="24">24 小时</option><option value="168">7 天</option><option value="0">永久</option></select></label><label class="hint">可读次数 <input id="share-reads" type="number" min="1" placeholder="不限" style="width:90px"></label><button class="primary" data-act="share-go">分享</button></div>')}
function openAccess(agent){var a=state.agents.find(function(x){return x.name===agent});if(!a)return;if(!state.items.length){toast('解锁并加载条目后再设置',true);return}
  var all=(a.allow||[]).length===0;var boxes=state.items.map(function(i){var checked=all||(a.allow||[]).indexOf(i.name)>=0;return '<label class="chk"><input type="checkbox" class="access-item" value="'+esc(i.name)+'"'+(checked?' checked':'')+'>'+esc(i.name)+'</label>'}).join('');
  openModal('「'+agent+'」可读条目','<label class="chk"><input type="checkbox" id="access-all"'+(all?' checked':'')+'> 全部条目</label><div>'+boxes+'</div><div class="row"><button class="primary" data-act="access-save" data-agent="'+esc(agent)+'">保存</button></div>')}
async function doShare(){var agents=[].slice.call(document.querySelectorAll('.share-agent:checked')).map(function(x){return x.value});if(!agents.length){toast('至少选一个 agent',true);return}var ttl=Number($('share-ttl').value);var reads=Number($('share-reads').value||0);for(var i=0;i<agents.length;i++){await post('/api/grants/create',{agent:agents[i],name:state.shareItem,ttlHours:ttl,maxReads:reads})}toast('已分享给 '+agents.join(', '));closeModal();loadAll()}
async function doAccess(agent){var all=$('access-all').checked;var names=all?'':[].slice.call(document.querySelectorAll('.access-item:checked')).map(function(x){return x.value}).join(',');await post('/api/agents/access',{name:agent,allow:names});toast('已保存');closeModal();loadAll()}
document.addEventListener('submit',async function(e){var f=e.target;try{
  if(f.id==='unlock-form'){e.preventDefault();toast('解锁中…');var r=await post('/api/unlock',{password:f.password.value});f.password.value='';toast(r.ok?'已解锁':'解锁失败');await loadAll()}
  else if(f.id==='item-form'){e.preventDefault();var d=new FormData(f);await post('/api/items/save',{name:d.get('name'),value:d.get('value')||'',notes:d.get('notes')||'',url:d.get('url')||'',group:d.get('group')||''});f.reset();toast('已保存');await loadAll()}
  else if(f.id==='agent-form'){e.preventDefault();await post('/api/agents/add',{name:f.name.value});f.reset();toast('已添加');await loadAll()}
  else if(f.id==='item-edit-form'){e.preventDefault();var ed=new FormData(f);await post('/api/items/save',{name:ed.get('name'),url:ed.get('url')||'',group:ed.get('group')||'',value:ed.get('value')||'',notes:ed.get('notes')||''});toast('已更新');closeModal();await loadAll()}
}catch(err){toast(err.message,true)}});
document.addEventListener('click',async function(e){var b=e.target.closest('[data-act]');if(!b)return;var act=b.getAttribute('data-act');
  try{
    if(act==='refresh'){await loadAll();toast('已刷新')}
    else if(act==='lock'){await post('/api/lock',{});await loadAll();toast('已锁定')}
    else if(act==='logout'){await post('/api/logout',{});location.href='/login'}
    else if(act==='decide'){await post('/api/requests/'+encodeURIComponent(b.getAttribute('data-id'))+'/decide',{decision:b.getAttribute('data-decision')});await loadAll()}
    else if(act==='share'){openShare(b.getAttribute('data-name'))}
    else if(act==='edit-item'){var it=state.items.find(function(x){return x.name===b.getAttribute('data-name')});if(it)openModal('编辑「'+it.name+'」','<form id="item-edit-form"><input type="hidden" name="name" value="'+esc(it.name)+'"><label class="hint">网址<input name="url" value="'+esc(it.url||'')+'" style="width:100%"></label><label class="hint">分组<input name="group" value="'+esc(it.group||'')+'" style="width:100%"></label><label class="hint">新密钥值（留空不改）<input type="password" name="value" style="width:100%"></label><label class="hint">备注<input name="notes" style="width:100%"></label><button class="primary">保存</button></form>')}
    else if(act==='share-go'){await doShare()}
    else if(act==='item-delete'){if(!confirm('删除条目「'+b.getAttribute('data-name')+'」？'))return;await post('/api/items/delete',{name:b.getAttribute('data-name')});await loadAll();toast('已删除')}
    else if(act==='access'){openAccess(b.getAttribute('data-agent'))}
    else if(act==='access-save'){await doAccess(b.getAttribute('data-agent'))}
    else if(act==='rotate'){if(!confirm('轮换 agent「'+b.getAttribute('data-agent')+'」的 token？'))return;await post('/api/agents/rotate',{name:b.getAttribute('data-agent')});toast('已轮换 token，点“复制”获取新值');await loadAll()}
    else if(act==='agent-delete'){if(!confirm('删除 agent「'+b.getAttribute('data-agent')+'」及其授权？'))return;await post('/api/agents/delete',{name:b.getAttribute('data-agent')});await loadAll()}
    else if(act==='copy'){try{var t=await post('/api/agents/token',{name:b.getAttribute('data-agent')});await navigator.clipboard.writeText(t.token);toast('已复制到剪贴板')}catch(err){toast('复制失败',true)}}
    else if(act==='g-extend'){await post('/api/grants/extend',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name'),seconds:b.getAttribute('data-s')});await loadAll()}
    else if(act==='g-set'){var v=prompt('新的到期时间（YYYY-MM-DD HH:MM，留空=永久）','');if(v===null)return;var iso='';if(v.trim()!==''){var dt=new Date(v.trim().replace(' ','T'));if(isNaN(dt.getTime())){toast('时间格式不对',true);return}iso=dt.toISOString()}await post('/api/grants/set-expiry',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name'),expiresAt:iso});await loadAll()}
    else if(act==='g-revoke'){await post('/api/grants/revoke',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='g-restore'){await post('/api/grants/restore',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='g-delete'){if(!confirm('删除这条授权记录？'))return;await post('/api/grants/delete',{agent:b.getAttribute('data-agent'),name:b.getAttribute('data-name')});await loadAll()}
    else if(act==='import'){var r=await post('/api/import',{});toast('导入完成：新增 '+(r.created||[]).length+'，跳过 '+(r.skipped||[]).length);await loadAll()}
    else if(act==='sync-items'){toast('正在从 NodeWarden 同步…');var r=await api('/api/items?sync=1');state.items=r.items||[];renderItems();toast('已同步')}
    else if(act==='logs-refresh'){await loadLogs(true)}
    else if(act==='logs-more'){await loadLogs(false)}
    else if(act==='stats-range'){await loadStats(b.getAttribute('data-range'))}
    else if(act==='profile-save'){await saveProfile()}
    else if(act==='totp-setup'){var r=await post('/api/profile/totp/setup',{});$('totp-setup-box').innerHTML='<div class="hint">密钥：<code>'+esc(r.secret)+'</code><br>otpauth：<code style="word-break:break-all">'+esc(r.otpauth)+'</code><br>用验证器（Bitwarden/Google Authenticator）添加后，点「启用 2FA」输入验证码。</div><button data-act="totp-enable">启用 2FA</button>'}
    else if(act==='totp-enable'){var code=prompt('输入验证器中的 6 位验证码');if(!code)return;await post('/api/profile/totp/enable',{code});toast('2FA 已启用');loadProfile()}
    else if(act==='totp-disable'){if(!confirm('关闭两步验证？'))return;await post('/api/profile/totp/disable',{});toast('已关闭');loadProfile()}
    else if(act==='oidc-unbind'){if(!confirm('解绑 OIDC？下次登录会重新绑定。'))return;await post('/api/profile/oidc/unbind',{});toast('已解绑');loadProfile()}
    else if(act==='settings-save'){await saveSettings()}
    else if(act==='settings-restart'){if(!confirm('保存并重启容器？重启后自动解锁。'))return;await saveSettings();toast('正在重启…');await post('/api/restart',{});setTimeout(function(){location.reload()},4000)}
    else if(act==='ntfy-test'){await saveSettings();var r=await post('/api/ntfy/test',{});toast(r.ok?'测试通知已发送':'发送失败：'+(r.error||''))}
    else if(act==='agent-write'){await post('/api/agents/write',{name:b.getAttribute('data-agent'),allow:b.getAttribute('data-allow')});await loadAll()}
    else if(act==='disable-auto'){if(!confirm('删除自动解锁密码文件？删除后重启需手动解锁。'))return;await post('/api/auto-unlock/disable',{});await loadAll();toast('已删除')}
    else if(act==='modal-close'){closeModal()}
  }catch(err){toast(err.message,true)}});
$('item-search').addEventListener('input',renderItems);
if($('group-filter'))$('group-filter').addEventListener('change',renderItems);
$('g-sort').addEventListener('change',renderGrants);
$('g-group').addEventListener('change',renderGrants);
$('theme-select').addEventListener('change',function(){applyTheme(this.value)});
initTheme();route();loadAll();
setInterval(function(){if(document.visibilityState==='visible')loadAll()},15000);
</script>
</div></body></html>`
}

function fmtTime(ms) {
  if (ms === null || ms === undefined) return '永久'
  return new Date(ms).toLocaleString('zh-CN', { hour12: false })
}

function agentFromRequest(req) {
  const header = req.headers.authorization ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
  if (token.length === 0) return undefined
  const presented = hashToken(token)
  // OAuth access tokens issued by the built-in MCP authorization server.
  const oauth = config.oauthTokens?.[hashToken(token)]
  if (oauth !== undefined && oauth.expiresAt > Date.now()) return `oauth:${oauth.clientId}`
  for (const [agent, value] of Object.entries(config.agents ?? {})) {
    if (typeof value !== 'string' || value.length === 0) continue
    if (value.startsWith('sha256:')) {
      const a = Buffer.from(value)
      const b = Buffer.from(presented)
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return agent
    } else if (value === token) {
      return agent
    }
  }
  return undefined
}

function globMatch(pattern, name) {
  const escaped = String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i').test(name)
}

/** Agent item allowlist: empty/absent means "all items". Supports `*` globs. */
function agentAllowed(agent, name) {
  const patterns = config.agentAccess?.[agent]
  if (!Array.isArray(patterns) || patterns.length === 0) return true
  return patterns.some((pattern) => globMatch(pattern, name))
}

async function dashboard() {
  let items = []
  let itemsError
  if (state.unlocked) {
    try {
      items = (await listItems()).map((item) => ({ name: item.name, id: item.id, type: item.type }))
    } catch (error) {
      itemsError = String(error.message ?? error)
    }
  }
  const pending = [...state.pending.values()].filter((entry) => entry.status === 'pending')
  const pendingRows = pending
    .map(
      (entry) => `<tr><td>${esc(entry.agent)}</td><td><code>${esc(entry.name)}</code></td><td>${new Date(entry.createdAt).toLocaleTimeString()}</td>
      <td>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="once">仅本次</button></form>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="1h">1 小时</button></form>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="24h">24 小时</button></form>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="7d">7 天</button></form>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="always">永久</button></form>
        <form method="post" action="/api/requests/${entry.id}/decide"><button name="decision" value="deny">拒绝</button></form>
      </td></tr>`,
    )
    .join('')
  const grantRows = grants
    .map(
      (grant) => `<tr><td>${esc(grant.agent)}</td><td><code>${esc(grant.name)}</code></td><td>${esc(grant.mode)}</td><td>${fmtTime(grant.expiresAt)}</td>
      <td><form method="post" action="/api/grants/revoke"><input type="hidden" name="agent" value="${esc(grant.agent)}"><input type="hidden" name="name" value="${esc(grant.name)}"><button>撤销</button></form></td></tr>`,
    )
    .join('')
  const agentRows = Object.entries(config.agents ?? {})
    .map(
      ([agent, token]) => `<tr><td>${esc(agent)}</td><td><code>${esc(token)}</code></td>
      <td>
        <form method="post" action="/api/agents/rotate"><input type="hidden" name="name" value="${esc(agent)}"><button>轮换 token</button></form>
        <form method="post" action="/api/agents/delete"><input type="hidden" name="name" value="${esc(agent)}"><button>删除 agent</button></form>
      </td></tr>`,
    )
    .join('')
  const itemRows = items
    .map(
      (item) => `<tr><td><code>${esc(item.name)}</code></td><td>${esc(item.type)}</td>
      <td>
        <form method="post" action="/api/items/delete"><input type="hidden" name="name" value="${esc(item.name)}"><button>删除</button></form>
      </td></tr>`,
    )
    .join('')
  const importInfo = state.lastImport
    ? `<p>上次解锁自动导入：${state.lastImport.created.length > 0 ? state.lastImport.created.map((n) => `<code>${esc(n)}</code>`).join('、') : '无新增'}${state.lastImport.skipped.length > 0 ? '；跳过：' + esc(state.lastImport.skipped.join('；')) : ''}</p>`
    : ''
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title>
<style>
:root{--bg:#0e1119;--card:#161b26;--line:#263041;--text:#e7ebf3;--muted:#93a0b5;--accent:#5b8cff;--ok:#2ecc71;--warn:#f5a623;--danger:#ff5c5c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 18px 60px}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:22px}
h1{font-size:20px;margin:0}.badge{padding:2px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.badge.on{color:var(--ok);border-color:#1f5134;background:#10241a}.badge.off{color:var(--warn);border-color:#513f1f;background:#241d10}
.sub{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px}
.card h2{font-size:15px;margin:0 0 12px;color:#cdd6e6;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}th{color:var(--muted);font-weight:500;text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid #1d2532;vertical-align:middle}
tr:last-child td{border-bottom:0}
code{background:#0b0f17;border:1px solid #1d2532;padding:1px 6px;border-radius:6px;font-size:12px}
button{cursor:pointer;border:1px solid var(--line);background:#1d2635;color:var(--text);border-radius:8px;padding:5px 10px;font-size:12px;margin:2px}
button:hover{background:#243049}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.primary:hover{filter:brightness(1.1)}
button.danger{color:#ffb4b4;border-color:#4a2222;background:#2a1616}
input{background:#0b0f17;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 9px;font-size:13px;margin:2px}
form.inline{display:inline} .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.hint{color:var(--muted);font-size:12px;margin-top:8px}.empty{color:var(--muted);font-size:13px}
.unlock{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
</style></head><body><div class="wrap">
<header>
<h1>Secrets Broker</h1>
<span class="badge ${state.unlocked ? 'on' : 'off'}">${state.unlocked ? '已解锁' : '未解锁'}</span>
${MOCK ? '<span class="badge off">MOCK</span>' : ''}
<span class="sub">Vault: <code>${esc(config.serverUrl)}</code></span>
${state.unlocked
      ? '<form class="inline" method="post" action="/api/lock"><button>锁定</button></form>'
      : `<form class="inline unlock" method="post" action="/api/unlock"><input type="password" name="password" placeholder="主密码" autocomplete="off" required><button class="primary">解锁</button></form>`}
${AUTH_REQUIRED ? '<form class="inline" method="post" action="/api/logout"><button>退出登录</button></form>' : ''}
</header>
${importInfo}
<div class="card"><h2>待批准请求</h2><div id="pending-box" class="empty">加载中…</div>
<div class="hint">点按钮即授权；「永久」可随时在下方撤销。</div></div>
<div class="card"><h2>授权与到期</h2>
<div class="row">
<label class="hint">排序 <select id="g-sort"><option value="expiry">到期时间</option><option value="created">授权时间</option><option value="agent">Agent</option><option value="name">密钥名</option></select></label>
<label class="hint">分组 <select id="g-group"><option value="none">不分组</option><option value="agent">按 agent</option></select></label>
</div>
<div id="grants-box" class="empty">加载中…</div></div>
<div class="card"><h2>密钥条目 ${state.unlocked ? `（${items.length}）` : '（需解锁）'}</h2>
${itemsError ? `<p class="hint">读取失败：${esc(itemsError)}</p>` : ''}
<div class="row"><form class="inline" method="post" action="/api/items/save">
<input type="text" name="name" placeholder="条目名（如 tavily-api-key）" required>
<input type="password" name="value" placeholder="密钥值（留空则不动）">
<input type="text" name="notes" placeholder="备注（可选）"><button class="primary">新增 / 更新</button></form></div>
<div class="row"><form class="inline" method="post" action="/api/grants/create">
<select name="agent">${Object.keys(config.agents ?? {}).map((agent) => `<option>${esc(agent)}</option>`).join('')}</select>
<input type="text" name="name" placeholder="要分享的条目名" required>
<input type="number" name="ttlHours" min="1" placeholder="有效小时（空=永久）">
<input type="number" name="maxReads" min="1" placeholder="可读次数（空=不限）">
<button class="primary">分享给 agent</button></form></div>
${items.length === 0 ? '<div class="empty">暂无条目</div>' : `<table><tr><th>名称</th><th>类型</th><th></th></tr>${items.map((item) => `<tr><td><code>${esc(item.name)}</code></td><td>${esc(item.type)}</td><td><form class="inline" method="post" action="/api/items/delete"><input type="hidden" name="name" value="${esc(item.name)}"><button class="danger">删除</button></form></td></tr>`).join('')}</table>`}
</div>
<div class="card"><h2>Agents</h2>
<div class="row"><form class="inline" method="post" action="/api/agents/add"><input type="text" name="name" placeholder="新 agent 名（如 codex-home）" required><button class="primary">添加</button></form></div>
<table><tr><th>Agent</th><th>Token</th><th>可读条目（逗号分隔，支持 * 通配；空=全部）</th><th></th></tr>${Object.entries(config.agents ?? {}).map(([agent, token]) => `<tr><td>${esc(agent)}</td><td><code>${esc(token)}</code> <button onclick="copyText('${esc(token)}')">复制</button></td><td><form class="inline" method="post" action="/api/agents/access"><input type="hidden" name="name" value="${esc(agent)}"><input type="text" name="allow" value="${esc((config.agentAccess?.[agent] ?? []).join(','))}" placeholder="例如：prod/*,tavily-api-key" style="width:260px"><button>保存权限</button></form></td><td><form class="inline" method="post" action="/api/agents/rotate"><input type="hidden" name="name" value="${esc(agent)}"><button>轮换</button></form><form class="inline" method="post" action="/api/agents/delete"><input type="hidden" name="name" value="${esc(agent)}"><button class="danger">删除</button></form></td></tr>`).join('')}</table></div>
<div class="card"><h2>导入本机明文密钥</h2>
<form class="inline" method="post" action="/api/import"><button>从 .credentials.yaml / .env / mcp-auth 导入</button></form>
<div class="hint">Agent API：<code>GET /secret?name=条目名</code>（Bearer token）· CLI：<code>node wh.mjs get 条目名</code> · 注入进程：<code>node wh.mjs run --var NAME=条目名 -- 命令</code><br>条目名可用 <code>项目/环境/名称</code> 约定做分类（如 <code>blog/prod/tavily-key</code>），配合 agent 权限前缀控制。</div></div>
<script>
const $ = (id) => document.getElementById(id);
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function post(p,d){await fetch(p,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d)})}
async function decide(id,d){await post('/api/requests/'+encodeURIComponent(id)+'/decide',{decision:d});refresh()}
async function revoke(a,n){await post('/api/grants/revoke',{agent:a,name:n});refresh()}
async function restore(a,n){await post('/api/grants/restore',{agent:a,name:n});refresh()}
async function extend(a,n,s){await post('/api/grants/extend',{agent:a,name:n,seconds:s});refresh()}
async function delGrant(a,n){if(!confirm('删除这条授权记录？'))return;await post('/api/grants/delete',{agent:a,name:n});refresh()}
async function setExpiry(a,n){const v=prompt('新的到期时间（YYYY-MM-DD HH:MM，留空=永久）');if(v===null)return;const iso=v.trim()===''?'':new Date(v.trim().replace(' ','T')).toISOString();if(v.trim()!==''&&iso===''){alert('时间格式不对');return}await post('/api/grants/set-expiry',{agent:a,name:n,expiresAt:iso});refresh()}
function grantStatus(g){if(g.revokedAt)return '<span style="color:#ff9b9b">已撤销</span>';if(g.expiresAt&&g.expiresAt<=Date.now())return '<span style="color:#f5a623">已过期</span>';if(g.maxReads&&(g.reads||0)>=g.maxReads)return '<span style="color:#f5a623">次数用尽</span>';return '<span style="color:#6ee7a8">生效中</span>'}
async function copyText(t){try{await navigator.clipboard.writeText(t)}catch(e){}}
function fmt(ms){return ms?new Date(ms).toLocaleString('zh-CN',{hour12:false}):'永久'}
function renderPending(rows){
  if(!rows.length){$('pending-box').innerHTML='<div class="empty">暂无待批准请求</div>';return}
  $('pending-box').innerHTML='<table><tr><th>Agent</th><th>条目</th><th>时间</th><th>授权</th></tr>'+rows.map(r=>'<tr><td>'+esc(r.agent)+'</td><td><code>'+esc(r.name)+'</code></td><td>'+esc(new Date(r.createdAt).toLocaleTimeString())+'</td><td>'+['once','1h','24h','7d','always'].map(d=>'<button class="primary" onclick="decide(\\''+r.id+'\\',\\''+d+'\\')">'+({once:'仅本次','1h':'1 小时','24h':'24 小时','7d':'7 天',always:'永久'}[d])+'</button>').join('')+'<button class="danger" onclick="decide(\\''+r.id+'\\',\\'deny\\')">拒绝</button></td></tr>').join('')+'</table>'}
function renderGrants(rows){
  const box=$('grants-box');
  if(!rows.length){box.innerHTML='<div class="empty">暂无授权</div>';return}
  const sort=$('g-sort')?$('g-sort').value:'expiry';
  const group=$('g-group')?$('g-group').value:'none';
  const list=[...rows];
  const key=sort==='created'?g=>g.createdAt?Date.parse(g.createdAt):0:sort==='agent'?g=>String(g.agent).toLowerCase():sort==='name'?g=>String(g.name).toLowerCase():g=>g.expiresAt===null||g.expiresAt===undefined?Number.MAX_SAFE_INTEGER:g.expiresAt;
  list.sort((x,y)=>{const a=key(x),b=key(y);return a<b?-1:a>b?1:0});
  const rowOf=(g)=>{
    const a=esc(g.agent),n=esc(g.name);
    const btn=(act,label,cls,extra)=>'<button data-act="'+act+'" data-a="'+a+'" data-n="'+n+'"'+(extra||'')+' class="'+(cls||'')+'">'+label+'</button>';
    const revokeBtn=g.revokedAt?btn('restore','恢复'):btn('revoke','撤销','danger');
    return '<tr><td>'+a+'</td><td><code>'+n+'</code></td><td>'+grantStatus(g)+'</td><td>'+fmt(g.expiresAt)+'</td><td>'+((g.reads||0))+'/'+(g.maxReads||'∞')+'</td><td>'+btn('extend','+1h','',' data-s="3600"')+btn('extend','+24h','',' data-s="86400"')+btn('extend','+7d','',' data-s="604800"')+btn('set','改期')+revokeBtn+btn('delete','删除','danger')+'</td></tr>';
  };
  const head='<table><tr><th>Agent</th><th>条目</th><th>状态</th><th>到期</th><th>读取</th><th>操作</th></tr>';
  if(group==='agent'){
    const groups={};for(const g of list){(groups[g.agent]=groups[g.agent]||[]).push(g)}
    box.innerHTML=Object.keys(groups).sort().map(name=>'<h3 style="font-size:13px;color:#9aa3b8;margin:10px 0 4px">'+esc(name)+'</h3>'+head+groups[name].map(rowOf).join('')+'</table>').join('');
    return;
  }
  box.innerHTML=head+list.map(rowOf).join('')+'</table>';
}
document.addEventListener('click',(e)=>{const b=e.target.closest('button[data-act]');if(!b)return;const a=b.getAttribute('data-a'),n=b.getAttribute('data-n');const act=b.getAttribute('data-act');if(act==='extend')extend(a,n,Number(b.getAttribute('data-s')));else if(act==='set')setExpiry(a,n);else if(act==='revoke')revoke(a,n);else if(act==='restore')restore(a,n);else if(act==='delete')delGrant(a,n)});
if($('g-sort'))$('g-sort').addEventListener('change',refresh);
if($('g-group'))$('g-group').addEventListener('change',refresh);
async function refresh(){
  try{
    const [p,g]=await Promise.all([fetch('/api/pending').then(r=>r.json()),fetch('/api/grants-list').then(r=>r.json())]);
    renderPending(p.requests||[]);renderGrants(g.grants||[]);
  }catch(e){}
}
setInterval(()=>{if(document.visibilityState==='visible')refresh()},8000);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')refresh()});
refresh();
</script>
</div></body></html>`
}

// ---- agent flow ----
async function createPending(agent, name) {
  for (const entry of state.pending.values()) {
    if (entry.agent === agent && entry.name === name && entry.status === 'pending') return entry
  }
  const entry = { id: crypto.randomUUID(), agent, name, createdAt: Date.now(), status: 'pending' }
  state.pending.set(entry.id, entry)
  audit({ event: 'request.create', agent, name })
  notifyPending(entry)
  return entry
}

/** Optional push notification (ntfy) when a new approval request appears. */
function notifyPending(entry) {
  telegramNotify(entry).catch(() => {})
  const text = [
    `Secrets Broker: 代理 ${entry.agent} 请求读取「${entry.name}」`,
    `允许一次：${approvalUrl(entry.id, 'once')}`,
    `允许 24 小时：${approvalUrl(entry.id, '24h')}`,
    `拒绝：${approvalUrl(entry.id, 'deny')}`,
    `管理页：${PUBLIC_URL}/`,
  ].join('\n')
  if (GOTIFY_URL && GOTIFY_TOKEN) {
    fetch(`${GOTIFY_URL}/message`, {
      method: 'POST',
      headers: { 'X-Gotify-Key': GOTIFY_TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'Secrets Broker approval', message: text, priority: 5 }),
    }).catch(() => {})
  }
  if (WXPUSH_URL && WXPUSH_TOKEN) {
    fetch(`${WXPUSH_URL}/wxsend`, {
      method: 'POST',
      headers: { authorization: WXPUSH_TOKEN, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title: 'Secrets Broker approval', content: text, token: WXPUSH_TOKEN }).toString(),
    }).catch(() => {})
  }
  if (!NTFY_URL) return
  fetch(NTFY_URL, {
    method: 'POST',
    headers: { Title: 'Secrets Broker approval', Tags: 'lock', Priority: 'high' },
    body: text,
  }).catch(() => {})
}

/** Apply an approval decision to a pending request (shared by web, Telegram, ntfy). */
function decideRequest(id, decision, source = 'web') {
  const entry = state.pending.get(id)
  if (entry === undefined || entry.status !== 'pending') return { ok: false, error: '请求不存在或已处理' }
  if (!state.unlocked) return { ok: false, error: '请先解锁 vault' }
  if (decision === 'deny') {
    entry.status = 'denied'
    audit({ event: 'request.deny', agent: entry.agent, name: entry.name, source })
  } else if (decision === 'once') {
    entry.status = 'approved'
    entry.mode = 'once'
    audit({ event: 'request.approve', mode: 'once', agent: entry.agent, name: entry.name, source })
  } else {
    const ttl = decision === '1h' ? 3600e3 : decision === '24h' ? 86400e3 : decision === '7d' ? 7 * 86400e3 : null
    addGrant(entry.agent, entry.name, decision, ttl)
    entry.status = 'approved'
    entry.mode = decision
    audit({ event: 'request.approve', mode: decision, agent: entry.agent, name: entry.name, source })
  }
  return { ok: true, entry }
}

function approvalSignature(id, decision, exp) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(`${id}|${decision}|${exp}`).digest('base64url')
}
function approvalUrl(id, decision, ttlMs = 10 * 60 * 1000) {
  const exp = Date.now() + ttlMs
  const sig = approvalSignature(id, decision, exp)
  return `${PUBLIC_URL}/approve/${encodeURIComponent(id)}?d=${encodeURIComponent(decision)}&exp=${exp}&sig=${sig}`
}

// ---- built-in OAuth 2.1 authorization server for MCP ----
const oauthCodes = new Map()
const OAUTH_SCOPE = 'mcp'
function oauthServerMetadata() {
  return {
    issuer: PUBLIC_URL,
    authorization_endpoint: `${PUBLIC_URL}/oauth/authorize`,
    token_endpoint: `${PUBLIC_URL}/oauth/token`,
    registration_endpoint: `${PUBLIC_URL}/oauth/register`,
    scopes_supported: [OAUTH_SCOPE],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    service_documentation: `${PUBLIC_URL}/`,
  }
}
function oauthProtectedResource() {
  return {
    resource: `${PUBLIC_URL}/mcp`,
    authorization_servers: [PUBLIC_URL],
    scopes_supported: [OAUTH_SCOPE],
    bearer_methods_supported: ['header'],
    resource_documentation: `${PUBLIC_URL}/`,
  }
}
function pkceMatches(verifier, challenge) {
  return b64url(crypto.createHash('sha256').update(String(verifier)).digest()) === String(challenge)
}
function redirectWith(url, params) {
  const target = new URL(url)
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) target.searchParams.set(key, value)
  }
  return target.toString()
}
function oauthConsentPage(params, client, message = '', loggedIn = false) {
  const hidden = Object.entries(params)
    .filter(([key]) => ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state', 'scope'].includes(key))
    .map(([key, value]) => `<input type="hidden" name="${esc(key)}" value="${esc(String(value ?? ''))}">`)
    .join('')
  const redirectUri = params.redirect_uri ?? ''
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权 MCP 客户端</title>
<style>body{font-family:system-ui;background:#0e1119;color:#e7ebf3;max-width:520px;margin:60px auto;padding:0 18px}input{width:100%;padding:8px;margin:6px 0;background:#0b0f17;border:1px solid #263041;color:#e7ebf3;border-radius:8px}button{padding:8px 14px;border-radius:8px;border:1px solid #263041;background:#5b8cff;color:#fff;cursor:pointer;margin-right:8px}button.deny{background:#2a1616;border-color:#4a2222;color:#ffb4b4}code{background:#0b0f17;padding:1px 4px}.muted{color:#93a0b5;font-size:12px}</style></head><body>
<h2>授权 MCP 客户端</h2>
<p><b>${esc(client?.clientName ?? params.client_id ?? '未命名客户端')}</b> 请求访问 Secrets Broker MCP。</p>
<p class="muted">回调地址：<code>${esc(redirectUri)}</code></p>
<p class="muted">授权后它将能：列出密钥名称；按你的审批读取；若开启写入权限还能创建条目。</p>
${message ? `<p style="color:#ffb4b4">${esc(message)}</p>` : ''}
<form method="post" action="/oauth/approve">${hidden}
${loggedIn ? '' : '<label class="muted">管理密码</label><input type="password" name="password" placeholder="管理密码" required>'}
<div style="margin-top:10px"><button name="decision" value="allow">允许</button><button class="deny" name="decision" value="deny">拒绝</button></div>
</form></body></html>`
}


// ---- TOTP (2FA) ----
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32Encode(buffer) {
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return output
}
function base32Decode(text) {
  let bits = 0
  let value = 0
  const out = []
  for (const char of String(text).toUpperCase().replace(/=+$/, '')) {
    const index = BASE32_ALPHABET.indexOf(char)
    if (index < 0) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}
function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20))
}
function totpCode(secret, offset = 0) {
  const counter = Math.floor(Date.now() / 30000) + offset
  const buffer = Buffer.alloc(8)
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0)
  buffer.writeUInt32BE(counter >>> 0, 4)
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buffer).digest()
  const dynamic = hmac[hmac.length - 1] & 0x0f
  const code = (((hmac[dynamic] & 0x7f) << 24) | (hmac[dynamic + 1] << 16) | (hmac[dynamic + 2] << 8) | hmac[dynamic + 3]) % 1e6
  return String(code).padStart(6, '0')
}
function verifyTotp(secret, code) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) return false
  const target = code.trim()
  for (const offset of [-1, 0, 1]) {
    if (totpCode(secret, offset) === target) return true
  }
  return false
}

// ---- Telegram bot (approve from chat) ----
const TELEGRAM_TOKEN = config.telegram?.token ?? process.env.TELEGRAM_BOT_TOKEN ?? ''
const GOTIFY_URL = (config.gotify?.url ?? process.env.GOTIFY_URL ?? '').replace(/\/+$/, '')
const GOTIFY_TOKEN = config.gotify?.token ?? process.env.GOTIFY_TOKEN ?? ''
const WXPUSH_URL = (config.wxpush?.url ?? process.env.WXPUSH_URL ?? '').replace(/\/+$/, '')
const WXPUSH_TOKEN = config.wxpush?.token ?? process.env.WXPUSH_TOKEN ?? ''
function telegramChat() {
  return String(config.telegram?.chatId ?? process.env.TELEGRAM_CHAT_ID ?? '')
}
let telegramOffset = 0
let telegramPolling = false

async function telegramApi(method, payload) {
  if (!TELEGRAM_TOKEN) return undefined
  try {
    const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })
    return await response.json()
  } catch {
    return undefined
  }
}

async function telegramNotify(entry) {
  if (!TELEGRAM_TOKEN || !telegramChat()) return
  const keyboard = [
    [
      { text: '仅本次', callback_data: `apr:${entry.id}:once` },
      { text: '1 小时', callback_data: `apr:${entry.id}:1h` },
      { text: '24 小时', callback_data: `apr:${entry.id}:24h` },
    ],
    [
      { text: '7 天', callback_data: `apr:${entry.id}:7d` },
      { text: '永久', callback_data: `apr:${entry.id}:always` },
      { text: '拒绝', callback_data: `deny:${entry.id}` },
    ],
    [{ text: '打开管理页', url: `${PUBLIC_URL}/` }],
  ]
  await telegramApi('sendMessage', {
    chat_id: telegramChat(),
    text: `🔐 Secrets Broker\n代理：${entry.agent}\n条目：${entry.name}\n\n请选择授权方式：`,
    reply_markup: { inline_keyboard: keyboard },
  })
}

async function telegramPoll() {
  if (!TELEGRAM_TOKEN || telegramPolling) return
  telegramPolling = true
  try {
    const result = await telegramApi('getUpdates', { offset: telegramOffset, timeout: 0, allowed_updates: ['callback_query', 'message'] })
    for (const update of result?.result ?? []) {
      telegramOffset = update.update_id + 1
      if (update.message && update.message.chat) {
        const chatId = String(update.message.chat.id)
        if (chatId !== telegramChat()) {
          config.telegram ??= {}
          config.telegram.chatId = chatId
          saveConfig()
          audit({ event: 'telegram.bind', chatId })
          await telegramApi('sendMessage', { chat_id: chatId, text: '✅ 已绑定 Secrets Broker 通知，之后审批消息会发到这里。' })
        }
      }
      const query = update.callback_query
      if (!query) continue
      const data = String(query.data ?? '')
      const [kind, id, decision] = data.split(':')
      let answer = ''
      if (kind === 'apr' && id && decision) {
        const outcome = decideRequest(id, decision, 'telegram')
        answer = outcome.ok ? `已批准（${decision}）` : outcome.error
        if (outcome.ok && query.message) {
          await telegramApi('editMessageText', {
            chat_id: query.message.chat.id,
            message_id: query.message.message_id,
            text: `✅ 已处理：${outcome.entry.agent} → ${outcome.entry.name}（${decision}）`,
          })
        }
      } else if (kind === 'deny' && id) {
        const outcome = decideRequest(id, 'deny', 'telegram')
        answer = outcome.ok ? '已拒绝' : outcome.error
      }
      await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: answer || 'ok' })
    }
  } finally {
    telegramPolling = false
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${config.port}`)
  const remote = req.socket.remoteAddress ?? ''
  const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1'
  const isAgentPath =
    url.pathname === '/secret' ||
    url.pathname.startsWith('/secret/') ||
    url.pathname === '/agent/items' ||
    url.pathname === '/agent/items/save' ||
    url.pathname === '/mcp'

  if (req.method === 'GET' && (url.pathname === '/oidc/login' || url.pathname === '/oidc/callback')) {
    try {
      if (!OIDC_ENABLED) throw new Error('OIDC is not configured')
      const discovery = await oidcDiscovery()
      if (url.pathname === '/oidc/login') {
        const bind = url.searchParams.get('bind') === '1'
        const state = randomUrlSafe(24)
        const nonce = randomUrlSafe(24)
        const verifier = randomUrlSafe(48)
        const challenge = b64url(crypto.createHash('sha256').update(verifier).digest())
        const authorize = new URL(discovery.authorization_endpoint)
        authorize.searchParams.set('response_type', 'code')
        authorize.searchParams.set('client_id', OIDC_CLIENT_ID)
        authorize.searchParams.set('redirect_uri', OIDC_REDIRECT_URI)
        authorize.searchParams.set('scope', OIDC_SCOPE)
        authorize.searchParams.set('state', state)
        authorize.searchParams.set('nonce', nonce)
        authorize.searchParams.set('code_challenge', challenge)
        authorize.searchParams.set('code_challenge_method', 'S256')
        res.writeHead(302, {
          location: authorize.toString(),
          'set-cookie': [
            `broker_oidc_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
            `broker_oidc_nonce=${nonce}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
            `broker_oidc_verifier=${verifier}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
            `broker_oidc_bind=${bind ? '1' : '0'}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
          ],
        })
        return res.end()
      }
      const state = url.searchParams.get('state') ?? ''
      const code = url.searchParams.get('code') ?? ''
      const jar = cookies(req)
      if (state.length === 0 || state !== jar.broker_oidc_state) throw new Error('state mismatch')
      if (code.length === 0) throw new Error('missing authorization code')
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        code_verifier: jar.broker_oidc_verifier ?? '',
      })
      if (OIDC_CLIENT_SECRET) body.set('client_secret', OIDC_CLIENT_SECRET)
      const tokenResponse = await fetch(discovery.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      })
      const tokenPayload = await tokenResponse.json().catch(() => ({}))
      if (!tokenResponse.ok || typeof tokenPayload.id_token !== 'string') {
        throw new Error(`token exchange failed: HTTP ${tokenResponse.status} ${JSON.stringify(tokenPayload).slice(0, 200)}`)
      }
      const claims = await verifyIdToken(tokenPayload.id_token, jar.broker_oidc_nonce)
      const claimMap = config.oidc?.claims ?? {}
      const identifier = claims[claimMap.identifier ?? 'sub'] ?? claims.sub
      const mappedEmail = claims[claimMap.email ?? 'email'] ?? claims.email ?? ''
      const mappedName = claims[claimMap.name ?? 'name'] ?? claims.name ?? ''
      const mappedAvatar = claims[claimMap.avatar ?? 'picture'] ?? claims.picture ?? ''
      if (!config.profile) config.profile = {}
      const bindRequested = jar.broker_oidc_bind === '1'
      if (bindRequested || !config.profile.oidcSub) {
        config.profile.oidcSub = String(identifier ?? '')
        config.profile.oidcEmail = mappedEmail
        if (!config.profile.email && mappedEmail) config.profile.email = mappedEmail
        if (!config.profile.name && mappedName) config.profile.name = mappedName
        if (!config.profile.avatarUrl && mappedAvatar) config.profile.avatarUrl = mappedAvatar
        saveConfig()
        audit({ event: 'profile.oidc-bind', sub: identifier, email: mappedEmail, explicit: bindRequested })
      }
      audit({ event: 'admin.oidc-login', sub: identifier, email: mappedEmail })
      res.writeHead(302, {
        location: jar.broker_oidc_bind === '1' ? '/#/profile' : '/',
        'set-cookie': [
          `broker_admin=${adminCookieValue()}; HttpOnly; SameSite=Lax; Path=/`,
          'broker_oidc_state=; Max-Age=0; Path=/',
          'broker_oidc_nonce=; Max-Age=0; Path=/',
          'broker_oidc_verifier=; Max-Age=0; Path=/',
          'broker_oidc_bind=; Max-Age=0; Path=/',
        ],
      })
      return res.end()
    } catch (error) {
      return html(res, loginPage(`OIDC 登录失败：${String(error?.message ?? error)}`))
    }
  }

  const approveMatch = url.pathname.match(/^\/approve\/([^/]+)$/)
  if (req.method === 'GET' && approveMatch) {
    const id = approveMatch[1]
    const decision = url.searchParams.get('d') ?? ''
    const exp = Number(url.searchParams.get('exp') ?? 0)
    const sig = url.searchParams.get('sig') ?? ''
    const expected = approvalSignature(id, decision, exp)
    const valid = exp > Date.now() && sig.length > 0 && expected.length === sig.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))
    if (!valid) return html(res, '<h2>链接无效或已过期</h2><p><a href="/">打开管理页</a></p>')
    const outcome = decideRequest(id, decision, 'ntfy')
    return html(
      res,
      `<h2>${outcome.ok ? '已处理' : '处理失败'}</h2><p>${outcome.ok ? `已选择：${esc(decision)}` : esc(outcome.error)}</p><p><a href="/">打开管理页</a></p>`,
    )
  }

  const oauthMetadataPaths = new Set([
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-authorization-server/mcp',
  ])
  if (req.method === 'GET' && oauthMetadataPaths.has(url.pathname)) {
    res.setHeader('access-control-allow-origin', '*')
    if (url.pathname.includes('protected-resource')) return json(res, 200, oauthProtectedResource())
    return json(res, 200, oauthServerMetadata())
  }

  if (req.method === 'POST' && url.pathname === '/oauth/register') {
    try {
      const body = await parseBody(req)
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((uri) => typeof uri === 'string') : []
      if (redirectUris.length === 0) return json(res, 400, { error: 'invalid_client_metadata', error_description: 'redirect_uris is required' })
      const clientId = `mcp_${randomUrlSafe(12)}`
      config.oauthClients ??= {}
      config.oauthClients[clientId] = {
        clientId,
        clientName: typeof body.client_name === 'string' ? body.client_name.slice(0, 120) : 'MCP client',
        redirectUris,
        createdAt: new Date().toISOString(),
      }
      saveConfig()
      audit({ event: 'oauth.client-register', clientId, clientName: config.oauthClients[clientId].clientName })
      res.setHeader('access-control-allow-origin', '*')
      return json(res, 201, {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_name: config.oauthClients[clientId].clientName,
        redirect_uris: redirectUris,
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      })
    } catch (error) {
      return json(res, 400, { error: 'invalid_client_metadata', error_description: String(error?.message ?? error) })
    }
  }

  if (req.method === 'GET' && url.pathname === '/oauth/authorize') {
    const params = Object.fromEntries(url.searchParams.entries())
    const client = config.oauthClients?.[params.client_id]
    if (!client) return html(res, oauthConsentPage(params, undefined, '未知的 client_id'))
    if (!client.redirectUris.includes(params.redirect_uri)) return html(res, oauthConsentPage(params, client, 'redirect_uri 未注册'))
    if (params.response_type !== 'code') return html(res, oauthConsentPage(params, client, '仅支持 response_type=code'))
    if (!params.code_challenge || params.code_challenge_method !== 'S256') return html(res, oauthConsentPage(params, client, '仅支持 PKCE S256'))
    return html(res, oauthConsentPage(params, client, '', isAdmin(req)))
  }

  if (req.method === 'POST' && url.pathname === '/oauth/approve') {
    const body = await parseBody(req)
    const params = body
    const client = config.oauthClients?.[params.client_id]
    if (!client) return html(res, '<h2>未知的 client_id</h2>')
    if (!client.redirectUris.includes(params.redirect_uri)) return html(res, '<h2>redirect_uri 未注册</h2>')
    let authorized = isAdmin(req)
    if (!authorized) {
      if (body.password === ADMIN_PASSWORD) {
        authorized = true
      } else if (config.profile?.totpEnabled && verifyTotp(config.profile.totpSecret, String(body.code ?? ''))) {
        authorized = true
      }
    }
    if (!authorized) return html(res, oauthConsentPage(params, client, '密码或验证码错误', false))
    if (params.decision !== 'allow') {
      res.writeHead(302, { location: redirectWith(params.redirect_uri, { error: 'access_denied', state: params.state }) })
      return res.end()
    }
    const code = randomUrlSafe(32)
    oauthCodes.set(code, {
      clientId: params.client_id,
      redirectUri: params.redirect_uri,
      codeChallenge: params.code_challenge,
      scope: params.scope ?? OAUTH_SCOPE,
      expiresAt: Date.now() + 5 * 60 * 1000,
    })
    audit({ event: 'oauth.authorize', clientId: params.client_id })
    res.writeHead(302, { location: redirectWith(params.redirect_uri, { code, state: params.state }) })
    return res.end()
  }

  if (req.method === 'POST' && url.pathname === '/oauth/token') {
    const body = await parseBody(req)
    if (body.grant_type !== 'authorization_code') return json(res, 400, { error: 'unsupported_grant_type' })
    const entry = oauthCodes.get(String(body.code ?? ''))
    if (!entry || entry.expiresAt < Date.now()) return json(res, 400, { error: 'invalid_grant' })
    oauthCodes.delete(String(body.code))
    if (String(body.client_id) !== entry.clientId) return json(res, 400, { error: 'invalid_grant' })
    if (String(body.redirect_uri) !== entry.redirectUri) return json(res, 400, { error: 'invalid_grant' })
    if (!pkceMatches(String(body.code_verifier ?? ''), entry.codeChallenge)) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' })
    const accessToken = randomUrlSafe(32)
    const agent = `oauth:${entry.clientId}`
    config.oauthTokens ??= {}
    for (const [key, token] of Object.entries(config.oauthTokens)) {
      if (token.expiresAt <= Date.now()) delete config.oauthTokens[key]
    }
    config.oauthTokens[hashToken(accessToken)] = {
      clientId: entry.clientId,
      agent,
      expiresAt: Date.now() + 24 * 3600e3,
      createdAt: new Date().toISOString(),
    }
    saveConfig()
    audit({ event: 'oauth.token-issue', clientId: entry.clientId, agent })
    res.setHeader('access-control-allow-origin', '*')
    return json(res, 200, { access_token: accessToken, token_type: 'Bearer', expires_in: 86400, scope: entry.scope })
  }

  if (!isAgentPath) {
    if (req.method === 'GET' && url.pathname === '/login') {
      return html(res, loginPage())
    }
    if (req.method === 'POST' && url.pathname === '/login') {
      const throttle = loginThrottle(req)
      if (throttle.blocked) {
        audit({ event: 'admin.login-blocked', ip: throttle.ip })
        res.writeHead(429, { 'content-type': 'text/html; charset=utf-8' })
        return res.end(loginPage('尝试次数过多，请 5 分钟后再试'))
      }
      const body = form(await readBody(req))
      if (body.get('password') === ADMIN_PASSWORD) {
        if (config.profile?.totpEnabled) {
          if (!verifyTotp(config.profile.totpSecret, body.get('code') ?? '')) {
            recordLoginFailure(throttle.ip)
            audit({ event: 'admin.2fa-fail', ip: throttle.ip })
            return html(res, loginPage('两步验证码错误'))
          }
        }
        loginFailures.delete(throttle.ip)
        res.writeHead(303, {
          location: '/',
          'set-cookie': `broker_admin=${adminCookieValue()}; HttpOnly; SameSite=Lax; Path=/`,
        })
        return res.end()
      }
      recordLoginFailure(throttle.ip)
      audit({ event: 'admin.login-fail', ip: throttle.ip })
      return html(res, loginPage('密码错误'))
    }
    if (!AUTH_REQUIRED) {
      if (!isLocal) {
        return json(res, 403, {
          error: 'local only; set SECRETS_BROKER_ADMIN_PASSWORD to allow remote administration',
        })
      }
    } else if (!isAdmin(req)) {
      return html(res, loginPage(''))
    }
  }

  try {
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      if (wantsJson(req)) {
        res.setHeader('set-cookie', 'broker_admin=; Max-Age=0; Path=/')
        return json(res, 200, { ok: true })
      }
      res.writeHead(303, { location: '/', 'set-cookie': 'broker_admin=; Max-Age=0; Path=/' })
      return res.end()
    }
    if (req.method === 'GET' && url.pathname === '/') return html(res, dashboardShellV2())

    if (req.method === 'POST' && url.pathname === '/api/unlock') {
      const body = form(await readBody(req))
      const result = await unlock(body.get('password') ?? '')
      invalidateItems()
      if (wantsJson(req)) return json(res, result.ok ? 200 : 400, result)
      res.writeHead(result.ok ? 303 : 400, result.ok ? { location: '/' } : { 'content-type': 'text/plain; charset=utf-8' })
      res.end(result.ok ? '' : `解锁失败：${result.error ?? '未知错误'}`)
      return
    }
    if (req.method === 'POST' && url.pathname === '/api/lock') {
      lock()
      invalidateItems()
      if (wantsJson(req)) return json(res, 200, { ok: true })
      res.writeHead(303, { location: '/' })
      return res.end()
    }
    if (req.method === 'POST' && url.pathname === '/api/import') {
      if (!state.unlocked) return json(res, 409, { error: '请先解锁' })
      state.lastImport = await importLocalSecrets()
      invalidateItems()
      if (wantsJson(req)) return json(res, 200, state.lastImport)
      res.writeHead(303, { location: '/' })
      return res.end()
    }
    if (req.method === 'GET' && url.pathname === '/api/items') {
      if (!state.unlocked) return json(res, 409, { error: 'locked' })
      const force = url.searchParams.get('sync') === '1'
      if (force) {
        const synced = await runBw(['sync'])
        if (synced.code !== 0) return json(res, 502, { error: (synced.stderr || synced.stdout).trim().slice(0, 400) })
      }
      const items = (await listItemsCached(force)).map((item) => ({
        name: item.name,
        id: item.id,
        type: item.type,
        url: itemUrl(item),
        group: config.itemGroups?.[item.name] ?? '',
      }))
      return json(res, 200, { items })
    }
    if (req.method === 'GET' && url.pathname === '/api/items/match') {
      const target = url.searchParams.get('url') ?? ''
      const items = await listItemsCached()
      const matches = items
        .filter((item) => itemMatchesUrl(item, target))
        .map((item) => ({ name: item.name, id: item.id, url: itemUrl(item), group: config.itemGroups?.[item.name] ?? '' }))
      return json(res, 200, { url: target, matches })
    }
    if (req.method === 'GET' && url.pathname === '/api/agents') {
      const tokens = loadAgentTokens()
      const agents = Object.entries(config.agents ?? {}).map(([name, token]) => ({
        name,
        tokenPreview: tokens[name] ? maskToken(tokens[name]) : `sha256:${String(token).slice(7, 11)}…`,
        allow: config.agentAccess?.[name] ?? [],
        write: config.agentWrite?.[name] === true,
      }))
      return json(res, 200, { agents })
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/token') {
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      if (!config.agents[name]) return json(res, 404, { error: 'unknown agent' })
      const tokens = loadAgentTokens()
      if (!tokens[name]) return json(res, 409, { error: '该 agent 的明文 token 不在本机 token 文件中，请轮换生成新 token' })
      audit({ event: 'agent.token-reveal', agent: name })
      return json(res, 200, { name, token: tokens[name] })
    }
    if (req.method === 'POST' && url.pathname === '/api/items/save') {
      if (!state.unlocked) return json(res, 409, { error: 'locked' })
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      const value = body.get('value') || undefined
      const notes = body.get('notes') || undefined
      const targetUrl = body.get('url') || undefined
      const group = (body.get('group') ?? '').trim()
      try {
        const result = await saveItem(name, value, notes, targetUrl)
        config.itemGroups ??= {}
        if (group.length === 0) delete config.itemGroups[name]
        else config.itemGroups[name] = group
        saveConfig()
        invalidateItems()
        return json(res, 200, result)
      } catch (error) {
        return json(res, 400, { error: String(error.message ?? error) })
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/items/delete') {
      if (!state.unlocked) return json(res, 409, { error: 'locked' })
      const body = form(await readBody(req))
      try {
        await deleteItem(body.get('name') ?? '')
        invalidateItems()
        return json(res, 200, { ok: true })
      } catch (error) {
        return json(res, 400, { error: String(error.message ?? error) })
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/add') {
      const body = form(await readBody(req))
      const name = (body.get('name') ?? '').trim()
      if (!/^[A-Za-z0-9._-]{1,32}$/.test(name)) return json(res, 400, { error: 'invalid agent name' })
      if (config.agents[name]) return json(res, 409, { error: 'agent already exists' })
      const newToken = randomToken()
      config.agents[name] = hashToken(newToken)
      const tokens = loadAgentTokens()
      tokens[name] = newToken
      saveAgentTokens(tokens)
      saveConfig()
      audit({ event: 'agent.add', agent: name })
      return json(res, 200, { name, token: newToken })
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/write') {
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      if (!config.agents[name]) return json(res, 404, { error: 'unknown agent' })
      config.agentWrite ??= {}
      config.agentWrite[name] = body.get('allow') === '1'
      saveConfig()
      audit({ event: 'agent.write-access', agent: name, allow: config.agentWrite[name] })
      return json(res, 200, { name, allow: config.agentWrite[name] })
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/access') {
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      if (!config.agents[name]) return json(res, 404, { error: 'unknown agent' })
      const raw = (body.get('allow') ?? '').trim()
      config.agentAccess ??= {}
      config.agentAccess[name] = raw.length === 0 ? [] : raw.split(',').map((part) => part.trim()).filter(Boolean)
      saveConfig()
      audit({ event: 'agent.access', agent: name, allow: config.agentAccess[name] })
      return json(res, 200, { agent: name, allow: config.agentAccess[name] })
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/rotate') {
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      if (!config.agents[name]) return json(res, 404, { error: 'unknown agent' })
      const newToken = randomToken()
      config.agents[name] = hashToken(newToken)
      const tokens = loadAgentTokens()
      tokens[name] = newToken
      saveAgentTokens(tokens)
      saveConfig()
      audit({ event: 'agent.rotate', agent: name })
      return json(res, 200, { name, token: newToken })
    }
    if (req.method === 'POST' && url.pathname === '/api/agents/delete') {
      const body = form(await readBody(req))
      const name = body.get('name') ?? ''
      if (!config.agents[name]) return json(res, 404, { error: 'unknown agent' })
      delete config.agents[name]
      const tokens = loadAgentTokens()
      delete tokens[name]
      saveAgentTokens(tokens)
      grants = grants.filter((grant) => grant.agent !== name)
      saveConfig()
      saveGrants()
      audit({ event: 'agent.delete', agent: name })
      return json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/revoke') {
      const body = form(await readBody(req))
      const grant = revokeGrant(body.get('agent') ?? '', body.get('name') ?? '')
      return grant === undefined ? json(res, 404, { error: 'unknown grant' }) : json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/restore') {
      const body = form(await readBody(req))
      const grant = restoreGrant(body.get('agent') ?? '', body.get('name') ?? '')
      return grant === undefined ? json(res, 404, { error: 'unknown grant' }) : json(res, 200, { grant })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/extend') {
      const body = form(await readBody(req))
      const grant = extendGrant(body.get('agent') ?? '', body.get('name') ?? '', Number(body.get('seconds') ?? 0))
      return grant === undefined ? json(res, 404, { error: 'unknown grant' }) : json(res, 200, { grant })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/set-expiry') {
      const body = form(await readBody(req))
      const raw = (body.get('expiresAt') ?? '').trim()
      const expiresAt = raw === '' ? null : Date.parse(raw)
      if (expiresAt !== null && Number.isNaN(expiresAt)) return json(res, 400, { error: 'invalid expiresAt' })
      const grant = setGrantExpiry(body.get('agent') ?? '', body.get('name') ?? '', expiresAt)
      return grant === undefined ? json(res, 404, { error: 'unknown grant' }) : json(res, 200, { grant })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/delete') {
      const body = form(await readBody(req))
      deleteGrant(body.get('agent') ?? '', body.get('name') ?? '')
      return json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/grants/create') {
      const body = form(await readBody(req))
      const agent = (body.get('agent') ?? '').trim()
      const name = (body.get('name') ?? '').trim()
      if (!config.agents[agent]) return json(res, 404, { error: 'unknown agent' })
      if (!validName(name)) return json(res, 400, { error: 'invalid item name' })
      const hours = Number(body.get('ttlHours') ?? 0)
      const maxReads = Number(body.get('maxReads') ?? 0)
      const grant = addGrant(agent, name, 'share', hours > 0 ? hours * 3600e3 : null, maxReads > 0 ? maxReads : null)
      audit({ event: 'grant.share', agent, name, ttlHours: hours, maxReads: maxReads || null })
      return json(res, 200, { grant })
    }
    if (req.method === 'GET' && url.pathname === '/api/status') {
      return json(res, 200, {
        unlocked: state.unlocked,
        pending: [...state.pending.values()].filter((entry) => entry.status === 'pending').length,
        grants: grants.filter((grant) => grantActive(grant)).length,
        agents: Object.keys(config.agents ?? {}),
        autoUnlock: fs.existsSync(MASTER_PASSWORD_FILE),
        oidc: OIDC_ENABLED,
        ntfy: NTFY_URL.length > 0,
        publicUrl: PUBLIC_URL,
      })
    }

    if (req.method === 'GET' && url.pathname === '/api/audit') {
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 200) || 200, 1000)
      const offset = Math.max(Number(url.searchParams.get('offset') ?? 0) || 0, 0)
      const agentFilter = (url.searchParams.get('agent') ?? '').trim().toLowerCase()
      const eventFilter = (url.searchParams.get('event') ?? '').trim().toLowerCase()
      const nameFilter = (url.searchParams.get('name') ?? '').trim().toLowerCase()
      let entries = []
      try {
        const lines = fs.existsSync(AUDIT_PATH) ? fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n') : []
        entries = lines
          .map((line) => {
            try {
              return JSON.parse(line)
            } catch {
              return undefined
            }
          })
          .filter(Boolean)
          .reverse()
      } catch {
        entries = []
      }
      if (agentFilter) entries = entries.filter((entry) => String(entry.agent ?? '').toLowerCase() === agentFilter)
      if (eventFilter) entries = entries.filter((entry) => String(entry.event ?? '').toLowerCase().includes(eventFilter))
      if (nameFilter) entries = entries.filter((entry) => String(entry.name ?? '').toLowerCase().includes(nameFilter))
      return json(res, 200, { total: entries.length, entries: entries.slice(offset, offset + limit) })
    }

    if (req.method === 'POST' && url.pathname === '/api/auto-unlock/disable') {
      try {
        if (fs.existsSync(MASTER_PASSWORD_FILE)) fs.unlinkSync(MASTER_PASSWORD_FILE)
        audit({ event: 'auto-unlock.disable' })
        return json(res, 200, { ok: true, autoUnlock: false })
      } catch (error) {
        return json(res, 500, { error: String(error?.message ?? error) })
      }
    }

    if (req.method === 'GET' && url.pathname === '/api/settings') {
      return json(res, 200, {
        publicUrl: PUBLIC_URL,
        serverUrl: config.serverUrl ?? '',
        oidc: {
          issuer: OIDC_ISSUER,
          clientId: OIDC_CLIENT_ID,
          hasSecret: OIDC_CLIENT_SECRET.length > 0,
          redirectUri: OIDC_REDIRECT_URI,
          authorizationEndpoint: config.oidc?.authorizationEndpoint ?? '',
          tokenEndpoint: config.oidc?.tokenEndpoint ?? '',
          userinfoEndpoint: config.oidc?.userinfoEndpoint ?? '',
          jwksUri: config.oidc?.jwksUri ?? '',
          scope: config.oidc?.scope ?? OIDC_SCOPE,
          claims: config.oidc?.claims ?? {},
        },
        ntfyUrl: NTFY_URL,
        port: config.port,
        bind: BIND,
        autoUnlock: fs.existsSync(MASTER_PASSWORD_FILE),
        encryptionKeyFingerprint: encryptionFingerprint(),
        agents: Object.keys(config.agents ?? {}),
        agentWrite: config.agentWrite ?? {},
        profile: { name: config.profile?.name ?? '', email: config.profile?.email ?? '', phone: config.profile?.phone ?? '', avatarUrl: config.profile?.avatarUrl ?? '', totpEnabled: config.profile?.totpEnabled === true, oidcBound: Boolean(config.profile?.oidcSub), oidcEmail: config.profile?.oidcEmail ?? '' },
        telegram: { configured: Boolean(TELEGRAM_TOKEN && telegramChat()), chatId: telegramChat() },
        gotify: { configured: Boolean(GOTIFY_URL && GOTIFY_TOKEN), url: GOTIFY_URL },
        wxpush: { configured: Boolean(WXPUSH_URL && WXPUSH_TOKEN), url: WXPUSH_URL },
      })
    }

    if (req.method === 'POST' && url.pathname === '/api/settings') {
      const body = await parseBody(req)
      if (typeof body.publicUrl === 'string') config.publicUrl = body.publicUrl.trim().replace(/\/+$/, '')
      if (typeof body.serverUrl === 'string') config.serverUrl = body.serverUrl.trim()
      if (typeof body.ntfyUrl === 'string') config.ntfyUrl = body.ntfyUrl.trim()
      config.oidc ??= {}
      if (typeof body.oidcIssuer === 'string') config.oidc.issuer = body.oidcIssuer.trim().replace(/\/+$/, '')
      if (typeof body.oidcClientId === 'string') config.oidc.clientId = body.oidcClientId.trim()
      if (typeof body.oidcClientSecret === 'string') config.oidc.clientSecret = body.oidcClientSecret
      if (typeof body.oidcRedirectUri === 'string') config.oidc.redirectUri = body.oidcRedirectUri.trim()
      if (typeof body.oidcScope === 'string') config.oidc.scope = body.oidcScope.trim() || 'openid profile email'
      if (typeof body.oidcAuthorizationEndpoint === 'string') config.oidc.authorizationEndpoint = body.oidcAuthorizationEndpoint.trim()
      if (typeof body.oidcTokenEndpoint === 'string') config.oidc.tokenEndpoint = body.oidcTokenEndpoint.trim()
      if (typeof body.oidcUserinfoEndpoint === 'string') config.oidc.userinfoEndpoint = body.oidcUserinfoEndpoint.trim()
      if (typeof body.oidcJwksUri === 'string') config.oidc.jwksUri = body.oidcJwksUri.trim()
      config.oidc.claims ??= {}
      for (const [key, field] of [
        ['identifier', 'oidcClaimIdentifier'],
        ['name', 'oidcClaimName'],
        ['email', 'oidcClaimEmail'],
        ['avatar', 'oidcClaimAvatar'],
      ]) {
        if (typeof body[field] === 'string') config.oidc.claims[key] = body[field].trim()
      }
      if (typeof body.telegramToken === 'string') config.telegram.token = body.telegramToken.trim()
      if (typeof body.telegramChatId === 'string') config.telegram.chatId = body.telegramChatId.trim()
      config.gotify ??= {}
      if (typeof body.gotifyUrl === 'string') config.gotify.url = body.gotifyUrl.trim().replace(/\/+$/, '')
      if (typeof body.gotifyToken === 'string') config.gotify.token = body.gotifyToken.trim()
      config.wxpush ??= {}
      if (typeof body.wxpushUrl === 'string') config.wxpush.url = body.wxpushUrl.trim().replace(/\/+$/, '')
      if (typeof body.wxpushToken === 'string') config.wxpush.token = body.wxpushToken.trim()
      saveConfig()
      refreshRuntimeSettings()
      audit({ event: 'settings.update' })
      return json(res, 200, { ok: true, restartRequired: Boolean(body.telegramToken || body.telegramChatId) })
    }

    if (req.method === 'GET' && url.pathname === '/api/profile') {
      return json(res, 200, {
        name: config.profile?.name ?? '',
        email: config.profile?.email ?? '',
        phone: config.profile?.phone ?? '',
        avatarUrl: config.profile?.avatarUrl ?? '',
        totpEnabled: config.profile?.totpEnabled === true,
        oidcBound: Boolean(config.profile?.oidcSub),
        oidcEmail: config.profile?.oidcEmail ?? '',
        oidcEnabled: OIDC_ENABLED,
        oidcIssuer: OIDC_ISSUER,
        oidcSubMasked: config.profile?.oidcSub ? `${String(config.profile.oidcSub).slice(0, 6)}…${String(config.profile.oidcSub).slice(-4)}` : '',
      })
    }
    if (req.method === 'POST' && url.pathname === '/api/profile') {
      const body = await parseBody(req)
      config.profile ??= {}
      for (const key of ['name', 'email', 'phone', 'avatarUrl']) {
        if (typeof body[key] === 'string') config.profile[key] = body[key].trim()
      }
      saveConfig()
      audit({ event: 'profile.update' })
      return json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/profile/totp/setup') {
      config.profile ??= {}
      const secret = generateTotpSecret()
      config.profile.totpPending = secret
      saveConfig()
      const issuer = encodeURIComponent('Secrets Broker')
      const account = encodeURIComponent(config.profile.email || 'admin')
      return json(res, 200, {
        secret,
        otpauth: `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
      })
    }
    if (req.method === 'POST' && url.pathname === '/api/profile/totp/enable') {
      const body = await parseBody(req)
      const secret = config.profile?.totpPending
      if (!secret) return json(res, 400, { error: '请先生成 2FA 密钥' })
      if (!verifyTotp(secret, String(body.code ?? ''))) return json(res, 400, { error: '验证码错误' })
      config.profile.totpSecret = secret
      config.profile.totpEnabled = true
      delete config.profile.totpPending
      saveConfig()
      audit({ event: 'profile.2fa-enable' })
      return json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/profile/totp/disable') {
      config.profile ??= {}
      config.profile.totpEnabled = false
      config.profile.totpSecret = ''
      delete config.profile.totpPending
      saveConfig()
      audit({ event: 'profile.2fa-disable' })
      return json(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/api/profile/oidc/unbind') {
      config.profile ??= {}
      config.profile.oidcSub = ''
      config.profile.oidcEmail = ''
      saveConfig()
      audit({ event: 'profile.oidc-unbind' })
      return json(res, 200, { ok: true })
    }

    if (req.method === 'POST' && url.pathname === '/api/restart') {
      audit({ event: 'server.restart' })
      json(res, 200, { ok: true })
      setTimeout(() => process.exit(0), 400)
      return
    }

    if (req.method === 'POST' && url.pathname === '/api/ntfy/test') {
      if (!NTFY_URL) return json(res, 400, { error: 'ntfy not configured' })
      try {
        const response = await fetch(NTFY_URL, {
          method: 'POST',
          headers: { Title: 'Secrets Broker test', Tags: 'bell' },
          body: 'Secrets Broker 测试通知',
        })
        return json(res, 200, { ok: response.ok, status: response.status })
      } catch (error) {
        return json(res, 502, { error: String(error?.message ?? error) })
      }
    }

    if (req.method === 'GET' && url.pathname === '/api/stats') {
      const range = url.searchParams.get('range') ?? '24h'
      const hours = range === '30d' ? 720 : range === '7d' ? 168 : range === '3d' ? 72 : 24
      const bucketHours = hours <= 72 ? 1 : hours <= 168 ? 6 : 24
      const bucketMs = bucketHours * 3600e3
      const now = Date.now()
      let entries = []
      try {
        const lines = fs.existsSync(AUDIT_PATH) ? fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n') : []
        entries = lines
          .map((line) => {
            try {
              return JSON.parse(line)
            } catch {
              return undefined
            }
          })
          .filter(Boolean)
      } catch {
        entries = []
      }
      const from = now - hours * 3600e3
      const reads = entries.filter((entry) => entry.event === 'secret.read' && Date.parse(entry.time) >= from)
      const buckets = Array.from({ length: Math.ceil(hours / bucketHours) }, (_, index) => {
        const start = now - (hours - index * bucketHours) * 3600e3
        return { time: start, label: new Date(start).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit' }).replace(/\//g, '-'), count: 0 }
      })
      const byAgent = {}
      const byItem = {}
      for (const entry of reads) {
        const time = Date.parse(entry.time)
        const index = Math.max(0, buckets.length - 1 - Math.floor((now - time) / bucketMs))
        if (buckets[index]) buckets[index].count += 1
        byAgent[entry.agent] = (byAgent[entry.agent] ?? 0) + 1
        byItem[entry.name] = (byItem[entry.name] ?? 0) + 1
      }
      const pending = [...state.pending.values()].filter((entry) => entry.status === 'pending').length
      return json(res, 200, {
        range,
        hours,
        buckets,
        totalReads: reads.length,
        activeAgents: Object.keys(byAgent).length,
        pending,
        activeGrants: grants.filter((grant) => grantActive(grant)).length,
        topItems: Object.entries(byItem).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, count]) => ({ name, count })),
        topAgents: Object.entries(byAgent).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([agent, count]) => ({ agent, count })),
      })
    }

    if (req.method === 'GET' && url.pathname === '/api/pending') {
      const requests = [...state.pending.values()]
        .filter((entry) => entry.status === 'pending')
        .map((entry) => ({ id: entry.id, agent: entry.agent, name: entry.name, createdAt: entry.createdAt }))
      return json(res, 200, { requests })
    }

    if (req.method === 'GET' && url.pathname === '/api/grants-list') {
      return json(res, 200, { grants: grants.map((grant) => ({ ...grant, active: grantActive(grant) })) })
    }

    const decideMatch = url.pathname.match(/^\/api\/requests\/([^/]+)\/decide$/)
    if (req.method === 'POST' && decideMatch) {
      const body = form(await readBody(req))
      const decision = body.get('decision')
      const entry = state.pending.get(decideMatch[1])
      if (entry === undefined || entry.status !== 'pending') {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
        return res.end('请求不存在或已处理')
      }
      if (!state.unlocked) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
        return res.end('请先解锁 vault')
      }
      if (decision === 'deny') {
        entry.status = 'denied'
        audit({ event: 'request.deny', agent: entry.agent, name: entry.name })
      } else if (decision === 'once') {
        entry.status = 'approved'
        entry.mode = 'once'
        audit({ event: 'request.approve', mode: 'once', agent: entry.agent, name: entry.name })
      } else {
        const ttl = decision === '1h' ? 3600e3 : decision === '24h' ? 86400e3 : decision === '7d' ? 7 * 86400e3 : null
        addGrant(entry.agent, entry.name, decision, ttl)
        entry.status = 'approved'
        entry.mode = decision
        audit({ event: 'request.approve', mode: decision, agent: entry.agent, name: entry.name })
      }
      res.writeHead(303, { location: '/' })
      res.end()
      return
    }

    // ---- agent API ----
    const agent = agentFromRequest(req)
    if (url.pathname.startsWith('/secret') || url.pathname.startsWith('/agent/') || url.pathname === '/mcp') {
      if (agent === undefined) {
        if (url.pathname === '/mcp') {
          res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`)
        }
        return json(res, 401, { error: 'invalid agent token' })
      }
      if (!state.unlocked) return json(res, 503, { error: 'vault locked' })
      if (url.pathname === '/mcp') {
        const request = await parseBody(req)
        const id = request?.id
        const reply = (result) => json(res, 200, { jsonrpc: '2.0', id, result })
        const fail = (code, message) => json(res, 200, { jsonrpc: '2.0', id, error: { code, message } })
        const allowRead = process.env.MCP_ALLOW_READ === '1' || config.mcpAllowRead === true
        const httpTools = [
          { name: 'list_secrets', description: '列出该 agent 可读的密钥条目名（不返回值）。', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
          { name: 'create_secret', description: '新增/更新密钥条目（需要该 agent 有写入权限）。', inputSchema: { type: 'object', properties: { name: { type: 'string' }, value: { type: 'string' }, notes: { type: 'string' }, url: { type: 'string' }, group: { type: 'string' } }, required: ['name', 'value'], additionalProperties: false } },
          { name: 'request_access', description: '发起读取申请（会出现在管理页/Telegram/ntfy 审批）。', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'], additionalProperties: false } },
        ]
        if (allowRead) {
          httpTools.push({ name: 'get_secret', description: '读取密钥明文（需要已有授权；值会进入模型上下文）。', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'], additionalProperties: false } })
        }
        const method = request?.method
        if (method === 'initialize') {
          return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'secrets-broker-http-mcp', version: '1.0.0' } })
        }
        if (method === 'notifications/initialized' || method === 'initialized') {
          res.writeHead(202)
          return res.end()
        }
        if (method === 'ping') return reply({})
        if (method === 'tools/list') return reply({ tools: httpTools })
        if (method === 'tools/call') {
          const toolName = request?.params?.name
          const args = request?.params?.arguments ?? {}
          try {
            audit({ event: 'mcp.call', agent, tool: toolName, name: args?.name })
            if (toolName === 'list_secrets') {
              const items = (await listItemsCached()).filter((item) => agentAllowed(agent, item.name))
              return reply({ content: [{ type: 'text', text: items.map((item) => `${item.name}${itemUrl(item) ? ` — ${itemUrl(item)}` : ''}`).join('\n') || '(no items)' }] })
            }
            if (toolName === 'create_secret') {
              if (config.agentWrite?.[agent] !== true) throw new Error(`agent "${agent}" is not allowed to create items`)
              const name = String(args.name ?? '').trim()
              if (!validName(name)) throw new Error('invalid item name')
              const result = await saveItem(name, String(args.value ?? ''), typeof args.notes === 'string' ? args.notes : undefined, typeof args.url === 'string' ? args.url : undefined)
              config.itemGroups ??= {}
              const group = String(args.group ?? '').trim()
              if (group.length === 0) delete config.itemGroups[name]
              else config.itemGroups[name] = group
              saveConfig()
              invalidateItems()
              audit({ event: 'secret.write', agent, name, via: 'mcp' })
              return reply({ content: [{ type: 'text', text: result.updated ? `updated ${name}` : `created ${name}` }] })
            }
            if (toolName === 'request_access') {
              const name = String(args.name ?? '').trim()
              if (!validName(name)) throw new Error('invalid item name')
              const entry = await createPending(agent, name)
              return reply({ content: [{ type: 'text', text: `approval required: ${PUBLIC_URL}/ (request ${entry.id})` }] })
            }
            if (toolName === 'get_secret') {
              if (!allowRead) throw new Error('get_secret is disabled (set MCP_ALLOW_READ=1)')
              const name = String(args.name ?? '').trim()
              if (!validName(name)) throw new Error('invalid item name')
              if (!agentAllowed(agent, name)) throw new Error(`agent "${agent}" is not allowed to read "${name}"`)
              if (validGrant(agent, name) === undefined) throw new Error(`no active grant; call request_access first (${PUBLIC_URL}/)`)
              const value = await readItemValue(name)
              const grant = validGrant(agent, name)
              grant.reads = (grant.reads ?? 0) + 1
              saveGrants()
              audit({ event: 'secret.read', agent, name, mode: 'grant', via: 'mcp' })
              return reply({ content: [{ type: 'text', text: value }] })
            }
            throw new Error(`unknown tool: ${toolName}`)
          } catch (error) {
            return fail(-32000, String(error?.message ?? error))
          }
        }
        return fail(-32601, `method not found: ${method}`)
      }
      if (req.method === 'GET' && url.pathname === '/agent/items') {
        let items = []
        try {
          items = (await listItemsCached()).map((item) => ({
            name: item.name,
            type: item.type,
            url: itemUrl(item),
            group: config.itemGroups?.[item.name] ?? '',
          }))
        } catch (error) {
          return json(res, 502, { error: String(error.message ?? error) })
        }
        return json(res, 200, { items: items.filter((item) => agentAllowed(agent, item.name)) })
      }
      if (req.method === 'POST' && url.pathname === '/agent/items/save') {
        if (config.agentWrite?.[agent] !== true) return json(res, 403, { error: `agent "${agent}" is not allowed to create items` })
        const body = await parseBody(req)
        const name = typeof body.name === 'string' ? body.name.trim() : ''
        const value = typeof body.value === 'string' ? body.value : undefined
        const notes = typeof body.notes === 'string' ? body.notes : undefined
        const targetUrl = typeof body.url === 'string' ? body.url : undefined
        const group = typeof body.group === 'string' ? body.group.trim() : ''
        if (!validName(name)) return json(res, 400, { error: 'invalid item name' })
        try {
          const result = await saveItem(name, value, notes, targetUrl)
          config.itemGroups ??= {}
          if (group.length === 0) delete config.itemGroups[name]
          else config.itemGroups[name] = group
          saveConfig()
          invalidateItems()
          audit({ event: 'secret.write', agent, name })
          return json(res, 200, result)
        } catch (error) {
          return json(res, 400, { error: String(error.message ?? error) })
        }
      }
      const pendingMatch = url.pathname.match(/^\/secret\/pending\/([^/]+)$/)
      if (req.method === 'GET' && pendingMatch) {
        const entry = state.pending.get(pendingMatch[1])
        if (entry === undefined || entry.agent !== agent) return json(res, 404, { error: 'unknown request' })
        if (entry.status === 'denied') return json(res, 403, { error: 'request denied' })
        if (!agentAllowed(agent, entry.name)) return json(res, 403, { error: `agent "${agent}" is not allowed to read "${entry.name}"` })
        if (entry.status !== 'approved') return json(res, 202, { status: 'pending', requestId: entry.id })
        try {
          const value = await readItemValue(entry.name)
          if (entry.mode === 'once') state.pending.delete(entry.id)
          audit({ event: 'secret.read', agent, name: entry.name, mode: entry.mode })
          return json(res, 200, { value })
        } catch (error) {
          return json(res, 502, { error: String(error.message ?? error) })
        }
      }
      if (req.method === 'GET' && url.pathname === '/secret') {
        let name = url.searchParams.get('name') ?? ''
        const targetUrl = url.searchParams.get('url') ?? ''
        if (name.length === 0 && targetUrl.length > 0) {
          let items = []
          try {
            items = await listItemsCached()
          } catch (error) {
            return json(res, 502, { error: String(error.message ?? error) })
          }
          const match = items.find((item) => itemMatchesUrl(item, targetUrl) && agentAllowed(agent, item.name))
          if (match === undefined) return json(res, 404, { error: `no item matches ${targetUrl}` })
          name = match.name
        }
        if (!validName(name)) return json(res, 400, { error: 'invalid name' })
        if (!agentAllowed(agent, name)) {
          audit({ event: 'secret.deny', agent, name, mode: 'allowlist' })
          return json(res, 403, { error: `agent "${agent}" is not allowed to read "${name}"` })
        }
        const grant = validGrant(agent, name)
        if (grant !== undefined) {
          try {
            const value = await readItemValue(name)
            grant.reads = (grant.reads ?? 0) + 1
            saveGrants()
            audit({ event: 'secret.read', agent, name, mode: grant.mode, reads: grant.reads, maxReads: grant.maxReads })
            return json(res, 200, { value })
          } catch (error) {
            return json(res, 502, { error: String(error.message ?? error) })
          }
        }
        const entry = await createPending(agent, name)
        return json(res, 202, { status: 'pending', requestId: entry.id, approveUrl: `http://127.0.0.1:${config.port}/` })
      }
    }

    json(res, 404, { error: 'not found' })
  } catch (error) {
    json(res, 500, { error: String(error?.message ?? error) })
  }
})

server.listen(config.port, BIND, () => {
  console.log(`[secrets-broker] listening on http://${BIND}:${config.port}${MOCK ? ' (MOCK)' : ''}`)
  console.log(`[secrets-broker] dashboard: http://${BIND === '0.0.0.0' ? '127.0.0.1' : BIND}:${config.port}/`)
  console.log(`[secrets-broker] admin auth: ${AUTH_REQUIRED ? 'password required' : 'local-only (no password set)'}`)
  console.log(`[secrets-broker] bw entry: ${config.bwJs}`)
  console.log(`[secrets-broker] agents: ${Object.keys(config.agents ?? {}).join(', ')}`)

  const autoPassword = readAutoUnlockPassword()
  const autoUnlockEnabled = Boolean(autoPassword)
  if (autoPassword) {
    unlock(autoPassword)
      .then((result) => {
        if (result.ok) console.log('[secrets-broker] auto-unlocked from SECRETS_BROKER_MASTER_PASSWORD')
        else console.log(`[secrets-broker] auto-unlock failed: ${result.error ?? 'unknown'}`)
      })
      .catch((error) => console.log(`[secrets-broker] auto-unlock error: ${String(error?.message ?? error)}`))
  }

  if (TELEGRAM_TOKEN) {
    console.log('[secrets-broker] telegram bot polling enabled')
    setInterval(() => {
      telegramPoll().catch(() => {})
    }, 2500)
  }
})
