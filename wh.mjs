#!/usr/bin/env node
/**
 * Agent-side helper for the Secrets Broker.
 *
 * Usage:
 *   node wh.mjs get <item-name>                                  # print one secret
 *   node wh.mjs run --var ENV=item [--var ...] -- cmd args...    # inject into a child process
 *
 * Environment:
 *   SECRETS_BROKER_URL    default http://127.0.0.1:8788
 *   SECRETS_BROKER_TOKEN  per-agent token (wins when set)
 *   SECRETS_BROKER_AGENT  agent name; token is read from the broker's config.json
 *   SECRETS_BROKER_HOME   default ~/.secrets-broker
 *
 * Exit codes: 0 ok, 2 approval timed out, 3 denied, 4 error.
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawn } from 'node:child_process'

const baseUrl = (process.env.SECRETS_BROKER_URL ?? 'http://127.0.0.1:8788').replace(/\/+$/, '')
const brokerHome = process.env.SECRETS_BROKER_HOME ?? path.join(os.homedir(), '.secrets-broker')
const agentName = process.env.SECRETS_BROKER_AGENT ?? ''
let token = process.env.SECRETS_BROKER_TOKEN ?? ''
if (!token && agentName) {
  try {
    const config = JSON.parse(fs.readFileSync(path.join(brokerHome, 'config.json'), 'utf8').replace(/^\uFEFF/, ''))
    token = config?.agents?.[agentName] ?? ''
  } catch {
    token = ''
  }
}
const timeoutMs = Number(process.env.SECRETS_BROKER_TIMEOUT_MS ?? 300000)

function fail(message, code = 4) {
  console.error(message)
  process.exit(code)
}

function requireToken() {
  if (!token) fail('no broker token: set SECRETS_BROKER_TOKEN or SECRETS_BROKER_AGENT')
}

async function request(pathname) {
  const response = await fetch(`${baseUrl}${pathname}`, { headers: { authorization: `Bearer ${token}` } })
  const payload = await response.json().catch(() => ({}))
  return { status: response.status, payload }
}

async function fetchSecret(name) {
  if (!name) fail('empty item name')
  const first = await request(`/secret?name=${encodeURIComponent(name)}`)
  if (first.status === 200) return first.payload.value
  if (first.status === 403) fail(`access denied for "${name}": ${first.payload.error ?? ''}`, 3)
  if (first.status === 503) fail(`broker vault is locked: ${first.payload.error ?? ''}`)
  if (first.status !== 202) fail(`broker error (${first.status}): ${first.payload.error ?? JSON.stringify(first.payload)}`)

  const requestId = first.payload.requestId
  console.error(`[wh] approval pending for "${name}" (request ${requestId}); open ${baseUrl}/`)
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 2000))
    const poll = await request(`/secret/pending/${requestId}`)
    if (poll.status === 200) return poll.payload.value
    if (poll.status === 403) fail(`access denied for "${name}"`, 3)
    if (poll.status !== 202) fail(`broker error (${poll.status}): ${poll.payload.error ?? JSON.stringify(poll.payload)}`)
  }
  fail(`timed out waiting for approval of "${name}"`, 2)
}

const mode = process.argv[2]

if (mode === 'get') {
  requireToken()
  const name = process.argv[3]
  if (!name) fail('usage: node wh.mjs get <item-name>')
  const value = await fetchSecret(name)
  process.stdout.write(`${value}\n`)
} else if (mode === 'run') {
  requireToken()
  const vars = []
  let index = 3
  for (; index < process.argv.length; index++) {
    const arg = process.argv[index]
    if (arg === '--') {
      index++
      break
    }
    if (arg === '--var') {
      const pair = process.argv[++index] ?? ''
      const eq = pair.indexOf('=')
      if (eq <= 0) fail(`invalid --var "${pair}" (expected NAME=item-name)`)
      vars.push({ envName: pair.slice(0, eq), item: pair.slice(eq + 1) })
      continue
    }
    fail(`unknown argument "${arg}" (usage: node wh.mjs run --var NAME=item -- command args...)`)
  }
  const command = process.argv[index]
  if (!command) fail('missing command after --')
  const commandArgs = process.argv.slice(index + 1)
  const injected = {}
  for (const entry of vars) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.envName)) fail(`invalid env name "${entry.envName}"`)
    injected[entry.envName] = await fetchSecret(entry.item)
  }
  const child = spawn(command, commandArgs, { stdio: 'inherit', env: { ...process.env, ...injected } })
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal)
    process.exit(code ?? 0)
  })
} else {
  fail('usage: node wh.mjs get <item-name> | node wh.mjs run --var NAME=item -- command args...')
}
