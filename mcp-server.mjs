#!/usr/bin/env node
/**
 * Minimal MCP (stdio) adapter for the Secrets Broker.
 *
 * Env:
 *   BROKER_URL          default http://127.0.0.1:8788
 *   BROKER_AGENT_TOKEN  agent token (or BROKER_AGENT + BROKER_CONFIG to read it)
 *   BROKER_CONFIG       default ~/.secrets-broker/config.json
 *   MCP_ALLOW_READ=1    expose get_secret (returns plaintext to the model)
 *   MCP_APPROVAL_WAIT_SEC default 90
 *
 * Tools:
 *   list_secrets                     names only
 *   create_secret {name,value,notes} agent must have write access (page: Agents → 写入:开)
 *   get_secret {name}                only when MCP_ALLOW_READ=1; approval still required
 *   exec_with_secrets {command,args,vars} injects secrets into a child process env
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawn } from 'node:child_process'

const BROKER_URL = (process.env.BROKER_URL ?? 'http://127.0.0.1:8788').replace(/\/+$/, '')
const CONFIG_PATH = process.env.BROKER_CONFIG ?? path.join(os.homedir(), '.secrets-broker', 'config.json')
const ALLOW_READ = process.env.MCP_ALLOW_READ === '1'
const WAIT_MS = Number(process.env.MCP_APPROVAL_WAIT_SEC ?? 90) * 1000

let token = process.env.BROKER_AGENT_TOKEN ?? ''
if (!token) {
  const agent = process.env.BROKER_AGENT ?? 'dsh'
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8').replace(/^\uFEFF/, ''))
    token = config?.agents?.[agent] ?? ''
  } catch {
    token = ''
  }
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}
function log(...args) {
  console.error('[mcp-secrets]', ...args)
}

async function broker(path, { method = 'GET', body } = {}) {
  const response = await fetch(`${BROKER_URL}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { status: response.status, payload }
}

async function readSecret(name) {
  const first = await broker(`/secret?name=${encodeURIComponent(name)}`)
  if (first.status === 200) return { value: first.payload.value }
  if (first.status === 403) throw new Error(`access denied: ${first.payload.error ?? ''}`)
  if (first.status === 503) throw new Error('broker vault is locked; unlock it at the broker page')
  if (first.status !== 202) throw new Error(`broker error ${first.status}: ${first.payload.error ?? ''}`)
  const requestId = first.payload.requestId
  log(`approval pending for ${name} (${requestId})`)
  const deadline = Date.now() + WAIT_MS
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 2000))
    const poll = await broker(`/secret/pending/${requestId}`)
    if (poll.status === 200) return { value: poll.payload.value }
    if (poll.status === 403) throw new Error('approval denied')
    if (poll.status !== 202) throw new Error(`broker error ${poll.status}: ${poll.payload.error ?? ''}`)
  }
  throw new Error(`timed out waiting for approval; open ${BROKER_URL}/ and approve, then retry`)
}

const tools = [
  {
    name: 'list_secrets',
    description: '列出当前 agent 可读的密钥条目名（不返回密钥值）。',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'create_secret',
    description: '在 vault 中新增或更新一个密钥条目（需要该 agent 有写入权限）。',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: '条目名，可用 项目/环境/名称' },
        value: { type: 'string', description: '密钥值' },
        notes: { type: 'string', description: '备注（可选）' },
        url: { type: 'string', description: '对应网址（可选，用于按域名匹配）' },
        group: { type: 'string', description: '分组（可选）' },
      },
      required: ['name', 'value'],
      additionalProperties: false,
    },
  },
  {
    name: 'exec_with_secrets',
    description: '把指定密钥注入子进程环境变量后执行命令；密钥不会出现在模型上下文里。',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        args: { type: 'array', items: { type: 'string' } },
        vars: { type: 'object', additionalProperties: { type: 'string' }, description: 'ENV_NAME → 条目名' },
      },
      required: ['command', 'vars'],
      additionalProperties: false,
    },
  },
]
if (ALLOW_READ) {
  tools.push({
    name: 'get_secret',
    description: '读取密钥明文（仅当 MCP_ALLOW_READ=1；值会进入模型上下文，每次仍需审批）。',
    inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'], additionalProperties: false },
  })
}

async function callTool(name, args = {}) {
  if (name === 'list_secrets') {
    const result = await broker('/agent/items')
    if (result.status !== 200) throw new Error(result.payload.error ?? `HTTP ${result.status}`)
    return result.payload.items.map((item) => `${item.name} (${item.type})`).join('\n') || '(no items)'
  }
  if (name === 'create_secret') {
    const result = await broker('/agent/items/save', {
      method: 'POST',
      body: { name: args.name, value: args.value, notes: args.notes, url: args.url, group: args.group },
    })
    if (result.status !== 200) throw new Error(result.payload.error ?? `HTTP ${result.status}`)
    return result.payload.updated ? `updated ${result.payload.name}` : `created ${result.payload.name}`
  }
  if (name === 'get_secret') {
    if (!ALLOW_READ) throw new Error('get_secret is disabled (set MCP_ALLOW_READ=1)')
    const result = await readSecret(args.name)
    return result.value
  }
  if (name === 'exec_with_secrets') {
    const vars = args.vars ?? {}
    const injected = {}
    for (const [envName, itemName] of Object.entries(vars)) {
      injected[envName] = (await readSecret(itemName)).value
    }
    const child = spawn(args.command, args.args ?? [], {
      env: { ...process.env, ...injected },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    const code = await new Promise((resolve) => child.on('close', resolve))
    return `exit=${code}\n${stdout}${stderr ? `\n[stderr]\n${stderr}` : ''}`
  }
  throw new Error(`unknown tool: ${name}`)
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result })
}
function errorReply(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } })
}

let buffer = ''
process.stdin.on('data', async (chunk) => {
  buffer += chunk
  let index
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    if (!line) continue
    let message
    try {
      message = JSON.parse(line)
    } catch {
      continue
    }
    const { id, method, params } = message
    try {
      if (method === 'initialize') {
        reply(id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'secrets-broker-mcp', version: '1.0.0' },
        })
      } else if (method === 'notifications/initialized' || method === 'initialized') {
        // no response
      } else if (method === 'tools/list') {
        reply(id, { tools })
      } else if (method === 'tools/call') {
        const text = await callTool(params?.name, params?.arguments ?? {})
        reply(id, { content: [{ type: 'text', text: String(text) }] })
      } else if (method === 'ping') {
        reply(id, {})
      } else if (id !== undefined) {
        errorReply(id, -32601, `method not found: ${method}`)
      }
    } catch (error) {
      if (id !== undefined) errorReply(id, -32000, String(error?.message ?? error))
    }
  }
})
log(`ready (broker=${BROKER_URL}, read=${ALLOW_READ}, token=${token ? 'set' : 'missing'})`)
