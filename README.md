# Secrets Broker

[![CI](https://github.com/otscup/secrets-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/otscup/secrets-broker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](package.json)

A small, self-hosted **secrets broker for AI agents**. It stores credentials in any
Bitwarden-compatible vault (NodeWarden, Vaultwarden, Bitwarden), and gives agents a
narrow API/MCP surface with per-agent tokens, explicit approvals, short-lived grants,
read limits and an audit log.

The important property: **the model never needs to see a secret**. Agents (or
connectors/plugins) ask the broker; the broker asks the human; the human approves once,
for an hour, a day, a week or forever. Every read is attributed to an agent and logged.

## Why

AI agents routinely need API keys, cookies, passwords and tokens. Pasting them into
prompts, `.env` files or tool configs is hard to audit and easy to leak. This project
keeps the vault where humans already manage it (Bitwarden clients, backups, 2FA) and
adds the missing agent-facing control plane.

- **Vault-native**: uses the Bitwarden CLI against your existing vault. No new
  encrypted database to operate.
- **Human in the loop**: first access opens a pending approval. Approve once, for a
  limited time, or permanently; revoke or restore later.
- **Per-agent identities**: each agent gets its own token (hashed at rest), item
  allowlists and optional write access. Rotate/delete independently.
- **Audit-first**: who requested what, when, from which channel, and how many reads.
- **Multiple approval channels**: web UI, ntfy, Telegram inline buttons, Gotify,
  wxpush (WeChat), or signed one-time links that need no login.
- **MCP native**: stdio adapter and a Streamable HTTP endpoint with OAuth 2.1
  discovery, dynamic client registration, PKCE and a browser consent page.

## Features

- Web dashboard: overview/charts, items (name, URL, group), search, edit, share,
  agents, grants, logs, profile/2FA, settings.
- URL matching: items can store a website; agents can ask by URL/hostname.
- Grants: once / 1h / 24h / 7d / permanent, optional read-count limit, extend,
  custom expiry, revoke, restore.
- Approval request headers include signed links valid for 10 minutes.
- Agent HTTP API: `GET /secret?name=...` or `GET /secret?url=...`.
- MCP:
  - HTTP: `POST /mcp` (JSON-RPC), OAuth 2.1 or Bearer token.
  - stdio: `mcp-server.mjs` (also supports `exec_with_secrets`, injecting secrets
    into a child process without exposing them to the model).
- At-rest hardening:
  - AES-256-GCM for the auto-unlock password, OIDC/Telegram/Gotify/wxpush secrets
    and the local token-reveal file.
  - Agent tokens stored as SHA-256 hashes in `config.json`.
  - Login throttling and optional TOTP (2FA) for the admin account.
- Optional OIDC login (passkeys supported by the identity provider, e.g. xid).
- Docker image, Compose file and a small dependency-free Node service.

## Quick start (Docker)

```bash
git clone https://github.com/otscup/secrets-broker.git
cd secrets-broker
./deploy/install.sh
```

The installer asks for the vault URL, API key, admin password and public URL,
writes `deploy/.env`, then runs `docker compose up -d --build`.

The Docker image installs `@bitwarden/cli` inside the container — you do **not**
need `bw` on the host and nothing is installed outside Docker. The image is
larger (Node base + Bitwarden CLI), but there is only one container and one
volume.

Manual path:

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env
docker compose up -d --build
```

Open `http://<host>:8788/`, log in with `SECRETS_BROKER_ADMIN_PASSWORD`, then enter
your vault master password to unlock. Alternatively put the master password in
`data/master-password` (encrypted automatically on first start) for auto-unlock.

Data lives in `data/` (mounted as `/data` in the container): `config.json`,
`grants.json`, `audit.log`, `encryption.key`, optional `master-password` and the
encrypted `agent-tokens.json`.

> Back up `encryption.key` together with `data/`; losing it makes encrypted fields
> unrecoverable.

## Local run (Node 20+)

```bash
npm start          # server on 127.0.0.1:8788
npm run mcp        # stdio MCP adapter
```

Prerequisites: the `bw` CLI (or set `SECRETS_BROKER_BW` to its JS entry point) and a
Bitwarden-compatible vault.

## Agent API

```bash
# Read by item name (opens an approval request on first access)
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?name=tavily-api-key"

# Read by website/hostname
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?url=https://example.com"

# Agent write access (enable "write" for that agent in the UI first)
curl -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"project/prod/api-key","value":"...","url":"https://example.com","group":"projects"}' \
  "https://broker.example.com/agent/items/save"
```

Tokens are managed in the UI (Agents): copy/reveal, rotate, allowlist, write toggle.

## MCP

### HTTP (Streamable HTTP)

```
https://broker.example.com/mcp
```

Two authentication modes:

1. **OAuth 2.1 (no API token)**: clients discover
   `/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`, register dynamically, open a browser
   consent page and exchange a PKCE code for a 24h access token.
2. **Bearer token**: `Authorization: Bearer <agent token>`.

Tools: `list_secrets`, `create_secret`, `request_access`, and optional `get_secret`
(disabled by default; set `MCP_ALLOW_READ=1`).

### stdio

```json
{
  "mcpServers": {
    "secrets": {
      "command": "node",
      "args": ["/path/to/secrets-broker/mcp-server.mjs"],
      "env": {
        "BROKER_URL": "https://broker.example.com",
        "BROKER_AGENT_TOKEN": "<agent token>"
      }
    }
  }
}
```

The stdio adapter adds `exec_with_secrets`, which injects secrets into a local child
process environment so the model only sees command output.

## Notifications

All optional. Configure in the UI (Settings) or via environment:

- **ntfy**: topic URL; approval message contains signed one-time links.
- **Telegram**: bot token + chat id. The bot sends inline buttons (approve once / 1h /
  24h / 7d / permanent / deny); callbacks are handled by long polling.
- **Gotify**: server URL + app token.
- **wxpush**: `WXPUSH_URL` + API token; sends WeChat notifications via
  [wxpush](https://github.com/frankiejun/wxpush).

## Security model (summary)

- Vault master password is only held in memory; optional auto-unlock stores it
  AES-256-GCM encrypted on disk.
- Agent tokens: SHA-256 hashes in config; plaintext only in the encrypted
  `agent-tokens.json` (for copy/rotate) — or use environment variables instead.
- Admin page: password (optional TOTP) or OIDC, login throttling, HttpOnly cookie.
- Every read is authorized by an active grant or an explicit approval, then audited.
- Approval links are HMAC-signed with an expiry.
- This is a self-hosted tool: run it behind a private network or a tunnel/Access
  policy; do not expose port 8788 directly.

## Configuration

Main environment variables:

| Variable | Meaning |
|---|---|
| `SECRETS_BROKER_HOME` | data directory (default `~/.secrets-broker`) |
| `SECRETS_BROKER_PORT` / `SECRETS_BROKER_BIND` | listen port/address |
| `SECRETS_BROKER_ADMIN_PASSWORD` | admin login password |
| `BROKER_PUBLIC_URL` | public URL for links/OAuth metadata |
| `SECRETS_BROKER_BW` | `bw` binary or path to `bw.js` |
| `SECRETS_BROKER_ENCRYPTION_KEY` | optional 32-byte base64 key (default key file) |
| `MCP_ALLOW_READ` | expose `get_secret` over MCP |

Most other settings (vault URL, OIDC, notification providers, public URL) can be
edited in the UI and are persisted to `config.json`.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [MCP](docs/mcp.md)
- [Notifications](docs/notifications.md)
- [Security](docs/security.md)

## Repository layout

```
server.mjs            broker + dashboard + HTTP/MCP/OAuth server
mcp-server.mjs        stdio MCP adapter
wh.mjs                CLI helper (get / run --var)
docker-compose.yml    one-command Docker deployment
deploy/Dockerfile     container image (includes @bitwarden/cli)
deploy/install.sh     interactive installer
deploy/.env.example
docs/                 English documentation
```

## License

MIT
