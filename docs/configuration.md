# Configuration

Settings can be supplied as environment variables or edited in the UI
(Settings → saved to `config.json`). UI values take precedence over environment
variables, so a self-hosted instance can be configured entirely in the browser.

## Core

| Variable | Default | Description |
|---|---|---|
| `SECRETS_BROKER_HOME` | `~/.secrets-broker` | data directory |
| `SECRETS_BROKER_PORT` | `8788` | listen port |
| `SECRETS_BROKER_BIND` | `127.0.0.1` | listen address (`0.0.0.0` in Docker) |
| `SECRETS_BROKER_ADMIN_PASSWORD` | — | admin login password |
| `BROKER_PUBLIC_URL` | `http://127.0.0.1:8788` | public URL used in links/OAuth metadata |
| `SECRETS_BROKER_BW` | `bw` | `bw` binary or path to `bw.js` |
| `SECRETS_BROKER_ENCRYPTION_KEY` | generated file | 32-byte base64 key for AES-256-GCM fields |
| `MCP_ALLOW_READ` | unset | expose `get_secret` over MCP |

## Vault

| Variable | Description |
|---|---|
| `BW_SERVER` | Bitwarden-compatible server URL |
| `BW_CLIENTID` | personal API key client id |
| `BW_CLIENTSECRET` | personal API key client secret |

The container's entrypoint runs `bw config server` and `bw login --apikey` once;
the unlock session is only kept in memory.

## OIDC (admin login)

| Variable | Description |
|---|---|
| `OIDC_ISSUER` | issuer URL (any standard OIDC provider) |
| `OIDC_CLIENT_ID` | client id |
| `OIDC_CLIENT_SECRET` | optional client secret (public PKCE clients can omit it) |
| `OIDC_REDIRECT_URI` | defaults to `${BROKER_PUBLIC_URL}/oidc/callback` |

The provider must allow the redirect URI above. The broker uses discovery, PKCE
and ID-token verification against the provider's JWKS.

### Advanced OIDC

The OIDC section has a collapsible advanced panel:

- **Endpoint overrides**: authorization/token/userinfo/JWKS URLs. Leave empty to
  use the issuer's discovery document; fill them for providers without discovery.
- **Scope**: default `openid profile email`.
- **Claim mapping**: identifier (default `sub`), name (`name`), email (`email`),
  avatar (`picture`). On first OIDC login the mapped claims are stored in the
  local profile; the identifier/email are also remembered for account binding.

## Optional features

- Auto-unlock: place the master password in `data/master-password`; it is
  encrypted with `encryption.key` on the first start.
- Notifications: `NTFY_URL`, `GOTIFY_URL`/`GOTIFY_TOKEN`,
  `WXPUSH_URL`/`WXPUSH_TOKEN`, `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`.
- TOTP 2FA and profile fields are configured in the UI (Profile).
