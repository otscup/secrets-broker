# Getting started

## Requirements

- Docker Engine 24+ with Compose v2 (recommended), or Node.js 20+ for a local run.
- A Bitwarden-compatible vault: [Vaultwarden](https://github.com/dani-garcia/vaultwarden),
  [NodeWarden](https://github.com/otscup/nodewarden), or Bitwarden itself.
- A personal API key from that vault (Account settings → Security → API key).

## One-command Docker install

```bash
git clone https://github.com/otscup/secrets-broker.git
cd secrets-broker
./deploy/install.sh
```

The script asks for the vault URL, API key, broker admin password and public URL,
writes `deploy/.env`, then runs `docker compose up -d --build`.

Open <http://127.0.0.1:8788/>, log in with the admin password and unlock the vault
with your master password.

## Manual Docker install

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env
docker compose up -d --build
```

Data is stored in `data/` (mounted at `/data`): configuration, grants, audit log,
encryption key and optionally the auto-unlock password.

## Local run (no Docker)

```bash
npm start
```

Requires the `bw` CLI on PATH (or `SECRETS_BROKER_BW` pointing at
`@bitwarden/cli/build/bw.js`) and a writable `SECRETS_BROKER_HOME` directory.

## First steps

1. **Items** — add credentials. A `url` lets agents look an item up by hostname.
2. **Agents** — create one agent per machine/tool. Copy its token; optionally
   restrict readable items and enable write access.
3. **Grants** — approve requests as they arrive, or pre-share an item to an agent
   with an expiry and optional read count.
4. **Notifications** — configure ntfy/Telegram/Gotify/wxpush in Settings if you
   want approvals outside the browser.

## Exposing it safely

Do not publish port 8788 to the internet. Put the broker behind a private
network (Tailscale/WireGuard) or a tunnel with an access policy. Set
`BROKER_PUBLIC_URL` to the URL users see; it is used in approval links and OAuth
metadata.
