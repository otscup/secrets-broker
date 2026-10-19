# Deployment

## Docker Compose

```bash
cp .env.example .env
# edit .env: BW_SERVER, BW_CLIENTID, BW_CLIENTSECRET,
#            SECRETS_BROKER_ADMIN_PASSWORD, BROKER_PUBLIC_URL
docker compose up -d --build
```

The service listens on `8788` and stores all state in `./data` (mounted at
`/data`). Keep `data/encryption.key` with your backups.

Expose it only through a private network or a tunnel (Cloudflare Tunnel,
Tailscale, WireGuard). If you use Cloudflare Tunnel, put an Access policy in front
of the admin hostname and keep the agent API on a separate hostname or path if
you need unauthenticated machine access.

## Synology / NAS

1. Create a directory such as `/volume1/docker/secrets-broker` and copy this
   repository into it (the Compose build context is the repository root).
2. `cp deploy/.env.example deploy/.env` and fill in the values.
3. `docker compose -f deploy/docker-compose.yml up -d --build`.
4. Open `http://<nas-ip>:8788/`, log in and unlock the vault.

Docker Engine 24+ and Compose v2 are required.

## Auto-unlock

To unlock without typing the master password after every restart, place the
master password in `data/master-password` (one line, file mode 600). The broker
encrypts it with `data/encryption.key` on first start. This is a deliberate
trade-off: anyone who can read the data volume can start the broker. Remove the
file (UI: Settings → delete auto-unlock file) to go back to manual unlock.

## Reverse proxy / Tunnel

A minimal generic configuration:

- Admin UI: `https://broker.example.com` → `http://127.0.0.1:8788`
- Agent API/MCP: use the same host, protected by agent tokens/OAuth approvals, or
  a separate hostname if you want Cloudflare Access on the admin UI only.

Set `BROKER_PUBLIC_URL` to the externally visible URL; it is used in approval
links and OAuth metadata.
