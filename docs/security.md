# Security

## Model

- **Vault**: secrets live in a Bitwarden-compatible vault (NodeWarden,
  Vaultwarden, Bitwarden). The broker uses the official `bw` CLI; the decrypted
  session lives in memory only.
- **Agents**: every agent has its own token. The token is stored as a SHA-256 hash
  in `config.json`; plaintext is kept only in the encrypted `agent-tokens.json`
  for copy/rotate, or can be supplied through `SECRETS_BROKER_TOKEN`.
- **Approval**: a read requires either an active grant or an explicit approval
  (once / 1h / 24h / 7d / permanent). Grants can have a read-count limit and an
  expiry; every read is audited.
- **Human channels**: web UI, Telegram buttons, ntfy/Gotify/wxpush messages with
  signed one-time links, or the MCP OAuth consent page.
- **Admin**: password (optional TOTP) or OIDC (PKCE), login throttling, HttpOnly
  session cookie.

## Encryption at rest

`encryption.key` (32 bytes, mode 600) is generated on first start and used with
AES-256-GCM for:

- the auto-unlock master password (`master-password`),
- OIDC client secret,
- Telegram / Gotify / wxpush tokens,
- plaintext agent tokens (`agent-tokens.json`).

Back up `encryption.key` together with `data/`. Losing it makes these fields
unrecoverable (agent tokens themselves remain valid for the agents that hold
them).

## Auto-unlock trade-off

To unlock without human input after a restart, the container needs the master
password. The broker stores it encrypted on the data volume. Anyone who can read
the volume and the key file can start the broker; this is equivalent to leaving
the vault unlocked. Delete `data/master-password` (Settings → delete auto-unlock
file) to go back to manual unlock.

## Deployment checklist

- Run behind a private network or a tunnel with an access policy; never expose
  port 8788 directly.
- Set a strong `SECRETS_BROKER_ADMIN_PASSWORD` and consider OIDC + TOTP.
- Keep the data volume on an encrypted disk where possible.
- Backup `data/` and `encryption.key`.
- Rotate agent tokens when a machine is retired (UI → Agents → rotate).
- Review the audit log (Logs) after connecting a new agent.
