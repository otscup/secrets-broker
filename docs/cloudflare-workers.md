# Can Secrets Broker run on Cloudflare Workers?

Short answer: **not by deploying the current `server.mjs` as-is**. A Workers-native
version is possible, but it is a separate implementation with a different vault-access
layer.

## Why the current code cannot run on Workers

The broker is a long-lived Node process that relies on:

- `child_process` to run the Bitwarden CLI (`bw`) — Workers have no child processes;
- a local filesystem (`config.json`, `grants.json`, `audit.log`, `encryption.key`,
  `master-password`) — Workers have no persistent local disk;
- an in-memory `bw unlock` session and in-memory pending approvals — isolates are
  short-lived and not shared between requests;
- background work (Telegram long polling, vault sync) — Workers request handlers
  must return, and there is no always-on loop.

None of these map to a Worker without redesigning the service.

## What a Workers-native version would look like

- **Vault access**: talk to the Bitwarden-compatible server over HTTP and decrypt the
  vault in the Worker with WebCrypto (Bitwarden KDF + AES). This replaces `bw`.
  - PBKDF2 KDF is feasible; Argon2 would need a WASM implementation.
  - Vault decryption is CPU-heavy; Workers CPU limits and cold starts matter, so a
    Durable Object should cache the unlocked symmetric key for a short time.
- **Storage**: D1 (or KV) for config, agent token hashes, grants and audit events;
  R2 optional for exports. Durable Objects for pending approvals, rate limits and the
  unlock session.
- **Notifications**:
  - Telegram: use `setWebhook` instead of long polling;
  - ntfy / Gotify / wxpush: plain `fetch` calls, unchanged;
  - signed one-time approval links work as-is.
- **MCP**: HTTP MCP and the OAuth 2.1 authorization server fit Workers well.
- **UI**: the dashboard can be served as static assets plus Worker API routes.
- **stdio MCP** and the `bw`-based import are not possible on Workers.

## Constraints to validate in a proof of concept

1. Vault KDF/decrypt performance inside Workers (CPU limits, WASM Argon2).
2. D1 schema/quotas for audit logs (write amplification).
3. Durable Object design for unlock sessions and pending approvals.
4. Telegram webhook security (secret token header).
5. Avoiding a long-lived `bw` session by re-unlocking on demand or caching a wrapped
   key in a Durable Object.

## Recommended path

Keep the NAS/Docker broker as the reference implementation. If serverless is a hard
requirement, build a **separate `workers/` package** with a reduced feature set:

- Phase 1: Worker + D1 + NodeWarden HTTP API; items list/read, approvals, audit.
- Phase 2: MCP HTTP + OAuth 2.1 + notification adapters.
- Phase 3: dashboard UI and folder filtering.

This is a rewrite of the vault layer and state model, not a port of `server.mjs`.
