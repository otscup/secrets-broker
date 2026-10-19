# MCP

The broker exposes MCP (Model Context Protocol) in two forms.

## Streamable HTTP

```
https://<your-broker>/mcp
```

Two authentication modes are supported:

### OAuth 2.1 (recommended)

Clients that implement MCP authorization discover the broker automatically:

1. request `/mcp` without a token → `401` with
   `WWW-Authenticate: Bearer resource_metadata=".../​.well-known/oauth-protected-resource"`;
2. read `/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`;
3. register a client with `POST /oauth/register` (dynamic client registration);
4. open `/oauth/authorize` in a browser — the user logs in to the broker if needed
   and clicks **Allow**;
5. exchange the code at `POST /oauth/token` with PKCE S256;
6. call `/mcp` with `Authorization: Bearer <access token>`.

Access tokens are valid for 24 hours and map to an agent named
`oauth:<client_id>`. Reads still require an explicit grant/approval and are
audited.

### Bearer token

```
Authorization: Bearer <agent token>
```

Agent tokens are created in the UI (Agents). They are stored hashed; copy them
from the UI.

## Tools

| Tool | Description |
|---|---|
| `list_secrets` | lists readable item names (and URLs) |
| `create_secret` | create/update an item; requires write access for the agent |
| `request_access` | create a pending approval for an item |
| `get_secret` | optional; only when `MCP_ALLOW_READ=1`; returns plaintext |

`get_secret` returns the value to the calling model, so it is disabled by
default. Prefer `request_access` + a connector that reads the value outside the
model, or the stdio adapter's `exec_with_secrets`.

## stdio adapter

```json
{
  "mcpServers": {
    "secrets": {
      "command": "node",
      "args": ["/path/to/secrets-broker/mcp-server.mjs"],
      "env": {
        "BROKER_URL": "https://<your-broker>",
        "BROKER_AGENT_TOKEN": "<agent token>",
        "MCP_ALLOW_READ": "0"
      }
    }
  }
}
```

The stdio adapter additionally provides `exec_with_secrets`, which injects
secrets into a child process environment and returns only the command output.
