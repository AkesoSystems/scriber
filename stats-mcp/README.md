# scriber-stats-mcp

Read-only MCP server that lets an AI client (Claude) pull **live Scriber analytics**
straight from `/api/stats` — no downloading JSON and pasting by hand.

It is a thin wrapper around the same endpoint the `stats.html` dashboard calls.
**No writes, no PHI**: the Scriber server already keeps free text (dictation/protocol
content) out of `analytics.jsonl`; this server only forwards aggregated + metadata-only data.

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `scriber_stats` | `user?` (login, e.g. `test2`) | Full `/api/stats` JSON. Without `user` → global aggregates + `users`/`nicks`. With `user` → also `recordingsLog` (every recording) and `byUserDay`. |
| `scriber_recordings` | `user` (required) | Compact per-doctor slice: nick, per-recording log, day-by-day dynamics, totals. |

## Setup

```bash
cd stats-mcp
npm install
```

Then register it in your MCP client config with the required env vars.
**Claude Code** (`~/.claude.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "scriber-stats": {
      "command": "node",
      "args": ["D:/obsidian/Knowledge Base/08_AkesoSystems_project/_scriber-source/stats-mcp/index.js"],
      "env": {
        "SCRIBER_URL": "https://scriber.akesosystems.com",
        "SCRIBER_ADMIN_KEY": "<ADMIN_KEY з env сервера>",
        "SCRIBER_BASIC_USER": "test",
        "SCRIBER_BASIC_PASS": "<basic-auth пароль>"
      }
    }
  }
}
```

### Env vars

| Var | Required | Notes |
|-----|----------|-------|
| `SCRIBER_URL` | yes | e.g. `https://scriber.akesosystems.com` |
| `SCRIBER_ADMIN_KEY` | yes | must match `ADMIN_KEY` on the server (a real value, not the disabled default `admtest`) |
| `SCRIBER_BASIC_USER` / `SCRIBER_BASIC_PASS` | prod only | nginx basic-auth gate creds; omit for a server without the gate (e.g. local `http://localhost:3000`) |

Creds live only in the client config — never commit them (`.env` and `node_modules` are git-ignored).

## Quick check

A wrong key/cred returns a clear error (HTTP 401/403/503 with a hint), not a silent empty result.
Test locally without an MCP client:

```bash
SCRIBER_URL=http://localhost:3000 SCRIBER_ADMIN_KEY=yourkey node -e "import('./index.js')"
```

(or just point the env at a running server and call the tools from the client).
