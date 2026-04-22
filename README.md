# tmux-mcp

> Upstream: <https://github.com/BANCS-Norway/tmux-mcp>

MCP server that bridges Claude Chat ↔ Claude Code by driving a `tmux` session
on the host machine. Authenticates users via **GitHub OAuth**; the MCP server
itself is a full OAuth 2.1 authorization server (with Dynamic Client
Registration), so it works as a remote connector in the Claude mobile app.

## Tools

| Tool                 | What it does                                        |
| -------------------- | --------------------------------------------------- |
| `tmux_list_sessions` | List active tmux sessions on the host               |
| `tmux_get_summary`   | Capture the last N lines from a tmux pane           |
| `tmux_send_prompt`   | Send a prompt string to a tmux pane (optional Enter)|

## Setup

### 1. Expose the server over HTTPS

Claude remote connectors require `https://`. The easiest path is
[Tailscale Serve](https://tailscale.com/kb/1312/serve):

```sh
sudo tailscale serve --bg --https=443 http://localhost:8747
```

Your public URL becomes `https://<machine>.<tailnet>.ts.net`. This is also
tailnet-scoped — only devices signed into your tailnet can reach it.

### 2. Create a GitHub OAuth App

At <https://github.com/settings/developers> → **New OAuth App**:

- **Homepage URL**: `https://<machine>.<tailnet>.ts.net`
- **Authorization callback URL**: `https://<machine>.<tailnet>.ts.net/oauth/github/callback`

Generate a client secret and save both values.

### 3. Configure `.env`

Copy the example and fill in the values:

```sh
cp .env.example .env
$EDITOR .env
```

Required:

| Env var                         | Purpose                                          |
| ------------------------------- | ------------------------------------------------ |
| `TMUX_MCP_PUBLIC_URL`           | HTTPS URL from step 1 (no trailing slash)        |
| `TMUX_MCP_GITHUB_CLIENT_ID`     | GitHub OAuth app client ID                       |
| `TMUX_MCP_GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret                   |
| `TMUX_MCP_ALLOWED_GITHUB_USERS` | Comma-separated GH usernames permitted to log in |

Optional:

| Env var            | Default   | Purpose                                                |
| ------------------ | --------- | ------------------------------------------------------ |
| `TMUX_MCP_PORT`    | `8747`    | Backend HTTP port                                      |
| `TMUX_MCP_HOST`    | `0.0.0.0` | Bind host. `127.0.0.1` when fronting with tailscale serve. `TAILSCALE` auto-binds to Tailscale IP. |
| `TMUX_MCP_SESSION` | `0`       | Default tmux session target for tools                  |

### 4. Install & run

```sh
uv sync
uv run tmux-mcp
```

### 5. Add as a connector in Claude

In Claude (desktop or mobile) → Settings → Connectors → Add custom connector:

- URL: `https://<machine>.<tailnet>.ts.net/mcp`

Claude will discover the OAuth endpoints, you'll be sent through GitHub login,
and if your username is in `TMUX_MCP_ALLOWED_GITHUB_USERS` the connector
activates.

## How the auth works

1. Claude hits `/.well-known/oauth-authorization-server` for discovery.
2. Claude registers itself via Dynamic Client Registration (`/register`).
   Registered clients persist in `~/.config/tmux-mcp/clients.json`.
3. Claude opens `/authorize` — the server redirects to GitHub.
4. GitHub redirects back to `/oauth/github/callback` with a code.
5. The server exchanges the code for a GitHub access token, fetches the
   username, and checks it against `TMUX_MCP_ALLOWED_GITHUB_USERS`.
6. The server issues an RS256 JWT (signed with a key auto-generated at
   `~/.config/tmux-mcp/jwt-key.pem`) and redirects back to Claude.
7. Every MCP request carries the JWT as a bearer token. The server verifies
   the signature and expiry before dispatching tools.

Access tokens live for 1 hour. There are no refresh tokens in v1 — clients
just re-auth, which is quick since GitHub remembers the authorization.

## Storage layout

```
~/.config/tmux-mcp/
├── clients.json   # DCR-registered clients (mode 600)
└── jwt-key.pem    # RSA private key for signing access tokens (mode 600)
```

## Development

```sh
uv run ruff check
uv run ruff format
```

## License

MIT
