# tmux-mcp

> Upstream: <https://github.com/BANCS-Norway/tmux-mcp>

MCP server that bridges Claude Chat ↔ Claude Code by driving a `tmux` session
on the host machine. Authenticates users via **GitHub OAuth**; the MCP server
itself is a full OAuth 2.1 authorization server (with Dynamic Client
Registration), so it works as a remote connector in the Claude mobile app.

## Commands

| Command              | What it does                                                            |
| -------------------- | ----------------------------------------------------------------------- |
| `tmux-mcp`           | Run the MCP server (the OAuth + tool host)                              |
| `tmux-mcp-enricher`  | Watch `logs/pending/`, enrich + move files to `logs/staged/`            |
| `tmux-mcp-report`    | Submit staged abuse reports from the shell (`--list`, `--all`, or a filename) |

`tmux-mcp-report` supports tab-completion of staged filenames. The CLI prints the right snippet for your shell — pipe it into your rc file:

```sh
# auto-detect from $SHELL
echo "$(tmux-mcp-report --register)" >> ~/.zshrc

# or pick the shell explicitly
tmux-mcp-report --register bash >> ~/.bashrc
tmux-mcp-report --register zsh  >> ~/.zshrc
```

## Tools

| Tool                  | What it does                                                  |
| --------------------- | ------------------------------------------------------------- |
| `tmux_list_sessions`  | List active tmux sessions on the host                         |
| `tmux_get_summary`    | Capture the last N lines from a tmux pane                     |
| `tmux_send_prompt`    | Send a prompt string to a tmux pane (optional Enter)          |
| `abuse_get_pending`   | List IPs still accumulating 429 responses in `pending/`       |
| `abuse_get_staged`    | List enriched abuse reports in `staged/` (ready to submit)    |
| `abuse_list_reported` | List archived submissions in `reported/` (period required)    |
| `abuse_send_report`   | Submit an abuse report to AbuseIPDB and archive the file      |

The `abuse_*` tools pair with the [optional abuse reporting pipeline](#abuse-reporting-pipeline-optional) below. `abuse_send_report` requires `TMUX_MCP_ABUSEIPDB_KEY`; the others work with just the log directory.

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

## Abuse reporting pipeline (optional)

A three-part pipeline for collecting malicious IP activity and submitting reports to [AbuseIPDB](https://www.abuseipdb.com/):

1. **Collector** — the rate-limit middleware writes every 429 to `{TMUX_MCP_LOG_DIR:-./logs}/pending/{ip}.log` (built into the server, always on).
2. **Enricher** — a separate process watches `pending/`, debounces (60s quiet window), looks up ASN + country via RIPE Stat, detects AbuseIPDB categories, and moves files to `staged/`. Run alongside the server:

   ```sh
   uv run tmux-mcp-enricher
   ```

   Runs independently — restart either without affecting the other. RIPE lookup failures are non-fatal; enrichment proceeds with `unknown` fields.
3. **MCP tools** — `abuse_get_pending`, `abuse_get_staged`, `abuse_list_reported`, `abuse_send_report`. Use them from the agent to inspect the pipeline and submit reports.

### Getting an AbuseIPDB API key

`abuse_send_report` requires a free AbuseIPDB account:

1. Sign up at [abuseipdb.com/register](https://www.abuseipdb.com/register).
2. Verify your email.
3. Go to [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) and click **Create Key**. The free tier allows up to 1,000 submissions per day — plenty for a single-host deployment.
4. Add the key to `.env`:

   ```sh
   TMUX_MCP_ABUSEIPDB_KEY=your-key-here
   ```

5. Restart the server (`uv run tmux-mcp`) so it picks up the new env var.

Without the key, `abuse_send_report` returns a clear error instead of attempting the call — the collector and enricher run fine without it, so you can start gathering data before deciding whether to submit.

## Shell integrations

Optional shell helpers that pair well with `tmux-mcp` — e.g. `repo-tmux` for auto-attaching to a per-repo tmux session when you open a terminal. See [`tools/shells/`](tools/shells/).

## Development

```sh
uv run ruff check
uv run ruff format
```

## License

MIT
