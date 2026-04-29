# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Install deps: `uv sync`
- Run server: `uv run tmux-mcp`
- Run enricher: `uv run tmux-mcp-enricher`
- Submit a staged report: `uv run tmux-mcp-report <filename.log>` (also `--list`, `--all`). Tab-completion via argcomplete — see below.
- Lint / format: `uv run ruff check` / `uv run ruff format`
- Run tests: `uv run pytest`
- Health check: `curl http://localhost:8747/healthz`

Python 3.13+ is required (see `.python-version`, `pyproject.toml`). Before pushing, every commit should pass `uv run ruff check`, `uv run ruff format --check`, and `uv run pytest` — CI runs the same checks.

### Tab-completion for `tmux-mcp-report`

The CLI uses [`argcomplete`](https://github.com/kislyuk/argcomplete). Register once per shell so that `tmux-mcp-report <TAB>` completes against `logs/staged/*.log`:

```sh
# bash
eval "$(register-python-argcomplete tmux-mcp-report)"

# zsh
autoload -U compinit && compinit
eval "$(register-python-argcomplete tmux-mcp-report)"
```

Add the appropriate line to `~/.bashrc` / `~/.zshrc` to make it permanent. The CLI works without registration — completion just won't fire.

### Pre-commit hooks

The repo ships a `.pre-commit-config.yaml` that runs ruff + pytest as a Git hook. Enable once per clone:

```
uv run pre-commit install
```

After that, `git commit` runs the hooks automatically and blocks the commit if anything fails. Use `git commit --no-verify` only when you genuinely need to bypass them.

## Architecture

This is an MCP server (FastMCP, streamable HTTP transport) that exposes tmux-driving tools (`tmux_list_sessions`, `tmux_get_summary`, `tmux_send_prompt`) and abuse-pipeline tools (`abuse_get_pending`, `abuse_get_staged`, `abuse_list_reported`, `abuse_send_report`) to remote Claude clients. It is designed to be fronted by `tailscale serve` for HTTPS and tailnet-only reachability.

Two modules, tightly coupled through `FastMCP`:

- `src/tmux_mcp/server.py` — config/env loading, FastMCP instantiation, tool definitions, and a custom `/oauth/github/callback` route. Tools shell out to `tmux` via `subprocess.run` with a 5s timeout. Target panes use the `=session.pane` form to force exact-name matching (no prefix fallback). `TMUX_MCP_HOST=TAILSCALE` auto-resolves to the host's Tailscale IP via `tailscale ip -4`.
- `src/tmux_mcp/auth.py` — `GithubOAuthProvider`, a full OAuth 2.1 + DCR authorization server that delegates user auth to GitHub. It is not a proxy: this server issues its own RS256 JWTs (access + refresh) signed with an auto-generated key.

### Auth flow (important — the non-obvious part)

The MCP server *is* the OAuth AS that Claude talks to. GitHub is only the upstream IdP for human login.

1. Claude discovers `/.well-known/oauth-authorization-server` and registers via DCR at `/register` (persisted to `~/.config/tmux-mcp/clients.json`).
2. Claude → `/authorize`. The provider stores a `_PendingAuth` keyed by a fresh `state` token (holds PKCE challenge, client redirect, mcp_state) and redirects the browser to GitHub.
3. GitHub → `/oauth/github/callback` (a `custom_route` on FastMCP, *not* an abstract provider method — this is why `handle_github_callback` exists as a separate method). The server exchanges code→GH token→username, checks it against `allowed_users`, mints an MCP auth code, and redirects back to the Claude client's `redirect_uri`.
4. Claude → `/token` with the auth code + PKCE verifier. `exchange_authorization_code` issues RS256 JWTs. `sub` = GitHub username, `aud` = DCR client_id, `typ` distinguishes access/refresh.
5. Every MCP request: `load_access_token` verifies JWT signature, issuer, and `typ=access`. Audience is not verified (`verify_aud: False`).

Refresh tokens are stateless JWTs, so server restarts don't invalidate them. Access-token revocation is a no-op (no denylist); this is intentional for v1.

### State on disk

`~/.config/tmux-mcp/` (override via `TMUX_MCP_STATE_DIR` or `XDG_CONFIG_HOME`):
- `jwt-key.pem` — RSA 2048 private key, generated on first run, mode 600. Regenerating invalidates all issued tokens.
- `clients.json` — DCR-registered clients, mode 600.

Everything else — pending auths, issued auth codes — is in-memory and lost on restart (10-minute TTLs make this fine).

### Required env

`TMUX_MCP_PUBLIC_URL` (must be `https://`), `TMUX_MCP_GITHUB_CLIENT_ID`, `TMUX_MCP_GITHUB_CLIENT_SECRET`, `TMUX_MCP_ALLOWED_GITHUB_USERS` (comma-separated, case-insensitive). Missing any of these aborts startup.

Tool argument types are declared as `Annotated` aliases at module scope (`SessionArg`, `PaneArg`) so the advertised JSON schema stays flat — MCP clients expect top-level properties, not nested `$ref`s.
