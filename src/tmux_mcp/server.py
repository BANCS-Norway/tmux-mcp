"""tmux_mcp — MCP server bridging Claude Chat ↔ Claude Code over Tailscale.

Exposes three tools:
  - tmux_get_summary: capture last N lines from a tmux pane
  - tmux_send_prompt: send a prompt string to a tmux pane
  - tmux_list_sessions: list active tmux sessions

Run with:
    uv run tmux-mcp

Env vars:
    TMUX_MCP_PORT     — listen port (default 8747)
    TMUX_MCP_SESSION  — default tmux session target (default "0")
    TMUX_MCP_HOST     — bind host (default 0.0.0.0)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from dotenv import load_dotenv
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from urllib.parse import urlparse
from typing import Annotated

from pydantic import AnyHttpUrl, Field
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse

from tmux_mcp.auth import STATE_DIR, GithubOAuthProvider
from tmux_mcp.ratelimit import RateLimitMiddleware

# Load .env from CWD or project root before any env reads.
load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────

PORT = int(os.environ.get("TMUX_MCP_PORT", "8747"))
HOST_RAW = os.environ.get("TMUX_MCP_HOST", "0.0.0.0")
DEFAULT_SESSION = os.environ.get("TMUX_MCP_SESSION") or None
DEFAULT_LINES = 50
SUBPROCESS_TIMEOUT = 5
DEBUG_REQUESTS = os.environ.get("TMUX_MCP_DEBUG_REQUESTS", "").lower() in (
    "1",
    "true",
    "yes",
)
DEBUG_BODY_MAX = 8192  # truncate logged request bodies to avoid flooding logs
CLAUDE_CHAT_COMPAT = os.environ.get("TMUX_MCP_CLAUDE_CHAT_COMPAT", "1").lower() in (
    "1",
    "true",
    "yes",
)
RATELIMIT_WINDOW_SECONDS = float(
    os.environ.get("TMUX_MCP_RATELIMIT_WINDOW_SECONDS", "10")
)
RATELIMIT_THRESHOLD = int(os.environ.get("TMUX_MCP_RATELIMIT_THRESHOLD", "10"))

PUBLIC_URL = os.environ.get("TMUX_MCP_PUBLIC_URL", "").rstrip("/")
GH_CLIENT_ID = os.environ.get("TMUX_MCP_GITHUB_CLIENT_ID", "")
GH_CLIENT_SECRET = os.environ.get("TMUX_MCP_GITHUB_CLIENT_SECRET", "")
ALLOWED_USERS = [
    u
    for u in os.environ.get("TMUX_MCP_ALLOWED_GITHUB_USERS", "").split(",")
    if u.strip()
]

_missing = [
    name
    for name, val in [
        ("TMUX_MCP_PUBLIC_URL", PUBLIC_URL),
        ("TMUX_MCP_GITHUB_CLIENT_ID", GH_CLIENT_ID),
        ("TMUX_MCP_GITHUB_CLIENT_SECRET", GH_CLIENT_SECRET),
        ("TMUX_MCP_ALLOWED_GITHUB_USERS", ",".join(ALLOWED_USERS)),
    ]
    if not val
]
if _missing:
    raise SystemExit(
        f"Missing required env vars: {', '.join(_missing)}. "
        "See README.md for GitHub OAuth setup."
    )

# ── Auth + server ────────────────────────────────────────────────────────────

_auth_provider = GithubOAuthProvider(
    public_url=PUBLIC_URL,
    github_client_id=GH_CLIENT_ID,
    github_client_secret=GH_CLIENT_SECRET,
    allowed_github_users=set(ALLOWED_USERS),
)

_public_host = urlparse(PUBLIC_URL).hostname or ""

mcp = FastMCP(
    "tmux_mcp",
    stateless_http=True,
    auth_server_provider=_auth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(PUBLIC_URL),
        resource_server_url=AnyHttpUrl(PUBLIC_URL),
        client_registration_options=ClientRegistrationOptions(enabled=True),
        required_scopes=[],
    ),
    transport_security=TransportSecuritySettings(
        allowed_hosts=[_public_host, "localhost", "127.0.0.1"],
        allowed_origins=[PUBLIC_URL, "https://claude.ai", "https://claude.com"],
    ),
)


@mcp.custom_route("/oauth/github/callback", methods=["GET"])
async def github_callback(request: Request) -> RedirectResponse | PlainTextResponse:
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return PlainTextResponse("missing code or state", status_code=400)
    try:
        redirect = await _auth_provider.handle_github_callback(code, state)
    except PermissionError as e:
        return PlainTextResponse(f"auth denied: {e}", status_code=403)
    return RedirectResponse(url=redirect, status_code=302)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _run(cmd: list[str]) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return "", f"timed out after {SUBPROCESS_TIMEOUT}s", 124
    return result.stdout, result.stderr, result.returncode


def _tmux_target(session: str, pane: int) -> str:
    # "=" prefix forces an exact session-name match (no prefix fallback).
    # tmux target grammar is session:window.pane — ":." selects the current window.
    return f"={session}:.{pane}"


def _list_tmux_sessions() -> tuple[list[str], str | None]:
    """Return (session_names, error). error is non-None on tmux failure."""
    stdout, stderr, code = _run(["tmux", "list-sessions", "-F", "#{session_name}"])
    if code != 0:
        return [], stderr.strip() or f"tmux list-sessions exit {code}"
    return [line.strip() for line in stdout.splitlines() if line.strip()], None


def _resolve_session(session: str | None) -> tuple[str | None, str | None]:
    """Resolve a possibly-None session arg to a concrete session name.

    Returns (name, error_json). If the caller supplied a name, pass it through.
    If not, auto-pick when exactly one session exists; otherwise return an
    error payload listing the available sessions so the caller can retry.
    """
    if DEBUG_REQUESTS:
        _debug_logger.info("tool received session=%r", session)
    if session:
        return session, None
    sessions, err = _list_tmux_sessions()
    if err is not None:
        return None, json.dumps(
            {
                "error": f"tmux list-sessions failed: {err}",
                "hint": "No tmux server running, or tmux is not installed.",
            }
        )
    if not sessions:
        return None, json.dumps({"error": "no tmux sessions running"})
    if len(sessions) == 1:
        return sessions[0], None
    return None, json.dumps(
        {
            "error": "session argument required — multiple tmux sessions are running",
            "available_sessions": sessions,
            "hint": "Re-call with one of the listed sessions as the 'session' argument.",
        }
    )


def _tailscale_ip() -> str | None:
    if not shutil.which("tailscale"):
        return None
    out, _, code = _run(["tailscale", "ip", "-4"])
    if code != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0]


def _resolve_host(raw: str) -> str:
    """Resolve TMUX_MCP_HOST: 'TAILSCALE' → detected tailscale IP, else passthrough."""
    if raw.upper() == "TAILSCALE":
        ip = _tailscale_ip()
        if ip is None:
            raise SystemExit(
                "TMUX_MCP_HOST=TAILSCALE but tailscale IP could not be detected"
            )
        return ip
    return raw


# ── Tools ────────────────────────────────────────────────────────────────────

# Argument-type aliases — keep tool signatures flat so the advertised JSON
# schema has top-level properties (MCP clients expect this shape).

SessionArg = Annotated[
    str | None,
    Field(
        default=DEFAULT_SESSION,
        description=(
            "tmux session name (e.g. 'milorg_co'). Optional: if omitted and "
            "exactly one session is running, it is used automatically; if "
            "multiple sessions exist, the tool returns the list so you can retry."
        ),
    ),
]
PaneArg = Annotated[
    int,
    Field(default=0, description="Pane index within the session window", ge=0, le=99),
]


@mcp.tool(
    name="tmux_get_summary",
    annotations={
        "title": "Get tmux Pane Output",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def tmux_get_summary(
    session: SessionArg = DEFAULT_SESSION,
    pane: PaneArg = 0,
    lines: Annotated[
        int,
        Field(
            default=DEFAULT_LINES,
            description="Number of lines to capture from the bottom of the pane",
            ge=1,
            le=500,
        ),
    ] = DEFAULT_LINES,
) -> str:
    """Capture the last N lines from a tmux pane."""
    resolved, err = _resolve_session(session)
    if err is not None:
        return err
    target = _tmux_target(resolved, pane)
    cmd = ["tmux", "capture-pane", "-p", "-t", target, "-S", f"-{lines}"]
    stdout, stderr, code = _run(cmd)

    if code != 0:
        return json.dumps(
            {
                "error": f"tmux capture-pane failed (exit {code}): {stderr.strip()}",
                "hint": f"Is session '{resolved}' running? Use tmux_list_sessions to check.",
            }
        )

    out_lines = stdout.splitlines()
    return json.dumps(
        {
            "target": target,
            "lines_captured": len(out_lines),
            "output": stdout,
        },
        indent=2,
    )


@mcp.tool(
    name="tmux_send_prompt",
    annotations={
        "title": "Send Prompt to tmux Pane",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def tmux_send_prompt(
    prompt: Annotated[
        str,
        Field(
            description="The prompt text to send to the tmux pane",
            min_length=1,
            max_length=4000,
        ),
    ],
    session: SessionArg = DEFAULT_SESSION,
    pane: PaneArg = 0,
    press_enter: Annotated[
        bool,
        Field(
            default=True, description="Whether to press Enter after sending the prompt"
        ),
    ] = True,
) -> str:
    """Send a prompt string to a tmux pane (optionally pressing Enter)."""
    resolved, err = _resolve_session(session)
    if err is not None:
        return err
    target = _tmux_target(resolved, pane)
    # -l forces literal interpretation so prompts containing words like
    # "Enter" or "C-c" are typed as text rather than interpreted as keys.
    _, stderr, code = _run(["tmux", "send-keys", "-t", target, "-l", prompt])
    if code != 0:
        return json.dumps(
            {
                "error": f"tmux send-keys failed (exit {code}): {stderr.strip()}",
                "hint": f"Is session '{resolved}' running? Use tmux_list_sessions to check.",
            }
        )

    if press_enter:
        _, stderr, code = _run(["tmux", "send-keys", "-t", target, "Enter"])
        if code != 0:
            return json.dumps(
                {
                    "error": f"tmux send-keys Enter failed (exit {code}): {stderr.strip()}",
                }
            )

    return json.dumps(
        {
            "sent": True,
            "target": target,
            "prompt_preview": prompt[:120] + ("…" if len(prompt) > 120 else ""),
            "enter_pressed": press_enter,
        },
        indent=2,
    )


@mcp.tool(
    name="tmux_list_sessions",
    annotations={
        "title": "List tmux Sessions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def tmux_list_sessions() -> str:
    """List all active tmux sessions on this machine."""
    stdout, stderr, code = _run(
        [
            "tmux",
            "list-sessions",
            "-F",
            "#{session_name} (#{session_windows} windows, created #{session_created_string})",
        ]
    )

    if code != 0:
        return json.dumps(
            {
                "error": f"tmux list-sessions failed: {stderr.strip()}",
                "hint": "No tmux server running, or tmux is not installed.",
            }
        )

    sessions = [line.strip() for line in stdout.splitlines() if line.strip()]
    return json.dumps({"sessions": sessions}, indent=2)


# ── Middleware ───────────────────────────────────────────────────────────────

_debug_logger = logging.getLogger("tmux_mcp.debug")
_compat_logger = logging.getLogger("tmux_mcp.compat")


def _unwrap_chat_arguments(msg: dict) -> bool:
    """Unwrap Claude Chat's double-encoded tools/call arguments in place.

    Claude Chat (as of early 2026) serializes tool-call arguments as a JSON
    string under a single top-level "params" key, instead of inlining the
    keys on "arguments" directly. Detect that exact shape and repair it so
    FastMCP's pydantic layer sees the real parameters.

    Returns True if a rewrite happened.
    """
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return False
    params = msg.get("params")
    if not isinstance(params, dict):
        return False
    arguments = params.get("arguments")
    if not (isinstance(arguments, dict) and set(arguments.keys()) == {"params"}):
        return False
    inner = arguments["params"]
    if not isinstance(inner, str):
        return False
    try:
        parsed = json.loads(inner)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False
    params["arguments"] = parsed
    return True


class ClaudeChatCompatMiddleware:
    """Pure-ASGI middleware that repairs Claude Chat's malformed tools/call bodies.

    Must be pure ASGI (not BaseHTTPMiddleware) because Starlette's
    BaseHTTPMiddleware.call_next ignores modifications to request.receive and
    wraps the original receive callable — so body mutations are dropped before
    they reach the inner app.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        ct = headers.get(b"content-type", b"").decode("latin-1").lower()
        if not ct.startswith("application/json"):
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        more = True
        while more:
            msg = await receive()
            if msg["type"] != "http.request":
                await self.app(scope, receive, send)
                return
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        if body:
            try:
                payload = json.loads(body)
                rewrote = False
                if isinstance(payload, list):
                    for item in payload:
                        rewrote |= _unwrap_chat_arguments(item)
                elif isinstance(payload, dict):
                    rewrote = _unwrap_chat_arguments(payload)
                if rewrote:
                    body = json.dumps(payload).encode("utf-8")
                    _compat_logger.info(
                        "repaired Claude Chat tools/call body on %s", scope.get("path")
                    )
            except json.JSONDecodeError:
                pass

        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            # After delivering the buffered body, defer to the real upstream
            # receive so MCP streamable-HTTP can observe genuine client
            # disconnects while the SSE response streams.
            return await receive()

        await self.app(scope, replay_receive, send)


class RequestDebugMiddleware:
    """Pure-ASGI middleware that logs incoming request bodies + key headers.

    Enabled via TMUX_MCP_DEBUG_REQUESTS=1. Sensitive headers are redacted.
    Pure ASGI (not BaseHTTPMiddleware) to avoid Starlette's body-stream
    consumption quirks that were breaking SSE responses from FastMCP.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        redacted_auth = (auth.split(" ", 1)[0] + " <redacted>") if auth else ""
        ct = headers.get(b"content-type", b"").decode("latin-1")
        method = scope.get("method", "")
        path = scope.get("path", "")

        chunks: list[bytes] = []
        more = True
        while more:
            msg = await receive()
            if msg["type"] != "http.request":
                _debug_logger.info(
                    "→ %s %s auth=%r ct=%r body=<none:%s>",
                    method,
                    path,
                    redacted_auth,
                    ct,
                    msg["type"],
                )
                pending = msg

                async def once_receive():
                    nonlocal pending
                    if pending is not None:
                        out, pending = pending, None
                        return out
                    return await receive()

                await self.app(scope, once_receive, send)
                return
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        body_preview = body[:DEBUG_BODY_MAX].decode("utf-8", errors="replace")
        truncated = " …[truncated]" if len(body) > DEBUG_BODY_MAX else ""
        _debug_logger.info(
            "→ %s %s auth=%r ct=%r body=%s%s",
            method,
            path,
            redacted_auth,
            ct,
            body_preview,
            truncated,
        )

        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    import uvicorn

    host = _resolve_host(HOST_RAW)
    mcp.settings.host = host
    mcp.settings.port = PORT
    ts_ip = _tailscale_ip()
    print(f"Starting tmux_mcp on {host}:{PORT} (streamable HTTP)")
    if ts_ip:
        print(f"Tailscale IP: http://{ts_ip}:{PORT}/mcp")

    app = mcp.streamable_http_app()
    # Starlette applies middleware in reverse insertion order, so insert the
    # compat shim FIRST and the debug logger LAST — that way debug sees the
    # raw wire body and compat runs after, transparently to FastMCP.
    if CLAUDE_CHAT_COMPAT:
        logging.getLogger("tmux_mcp.compat").setLevel(logging.INFO)
        app.add_middleware(ClaudeChatCompatMiddleware)
    if DEBUG_REQUESTS:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s %(name)s %(message)s"
        )
        _debug_logger.setLevel(logging.INFO)
        app.add_middleware(RequestDebugMiddleware)
        print("Request debug logging ENABLED (TMUX_MCP_DEBUG_REQUESTS=1)")
    if not CLAUDE_CHAT_COMPAT:
        print("Claude Chat compat shim DISABLED (TMUX_MCP_CLAUDE_CHAT_COMPAT=0)")
    logging.getLogger("tmux_mcp.ratelimit").setLevel(logging.INFO)
    app.add_middleware(
        RateLimitMiddleware,
        whitelist_path=STATE_DIR / "whitelist.txt",
        banned_path=STATE_DIR / "banned.txt",
        window_seconds=RATELIMIT_WINDOW_SECONDS,
        threshold=RATELIMIT_THRESHOLD,
    )

    config = uvicorn.Config(
        app, host=host, port=PORT, log_level=mcp.settings.log_level.lower()
    )
    try:
        uvicorn.Server(config).run()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
