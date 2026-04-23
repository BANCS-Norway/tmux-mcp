"""Pure-ASGI IP-based rate-limiting middleware.

Two persistent lists in the state directory:

- ``whitelist.txt`` — IPs that have successfully authenticated at least once
  (observed by a 2xx response to a request carrying ``Authorization: Bearer``).
  Whitelisted IPs bypass all checks. Populated lazily on first successful auth.

- ``banned.txt`` — IPs that triggered a freeze. Whitelist is checked first, so
  once an IP is whitelisted it cannot be banned. Bans are permanent; manual
  unban is ``edit file + restart``.

Freeze triggers:

- A single 404 response (scanner signal — no legit client hits unknown paths).
- More than ``threshold`` 401/403 responses in a ``window`` sliding window.

Pure ASGI (not ``BaseHTTPMiddleware``) to match the other middlewares in this
project — ``BaseHTTPMiddleware`` buffers bodies and breaks FastMCP's SSE
streaming.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Iterable


logger = logging.getLogger("tmux_mcp.ratelimit")


def _load_ip_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    ips: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips


def _append_ip(path: Path, ip: str) -> None:
    existed = path.exists()
    with path.open("a") as f:
        f.write(ip + "\n")
    if not existed:
        path.chmod(0o600)


def _client_ip(scope: dict) -> str | None:
    for name, value in scope.get("headers") or []:
        if name == b"x-forwarded-for":
            first = value.decode("latin-1").split(",")[0].strip()
            if first:
                return first
    client = scope.get("client")
    if client:
        return client[0]
    return None


class RateLimitMiddleware:
    """Pure-ASGI middleware enforcing IP whitelist / freeze rules."""

    def __init__(
        self,
        app,
        *,
        whitelist_path: Path,
        banned_path: Path,
        pending_log_dir: Path | None = None,
        window_seconds: float = 10.0,
        threshold: int = 10,
    ):
        self.app = app
        self.whitelist_path = whitelist_path
        self.banned_path = banned_path
        self.pending_log_dir = pending_log_dir
        self.window_seconds = window_seconds
        self.threshold = threshold

        self._whitelist: set[str] = _load_ip_file(whitelist_path)
        self._banned: set[str] = _load_ip_file(banned_path)
        self._auth_failures: dict[str, deque[float]] = {}
        self._lock = Lock()

        logger.info(
            "rate-limit loaded: whitelist=%d banned=%d window=%.1fs threshold=%d log_dir=%s",
            len(self._whitelist),
            len(self._banned),
            window_seconds,
            threshold,
            pending_log_dir or "<off>",
        )

    # ── Public hooks (used by tests) ────────────────────────────────────────

    def whitelist(self) -> Iterable[str]:
        return frozenset(self._whitelist)

    def banned(self) -> Iterable[str]:
        return frozenset(self._banned)

    # ── ASGI entry point ────────────────────────────────────────────────────

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        ip = _client_ip(scope)
        if ip is None:
            await self.app(scope, receive, send)
            return

        if ip in self._whitelist:
            await self.app(scope, receive, send)
            return

        if ip in self._banned:
            self._log_pending(ip, scope)
            await self._send_forbidden(send)
            return

        has_bearer = any(
            name == b"authorization" and value.lower().startswith(b"bearer ")
            for name, value in (scope.get("headers") or [])
        )

        status_holder: dict[str, int] = {}

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message["status"])
            await send(message)

        await self.app(scope, receive, wrapped_send)

        status = status_holder.get("status")
        if status is None:
            return

        if status == 404:
            self._ban(ip, reason="404")
            return

        if status == 429:
            # Inner app emitted 429 independently of the middleware reject path.
            self._log_pending(ip, scope)
            return

        if status in (401, 403):
            self._record_auth_failure(ip)
            return

        if 200 <= status < 300 and has_bearer:
            self._whitelist_ip(ip)

    # ── State mutations ─────────────────────────────────────────────────────

    def _whitelist_ip(self, ip: str) -> None:
        with self._lock:
            if ip in self._whitelist:
                return
            self._whitelist.add(ip)
            self._auth_failures.pop(ip, None)
        _append_ip(self.whitelist_path, ip)
        logger.info("whitelisted ip=%s (authenticated)", ip)

    def _ban(self, ip: str, *, reason: str) -> None:
        with self._lock:
            if ip in self._banned:
                return
            self._banned.add(ip)
            self._auth_failures.pop(ip, None)
        _append_ip(self.banned_path, ip)
        logger.warning("banned ip=%s reason=%s", ip, reason)

    def _record_auth_failure(self, ip: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        should_ban = False
        with self._lock:
            dq = self._auth_failures.setdefault(ip, deque())
            dq.append(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) > self.threshold:
                should_ban = True
        if should_ban:
            self._ban(ip, reason=f"auth-fail>{self.threshold}/{self.window_seconds}s")

    # ── Pending-log write (best-effort) ─────────────────────────────────────

    def _log_pending(self, ip: str, scope: dict) -> None:
        if self.pending_log_dir is None:
            return
        try:
            self.pending_log_dir.mkdir(parents=True, exist_ok=True)
            # Colons in IPv6 addresses are legal in filenames on Linux/macOS
            # but ugly — normalize so `2001:db8::1` → `2001_db8__1.log`.
            safe_ip = ip.replace(":", "_")
            path = self.pending_log_dir / f"{safe_ip}.log"
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            method = scope.get("method", "?")
            req_path = scope.get("path", "?")
            line = f"{ts} {ip} {method} {req_path} 429\n"
            with path.open("a") as f:
                f.write(line)
        except OSError as e:
            logger.warning("pending-log write failed for ip=%s: %s", ip, e)

    # ── Reject path ─────────────────────────────────────────────────────────

    @staticmethod
    async def _send_forbidden(send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": b"banned\n"})
