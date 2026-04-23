"""Tests for the RateLimitMiddleware.

Exercises the middleware directly against a scripted ASGI inner app so we can
assert whitelist, banned, 404-instant-freeze, auth-failure threshold, and the
persistence files without spinning up a real server.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tmux_mcp.ratelimit import RateLimitMiddleware


def make_inner(status: int):
    async def inner(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    return inner


def make_scope(ip: str, *, path: str = "/mcp", headers=None):
    hdrs = list(headers or [])
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": hdrs,
        "client": (ip, 12345),
    }


async def drive(mw, scope):
    received = []

    async def send(message):
        received.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await mw(scope, receive, send)
    return received


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "whitelist.txt", tmp_path / "banned.txt"


@pytest.fixture
def pending_dir(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "pending"


def test_404_bans_instantly(paths):
    wl, bl = paths
    mw = RateLimitMiddleware(
        make_inner(404), whitelist_path=wl, banned_path=bl, threshold=10
    )
    asyncio.run(drive(mw, make_scope("1.2.3.4")))
    assert "1.2.3.4" in mw.banned()
    assert bl.read_text().splitlines() == ["1.2.3.4"]


def test_banned_ip_gets_429_without_reaching_inner(paths):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    hits = 0

    async def inner(scope, receive, send):
        nonlocal hits
        hits += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = RateLimitMiddleware(inner, whitelist_path=wl, banned_path=bl)
    received = asyncio.run(drive(mw, make_scope("9.9.9.9")))
    assert hits == 0
    assert received[0]["status"] == 429


def test_whitelist_bypasses_404_ban(paths):
    wl, bl = paths
    wl.write_text("5.5.5.5\n")
    mw = RateLimitMiddleware(make_inner(404), whitelist_path=wl, banned_path=bl)
    asyncio.run(drive(mw, make_scope("5.5.5.5")))
    assert "5.5.5.5" not in mw.banned()


def test_auth_failures_threshold_freezes(paths):
    wl, bl = paths
    mw = RateLimitMiddleware(
        make_inner(401), whitelist_path=wl, banned_path=bl, threshold=3
    )
    for _ in range(3):
        asyncio.run(drive(mw, make_scope("7.7.7.7")))
    assert "7.7.7.7" not in mw.banned()
    asyncio.run(drive(mw, make_scope("7.7.7.7")))
    assert "7.7.7.7" in mw.banned()


def test_auth_failures_outside_window_dont_count(paths, monkeypatch):
    wl, bl = paths
    mw = RateLimitMiddleware(
        make_inner(401),
        whitelist_path=wl,
        banned_path=bl,
        threshold=3,
        window_seconds=10,
    )
    t = [1000.0]
    monkeypatch.setattr("tmux_mcp.ratelimit.time.monotonic", lambda: t[0], raising=True)
    for _ in range(3):
        asyncio.run(drive(mw, make_scope("8.8.8.8")))
    t[0] += 20
    asyncio.run(drive(mw, make_scope("8.8.8.8")))
    assert "8.8.8.8" not in mw.banned()


def test_successful_auth_whitelists_ip(paths):
    wl, bl = paths
    mw = RateLimitMiddleware(make_inner(200), whitelist_path=wl, banned_path=bl)
    scope = make_scope("4.4.4.4", headers=[(b"authorization", b"Bearer xyz")])
    asyncio.run(drive(mw, scope))
    assert "4.4.4.4" in mw.whitelist()
    assert wl.read_text().splitlines() == ["4.4.4.4"]


def test_200_without_bearer_does_not_whitelist(paths):
    wl, bl = paths
    mw = RateLimitMiddleware(make_inner(200), whitelist_path=wl, banned_path=bl)
    asyncio.run(drive(mw, make_scope("3.3.3.3")))
    assert "3.3.3.3" not in mw.whitelist()


def test_x_forwarded_for_is_honored(paths):
    wl, bl = paths
    mw = RateLimitMiddleware(make_inner(404), whitelist_path=wl, banned_path=bl)
    scope = make_scope(
        "127.0.0.1",
        headers=[(b"x-forwarded-for", b"203.0.113.7, 10.0.0.1")],
    )
    asyncio.run(drive(mw, scope))
    assert "203.0.113.7" in mw.banned()
    assert "127.0.0.1" not in mw.banned()


def test_startup_loads_existing_files(paths):
    wl, bl = paths
    wl.write_text("1.1.1.1\n2.2.2.2\n")
    bl.write_text("6.6.6.6\n")
    mw = RateLimitMiddleware(make_inner(200), whitelist_path=wl, banned_path=bl)
    assert mw.whitelist() == frozenset({"1.1.1.1", "2.2.2.2"})
    assert mw.banned() == frozenset({"6.6.6.6"})


# ── Pending-log (abuse pipeline Part 1) ─────────────────────────────────────


def test_banned_ip_request_is_logged_to_pending(paths, pending_dir):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("9.9.9.9", path="/auth.js")))
    log = (pending_dir / "9.9.9.9.log").read_text()
    assert "9.9.9.9 GET /auth.js 429" in log


def test_multiple_banned_requests_append(paths, pending_dir):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("9.9.9.9", path="/robots.txt")))
    asyncio.run(drive(mw, make_scope("9.9.9.9", path="/bot-connect.js")))
    lines = (pending_dir / "9.9.9.9.log").read_text().splitlines()
    assert len(lines) == 2
    assert "/robots.txt" in lines[0]
    assert "/bot-connect.js" in lines[1]


def test_inner_app_429_is_also_logged(paths, pending_dir):
    wl, bl = paths
    mw = RateLimitMiddleware(
        make_inner(429),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("7.7.7.7", path="/some/path")))
    log = (pending_dir / "7.7.7.7.log").read_text()
    assert "7.7.7.7 GET /some/path 429" in log


def test_whitelisted_ip_is_never_logged(paths, pending_dir):
    wl, bl = paths
    wl.write_text("5.5.5.5\n")
    mw = RateLimitMiddleware(
        make_inner(429),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("5.5.5.5")))
    assert not pending_dir.exists() or not any(pending_dir.iterdir())


def test_pending_dir_autocreated(paths, pending_dir):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    assert not pending_dir.exists()
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("9.9.9.9")))
    assert pending_dir.is_dir()
    assert (pending_dir / "9.9.9.9.log").exists()


def test_logging_disabled_when_no_dir(paths, tmp_path):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=None,
    )
    asyncio.run(drive(mw, make_scope("9.9.9.9")))
    # No log dir provided, no files created anywhere.
    assert not any(tmp_path.glob("**/*.log"))


def test_ipv6_colons_normalized_in_filename(paths, pending_dir):
    wl, bl = paths
    bl.write_text("2001:db8::1\n")
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=pending_dir,
    )
    asyncio.run(drive(mw, make_scope("2001:db8::1")))
    assert (pending_dir / "2001_db8__1.log").exists()


def test_log_write_failure_does_not_break_request(paths, tmp_path, caplog):
    wl, bl = paths
    bl.write_text("9.9.9.9\n")
    # Point log dir at an existing file so mkdir will fail.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    mw = RateLimitMiddleware(
        make_inner(200),
        whitelist_path=wl,
        banned_path=bl,
        pending_log_dir=blocker / "pending",
    )
    received = asyncio.run(drive(mw, make_scope("9.9.9.9")))
    # Request still completes with 429 reject.
    assert received[0]["status"] == 429
