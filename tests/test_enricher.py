"""Tests for the abuse-pipeline enricher."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from tmux_mcp.enricher import (
    CATEGORY_BRUTE_FORCE,
    CATEGORY_PORT_SCAN,
    CATEGORY_WEB_APP_ATTACK,
    detect_categories,
    parse_log_line,
    promote_file,
    report_to,
    rir_for_country,
    run_watcher,
)


# ── Parsing ─────────────────────────────────────────────────────────────────


def test_parse_log_line_roundtrip():
    parsed = parse_log_line("2026-04-23T14:07:37Z 155.2.225.177 GET /auth.js 429")
    assert parsed == {
        "ts": "2026-04-23T14:07:37Z",
        "ip": "155.2.225.177",
        "method": "GET",
        "path": "/auth.js",
        "status": "429",
    }


def test_parse_log_line_rejects_garbage():
    assert parse_log_line("") is None
    assert parse_log_line("not a log line") is None


# ── RIR lookup ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "country,expected",
    [
        ("CH", "RIPE NCC"),
        ("ch", "RIPE NCC"),  # case-insensitive
        ("US", "ARIN"),
        ("CN", "APNIC"),
        ("BR", "LACNIC"),
        ("ZA", "AFRINIC"),
        ("XX", "ARIN"),  # unknown defaults to ARIN
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_rir_for_country(country, expected):
    assert rir_for_country(country) == expected


def test_report_to_always_includes_abuseipdb():
    assert "AbuseIPDB" in report_to("RIPE NCC")
    assert "RIPE NCC" in report_to("RIPE NCC")
    assert report_to("unknown") == "AbuseIPDB"
    assert report_to("") == "AbuseIPDB"


# ── Category detection ─────────────────────────────────────────────────────


def _req(path, method="GET"):
    return {
        "ts": "2026-04-23T00:00:00Z",
        "method": method,
        "path": path,
        "status": "429",
    }


def test_web_app_attack_on_wp_login():
    assert CATEGORY_WEB_APP_ATTACK in detect_categories([_req("/wp-login.php")])


def test_web_app_attack_on_env_exfil():
    assert CATEGORY_WEB_APP_ATTACK in detect_categories([_req("/.env")])


def test_web_app_attack_on_payment_scanner():
    # Payment-form scanner pattern — cart/checkout path carrying CC-like params.
    cats = detect_categories([_req("/cart/checkout?ccnum=4111111111111111&cvv=123")])
    assert CATEGORY_WEB_APP_ATTACK in cats


def test_web_app_attack_on_webshell():
    assert CATEGORY_WEB_APP_ATTACK in detect_categories([_req("/uploads/c99.php")])


def test_port_scan_triggers_on_distinct_paths():
    reqs = [_req(f"/path/{i}") for i in range(3)]
    assert CATEGORY_PORT_SCAN in detect_categories(reqs)


def test_port_scan_does_not_trigger_on_two_paths():
    reqs = [_req("/a"), _req("/b")]
    assert CATEGORY_PORT_SCAN not in detect_categories(reqs)


def test_brute_force_triggers_on_same_path_repeated():
    reqs = [_req("/api/login") for _ in range(5)]
    cats = detect_categories(reqs)
    assert CATEGORY_BRUTE_FORCE in cats


def test_brute_force_does_not_trigger_below_threshold():
    reqs = [_req("/api/login") for _ in range(4)]
    assert CATEGORY_BRUTE_FORCE not in detect_categories(reqs)


def test_categories_can_combine():
    # 5 hits on an exploit path → 18 + 19 (and 21 needs distinct paths, so not here)
    reqs = [_req("/wp-login.php") for _ in range(5)]
    cats = detect_categories(reqs)
    assert CATEGORY_WEB_APP_ATTACK in cats
    assert CATEGORY_BRUTE_FORCE in cats


# ── File promotion ─────────────────────────────────────────────────────────


@pytest.fixture
def pending_and_staged(tmp_path: Path) -> tuple[Path, Path]:
    pending = tmp_path / "pending"
    staged = tmp_path / "staged"
    pending.mkdir()
    return pending, staged


def _write_pending(pending: Path, ip: str, lines: list[str]) -> Path:
    file = pending / f"{ip}.log"
    file.write_text("\n".join(lines) + "\n")
    return file


def test_promote_file_writes_staged_and_removes_pending(pending_and_staged):
    pending, staged = pending_and_staged
    file = _write_pending(
        pending,
        "155.2.225.177",
        [
            "2026-04-23T14:07:37Z 155.2.225.177 GET /wp-login.php 429",
            "2026-04-23T14:07:38Z 155.2.225.177 GET /wp-admin/ 429",
            "2026-04-23T14:07:39Z 155.2.225.177 GET /.env 429",
        ],
    )

    client = AsyncMock()
    client.get = AsyncMock(side_effect=Exception("ripe offline"))
    result = asyncio.run(promote_file(file, staged, client))

    assert result is not None
    assert not file.exists()
    assert result.parent == staged
    content = result.read_text()
    assert "IP: 155.2.225.177" in content
    assert "ASN: unknown" in content
    assert "Country: unknown" in content
    assert "RIR: unknown" in content
    assert "ReportTo: AbuseIPDB" in content
    assert "AbuseIPDB-Categories: 19,21" in content
    assert "RequestCount: 3" in content
    assert "FirstSeen: 2026-04-23T14:07:37Z" in content
    assert "LastSeen: 2026-04-23T14:07:39Z" in content
    assert "/wp-login.php 429" in content


def test_promote_file_with_ripe_lookup_populates_asn_country(pending_and_staged):
    pending, staged = pending_and_staged
    file = _write_pending(
        pending,
        "155.2.225.177",
        ["2026-04-23T14:07:37Z 155.2.225.177 GET /.env 429"],
    )

    # Fake RIPE Stat responses.
    prefix_resp = AsyncMock()
    prefix_resp.raise_for_status = lambda: None
    prefix_resp.json = lambda: {"data": {"asns": [{"asn": 8758, "holder": "Iway AG"}]}}

    geoloc_resp = AsyncMock()
    geoloc_resp.raise_for_status = lambda: None
    geoloc_resp.json = lambda: {"data": {"locations": [{"country": "CH"}]}}

    async def fake_get(url, **_):
        return prefix_resp if "prefix-overview" in url else geoloc_resp

    client = AsyncMock()
    client.get = AsyncMock(side_effect=fake_get)

    result = asyncio.run(promote_file(file, staged, client))
    content = result.read_text()
    assert "ASN: AS8758 (Iway AG)" in content
    assert "Country: CH" in content
    assert "RIR: RIPE NCC" in content
    assert "ReportTo: AbuseIPDB, RIPE NCC" in content


def test_promote_file_empty_is_skipped(pending_and_staged):
    pending, staged = pending_and_staged
    file = pending / "1.2.3.4.log"
    file.write_text("\n\n\n")  # no valid lines
    client = AsyncMock()
    client.get = AsyncMock()
    result = asyncio.run(promote_file(file, staged, client))
    assert result is None
    assert not file.exists()


# ── Watcher loop ────────────────────────────────────────────────────────────


def test_watcher_promotes_quiet_file(pending_and_staged):
    pending, staged = pending_and_staged
    file = _write_pending(
        pending, "9.9.9.9", ["2026-04-23T14:07:37Z 9.9.9.9 GET /a 429"]
    )
    # Force mtime to be old enough.
    old = file.stat().st_mtime - 3600
    os.utime(file, (old, old))

    client = AsyncMock()
    client.get = AsyncMock(side_effect=Exception("offline"))

    async def run_briefly():
        task = asyncio.create_task(
            run_watcher(
                pending,
                staged,
                quiet_seconds=60.0,
                tick_seconds=0.01,
                client=client,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_briefly())
    assert not file.exists()
    assert (staged / "9.9.9.9.log").exists()


def test_watcher_leaves_recent_file_alone(pending_and_staged):
    pending, staged = pending_and_staged
    file = _write_pending(
        pending, "9.9.9.9", ["2026-04-23T14:07:37Z 9.9.9.9 GET /a 429"]
    )
    # mtime is now — watcher should not promote yet.

    client = AsyncMock()
    client.get = AsyncMock()

    async def run_briefly():
        task = asyncio.create_task(
            run_watcher(
                pending,
                staged,
                quiet_seconds=60.0,
                tick_seconds=0.01,
                client=client,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_briefly())
    assert file.exists()
    assert not staged.exists() or not any(staged.iterdir())


def test_watcher_handles_missing_pending_dir(tmp_path):
    client = AsyncMock()
    client.get = AsyncMock()

    async def run_briefly():
        task = asyncio.create_task(
            run_watcher(
                tmp_path / "pending-does-not-exist",
                tmp_path / "staged",
                quiet_seconds=60.0,
                tick_seconds=0.01,
                client=client,
            )
        )
        await asyncio.sleep(0.03)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Should not raise.
    asyncio.run(run_briefly())
