"""Tests for abuse-pipeline MCP tool implementations."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from tmux_mcp.reports import (
    EMPTY_PENDING,
    EMPTY_REPORTED,
    EMPTY_STAGED,
    get_pending,
    get_staged,
    list_reported,
    parse_period,
    send_report,
)


# ── parse_period ────────────────────────────────────────────────────────────


def test_parse_period_none_returns_none():
    assert parse_period(None) is None
    assert parse_period("") is None


def test_parse_period_last_day():
    now = datetime.now(timezone.utc)
    cutoff = parse_period("last_day")
    assert cutoff is not None
    assert abs((now - cutoff) - timedelta(days=1)) < timedelta(seconds=5)


def test_parse_period_last_week():
    now = datetime.now(timezone.utc)
    cutoff = parse_period("last_week")
    assert cutoff is not None
    assert abs((now - cutoff) - timedelta(days=7)) < timedelta(seconds=5)


def test_parse_period_since():
    cutoff = parse_period("since:2025-01-15")
    assert cutoff == datetime(2025, 1, 15, tzinfo=timezone.utc)


def test_parse_period_invalid_since():
    with pytest.raises(ValueError):
        parse_period("since:not-a-date")


def test_parse_period_unknown():
    with pytest.raises(ValueError):
        parse_period("yesterday")


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def log_root(tmp_path: Path) -> Path:
    (tmp_path / "pending").mkdir()
    (tmp_path / "staged").mkdir()
    (tmp_path / "reported").mkdir()
    return tmp_path


def _write_pending(log_root: Path, ip: str, lines: list[str]) -> Path:
    f = log_root / "pending" / f"{ip}.log"
    f.write_text("\n".join(lines) + "\n")
    return f


def _write_staged(log_root: Path, ip: str, header: dict, body: list[str]) -> Path:
    f = log_root / "staged" / f"{ip}.log"
    head = "\n".join(f"{k}: {v}" for k, v in header.items())
    body_text = "\n".join(body)
    f.write_text(f"{head}\n\nRequests:\n{body_text}\n")
    return f


# ── get_pending ─────────────────────────────────────────────────────────────


def test_get_pending_empty_folder(log_root):
    assert get_pending(log_root) == EMPTY_PENDING


def test_get_pending_missing_folder(tmp_path):
    assert get_pending(tmp_path) == EMPTY_PENDING


def test_get_pending_lists_ips_with_counts(log_root):
    _write_pending(
        log_root,
        "1.2.3.4",
        [
            "2026-04-23T10:00:00Z 1.2.3.4 GET /a 429",
            "2026-04-23T10:00:01Z 1.2.3.4 GET /b 429",
        ],
    )
    _write_pending(log_root, "5.6.7.8", ["2026-04-23T11:00:00Z 5.6.7.8 GET /c 429"])
    out = get_pending(log_root)
    assert "2 pending IP(s)" in out
    assert "1.2.3.4 — 2 entries" in out
    assert "5.6.7.8 — 1 entries" in out


def test_get_pending_period_filter_by_last_seen(log_root):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _write_pending(log_root, "1.1.1.1", [f"{today} 1.1.1.1 GET /new 429"])
    _write_pending(log_root, "2.2.2.2", [f"{old} 2.2.2.2 GET /old 429"])
    out = get_pending(log_root, "last_week")
    assert "1.1.1.1" in out
    assert "2.2.2.2" not in out


# ── get_staged ──────────────────────────────────────────────────────────────


def test_get_staged_empty_folder(log_root):
    assert get_staged(log_root) == EMPTY_STAGED


def test_get_staged_missing_folder(tmp_path):
    assert get_staged(tmp_path) == EMPTY_STAGED


def test_get_staged_lists_header_summary(log_root):
    _write_staged(
        log_root,
        "1.2.3.4",
        {
            "IP": "1.2.3.4",
            "ASN": "AS8758 (Iway AG)",
            "Country": "CH",
            "RIR": "RIPE NCC",
            "ReportTo": "AbuseIPDB, RIPE NCC",
            "AbuseIPDB-Categories": "19,21",
            "FirstSeen": "2026-04-23T10:00:00Z",
            "LastSeen": "2026-04-23T10:05:00Z",
            "RequestCount": "7",
        },
        ["2026-04-23T10:00:00Z GET /wp-login.php 429"],
    )
    out = get_staged(log_root)
    assert "1 staged report(s)" in out
    assert "1.2.3.4" in out
    assert "RIPE NCC" in out
    assert "19,21" in out
    assert "7 requests" in out


def test_get_staged_period_filter(log_root):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _write_staged(
        log_root,
        "1.1.1.1",
        {"IP": "1.1.1.1", "LastSeen": today, "AbuseIPDB-Categories": "19"},
        [f"{today} GET / 429"],
    )
    _write_staged(
        log_root,
        "2.2.2.2",
        {"IP": "2.2.2.2", "LastSeen": old, "AbuseIPDB-Categories": "19"},
        [f"{old} GET / 429"],
    )
    out = get_staged(log_root, "last_week")
    assert "1.1.1.1" in out
    assert "2.2.2.2" not in out


# ── list_reported ───────────────────────────────────────────────────────────


def test_list_reported_requires_period(log_root):
    with pytest.raises(ValueError):
        list_reported(log_root, "")


def test_list_reported_empty_folder(log_root):
    assert list_reported(log_root, "last_day") == EMPTY_REPORTED


def test_list_reported_missing_folder(tmp_path):
    assert list_reported(tmp_path, "last_day") == EMPTY_REPORTED


def test_list_reported_filters_by_filename_timestamp(log_root):
    now = datetime.now(timezone.utc)
    old_ts = (now - timedelta(days=30)).strftime("%Y%m%dT%H%M%SZ")
    new_ts = now.strftime("%Y%m%dT%H%M%SZ")
    (log_root / "reported" / f"1.1.1.1-{new_ts}.log").write_text("x")
    (log_root / "reported" / f"2.2.2.2-{old_ts}.log").write_text("x")
    out = list_reported(log_root, "last_week")
    assert "1.1.1.1" in out
    assert "2.2.2.2" not in out


def test_list_reported_ignores_bad_filenames(log_root):
    (log_root / "reported" / "not-a-report.log").write_text("x")
    out = list_reported(log_root, "last_day")
    assert out == EMPTY_REPORTED


# ── send_report ─────────────────────────────────────────────────────────────


def _fake_abuseipdb_ok():
    resp = AsyncMock()
    resp.status_code = 200
    resp.text = '{"data":{"abuseConfidenceScore":100}}'
    return resp


def _fake_abuseipdb_err(status=429):
    resp = AsyncMock()
    resp.status_code = status
    resp.text = '{"errors":[{"detail":"rate limited"}]}'
    return resp


def test_send_report_without_key_returns_error(log_root):
    result = asyncio.run(send_report(log_root, "1.2.3.4.log", None))
    assert "TMUX_MCP_ABUSEIPDB_KEY" in result


def test_send_report_rejects_path_traversal(log_root):
    result = asyncio.run(send_report(log_root, "../../../etc/passwd", "key"))
    assert "Invalid filename" in result


def test_send_report_file_not_found(log_root):
    client = AsyncMock()
    result = asyncio.run(send_report(log_root, "missing.log", "key", client=client))
    assert "not found" in result


def test_send_report_staged_submits_and_archives(log_root):
    _write_staged(
        log_root,
        "1.2.3.4",
        {
            "IP": "1.2.3.4",
            "RIR": "RIPE NCC",
            "AbuseIPDB-Categories": "19,21",
            "FirstSeen": "2026-04-23T10:00:00Z",
            "LastSeen": "2026-04-23T10:05:00Z",
            "RequestCount": "3",
        },
        ["2026-04-23T10:00:00Z GET /wp-login.php 429"],
    )
    client = AsyncMock()
    client.post = AsyncMock(return_value=_fake_abuseipdb_ok())
    result = asyncio.run(
        send_report(log_root, "1.2.3.4.log", "test-key", client=client)
    )
    assert "AbuseIPDB accepted" in result
    assert "Archived" in result
    assert not (log_root / "staged" / "1.2.3.4.log").exists()
    assert any((log_root / "reported").glob("1.2.3.4-*.log"))
    # Verify POST was called with correct shape.
    _, kwargs = client.post.call_args
    assert kwargs["data"]["ip"] == "1.2.3.4"
    assert kwargs["data"]["categories"] == "19,21"
    assert kwargs["headers"]["Key"] == "test-key"


def test_send_report_leaves_file_on_abuseipdb_error(log_root):
    _write_staged(
        log_root,
        "1.2.3.4",
        {"IP": "1.2.3.4", "AbuseIPDB-Categories": "19"},
        ["2026-04-23T10:00:00Z GET /wp-login.php 429"],
    )
    client = AsyncMock()
    client.post = AsyncMock(return_value=_fake_abuseipdb_err(429))
    result = asyncio.run(
        send_report(log_root, "1.2.3.4.log", "test-key", client=client)
    )
    assert "rejected" in result
    assert "retry" in result
    # File still in staged/; nothing in reported/.
    assert (log_root / "staged" / "1.2.3.4.log").exists()
    assert not any((log_root / "reported").glob("*.log"))


def test_send_report_on_pending_runs_enrichment_inline(log_root):
    _write_pending(
        log_root,
        "1.2.3.4",
        [
            "2026-04-23T10:00:00Z 1.2.3.4 GET /wp-login.php 429",
            "2026-04-23T10:00:01Z 1.2.3.4 GET /.env 429",
            "2026-04-23T10:00:02Z 1.2.3.4 GET /phpmyadmin 429",
        ],
    )
    client = AsyncMock()

    # Simulate RIPE offline (irrelevant for category detection).
    async def _get(url, **_):
        raise Exception("ripe offline")

    client.get = AsyncMock(side_effect=_get)
    client.post = AsyncMock(return_value=_fake_abuseipdb_ok())

    result = asyncio.run(
        send_report(log_root, "1.2.3.4.log", "test-key", client=client)
    )
    assert "accepted" in result
    assert "Archived" in result
    # Pending file gone (promoted then archived).
    assert not (log_root / "pending" / "1.2.3.4.log").exists()
    # Reported archive has it.
    assert any((log_root / "reported").glob("1.2.3.4-*.log"))


def test_send_report_no_categories_refuses(log_root):
    _write_staged(
        log_root,
        "1.2.3.4",
        {"IP": "1.2.3.4", "AbuseIPDB-Categories": "none"},
        ["2026-04-23T10:00:00Z GET / 429"],
    )
    client = AsyncMock()
    client.post = AsyncMock()
    result = asyncio.run(send_report(log_root, "1.2.3.4.log", "key", client=client))
    assert "no categories" in result
    client.post.assert_not_called()
    assert (log_root / "staged" / "1.2.3.4.log").exists()


# ── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_list_empty(log_root, monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--list"])

    rc = cli_main()
    assert rc == 0
    assert capsys.readouterr().out.strip() == EMPTY_STAGED


def test_cli_list_returns_filenames(log_root, monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    _write_staged(
        log_root,
        "1.2.3.4",
        {"IP": "1.2.3.4", "AbuseIPDB-Categories": "19"},
        ["2026-04-23T10:00:00Z GET /.env 429"],
    )
    _write_staged(
        log_root,
        "5.6.7.8",
        {"IP": "5.6.7.8", "AbuseIPDB-Categories": "21"},
        ["2026-04-23T10:00:00Z GET /a 429"],
    )

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--list"])

    rc = cli_main()
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert sorted(out) == ["1.2.3.4.log", "5.6.7.8.log"]


def test_cli_submit_filename_succeeds(log_root, monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    _write_staged(
        log_root,
        "1.2.3.4",
        {"IP": "1.2.3.4", "AbuseIPDB-Categories": "19"},
        ["2026-04-23T10:00:00Z GET /.env 429"],
    )

    async def fake_send_report(log_root_arg, filename, api_key, client=None):
        return f"AbuseIPDB accepted submission (HTTP 200)\nArchived to {filename}."

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    monkeypatch.setenv("TMUX_MCP_ABUSEIPDB_KEY", "test-key")
    monkeypatch.setattr("tmux_mcp.reports.send_report", fake_send_report)
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "1.2.3.4.log"])

    rc = cli_main()
    assert rc == 0
    assert "Archived to" in capsys.readouterr().out


def test_cli_submit_failure_returns_nonzero(log_root, monkeypatch):
    from tmux_mcp.reports import cli_main

    async def fake_send_report(log_root_arg, filename, api_key, client=None):
        return "AbuseIPDB rejected submission (HTTP 422): bad categories"

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    monkeypatch.setattr("tmux_mcp.reports.send_report", fake_send_report)
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "1.2.3.4.log"])

    assert cli_main() == 1


def test_cli_no_args_errors(log_root, monkeypatch):
    from tmux_mcp.reports import cli_main

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report"])
    with pytest.raises(SystemExit):
        cli_main()


def test_staged_completer_matches_prefix(log_root, monkeypatch):
    from tmux_mcp.reports import _staged_completer

    _write_staged(
        log_root,
        "1.2.3.4",
        {"IP": "1.2.3.4", "AbuseIPDB-Categories": "19"},
        ["2026-04-23T10:00:00Z GET /.env 429"],
    )
    _write_staged(
        log_root,
        "1.2.99.99",
        {"IP": "1.2.99.99", "AbuseIPDB-Categories": "21"},
        ["2026-04-23T10:00:00Z GET /a 429"],
    )
    _write_staged(
        log_root,
        "9.9.9.9",
        {"IP": "9.9.9.9", "AbuseIPDB-Categories": "21"},
        ["2026-04-23T10:00:00Z GET /b 429"],
    )

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(log_root))
    matches = _staged_completer("1.2.")
    assert sorted(matches) == ["1.2.3.4.log", "1.2.99.99.log"]


def test_staged_completer_handles_missing_dir(tmp_path, monkeypatch):
    from tmux_mcp.reports import _staged_completer

    monkeypatch.setenv("TMUX_MCP_LOG_DIR", str(tmp_path / "nope"))
    assert _staged_completer("") == []


def test_cli_register_bash_prints_snippet(monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--register", "bash"])
    rc = cli_main()
    out = capsys.readouterr().out
    assert rc == 0
    assert 'eval "$(register-python-argcomplete tmux-mcp-report)"' in out
    assert "compinit" not in out


def test_cli_register_zsh_includes_compinit(monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--register", "zsh"])
    rc = cli_main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "autoload -U compinit && compinit" in out
    assert 'eval "$(register-python-argcomplete tmux-mcp-report)"' in out


def test_cli_register_autodetect_zsh_from_env(monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    monkeypatch.setenv("SHELL", "/usr/bin/zsh")
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--register"])
    rc = cli_main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "compinit" in out


def test_cli_register_autodetect_falls_back_to_bash(monkeypatch, capsys):
    from tmux_mcp.reports import cli_main

    monkeypatch.delenv("SHELL", raising=False)
    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--register"])
    rc = cli_main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "compinit" not in out
    assert 'eval "$(register-python-argcomplete tmux-mcp-report)"' in out


def test_cli_register_unknown_shell_rejected(monkeypatch):
    from tmux_mcp.reports import cli_main

    monkeypatch.setattr("sys.argv", ["tmux-mcp-report", "--register", "fish"])
    with pytest.raises(SystemExit):
        cli_main()
