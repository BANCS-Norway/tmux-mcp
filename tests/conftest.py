"""Shared test fixtures.

Every test runs against a temp TMUX_MCP_STATE_DIR so nothing writes to
~/.config/tmux-mcp. Required env vars are populated with dummy values so
importing tmux_mcp.server doesn't raise SystemExit at import time.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Set required env vars at module import so pytest collection can safely import
# tmux_mcp.server (which raises SystemExit on missing env). Individual tests
# can still override via monkeypatch.setenv.
os.environ.setdefault("TMUX_MCP_PUBLIC_URL", "https://test.example")
os.environ.setdefault("TMUX_MCP_GITHUB_CLIENT_ID", "gh-client-id")
os.environ.setdefault("TMUX_MCP_GITHUB_CLIENT_SECRET", "gh-client-secret")
os.environ.setdefault("TMUX_MCP_ALLOWED_GITHUB_USERS", "alice,bob")


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state_dir = tmp_path / "tmux-mcp-state"
    state_dir.mkdir()
    monkeypatch.setenv("TMUX_MCP_STATE_DIR", str(state_dir))
    monkeypatch.setenv("TMUX_MCP_PUBLIC_URL", "https://test.example")
    monkeypatch.setenv("TMUX_MCP_GITHUB_CLIENT_ID", "gh-client-id")
    monkeypatch.setenv("TMUX_MCP_GITHUB_CLIENT_SECRET", "gh-client-secret")
    monkeypatch.setenv("TMUX_MCP_ALLOWED_GITHUB_USERS", "alice,bob")
    # Ensure auth module picks up the temp state dir even if previously imported.
    for mod in ("tmux_mcp.auth", "tmux_mcp.server"):
        if mod in os.sys.modules:
            del os.sys.modules[mod]
    return state_dir
