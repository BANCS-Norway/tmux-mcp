"""Smoke tests for the three tmux tool handlers and the session resolver.

No real tmux — subprocess.run is monkeypatched to return scripted
(stdout, stderr, returncode) for each invocation. Each test asserts on
the exact argv the tool would have handed to tmux.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest


class FakeRun:
    """Records argv for each subprocess.run call and replays scripted responses."""

    def __init__(self, scripts: list[tuple[str, str, int]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self._scripts = list(scripts or [])
        self.default = ("", "", 0)

    def __call__(self, cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        stdout, stderr, rc = self._scripts.pop(0) if self._scripts else self.default
        return subprocess.CompletedProcess(
            args=cmd, returncode=rc, stdout=stdout, stderr=stderr
        )


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    """Replace subprocess.run inside the server module with a scripted fake."""
    from tmux_mcp import server

    fake = FakeRun()
    monkeypatch.setattr(server.subprocess, "run", fake)
    return fake


# ── tmux_get_summary ─────────────────────────────────────────────────────────


class TestGetSummary:
    async def test_builds_capture_pane_with_target_and_lines(
        self, fake_run: FakeRun
    ) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("hello\nworld\n", "", 0)]
        result = await server.tmux_get_summary(session="milorg", pane=0, lines=42)

        assert len(fake_run.calls) == 1
        assert fake_run.calls[0] == [
            "tmux",
            "capture-pane",
            "-p",
            "-t",
            "=milorg:.0",
            "-S",
            "-42",
        ]
        payload = json.loads(result)
        assert payload["target"] == "=milorg:.0"
        assert payload["lines_captured"] == 2

    async def test_nonzero_exit_returns_json_error_with_hint(
        self, fake_run: FakeRun
    ) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "can't find session milorg", 1)]
        result = await server.tmux_get_summary(session="milorg", pane=0, lines=5)

        payload = json.loads(result)
        assert "error" in payload
        assert "tmux capture-pane failed" in payload["error"]
        assert "can't find session" in payload["error"]
        assert "milorg" in payload["hint"]
        assert "tmux_list_sessions" in payload["hint"]


# ── tmux_send_prompt ─────────────────────────────────────────────────────────


class TestSendPrompt:
    async def test_sends_literal_and_presses_enter_by_default(
        self, fake_run: FakeRun
    ) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "", 0), ("", "", 0)]
        result = await server.tmux_send_prompt(
            prompt="echo hi", session="milorg", pane=0
        )

        assert len(fake_run.calls) == 2
        # Literal prompt first — note the -l flag to avoid interpreting "Enter" etc. as keys.
        assert fake_run.calls[0] == [
            "tmux",
            "send-keys",
            "-t",
            "=milorg:.0",
            "-l",
            "echo hi",
        ]
        # Then a separate Enter keystroke (without -l so tmux treats it as a key).
        assert fake_run.calls[1] == ["tmux", "send-keys", "-t", "=milorg:.0", "Enter"]
        assert json.loads(result)["enter_pressed"] is True

    async def test_skips_enter_when_press_enter_false(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "", 0)]
        result = await server.tmux_send_prompt(
            prompt="echo hi", session="milorg", pane=0, press_enter=False
        )

        assert len(fake_run.calls) == 1
        assert fake_run.calls[0][-1] == "echo hi"
        assert "Enter" not in fake_run.calls[0]
        assert json.loads(result)["enter_pressed"] is False

    async def test_send_failure_returns_json_error_with_hint(
        self, fake_run: FakeRun
    ) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "no such pane", 1)]
        result = await server.tmux_send_prompt(
            prompt="echo hi", session="milorg", pane=0
        )

        payload = json.loads(result)
        assert "tmux send-keys failed" in payload["error"]
        assert "tmux_list_sessions" in payload["hint"]

    async def test_enter_failure_after_literal_success(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "", 0), ("", "Enter failed", 1)]
        result = await server.tmux_send_prompt(
            prompt="echo hi", session="milorg", pane=0
        )

        payload = json.loads(result)
        assert "Enter failed" in payload["error"]


# ── tmux_list_sessions ───────────────────────────────────────────────────────


class TestListSessions:
    async def test_success_returns_lines(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [
            (
                "milorg (1 windows, created X)\nbancs_blog (2 windows, created Y)\n",
                "",
                0,
            )
        ]
        result = await server.tmux_list_sessions()

        payload = json.loads(result)
        assert len(payload["sessions"]) == 2
        assert "milorg" in payload["sessions"][0]

    async def test_failure_returns_json_error_with_hint(
        self, fake_run: FakeRun
    ) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "no server running on /tmp/tmux-1000/default", 1)]
        result = await server.tmux_list_sessions()

        payload = json.loads(result)
        assert "tmux list-sessions failed" in payload["error"]
        assert "No tmux server running" in payload["hint"]


# ── _resolve_session ─────────────────────────────────────────────────────────


class TestResolveSession:
    def test_explicit_session_passes_through(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        name, err = server._resolve_session("bancs_blog")
        assert name == "bancs_blog"
        assert err is None
        # No subprocess call needed when session is explicit
        assert fake_run.calls == []

    def test_auto_picks_single_session(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("only_one\n", "", 0)]
        name, err = server._resolve_session(None)
        assert name == "only_one"
        assert err is None

    def test_multiple_sessions_returns_error_with_list(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("a\nb\nc\n", "", 0)]
        name, err = server._resolve_session(None)
        assert name is None
        assert err is not None
        payload = json.loads(err)
        assert payload["available_sessions"] == ["a", "b", "c"]
        assert "session argument required" in payload["error"]

    def test_no_sessions_returns_error(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "", 0)]
        name, err = server._resolve_session(None)
        assert name is None
        assert json.loads(err)["error"] == "no tmux sessions running"

    def test_list_failure_surfaces(self, fake_run: FakeRun) -> None:
        from tmux_mcp import server

        fake_run._scripts = [("", "connection refused", 1)]
        name, err = server._resolve_session(None)
        assert name is None
        payload = json.loads(err)
        assert "tmux list-sessions failed" in payload["error"]


# ── Claude Chat compat unwrap ────────────────────────────────────────────────


class TestUnwrapChatArguments:
    def test_unwraps_the_exact_broken_shape(self) -> None:
        from tmux_mcp.server import _unwrap_chat_arguments

        msg = {
            "method": "tools/call",
            "params": {
                "name": "tmux_get_summary",
                "arguments": {"params": '{"session": "bancs_blog", "lines": 80}'},
            },
        }
        assert _unwrap_chat_arguments(msg) is True
        assert msg["params"]["arguments"] == {"session": "bancs_blog", "lines": 80}

    def test_leaves_well_formed_arguments_alone(self) -> None:
        from tmux_mcp.server import _unwrap_chat_arguments

        msg = {
            "method": "tools/call",
            "params": {
                "name": "tmux_get_summary",
                "arguments": {"session": "bancs_blog", "lines": 80},
            },
        }
        before = dict(msg["params"]["arguments"])
        assert _unwrap_chat_arguments(msg) is False
        assert msg["params"]["arguments"] == before

    def test_ignores_non_tools_call_methods(self) -> None:
        from tmux_mcp.server import _unwrap_chat_arguments

        msg = {
            "method": "tools/list",
            "params": {"arguments": {"params": '{"x": 1}'}},
        }
        assert _unwrap_chat_arguments(msg) is False

    def test_ignores_params_key_when_other_keys_present(self) -> None:
        from tmux_mcp.server import _unwrap_chat_arguments

        msg = {
            "method": "tools/call",
            "params": {
                "name": "x",
                "arguments": {"params": '{"x": 1}', "other": "keep"},
            },
        }
        # strict shape: arguments must be exactly {"params": "<json>"}
        assert _unwrap_chat_arguments(msg) is False

    def test_ignores_invalid_inner_json(self) -> None:
        from tmux_mcp.server import _unwrap_chat_arguments

        msg = {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {"params": "not json {"}},
        }
        assert _unwrap_chat_arguments(msg) is False
