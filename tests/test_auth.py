"""Unit tests for tmux_mcp.auth.GithubOAuthProvider.

No real network: httpx.AsyncClient is monkeypatched. No real ~/.config:
conftest redirects TMUX_MCP_STATE_DIR to a tmp_path per test.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_provider() -> Any:
    """Fresh provider instance per test. Imported lazily so conftest's env
    vars and sys.modules purging apply."""
    from tmux_mcp.auth import GithubOAuthProvider

    return GithubOAuthProvider(
        public_url="https://test.example",
        github_client_id="gh-id",
        github_client_secret="gh-secret",
        allowed_github_users={"alice", "BOB"},  # mixed case → lowered internally
    )


def _make_client(client_id: str = "mcp-client-1") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["https://client.example/cb"],
        token_endpoint_auth_method="none",
    )


def _make_params(state: str = "mcp-state-xyz") -> AuthorizationParams:
    return AuthorizationParams(
        state=state,
        scopes=["mcp:read"],
        code_challenge="test-pkce-challenge",
        redirect_uri="https://client.example/cb",
        redirect_uri_provided_explicitly=True,
        resource="https://test.example",
    )


def _mock_httpx(
    monkeypatch: pytest.MonkeyPatch, *, login: str, include_token: bool = True
) -> None:
    """Wire httpx.AsyncClient to return a scripted GitHub token+user response."""
    import httpx

    tok_resp = MagicMock()
    tok_resp.raise_for_status = MagicMock()
    tok_resp.json = MagicMock(
        return_value={"access_token": "gh-access"} if include_token else {}
    )
    user_resp = MagicMock()
    user_resp.raise_for_status = MagicMock()
    user_resp.json = MagicMock(return_value={"login": login})

    client = MagicMock()
    client.post = AsyncMock(return_value=tok_resp)
    client.get = AsyncMock(return_value=user_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: client)


# ── Allowlist ────────────────────────────────────────────────────────────────


class TestAllowlist:
    def test_empty_allowlist_rejected(self) -> None:
        from tmux_mcp.auth import GithubOAuthProvider

        with pytest.raises(ValueError, match="ALLOWED_GITHUB_USERS"):
            GithubOAuthProvider(
                public_url="https://test.example",
                github_client_id="x",
                github_client_secret="x",
                allowed_github_users=set(),
            )

    def test_http_public_url_rejected(self) -> None:
        from tmux_mcp.auth import GithubOAuthProvider

        with pytest.raises(ValueError, match="https"):
            GithubOAuthProvider(
                public_url="http://test.example",
                github_client_id="x",
                github_client_secret="x",
                allowed_github_users={"alice"},
            )

    def test_allowlist_is_lowered(self) -> None:
        provider = _make_provider()
        assert provider.allowed_users == {"alice", "bob"}

    async def test_allowed_user_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = _make_provider()
        params = _make_params()
        await provider.register_client(_make_client())
        await provider.authorize(_make_client(), params)
        state = next(iter(provider._pending))

        _mock_httpx(
            monkeypatch, login="Alice"
        )  # mixed case — GitHub often returns display-case
        redirect = await provider.handle_github_callback("gh-code", state)

        assert "code=" in redirect
        assert state not in provider._pending  # consumed

    async def test_disallowed_user_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        await provider.register_client(_make_client())
        await provider.authorize(_make_client(), _make_params())
        state = next(iter(provider._pending))

        _mock_httpx(monkeypatch, login="eve")
        with pytest.raises(PermissionError, match="not in allowlist"):
            await provider.handle_github_callback("gh-code", state)

    async def test_github_refusing_token_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        await provider.register_client(_make_client())
        await provider.authorize(_make_client(), _make_params())
        state = next(iter(provider._pending))

        _mock_httpx(monkeypatch, login="alice", include_token=False)
        with pytest.raises(PermissionError, match="declined"):
            await provider.handle_github_callback("gh-code", state)


# ── authorize → callback round-trip ──────────────────────────────────────────


class TestAuthorizeRoundtrip:
    async def test_authorize_stores_pending(self) -> None:
        provider = _make_provider()
        params = _make_params()
        await provider.register_client(_make_client())

        url = await provider.authorize(_make_client(), params)

        assert url.startswith("https://github.com/login/oauth/authorize?")
        assert len(provider._pending) == 1
        pending = next(iter(provider._pending.values()))
        assert pending.code_challenge == "test-pkce-challenge"
        assert pending.mcp_state == "mcp-state-xyz"
        assert pending.redirect_uri == "https://client.example/cb"

    async def test_callback_consumes_pending_and_issues_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        await provider.register_client(_make_client())
        await provider.authorize(_make_client(), _make_params())
        state = next(iter(provider._pending))

        _mock_httpx(monkeypatch, login="alice")
        redirect = await provider.handle_github_callback("gh-code", state)

        assert state not in provider._pending
        assert len(provider._codes) == 1
        assert "state=mcp-state-xyz" in redirect
        assert "code=" in redirect

    async def test_callback_with_unknown_state_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        _mock_httpx(monkeypatch, login="alice")
        with pytest.raises(PermissionError, match="unknown or expired"):
            await provider.handle_github_callback("gh-code", "no-such-state")


# ── Auth codes ───────────────────────────────────────────────────────────────


class TestAuthorizationCodes:
    async def test_code_expiry_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tmux_mcp.auth import AUTH_CODE_TTL

        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)

        code_str, code = next(iter(provider._codes.items()))
        code.expires_at = time.time() - 1  # force expiry
        assert code.expires_at < time.time()

        loaded = await provider.load_authorization_code(client, code_str)
        assert loaded is None
        # Expired codes are evicted on load
        assert code_str not in provider._codes
        # And the TTL constant is the one we think it is
        assert AUTH_CODE_TTL == 600

    async def test_code_is_single_use(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)

        code_str = next(iter(provider._codes))
        loaded = await provider.load_authorization_code(client, code_str)
        assert loaded is not None
        await provider.exchange_authorization_code(client, loaded)
        # Second exchange fails because code is gone
        assert await provider.load_authorization_code(client, code_str) is None

    async def test_code_wrong_client_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        client_a = _make_client("client-A")
        client_b = _make_client("client-B")
        await provider.register_client(client_a)
        await provider.register_client(client_b)
        await provider.authorize(client_a, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)

        code_str = next(iter(provider._codes))
        # Same code, wrong client → None
        assert await provider.load_authorization_code(client_b, code_str) is None


# ── JWT issuance ─────────────────────────────────────────────────────────────


class TestJwtIssuance:
    async def test_access_and_refresh_tokens_differ(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)
        code_str = next(iter(provider._codes))
        code = await provider.load_authorization_code(client, code_str)
        assert code is not None
        tokens = await provider.exchange_authorization_code(client, code)

        assert tokens.access_token != tokens.refresh_token

        access_claims = jwt.decode(
            tokens.access_token,
            provider._public_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer="tmux-mcp",
        )
        refresh_claims = jwt.decode(
            tokens.refresh_token,
            provider._public_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer="tmux-mcp",
        )
        assert access_claims["typ"] == "access"
        assert refresh_claims["typ"] == "refresh"
        # refresh lives strictly longer than access
        assert refresh_claims["exp"] > access_claims["exp"]
        # same subject + audience
        assert access_claims["sub"] == refresh_claims["sub"] == "alice"
        assert access_claims["aud"] == refresh_claims["aud"] == client.client_id

    async def test_load_access_token_rejects_refresh(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)
        code_str = next(iter(provider._codes))
        code = await provider.load_authorization_code(client, code_str)
        tokens = await provider.exchange_authorization_code(client, code)

        # access token loads as access
        loaded = await provider.load_access_token(tokens.access_token)
        assert loaded is not None
        assert loaded.client_id == client.client_id

        # refresh token MUST NOT load as access
        assert await provider.load_access_token(tokens.refresh_token) is None

    async def test_load_refresh_token_rejects_access(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)
        code_str = next(iter(provider._codes))
        code = await provider.load_authorization_code(client, code_str)
        tokens = await provider.exchange_authorization_code(client, code)

        assert await provider.load_refresh_token(client, tokens.access_token) is None
        rt = await provider.load_refresh_token(client, tokens.refresh_token)
        assert rt is not None

    async def test_refresh_exchange_preserves_sub_and_resource(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _make_provider()
        client = _make_client()
        await provider.register_client(client)
        await provider.authorize(client, _make_params())
        state = next(iter(provider._pending))
        _mock_httpx(monkeypatch, login="alice")
        await provider.handle_github_callback("gh-code", state)
        code_str = next(iter(provider._codes))
        code = await provider.load_authorization_code(client, code_str)
        tokens = await provider.exchange_authorization_code(client, code)

        rt = await provider.load_refresh_token(client, tokens.refresh_token)
        new_tokens = await provider.exchange_refresh_token(client, rt, scopes=[])

        new_claims = jwt.decode(
            new_tokens.access_token,
            provider._public_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer="tmux-mcp",
        )
        assert new_claims["sub"] == "alice"
        assert new_claims["resource"] == "https://test.example"
        assert new_claims["aud"] == client.client_id


# ── Housekeeping ─────────────────────────────────────────────────────────────


class TestHousekeeping:
    async def test_pending_gc_drops_expired(self) -> None:
        from tmux_mcp.auth import PENDING_AUTH_TTL, _PendingAuth

        provider = _make_provider()
        fresh = _PendingAuth(
            client_id="c",
            scopes=[],
            code_challenge="x",
            redirect_uri="https://client.example/cb",
            redirect_uri_provided_explicitly=True,
            resource=None,
            mcp_state=None,
        )
        stale = _PendingAuth(
            client_id="c",
            scopes=[],
            code_challenge="x",
            redirect_uri="https://client.example/cb",
            redirect_uri_provided_explicitly=True,
            resource=None,
            mcp_state=None,
        )
        stale.created_at = time.time() - PENDING_AUTH_TTL - 1

        provider._pending["fresh"] = fresh
        provider._pending["stale"] = stale
        provider._gc_pending()

        assert "fresh" in provider._pending
        assert "stale" not in provider._pending


# ── DCR ─────────────────────────────────────────────────────────────────────


class TestDynamicClientRegistration:
    async def test_register_mints_client_id_and_persists(self) -> None:
        from tmux_mcp.auth import CLIENTS_PATH

        provider = _make_provider()
        client = OAuthClientInformationFull(
            client_id="",
            redirect_uris=["https://client.example/cb"],
            token_endpoint_auth_method="none",
        )
        await provider.register_client(client)

        assert client.client_id.startswith("mcp-")
        assert CLIENTS_PATH.exists()
        persisted = json.loads(CLIENTS_PATH.read_text())
        assert client.client_id in persisted

    async def test_register_mints_client_secret_when_basic_auth(self) -> None:
        provider = _make_provider()
        client = OAuthClientInformationFull(
            client_id="",
            redirect_uris=["https://client.example/cb"],
            token_endpoint_auth_method="client_secret_basic",
        )
        await provider.register_client(client)

        assert client.client_secret  # minted
        assert len(client.client_secret) >= 20

    async def test_register_preserves_existing_client_id(self) -> None:
        provider = _make_provider()
        client = OAuthClientInformationFull(
            client_id="preset-id",
            redirect_uris=["https://client.example/cb"],
            token_endpoint_auth_method="none",
        )
        await provider.register_client(client)
        assert client.client_id == "preset-id"

    async def test_get_client_roundtrip(self) -> None:
        provider = _make_provider()
        original = _make_client("rt-client")
        await provider.register_client(original)

        loaded = await provider.get_client("rt-client")
        assert loaded is not None
        assert loaded.client_id == "rt-client"
        assert await provider.get_client("does-not-exist") is None
