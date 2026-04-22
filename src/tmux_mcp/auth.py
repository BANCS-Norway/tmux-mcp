"""OAuth 2.1 + DCR provider for tmux_mcp, using GitHub as the upstream IdP.

Flow:
  1. Claude client discovers /.well-known/oauth-authorization-server
  2. Client registers via DCR (/register) — we persist it
  3. Client redirects user to our /authorize
  4. We redirect to github.com/login/oauth/authorize (with a local state token
     that maps back to the MCP auth code challenge)
  5. GitHub redirects to /oauth/github/callback — we exchange for a GH token,
     fetch the username, check against ALLOWED_GITHUB_USERS, issue a
     short-lived authorization code, and redirect back to the MCP client
  6. Client hits /token — we exchange the code for an RS256 JWT access token
  7. On each MCP request, load_access_token verifies the JWT

Storage lives in ~/.config/tmux-mcp/ (XDG-ish):
  jwt-key.pem   — RSA private key (auto-generated on first run)
  clients.json  — DCR-registered clients
"""

from __future__ import annotations

import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# ── Config & storage ─────────────────────────────────────────────────────────

STATE_DIR = Path(
    os.environ.get("TMUX_MCP_STATE_DIR")
    or (Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "tmux-mcp")
)
STATE_DIR.mkdir(parents=True, exist_ok=True)

JWT_KEY_PATH = STATE_DIR / "jwt-key.pem"
CLIENTS_PATH = STATE_DIR / "clients.json"

JWT_ALGORITHM = "RS256"
JWT_ISSUER = "tmux-mcp"
ACCESS_TOKEN_TTL = 3600       # 1h
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30  # 30d
AUTH_CODE_TTL = 600            # 10m
PENDING_AUTH_TTL = 600         # 10m — github round-trip

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"


# ── Key management ───────────────────────────────────────────────────────────

def _load_or_create_jwt_key() -> tuple[str, str]:
    """Return (private_pem, public_pem). Auto-generates RSA 2048 on first run."""
    if JWT_KEY_PATH.exists():
        private_pem = JWT_KEY_PATH.read_text()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        JWT_KEY_PATH.write_text(private_pem)
        JWT_KEY_PATH.chmod(0o600)

    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


# ── DCR client store ─────────────────────────────────────────────────────────

def _load_clients() -> dict[str, dict]:
    if not CLIENTS_PATH.exists():
        return {}
    try:
        return json.loads(CLIENTS_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def _save_clients(clients: dict[str, dict]) -> None:
    CLIENTS_PATH.write_text(json.dumps(clients, indent=2))
    CLIENTS_PATH.chmod(0o600)


# ── In-memory state ──────────────────────────────────────────────────────────

@dataclass
class _PendingAuth:
    """Between /authorize and /oauth/github/callback."""
    client_id: str
    scopes: list[str]
    code_challenge: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    resource: str | None
    mcp_state: str | None         # the MCP client's state param
    created_at: float = field(default_factory=time.time)


class _IssuedCode(AuthorizationCode):
    github_user: str = ""


class GithubOAuthProvider(
    OAuthAuthorizationServerProvider[_IssuedCode, RefreshToken, AccessToken]
):
    """MCP OAuth server that delegates user auth to GitHub."""

    def __init__(
        self,
        *,
        public_url: str,
        github_client_id: str,
        github_client_secret: str,
        allowed_github_users: set[str],
    ) -> None:
        if not public_url.startswith("https://"):
            raise ValueError("TMUX_MCP_PUBLIC_URL must be an https:// URL")
        self.public_url = public_url.rstrip("/")
        self.gh_client_id = github_client_id
        self.gh_client_secret = github_client_secret
        self.allowed_users = {u.strip().lower() for u in allowed_github_users if u.strip()}
        if not self.allowed_users:
            raise ValueError("TMUX_MCP_ALLOWED_GITHUB_USERS must list at least one user")

        self._private_pem, self._public_pem = _load_or_create_jwt_key()
        self._clients: dict[str, dict] = _load_clients()
        self._pending: dict[str, _PendingAuth] = {}      # state → PendingAuth
        self._codes: dict[str, _IssuedCode] = {}          # code → IssuedCode

    # ── DCR ──────────────────────────────────────────────────────────────

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            client_info.client_id = f"mcp-{uuid.uuid4().hex[:16]}"
        if client_info.token_endpoint_auth_method == "client_secret_basic" and not client_info.client_secret:
            client_info.client_secret = secrets.token_urlsafe(32)
        self._clients[client_info.client_id] = client_info.model_dump(mode="json")
        _save_clients(self._clients)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self._clients.get(client_id)
        if raw is None:
            return None
        return OAuthClientInformationFull.model_validate(raw)

    # ── /authorize ───────────────────────────────────────────────────────

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Return the URL to redirect the user to (GitHub)."""
        state = secrets.token_urlsafe(32)
        self._pending[state] = _PendingAuth(
            client_id=client.client_id,
            scopes=params.scopes or [],
            code_challenge=params.code_challenge,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            mcp_state=params.state,
        )
        self._gc_pending()
        qs = urlencode({
            "client_id": self.gh_client_id,
            "redirect_uri": f"{self.public_url}/oauth/github/callback",
            "scope": "read:user",
            "state": state,
        })
        return f"{GITHUB_AUTHORIZE_URL}?{qs}"

    # ── GitHub callback (called from custom route, not abstract method) ──

    async def handle_github_callback(self, code: str, state: str) -> str:
        """Exchange GitHub code → username → issue MCP auth code. Returns MCP
        redirect URL (client_redirect_uri?code=...&state=...)."""
        pending = self._pending.pop(state, None)
        if pending is None:
            raise PermissionError("unknown or expired state")
        if time.time() - pending.created_at > PENDING_AUTH_TTL:
            raise PermissionError("pending auth expired")

        async with httpx.AsyncClient() as http:
            tok_resp = await http.post(
                GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.gh_client_id,
                    "client_secret": self.gh_client_secret,
                    "code": code,
                },
            )
            tok_resp.raise_for_status()
            gh_access = tok_resp.json().get("access_token")
            if not gh_access:
                raise PermissionError("github declined token exchange")

            user_resp = await http.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {gh_access}",
                    "Accept": "application/vnd.github+json",
                },
            )
            user_resp.raise_for_status()
            gh_username = user_resp.json().get("login", "").lower()

        if gh_username not in self.allowed_users:
            raise PermissionError(f"github user '{gh_username}' not in allowlist")

        mcp_code = secrets.token_urlsafe(32)
        self._codes[mcp_code] = _IssuedCode(
            code=mcp_code,
            scopes=pending.scopes,
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending.client_id,
            code_challenge=pending.code_challenge,
            redirect_uri=pending.redirect_uri,  # pydantic will coerce
            redirect_uri_provided_explicitly=pending.redirect_uri_provided_explicitly,
            resource=pending.resource,
            github_user=gh_username,
        )
        self._gc_codes()

        params = {"code": mcp_code}
        if pending.mcp_state:
            params["state"] = pending.mcp_state
        sep = "&" if "?" in pending.redirect_uri else "?"
        return f"{pending.redirect_uri}{sep}{urlencode(params)}"

    # ── Token endpoint ───────────────────────────────────────────────────

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[_IssuedCode]:
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if time.time() > code.expires_at:
            self._codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: _IssuedCode
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return self._issue_tokens(
            client_id=client.client_id,
            github_user=authorization_code.github_user,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    def _issue_tokens(
        self, *, client_id: str, github_user: str, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        now = int(time.time())
        base = {
            "iss": JWT_ISSUER,
            "sub": github_user,
            "aud": client_id,
            "iat": now,
            "scope": " ".join(scopes),
            "resource": resource,
        }
        access_jwt = jwt.encode(
            {**base, "typ": "access", "exp": now + ACCESS_TOKEN_TTL},
            self._private_pem,
            algorithm=JWT_ALGORITHM,
        )
        refresh_jwt = jwt.encode(
            {**base, "typ": "refresh", "exp": now + REFRESH_TOKEN_TTL},
            self._private_pem,
            algorithm=JWT_ALGORITHM,
        )
        return OAuthToken(
            access_token=access_jwt,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes) or None,
            refresh_token=refresh_jwt,
        )

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        claims = self._decode_jwt(token, expected_typ="access")
        if claims is None:
            return None
        return AccessToken(
            token=token,
            client_id=claims.get("aud", ""),
            scopes=(claims.get("scope") or "").split() if claims.get("scope") else [],
            expires_at=claims.get("exp"),
            resource=claims.get("resource"),
        )

    # ── Refresh tokens (stateless JWTs, so restarts are survived) ────────

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        claims = self._decode_jwt(refresh_token, expected_typ="refresh")
        if claims is None or claims.get("aud") != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=claims["aud"],
            scopes=(claims.get("scope") or "").split() if claims.get("scope") else [],
            expires_at=claims.get("exp"),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        claims = self._decode_jwt(refresh_token.token, expected_typ="refresh")
        if claims is None or claims.get("aud") != client.client_id:
            raise PermissionError("invalid refresh token")
        return self._issue_tokens(
            client_id=client.client_id,
            github_user=claims["sub"],
            scopes=scopes or refresh_token.scopes,
            resource=claims.get("resource"),
        )

    def _decode_jwt(self, token: str, *, expected_typ: str) -> Optional[dict]:
        try:
            claims = jwt.decode(
                token,
                self._public_pem,
                algorithms=[JWT_ALGORITHM],
                options={"verify_aud": False},
                issuer=JWT_ISSUER,
            )
        except jwt.InvalidTokenError:
            return None
        if claims.get("typ") != expected_typ:
            return None
        return claims

    async def revoke_token(self, token) -> None:  # noqa: ANN001
        # Stateless JWTs; revocation would need a denylist. No-op for v1.
        return None

    # ── Housekeeping ─────────────────────────────────────────────────────

    def _gc_pending(self) -> None:
        now = time.time()
        for s, p in list(self._pending.items()):
            if now - p.created_at > PENDING_AUTH_TTL:
                self._pending.pop(s, None)

    def _gc_codes(self) -> None:
        now = time.time()
        for c, code in list(self._codes.items()):
            if now > code.expires_at:
                self._codes.pop(c, None)
