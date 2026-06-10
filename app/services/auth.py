"""Clerk JWT authentication dependency for FastAPI.

How it works
------------
Every protected endpoint declares ``user_id: str = Depends(require_user)``.
On each request the dependency:

1. Looks for the Clerk session token in the ``__session`` cookie (set by
   Clerk.js in the browser) or in the ``Authorization: Bearer <token>`` header
   (for programmatic / API callers).
2. Fetches Clerk's JWKS from ``https://api.clerk.com/v1/jwks`` (cached for
   60 seconds) and verifies the JWT signature + expiry.
3. Returns the ``sub`` claim (Clerk user_id, e.g. ``user_2abc…``).

When ``CLERK_SECRET_KEY`` is not set (local dev / tests) the dependency
returns the constant ``"test-user"`` so tests don't need to fake tokens.
"""
from __future__ import annotations

import os
import time
from typing import Optional

import httpx
from fastapi import Cookie, Depends, Header, HTTPException, status

# ---------------------------------------------------------------------------
# Optional PyJWT dependency — install automatically if absent (prod) or skip
# gracefully (tests/offline). We import lazily so the module always loads.
# ---------------------------------------------------------------------------
_JWT_AVAILABLE = False
try:
    import jwt  # PyJWT

    _JWT_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CLERK_SECRET_KEY: str | None = os.getenv("CLERK_SECRET_KEY")
CLERK_PUBLISHABLE_KEY: str | None = os.getenv("CLERK_PUBLISHABLE_KEY")

_AUTH_ENABLED = bool(CLERK_SECRET_KEY)

# JWKS cache: (fetched_at_epoch, {kid: public_key_pem})
_jwks_cache: tuple[float, dict] | None = None
_JWKS_TTL = 60  # seconds


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_jwks() -> dict:
    """Return the Clerk JWKS key map, refreshing the cache when stale."""
    global _jwks_cache
    now = time.monotonic()
    if _jwks_cache and now - _jwks_cache[0] < _JWKS_TTL:
        return _jwks_cache[1]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.clerk.com/v1/jwks",
                headers={"Authorization": f"Bearer {CLERK_SECRET_KEY}"},
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to fetch Clerk JWKS (HTTP {exc.response.status_code}). "
                   "Check CLERK_SECRET_KEY.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to reach Clerk JWKS endpoint: {exc}",
        )

    # Build kid → public key map using PyJWT's algorithms helper.
    from jwt.algorithms import RSAAlgorithm

    key_map: dict[str, object] = {}
    for jwk in data.get("keys", []):
        kid = jwk.get("kid")
        if kid:
            try:
                key_map[kid] = RSAAlgorithm.from_jwk(jwk)
            except Exception:
                pass  # Skip malformed keys

    _jwks_cache = (now, key_map)
    return key_map


async def _verify_token(token: str) -> str:
    """Verify a Clerk JWT and return the user_id (sub claim)."""
    if not _JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PyJWT is not installed. Run: pip install PyJWT cryptography",
        )

    # Decode header without verification to get the kid.
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token header: {exc}",
        )

    kid = unverified_header.get("kid")
    key_map = await _get_jwks()
    public_key = key_map.get(kid)
    if not public_key:
        # Key not in cache — refresh once and retry.
        global _jwks_cache
        _jwks_cache = None
        key_map = await _get_jwks()
        public_key = key_map.get(kid)

    if not public_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown signing key — token rejected.",
        )

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False},  # Clerk doesn't set aud on session tokens
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired."
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        )

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing sub claim.",
        )
    return user_id


def _extract_token(
    session_cookie: Optional[str],
    client_uat_cookie: Optional[str],
    auth_header: Optional[str],
) -> str | None:
    """Pull the raw JWT from any Clerk cookie or Authorization header.

    ClerkJS v5 sets several cookies depending on environment:
    - __session          — standard session JWT (same-domain)
    - __clerk_db_jwt     — development-mode session JWT (localhost)
    - Authorization: Bearer <token> — set explicitly by the JS on API calls
    """
    # Prefer explicit Authorization header (set by our JS fetch calls)
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Session cookie (standard / production)
    if session_cookie:
        return session_cookie
    # ClerkJS v5 dev-mode cookie
    if client_uat_cookie:
        return client_uat_cookie
    return None


# ---------------------------------------------------------------------------
# Public FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    __session: Optional[str] = Cookie(default=None),
    __clerk_db_jwt: Optional[str] = Cookie(default=None),
    authorization: Optional[str] = Header(default=None),
) -> str | None:
    if not _AUTH_ENABLED:
        return None

    token = _extract_token(__session, __clerk_db_jwt, authorization)
    if not token:
        return None

    try:
        return await _verify_token(token)
    except HTTPException:
        return None


async def require_user(
    __session: Optional[str] = Cookie(default=None),
    __clerk_db_jwt: Optional[str] = Cookie(default=None),
    authorization: Optional[str] = Header(default=None),
) -> str:
    if not _AUTH_ENABLED:
        return "test-user"

    token = _extract_token(__session, __clerk_db_jwt, authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not signed in. Please sign in to continue.",
        )
    return await _verify_token(token)
