"""JWT authentication — shared helpers.

HS256 simple JWT; reads NIZAM_JWT_SECRET from env. In production, use asymmetric
(RS256) + public key distribution + 15-minute token TTL recommended.

Usage:
    token = issue_token(subject="opr-01", role="operator", ttl_s=3600)
    payload = verify_token(token)   # dict or raise AuthError
"""
from __future__ import annotations

import os
import time
from typing import Any

import jwt   # PyJWT (requirements.txt)

JWT_ALG = "HS256"
DEFAULT_TTL_S = 3600


class AuthError(Exception):
    """Token invalid, expired, or signature mismatch."""


def _secret() -> str:
    secret = os.getenv("NIZAM_JWT_SECRET")
    if not secret:
        raise AuthError("NIZAM_JWT_SECRET env must be set (>=32 chars in production)")
    if len(secret) < 16:
        raise AuthError("NIZAM_JWT_SECRET too short (min 16 chars)")
    return secret


def issue_token(subject: str, role: str = "operator", ttl_s: int = DEFAULT_TTL_S, **extra: Any) -> str:
    """Issue a token. sub = user ID, role = operator/admin/service."""
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + ttl_s,
        **extra,
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG)


def verify_token(token: str) -> dict:
    """Verify token and return payload. Raises AuthError on failure."""
    try:
        return jwt.decode(token, _secret(), algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"invalid token: {exc}") from exc
