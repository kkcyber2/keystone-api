"""Password hashing and HS256 JSON Web Tokens, on the standard library alone.

The whole authentication surface lives in this one file so it can be read end to
end during review. Nothing here reaches for a third-party crypto package.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

PBKDF2_ROUNDS = 210_000
ALGORITHM = "HS256"


class TokenError(Exception):
    """A token was malformed, mis-signed, or past its expiry."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return a self-describing PBKDF2-SHA256 hash: algorithm$rounds$salt$digest."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of a password against a stored hash."""
    try:
        algorithm, rounds, salt_b64, digest_b64 = encoded.split("$")
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        expected = _b64d(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64d(salt_b64), int(rounds)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _sign(signing_input: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256)
    return _b64e(mac.digest())


def encode_token(payload: dict[str, Any], secret: str, *, ttl_seconds: int = 3600) -> str:
    """Sign a payload into a compact JWS, stamping `iat`, `exp` and a unique `jti`."""
    header = {"alg": ALGORITHM, "typ": "JWT"}
    now = int(time.time())
    body = {**payload, "iat": now, "exp": now + ttl_seconds, "jti": secrets.token_hex(8)}
    head = _b64e(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    claims = _b64e(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{head}.{claims}"
    return f"{signing_input}.{_sign(signing_input, secret)}"


def decode_token(token: str, secret: str) -> dict[str, Any]:
    """Verify a token and return its claims, or raise `TokenError`."""
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("token must have three segments")
    signing_input = f"{parts[0]}.{parts[1]}"
    if not hmac.compare_digest(_sign(signing_input, secret), parts[2]):
        raise TokenError("signature mismatch")
    try:
        header = json.loads(_b64d(parts[0]))
        claims = json.loads(_b64d(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed token body") from exc
    if header.get("alg") != ALGORITHM:
        raise TokenError(f"unsupported algorithm {header.get('alg')!r}")
    if int(claims.get("exp", 0)) < int(time.time()):
        raise TokenError("token expired")
    return claims
