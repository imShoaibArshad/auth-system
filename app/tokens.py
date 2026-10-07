"""Session tokens: signed, expiring, and tamper-evident.

A session ID alone is a bearer secret that never expires; if it leaks it is
valid forever. So each token carries an issued-at timestamp, and its signature
covers the whole payload — changing the expiry or swapping in another user's
id invalidates it.

Token format:  <payload_b64>.<hmac_sha256_b64>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

DEFAULT_TTL = 60 * 60 * 12     # 12 hours
MAX_TTL = 60 * 60 * 24 * 30    # refuse absurd expiries
TOKEN_BYTES = 32


class TokenError(ValueError):
    """Raised when a token is malformed, forged or expired."""


@dataclass(frozen=True)
class Session:
    user_id: int
    issued_at: int
    expires_at: int
    nonce: str

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_dict(self) -> dict:
        return {
            "uid": self.user_id,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "n": self.nonce,
        }


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()


def issue_token(user_id: int, secret: str, ttl: int = DEFAULT_TTL,
                now: int | None = None) -> str:
    """Create a signed token for `user_id`."""
    if not secret:
        raise TokenError("a signing secret is required")
    if not isinstance(user_id, int) or user_id < 1:
        raise TokenError("user_id must be a positive integer")
    if not 0 < ttl <= MAX_TTL:
        raise TokenError(f"ttl must be between 1 and {MAX_TTL} seconds")

    issued = int(time.time() if now is None else now)
    session = Session(
        user_id=user_id,
        issued_at=issued,
        expires_at=issued + ttl,
        nonce=secrets.token_urlsafe(TOKEN_BYTES),
    )
    payload = json.dumps(session.to_dict(), separators=(",", ":"), sort_keys=True).encode()
    return f"{_b64(payload)}.{_b64(_sign(payload, secret))}"


def parse_token(token: str, secret: str, *, now: int | None = None) -> Session:
    """Validate and decode a token.

    Order matters: signature is checked **before** anything is trusted about
    the payload, so a tampered expiry can never be read as legitimate.
    """
    if not token or not secret:
        raise TokenError("missing token or secret")
    if len(token) > 4096:
        raise TokenError("token too large")

    parts = token.split(".")
    if len(parts) != 2:
        raise TokenError("malformed token")
    raw_payload, raw_signature = parts

    try:
        payload = _unb64(raw_payload)
        signature = _unb64(raw_signature)
    except Exception as exc:  # noqa: BLE001 - any decode failure is just invalid
        raise TokenError("token is not valid base64") from exc

    # Constant-time compare — a timing difference here leaks the signature.
    if not hmac.compare_digest(_sign(payload, secret), signature):
        raise TokenError("signature mismatch")

    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise TokenError("payload is not JSON") from exc

    if not isinstance(data, dict):
        raise TokenError("payload must be an object")
    for key in ("uid", "iat", "exp", "n"):
        if key not in data:
            raise TokenError(f"payload missing {key!r}")

    session = Session(
        user_id=data["uid"],
        issued_at=data["iat"],
        expires_at=data["exp"],
        nonce=data["n"],
    )

    if not isinstance(session.user_id, int) or session.user_id < 1:
        raise TokenError("invalid user id")
    if session.expires_at <= session.issued_at:
        raise TokenError("expiry is not after issue time")

    current = int(time.time() if now is None else now)
    if current >= session.expires_at:
        raise TokenError("token expired")
    if session.issued_at > current + 60:
        raise TokenError("token issued in the future")

    return session


def new_secret(nbytes: int = 32) -> str:
    """Generate a strong signing secret (for session SECRET_KEY)."""
    return secrets.token_urlsafe(nbytes)
