"""Password hashing — the core of the project.

Uses PBKDF2-HMAC-SHA256 from the standard library (`hashlib.scrypt` and
`pbkdf2_hmac` are both stdlib, so no bcrypt dependency to audit).

A stored credential is a self-describing string:

    pbkdf2_sha256$260000$<salt_b64>$<hash_b64>

That format means:
  * the algorithm and cost are stored WITH the hash, so cost can be raised
    later without invalidating existing passwords
  * verification re-derives with the stored parameters and compares
  * a plain-text password can never be mistaken for a hash

Timing: `hmac.compare_digest` is used so verification time does not leak
whether the first byte of the hash matched.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

SCHEME = "pbkdf2_sha256"

# OWASP's 2023 guidance for PBKDF2-HMAC-SHA256 is >= 600,000 iterations.
# 260,000 keeps signup/login responsive on modest hardware while still being
# far above the old 10k-100k defaults that made dictionary attacks cheap.
# Raise this as hardware improves — old hashes keep working (see needs_rehash).
DEFAULT_ITERATIONS = 260_000
MIN_ITERATIONS = 100_000

SALT_BYTES = 16
KEY_LEN = 32
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 1024     # bcrypt silently truncates at 72; pbkdf2 doesn't,
                             # but an unbounded input is a trivial DoS vector.


class PasswordError(ValueError):
    """Raised for policy violations before any hashing happens."""


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Hash a password into the self-describing storage format."""
    if iterations < MIN_ITERATIONS:
        raise PasswordError(f"iterations must be >= {MIN_ITERATIONS}")

    _validate(password, enforce_policy=True)

    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, KEY_LEN)
    return "$".join((
        SCHEME,
        str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    ))


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of `password` against a stored hash.

    Returns False — never raises — for malformed, empty or foreign-format
    stored values: a corrupt database row must not become a 500.
    """
    if not password or not stored:
        return False
    if len(password) > MAX_PASSWORD_LEN:
        return False

    parsed = parse(stored)
    if parsed is None:
        return False
    scheme, iterations, salt, expected = parsed
    if scheme != SCHEME:
        return False

    try:
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, len(expected)
        )
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(candidate, expected)


def parse(stored: str) -> tuple[str, int, bytes, bytes] | None:
    """Split a stored value into (scheme, iterations, salt, digest)."""
    if not stored or not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 4:
        return None
    scheme, raw_iterations, raw_salt, raw_digest = parts
    if not scheme or not raw_iterations or not raw_salt or not raw_digest:
        return None
    try:
        iterations = int(raw_iterations)
        if iterations <= 0:
            return None
        salt = base64.b64decode(raw_salt, validate=True)
        digest = base64.b64decode(raw_digest, validate=True)
    except (ValueError, TypeError):
        return None
    if not salt or not digest:
        return None
    return scheme, iterations, salt, digest


def needs_rehash(stored: str, *, iterations: int = DEFAULT_ITERATIONS) -> bool:
    """True when a stored hash was made with weaker parameters.

    Lets you raise the work factor on login without forcing a password reset.
    """
    parsed = parse(stored)
    if parsed is None:
        return True
    scheme, stored_iterations, _salt, digest = parsed
    return scheme != SCHEME or stored_iterations < iterations or len(digest) != KEY_LEN


def check_password_strength(password: str) -> list[str]:
    """Return a list of human-readable problems; empty means acceptable.

    Deliberately avoids the classic "must have a symbol/uppercase" rules —
    length beats composition, and those rules push people toward `Passw0rd!`.
    Minimum length plus a small breach-style check is what actually helps.
    """
    problems: list[str] = []

    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        problems.append(f"must be at most {MAX_PASSWORD_LEN} characters")
    if password != password.strip():
        problems.append("must not start or end with whitespace")

    if not problems:
        lowered = password.lower()
        for common in _COMMON_PASSWORDS:
            if common in lowered:
                problems.append(
                    f"contains a common password pattern ({common!r}) — pick something less guessable"
                )
                break
        if len(set(password)) <= 3:
            problems.append("uses too few distinct characters")
        if _is_sequential(password):
            problems.append("is a simple sequence like 12345678 or abcdefgh")

    return problems


def _validate(password: str, *, enforce_policy: bool) -> None:
    if not isinstance(password, str):
        raise PasswordError("password must be a string")
    if not password:
        raise PasswordError("password must not be empty")
    if len(password) > MAX_PASSWORD_LEN:
        raise PasswordError(f"password must be at most {MAX_PASSWORD_LEN} characters")
    if enforce_policy:
        problems = check_password_strength(password)
        if problems:
            raise PasswordError("; ".join(problems))


def _is_sequential(text: str) -> bool:
    if len(text) < 4:
        return False
    low = text.lower()
    ascending = all(ord(low[i]) + 1 == ord(low[i + 1]) for i in range(len(low) - 1))
    descending = all(ord(low[i]) - 1 == ord(low[i + 1]) for i in range(len(low) - 1))
    return ascending or descending


_COMMON_PASSWORDS = (
    "password", "123456", "12345678", "qwerty", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "football", "baseball",
    "passw0rd", "abc123", "000000", "sunshine", "princess", "trustno1",
)
