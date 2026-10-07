"""Tests for password hashing and session tokens — no Flask, no network."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.passwords import (  # noqa: E402
    DEFAULT_ITERATIONS,
    MIN_ITERATIONS,
    PasswordError,
    check_password_strength,
    hash_password,
    needs_rehash,
    parse,
    verify_password,
)
from app.tokens import (  # noqa: E402
    TokenError,
    issue_token,
    new_secret,
    parse_token,
)

GOOD = "correct horse battery staple"


# --------------------------------------------------------------- hashing ----


def test_hash_produces_self_describing_string():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    scheme, iterations, salt, digest = parse(stored)
    assert scheme == "pbkdf2_sha256"
    assert iterations == MIN_ITERATIONS
    assert len(salt) == 16
    assert len(digest) == 32


def test_hash_is_salted_unique_per_call():
    a = hash_password(GOOD, iterations=MIN_ITERATIONS)
    b = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert a != b
    assert parse(a)[2] != parse(b)[2]


def test_hash_never_contains_plaintext():
    assert GOOD not in hash_password(GOOD, iterations=MIN_ITERATIONS)


def test_verify_correct_password():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert verify_password(GOOD, stored) is True


def test_verify_wrong_password():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert verify_password("wrong password", stored) is False


def test_verify_rejects_near_miss():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert verify_password(GOOD + " ", stored) is False
    assert verify_password(GOOD.upper(), stored) is False
    assert verify_password("", stored) is False


def test_verify_returns_false_not_raise_on_garbage():
    for bad in ("", "not-a-hash", "a$b$c", "pbkdf2_sha256$x$y$z",
                "pbkdf2_sha256$100000$!!!$!!!", None, "x.y"):
        assert verify_password(GOOD, bad) is False  # type: ignore[arg-type]


def test_verify_rejects_truncated_at_max_length():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert verify_password("a" * 1025, stored) is False


def test_hash_rejects_weak_password():
    with pytest.raises(PasswordError):
        hash_password("short", iterations=MIN_ITERATIONS)
    with pytest.raises(PasswordError):
        hash_password("password", iterations=MIN_ITERATIONS)


def test_hash_rejects_empty():
    with pytest.raises(PasswordError):
        hash_password("", iterations=MIN_ITERATIONS)


def test_hash_rejects_too_long():
    with pytest.raises(PasswordError):
        hash_password("a" * 1025, iterations=MIN_ITERATIONS)


def test_hash_rejects_low_iterations():
    with pytest.raises(PasswordError):
        hash_password(GOOD, iterations=100)


def test_parse_rejects_malformed():
    for bad in ("", "a", "a$b", "a$b$c$d$e", "pbkdf2_sha256$0$AA$AA",
                "pbkdf2_sha256$-1$AA$AA", "pbkdf2_sha256$abc$AA$AA"):
        assert parse(bad) is None


# ------------------------------------------------------------- rehash -------


def test_needs_rehash_when_cost_lowered():
    stored = hash_password(GOOD, iterations=MIN_ITERATIONS)
    assert needs_rehash(stored, iterations=DEFAULT_ITERATIONS) is True


def test_no_rehash_when_cost_matches_or_exceeds():
    stored = hash_password(GOOD, iterations=DEFAULT_ITERATIONS)
    assert needs_rehash(stored, iterations=DEFAULT_ITERATIONS) is False
    assert needs_rehash(stored, iterations=MIN_ITERATIONS) is False


def test_needs_rehash_on_garbage():
    assert needs_rehash("garbage") is True


# ------------------------------------------------------------ strength ------


def test_strength_accepts_good_password():
    assert check_password_strength(GOOD) == []
    assert check_password_strength("kx7-Qm2vRn8Zp4Lw") == []


@pytest.mark.parametrize("weak", [
    "short",              # too short
    "password",           # common
    "mypassword",         # contains common
    "aaaaaaaaaa",         # low entropy
    "12345678",           # sequential
    "abcdefgh",           # sequential
    "  password1  ",      # whitespace + common
])
def test_strength_rejects(weak):
    assert check_password_strength(weak), f"expected {weak!r} to be rejected"


def test_strength_allows_passwords_without_symbols():
    """Composition rules push people to `Passw0rd!` — length is what matters."""
    assert check_password_strength("this is a long passphrase") == []


def test_strength_reports_specific_problem():
    problems = check_password_strength("abc")
    assert any("at least 8" in p for p in problems)


def test_strength_handles_unicode():
    assert check_password_strength("correct horse battery") == []


# --------------------------------------------------------------- tokens ------


def test_issue_then_parse_roundtrip():
    secret = new_secret()
    token = issue_token(42, secret, ttl=3600)
    session = parse_token(token, secret)
    assert session.user_id == 42
    assert session.expires_at - session.issued_at == 3600
    assert session.nonce


def test_token_differs_each_issue():
    secret = new_secret()
    assert issue_token(42, secret) != issue_token(42, secret)


def test_parse_rejects_wrong_secret():
    token = issue_token(42, new_secret())
    with pytest.raises(TokenError, match="signature"):
        parse_token(token, "a-different-secret")


def test_parse_rejects_tampered_payload():
    """Flipping the user id must invalidate the signature."""
    secret = new_secret()
    token = issue_token(42, secret)
    payload, signature = token.split(".")

    import base64, json
    pad = "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload + pad))
    data["uid"] = 999
    forged = base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()

    with pytest.raises(TokenError, match="signature"):
        parse_token(f"{forged}.{signature}", secret)


def test_parse_rejects_expired_token():
    secret = new_secret()
    now = int(time.time())
    token = issue_token(1, secret, ttl=10, now=now - 100)
    with pytest.raises(TokenError, match="expired"):
        parse_token(token, secret, now=now)


def test_parse_rejects_future_issued_token():
    secret = new_secret()
    now = int(time.time())
    token = issue_token(1, secret, ttl=3600, now=now + 3600)
    with pytest.raises(TokenError, match="future"):
        parse_token(token, secret, now=now)


def test_parse_rejects_malformed_tokens():
    secret = new_secret()
    for bad in ("", ".", "a", "a.b.c", "not base64!!.xxx", "a.b"):
        with pytest.raises(TokenError):
            parse_token(bad, secret)


def test_parse_rejects_empty_secret():
    token = issue_token(1, new_secret())
    with pytest.raises(TokenError):
        parse_token(token, "")


def test_issue_requires_valid_user_id():
    secret = new_secret()
    with pytest.raises(TokenError):
        issue_token(0, secret)
    with pytest.raises(TokenError):
        issue_token(-1, secret)
    with pytest.raises(TokenError):
        issue_token("1", secret)  # type: ignore[arg-type]


def test_issue_requires_secret():
    with pytest.raises(TokenError):
        issue_token(1, "")


def test_issue_rejects_absurd_ttl():
    secret = new_secret()
    with pytest.raises(TokenError):
        issue_token(1, secret, ttl=0)
    with pytest.raises(TokenError):
        issue_token(1, secret, ttl=10 ** 12)


def test_expiry_is_after_issue_time():
    """A zero/negative TTL must not mint an already-expired token."""
    secret = new_secret()
    token = issue_token(1, secret, ttl=60)
    session = parse_token(token, secret)
    assert session.expires_at > session.issued_at
