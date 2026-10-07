"""End-to-end API tests: registration, login, lockout, tokens, rate limits."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app  # noqa: E402
from app.store import AuthError, UserStore  # noqa: E402
from app.passwords import MIN_ITERATIONS  # noqa: E402

EMAIL = "shoaib@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret-key-not-for-production",
        "TOKEN_TTL": 3600,
    })
    # Lower cost so the suite is not dominated by PBKDF2 time.
    app.extensions["user_store"].iterations = MIN_ITERATIONS
    yield app
    app.extensions["user_store"].close()


@pytest.fixture()
def client(app):
    return app.test_client()


def json_of(resp):
    return resp.get_json()


# ------------------------------------------------------------- register ------


def test_register_returns_201_and_token(client):
    resp = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    assert resp.status_code == 201
    body = json_of(resp)
    assert body["data"]["email"] == EMAIL
    assert body["token"]
    assert "token" not in body["data"]


def test_register_sets_httponly_cookie(client):
    resp = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    set_cookie = resp.headers.getlist("Set-Cookie")
    assert any("session=" in c and "HttpOnly" in c for c in set_cookie)


def test_register_rejects_duplicate_email(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    resp = client.post("/api/register", json={"email": EMAIL.upper(), "password": PASSWORD})
    assert resp.status_code == 409
    assert json_of(resp)["error"]["code"] == "email_taken"


def test_register_rejects_invalid_email(client):
    for bad in ("not-an-email", "", "a" * 250 + "@x.com"):
        resp = client.post("/api/register", json={"email": bad, "password": PASSWORD})
        assert resp.status_code == 400, bad
        assert json_of(resp)["error"]["code"] == "invalid_email"


def test_register_rejects_weak_password(client):
    resp = client.post("/api/register", json={"email": EMAIL, "password": "short"})
    assert resp.status_code == 400
    assert json_of(resp)["error"]["code"] == "weak_password"


def test_register_normalises_email(client):
    resp = client.post("/api/register",
                       json={"email": "  Shoaib@Example.COM  ", "password": PASSWORD})
    assert resp.status_code == 201
    assert json_of(resp)["data"]["email"] == "shoaib@example.com"


def test_register_rejects_non_json_body(client):
    resp = client.post("/api/register", data="email=x",
                       content_type="text/plain")
    assert resp.status_code in (400, 415)


# ---------------------------------------------------------------- login ------


def test_login_success(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    resp = client.post("/api/login", json={"email": EMAIL, "password": PASSWORD})
    assert resp.status_code == 200
    assert json_of(resp)["token"]


def test_login_wrong_password_is_generic(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    resp = client.post("/api/login", json={"email": EMAIL, "password": "wrong one here"})
    assert resp.status_code == 401
    err = json_of(resp)["error"]
    assert err["code"] == "invalid_credentials"
    assert err["message"] == "wrong email or password"


def test_login_unknown_user_gives_identical_error(client):
    """User enumeration check — unknown user must not differ from wrong password."""
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})

    wrong_pw = client.post("/api/login", json={"email": EMAIL, "password": "nope nope nope"})
    unknown = client.post("/api/login", json={"email": "ghost@example.com",
                                              "password": "nope nope nope"})

    assert wrong_pw.status_code == unknown.status_code == 401
    assert json_of(wrong_pw) == json_of(unknown)


def test_login_is_case_insensitive_on_email(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    resp = client.post("/api/login", json={"email": EMAIL.upper(), "password": PASSWORD})
    assert resp.status_code == 200


# -------------------------------------------------------------- lockout ------


def test_lockout_after_five_failures(app, client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})

    for i in range(5):
        resp = client.post("/api/login",
                           json={"email": EMAIL, "password": f"wrong pass {i}xx"})
        assert resp.status_code == 401, f"attempt {i} should be 401"

    # 6th attempt locks, even with the CORRECT password.
    resp = client.post("/api/login", json={"email": EMAIL, "password": PASSWORD})
    assert resp.status_code == 423
    assert json_of(resp)["error"]["code"] == "account_locked"


def test_lockout_exposes_remaining_time(app, client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    for i in range(5):
        client.post("/api/login", json={"email": EMAIL, "password": f"wrong {i}xxxx"})
    resp = client.post("/api/login", json={"email": EMAIL, "password": PASSWORD})
    assert "try again in" in json_of(resp)["error"]["message"]


def test_successful_login_resets_failures(app, client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    for i in range(3):
        client.post("/api/login", json={"email": EMAIL, "password": f"wrong {i}xxxx"})

    assert client.post("/api/login",
                       json={"email": EMAIL, "password": PASSWORD}).status_code == 200

    store = app.extensions["user_store"]
    user = store.find_by_email(EMAIL)
    row = store._conn.execute("SELECT failed_attempts, locked_until FROM users "
                              "WHERE id = ?", (user["id"],)).fetchone()
    assert row["failed_attempts"] == 0
    assert row["locked_until"] is None


def test_lockout_only_affects_the_target_account(app, client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    client.post("/api/register", json={"email": "other@example.com",
                                       "password": PASSWORD})
    for i in range(5):
        client.post("/api/login", json={"email": EMAIL, "password": f"wrong {i}xxxx"})

    resp = client.post("/api/login", json={"email": "other@example.com",
                                           "password": PASSWORD})
    assert resp.status_code == 200


def test_store_is_lockout_aware_directly(app):
    store = app.extensions["user_store"]
    store.create_user("direct@example.com", PASSWORD)
    for i in range(5):
        with pytest.raises(AuthError):
            store.authenticate("direct@example.com", f"wrong {i}xxxx")
    assert store.is_locked("direct@example.com") is True
    assert store.lockout_seconds("direct@example.com") > 0


# ---------------------------------------------------------------- tokens ------


def test_me_requires_token(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    # Use a fresh client so the cookie from register does not leak in.
    fresh = client.application.test_client()
    resp = fresh.get("/api/me")
    assert resp.status_code == 401
    assert json_of(resp)["error"]["code"] == "unauthenticated"


def test_me_returns_user_with_valid_token(client):
    reg = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    token = json_of(reg)["token"]
    resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert json_of(resp)["data"]["email"] == EMAIL


def test_me_rejects_forged_token(client):
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    resp = client.get("/api/me", headers={"Authorization": "Bearer not.a.token"})
    assert resp.status_code == 401


def test_me_rejects_expired_token(app, client):
    import time as _t
    from app.tokens import issue_token
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    # Mint a token that expired a moment ago.
    secret = app.config["SECRET_KEY"]
    token = issue_token(1, secret, ttl=1, now=int(_t.time()) - 100)
    resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_logout_clears_session(client):
    reg = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    token = json_of(reg)["token"]
    resp = client.post("/api/logout", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204
    assert any("session=" in c and "Expires" in c or "Max-Age=0" in c
               for c in resp.headers.getlist("Set-Cookie"))


def test_logout_without_token_401(client):
    resp = client.post("/api/logout")
    assert resp.status_code == 401


# ------------------------------------------------------- change password ------


def test_change_password_flow(client):
    reg = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    token = json_of(reg)["token"]

    resp = client.post("/api/change-password", json={
        "current_password": PASSWORD,
        "new_password": "another good passphrase 42",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204

    assert client.post("/api/login",
                       json={"email": EMAIL, "password": "another good passphrase 42"}
                       ).status_code == 200
    assert client.post("/api/login",
                       json={"email": EMAIL, "password": PASSWORD}).status_code == 401


def test_change_password_rejects_wrong_current(client):
    reg = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    token = json_of(reg)["token"]
    resp = client.post("/api/change-password", json={
        "current_password": "not the right one",
        "new_password": "another good passphrase 42",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_change_password_rejects_weak_new(client):
    reg = client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    token = json_of(reg)["token"]
    resp = client.post("/api/change-password", json={
        "current_password": PASSWORD,
        "new_password": "short",
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 400
    assert json_of(resp)["error"]["code"] == "weak_password"


def test_change_password_requires_auth(client):
    resp = client.post("/api/change-password", json={
        "current_password": PASSWORD, "new_password": "another good passphrase 42"})
    assert resp.status_code == 401


# ------------------------------------------------------------- rate limit ----


def test_login_rate_limited_per_ip(client):
    """30 failed attempts from one IP trips the window before lockout would."""
    client.post("/api/register", json={"email": EMAIL, "password": PASSWORD})
    codes = []
    for i in range(35):
        codes.append(client.post("/api/login",
                                 json={"email": EMAIL, "password": f"wrong {i}xxxx"}).status_code)
    assert 429 in codes, f"expected a 429 somewhere, got {codes}"
    assert codes.count(429) >= 1


# ------------------------------------------------------------------ errors ----


def test_unknown_route_is_json_404(client):
    resp = client.get("/api/nope")
    assert resp.status_code == 404
    assert json_of(resp)["error"]["code"] == "not_found"


def test_wrong_method_is_json_405(client):
    resp = client.get("/api/register")
    assert resp.status_code == 405
    assert json_of(resp)["error"]["code"] == "method_not_allowed"


# ------------------------------------------------------------- store level ----


def test_store_create_and_get(tmp_path):
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        uid = store.create_user("a@b.com", PASSWORD)
        assert uid >= 1
        assert store.get_user(uid)["email"] == "a@b.com"
        assert store.find_by_email("A@B.COM")["id"] == uid
        assert store.user_count() == 1
        assert store.get_user(999) is None
        assert store.find_by_email("nobody@b.com") is None
    finally:
        store.close()


def test_store_rejects_duplicate(tmp_path):
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        store.create_user("a@b.com", PASSWORD)
        with pytest.raises(AuthError) as exc:
            store.create_user("A@B.com", PASSWORD)
        assert exc.value.code == "email_taken"
    finally:
        store.close()


def test_store_rejects_bad_email(tmp_path):
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        with pytest.raises(AuthError) as exc:
            store.create_user("", PASSWORD)
        assert exc.value.code == "invalid_email"
    finally:
        store.close()


def test_store_rehashes_on_login(tmp_path):
    from app.passwords import parse
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        store.create_user("a@b.com", PASSWORD)
        assert store.authenticate("a@b.com", PASSWORD) == 1
        # Bump cost, then log in again — hash should be upgraded transparently.
        store.iterations = MIN_ITERATIONS + 50_000
        store.authenticate("a@b.com", PASSWORD)
        with store._lock:
            row = store._conn.execute("SELECT password_hash FROM users").fetchone()
        assert parse(row["password_hash"])[1] == MIN_ITERATIONS + 50_000
    finally:
        store.close()


def test_weak_password_login_does_not_500_on_unknown_user(tmp_path):
    """Regression: the unknown-user timing branch used to call hash_password(),
    which enforces *registration* policy.

    So a weak password against a fake account raised PasswordError -> 500,
    while the same password against a real account returned 401. That made the
    timing-equalisation branch a user-enumeration oracle as well as a crash.
    """
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        store.create_user("real@example.com", PASSWORD)

        # Every combination must fail identically: same code, same message,
        # and never an unhandled exception.
        cases = [
            ("no-such-user@example.com", "short"),        # weak + unknown
            ("no-such-user@example.com", "password"),     # common + unknown
            ("no-such-user@example.com", "xyz"),          # short + unknown
            ("no-such-user@example.com", PASSWORD),       # good pw + unknown
            ("real@example.com", "short"),                # weak + known
        ]
        for email, password in cases:
            with pytest.raises(AuthError) as exc:
                store.authenticate(email, password)
            assert exc.value.code == "auth_failed", (email, password)
            assert str(exc.value) == "wrong email or password", (email, password)
    finally:
        store.close()


def test_attempt_history_recorded(tmp_path):
    store = UserStore(tmp_path / "s.db", iterations=MIN_ITERATIONS)
    try:
        store.create_user("a@b.com", PASSWORD)
        with pytest.raises(AuthError):
            store.authenticate("a@b.com", "wrong password", ip="1.2.3.4")
        store.authenticate("a@b.com", PASSWORD, ip="1.2.3.4")
        history = store.attempt_history("a@b.com")
        assert len(history) == 2
        assert history[0]["successful"] == 1   # most recent first
        assert history[0]["ip"] == "1.2.3.4"
    finally:
        store.close()
