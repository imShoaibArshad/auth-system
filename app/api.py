"""Flask auth API.

Endpoints:

    POST /api/register     {email, password}        -> 201 + token
    POST /api/login        {email, password}        -> 200 + token
    POST /api/logout       (Bearer token)           -> 204
    GET  /api/me           (Bearer token)           -> 200
    POST /api/change-password {current_password, new_password} -> 204

Design rules enforced here:
  * one generic "wrong email or password" for every credential failure
  * login rate-limited per-IP in addition to per-account lockout
  * tokens are stateless (HMAC-signed) — logout invalidates the current
    session by clearing the cookie, and a token blacklist is noted as a
    limitation rather than quietly faked
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request

from .passwords import check_password_strength
from .store import AuthError, UserStore
from .tokens import TokenError, issue_token, new_secret, parse_token

# Per-IP sliding window: 30 login attempts per 10 minutes.
IP_RATE_LIMIT = 30
IP_WINDOW_SECONDS = 600

GENERIC_LOGIN_ERROR = "wrong email or password"


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.setdefault("SECRET_KEY", new_secret())
    app.config.setdefault("DATABASE", "users.db")
    app.config.setdefault("TOKEN_TTL", 60 * 60 * 12)
    app.config.setdefault("TESTING", False)
    if config:
        app.config.update(config)

    store = UserStore(app.config["DATABASE"])
    app.extensions["user_store"] = store
    app.extensions["ip_hits"] = defaultdict(deque)

    # ---------------------------------------------------------- helpers ----

    def json_error(status: int, code: str, message: str):
        return jsonify({"error": {"code": code, "message": message}}), status

    def bearer_token() -> str | None:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return request.cookies.get("session")

    def current_session():
        token = bearer_token()
        if not token:
            return None
        try:
            return parse_token(token, app.config["SECRET_KEY"])
        except TokenError:
            return None

    def client_ip() -> str:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

    def ip_allowed() -> bool:
        """Sliding-window rate limit per IP."""
        ip = client_ip()
        now = time.time()
        hits = app.extensions["ip_hits"][ip]
        while hits and now - hits[0] > IP_WINDOW_SECONDS:
            hits.popleft()
        return len(hits) < IP_RATE_LIMIT

    def register_ip_hit() -> None:
        app.extensions["ip_hits"][client_ip()].append(time.time())

    def read_json() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    # ----------------------------------------------------------- routes ----

    @app.post("/api/register")
    def register():
        if not ip_allowed():
            return json_error(429, "rate_limited", "Too many requests. Try again later.")

        body = read_json()
        email = body.get("email", "")
        password = body.get("password", "")

        if not isinstance(email, str) or "@" not in email or len(email) > 254:
            return json_error(400, "invalid_email", "Enter a valid email address.")
        if not isinstance(password, str):
            return json_error(400, "weak_password", "Password is required.")
        if request.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return json_error(415, "unsupported_media_type",
                              "Send Content-Type: application/json.")

        register_ip_hit()

        try:
            user_id = store.create_user(email, password)
        except AuthError as exc:
            status = 409 if exc.code == "email_taken" else 400
            return json_error(status, exc.code, str(exc))

        token = issue_token(user_id, app.config["SECRET_KEY"],
                            ttl=app.config["TOKEN_TTL"])
        return _auth_response(201, user_id, token, email.strip().lower())

    @app.post("/api/login")
    def login():
        if not ip_allowed():
            return json_error(429, "rate_limited", "Too many requests. Try again later.")

        body = read_json()
        email = body.get("email", "")
        password = body.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            return json_error(400, "invalid_request", "email and password are required.")

        register_ip_hit()

        try:
            user_id = store.authenticate(email, password, ip=client_ip())
        except AuthError as exc:
            if exc.code == "account_locked":
                # Lockout is safe to reveal: it does not confirm the account
                # exists in a useful way (any address can be "locked" by an
                # attacker, so it is not an enumeration oracle on its own) and
                # it tells a legitimate user what to do.
                return json_error(423, "account_locked", str(exc))
            # Everything else stays deliberately vague.
            return json_error(401, "invalid_credentials", GENERIC_LOGIN_ERROR)

        token = issue_token(user_id, app.config["SECRET_KEY"],
                            ttl=app.config["TOKEN_TTL"])
        user = store.get_user(user_id)
        return _auth_response(200, user_id, token, user["email"] if user else "")

    @app.post("/api/logout")
    def logout():
        if current_session() is None:
            return json_error(401, "unauthenticated", "No active session.")
        response = jsonify({"status": "logged_out"})
        response.delete_cookie("session")
        return response, 204

    @app.get("/api/me")
    def me():
        session = current_session()
        if session is None:
            return json_error(401, "unauthenticated", "Invalid or expired token.")
        user = store.get_user(session.user_id)
        if user is None:
            return json_error(401, "unauthenticated", "Account no longer exists.")
        return jsonify({"data": {
            "id": user["id"],
            "email": user["email"],
            "last_login_at": user["last_login_at"],
            "created_at": user["created_at"],
        }})

    @app.post("/api/change-password")
    def change_password():
        session = current_session()
        if session is None:
            return json_error(401, "unauthenticated", "Invalid or expired token.")

        body = read_json()
        current_password = body.get("current_password", "")
        new_password = body.get("new_password", "")
        if not isinstance(current_password, str) or not isinstance(new_password, str):
            return json_error(400, "invalid_request",
                              "current_password and new_password are required.")

        user = store.get_user(session.user_id)
        if user is None:
            return json_error(401, "unauthenticated", "Account no longer exists.")

        # Re-verify the current password before changing it — a stolen token
        # should not be enough to lock the real owner out.
        try:
            store.authenticate(user["email"], current_password, ip=client_ip())
        except AuthError:
            return json_error(401, "invalid_credentials", GENERIC_LOGIN_ERROR)

        problems = check_password_strength(new_password)
        if problems:
            return json_error(400, "weak_password", "; ".join(problems))

        with store._lock:  # noqa: SLF001 - same package
            from .passwords import hash_password
            new_hash = hash_password(new_password, iterations=store.iterations)
            with store._conn:
                store._conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, session.user_id),
                )

        response = jsonify({"status": "password_changed"})
        response.delete_cookie("session")
        return response, 204

    # ------------------------------------------------------ error routes ----

    @app.errorhandler(404)
    def not_found(_e):
        return json_error(404, "not_found", "Resource not found.")

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return json_error(405, "method_not_allowed", "Method not allowed.")

    @app.errorhandler(Exception)
    def unhandled(exc):
        if app.config["TESTING"]:
            raise exc
        app.logger.exception("unhandled error")
        return json_error(500, "internal_error", "Unexpected server error.")

    def _auth_response(status: int, user_id: int, token: str, email: str):
        response = jsonify({"data": {"user_id": user_id, "email": email,
                                     "token_type": "Bearer",
                                     "expires_in": app.config["TOKEN_TTL"]},
                            "token": token})
        response.status_code = status
        # httpOnly keeps JS from reading it (XSS mitigation); SameSite=Lax
        # blocks cross-site POSTs. `secure` is left off so http://localhost
        # works — flip it in production.
        response.set_cookie(
            "session", token,
            httponly=True, samesite="Lax", max_age=app.config["TOKEN_TTL"],
        )
        return response

    return app
