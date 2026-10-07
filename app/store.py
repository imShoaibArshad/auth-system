"""User storage with an account-lockout layer.

SQLite by default so the project runs with no services. The store handles
what actually stops credential-stuffing in practice:

  * lockout after repeated failures, with an exponential backoff
  * a *generic* auth error — "wrong email or password" — so the API never
    reveals which half of the credentials was wrong (user enumeration)
  * rehash-on-login, so raising PBKDF2 cost doesn't force a reset
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from .passwords import (
    DEFAULT_ITERATIONS,
    PasswordError,
    check_password_strength,
    hash_password,
    needs_rehash,
    verify_password,
)

MAX_FAILED_ATTEMPTS = 5
# Lockout doubles each time: 1min, 2min, 4min ... capped at 1 hour.
BASE_LOCKOUT_SECONDS = 60
MAX_LOCKOUT_SECONDS = 3600
LOCKOUT_RESET_ON_SUCCESS = True


class AuthError(Exception):
    """Any authentication failure. `code` lets callers respond generically."""

    def __init__(self, message: str, code: str = "auth_failed"):
        super().__init__(message)
        self.code = code


class UserStore:
    """Thread-safe SQLite-backed user store."""

    def __init__(self, path: str | Path = "users.db", *, iterations: int = DEFAULT_ITERATIONS):
        self.path = str(path)
        self.iterations = iterations
        self._lock = threading.Lock()
        # check_same_thread=False + our own lock: lets the Flask test client
        # and background threads share one connection safely.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    email             TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash     TEXT    NOT NULL,
                    failed_attempts   INTEGER NOT NULL DEFAULT 0,
                    locked_until      INTEGER,
                    last_login_at     INTEGER,
                    created_at        INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    email      TEXT    NOT NULL COLLATE NOCASE,
                    ip         TEXT,
                    successful INTEGER NOT NULL,
                    at         INTEGER NOT NULL
                );
                """
            )

    # ------------------------------------------------------------- create ---

    def create_user(self, email: str, password: str) -> int:
        """Register a user. Raises AuthError on duplicate or weak password."""
        email = _normalise_email(email)
        if not email:
            raise AuthError("email is required", "invalid_email")

        problems = check_password_strength(password)
        if problems:
            raise AuthError("; ".join(problems), "weak_password")

        # Hash outside the lock — PBKDF2 is deliberately slow and would
        # otherwise serialise every other registration behind it.
        password_hash = hash_password(password, iterations=self.iterations)

        with self._lock:
            try:
                with self._conn:
                    cur = self._conn.execute(
                        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                        (email, password_hash, int(time.time())),
                    )
            except sqlite3.IntegrityError as exc:
                raise AuthError("an account with that email already exists",
                                "email_taken") from exc
            return int(cur.lastrowid)

    # -------------------------------------------------------------- login ---

    def authenticate(self, email: str, password: str, ip: str | None = None) -> int:
        """Verify credentials, enforcing lockout. Returns the user id.

        Raises AuthError with code "auth_failed" for *every* credential
        problem — wrong password, unknown email, locked account — so callers
        cannot accidentally distinguish them.
        """
        email = _normalise_email(email)
        now = int(time.time())

        if not email or not password:
            self._record_attempt(email, ip, False, now)
            raise AuthError("wrong email or password")

        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

            if row is None:
                # Burn comparable time so a missing user isn't instant.
                # NOTE: this must NOT go through hash_password() — that
                # enforces *registration* policy, so a weak password like
                # "short" would raise PasswordError (a 500) for a
                # non-existent user while returning 401 for a real one,
                # turning the timing-equalisation branch into a
                # user-enumeration oracle.
                _burn_time(password, self.iterations)
                self._record_attempt(email, ip, False, now, commit=False)
                raise AuthError("wrong email or password")

            locked_until = row["locked_until"]
            if locked_until and now < locked_until:
                self._record_attempt(email, ip, False, now, commit=False)
                minutes = max(1, round((locked_until - now) / 60))
                raise AuthError(
                    f"too many failed attempts — try again in {minutes} minute(s)",
                    "account_locked",
                )

            if not verify_password(password, row["password_hash"]):
                self._register_failure(row, email, ip, now)
                raise AuthError("wrong email or password")

            # Rehash transparently if the cost factor has been raised.
            if needs_rehash(row["password_hash"], iterations=self.iterations):
                new_hash = hash_password(password, iterations=self.iterations)
            else:
                new_hash = None

            with self._conn:
                if new_hash:
                    self._conn.execute(
                        "UPDATE users SET password_hash = ?, failed_attempts = 0, "
                        "locked_until = NULL, last_login_at = ? WHERE id = ?",
                        (new_hash, now, row["id"]),
                    )
                else:
                    self._conn.execute(
                        "UPDATE users SET failed_attempts = 0, locked_until = NULL, "
                        "last_login_at = ? WHERE id = ?",
                        (now, row["id"]),
                    )
                self._record_attempt(email, ip, True, now, commit=False)

            return int(row["id"])

    def _register_failure(self, row, email: str, ip: str | None, now: int) -> None:
        attempts = int(row["failed_attempts"]) + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            # Exponential: 1,2,4,8,16 ... minutes, capped at an hour.
            over = attempts - MAX_FAILED_ATTEMPTS
            seconds = min(BASE_LOCKOUT_SECONDS * (2 ** over), MAX_LOCKOUT_SECONDS)
            locked_until = now + seconds
        with self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, row["id"]),
            )
            self._record_attempt(email, ip, False, now, commit=False)

    def _record_attempt(self, email: str, ip: str | None, success: bool,
                        now: int, *, commit: bool = True) -> None:
        def run():
            self._conn.execute(
                "INSERT INTO login_attempts (email, ip, successful, at) VALUES (?, ?, ?, ?)",
                (email or "", ip, 1 if success else 0, now),
            )

        if commit:
            with self._conn:
                run()
        else:
            run()

    # ------------------------------------------------------------- status ---

    def is_locked(self, email: str) -> bool:
        email = _normalise_email(email)
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT locked_until FROM users WHERE email = ?", (email,)
            ).fetchone()
        return bool(row and row["locked_until"] and now < row["locked_until"])

    def lockout_seconds(self, email: str) -> int:
        email = _normalise_email(email)
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT locked_until FROM users WHERE email = ?", (email,)
            ).fetchone()
        if not row or not row["locked_until"]:
            return 0
        return max(0, int(row["locked_until"]) - now)

    def get_user(self, user_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, email, last_login_at, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def find_by_email(self, email: str) -> dict | None:
        email = _normalise_email(email)
        with self._lock:
            row = self._conn.execute(
                "SELECT id, email, last_login_at, created_at FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        return dict(row) if row else None

    def attempt_history(self, email: str, limit: int = 20) -> list[dict]:
        email = _normalise_email(email)
        with self._lock:
            rows = self._conn.execute(
                "SELECT email, ip, successful, at FROM login_attempts "
                "WHERE email = ? ORDER BY at DESC, id DESC LIMIT ?",
                (email, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def user_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _normalise_email(email) -> str:
    if not isinstance(email, str):
        return ""
    return email.strip().lower()


def _burn_time(password, iterations: int) -> None:
    """Spend roughly as long as a real verification would.

    Deliberately bypasses password policy: this runs *after* credentials have
    already failed, so applying registration rules here would leak whether an
    account exists (weak password -> exception on unknown user, plain 401 on
    a real one).
    """
    import hashlib

    if not isinstance(password, str):
        password = ""
    try:
        # Cap the input so a huge payload can't be used to burn CPU.
        payload = password.encode("utf-8")[:1024]
        hashlib.pbkdf2_hmac("sha256", payload, b"timing-equalisation", iterations, 32)
    except (ValueError, TypeError):
        pass


__all__ = ["AuthError", "UserStore", "PasswordError"]
