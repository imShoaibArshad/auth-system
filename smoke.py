"""End-to-end smoke test: boots the real server and drives it over HTTP.

pytest covers the app in-process; this covers real sockets, cookies and
status lines. Run:  python smoke.py
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://127.0.0.1:5098/api"
EMAIL = "smoke@example.com"
PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a different good passphrase"

ok = True
cookie: str | None = None


def check(label: str, condition: bool, detail: str = "") -> None:
    global ok
    ok = ok and bool(condition)
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          f"{(' -> ' + detail) if detail else ''}")


def call(method: str, path: str, payload=None, token=None, ctype="application/json",
         send_cookie=True):
    global cookie
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": ctype} if data else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # `send_cookie=False` lets a check exercise a truly credential-less
    # request; without it the session cookie from register would silently
    # authenticate and the check would pass for the wrong reason.
    if cookie and send_cookie:
        headers["Cookie"] = cookie

    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode()
            hdrs = dict(resp.headers)
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        hdrs = dict(exc.headers)
        status = exc.code

    # Remember the session cookie the way a browser would.
    if "Set-Cookie" in hdrs:
        raw = hdrs["Set-Cookie"]
        if raw.startswith("session=;"):
            cookie = None
        else:
            cookie = raw.split(";")[0]

    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = body
    return status, parsed, hdrs


def main() -> int:
    server = subprocess.Popen(
        [sys.executable, "run.py", "--port", "5098", "--db", "smoke_users.db"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            time.sleep(0.25)
            try:
                status, _, _ = call("GET", "/me")
                if status == 401:   # up, just unauthenticated
                    break
            except OSError:
                continue
        else:
            print("server never came up")
            return 1

        print("Register")
        status, body, headers = call("POST", "/register",
                                     {"email": EMAIL, "password": PASSWORD})
        check("201 Created", status == 201, str(status))
        token = body["token"]
        check("token returned", bool(token))
        check("httpOnly cookie set", "HttpOnly" in headers.get("Set-Cookie", ""))

        status, body, _ = call("POST", "/register",
                               {"email": EMAIL.upper(), "password": PASSWORD})
        check("duplicate -> 409", status == 409, str(status))

        status, body, _ = call("POST", "/register",
                               {"email": "bad", "password": PASSWORD})
        check("bad email -> 400", status == 400, str(status))

        status, body, _ = call("POST", "/register",
                               {"email": "weak@example.com", "password": "short"})
        check("weak password -> 400", status == 400, str(status))

        print("Login")
        status, body, _ = call("POST", "/login",
                               {"email": EMAIL.upper(), "password": PASSWORD})
        check("success -> 200", status == 200, str(status))
        good_token = body["token"]

        status, body, _ = call("POST", "/login",
                               {"email": EMAIL, "password": "wrong password here"})
        check("wrong password -> 401", status == 401, str(status))
        check("generic message", body["error"]["message"] == "wrong email or password",
              body["error"]["message"])

        status, body, _ = call("POST", "/login",
                               {"email": "ghost@example.com",
                                "password": "wrong password here"})
        check("unknown user -> identical body", status == 401
              and body["error"]["message"] == "wrong email or password",
              "no user enumeration")

        print("Auth")
        status, body, _ = call("GET", "/me", send_cookie=False)
        check("no credentials -> 401", status == 401, str(status))

        status, body, _ = call("GET", "/me", token=good_token)
        check("valid token -> 200", status == 200, str(status))
        check("returns own email", body["data"]["email"] == EMAIL)

        status, body, _ = call("GET", "/me", token="forged.token")
        check("forged token -> 401", status == 401, str(status))

        print("Change password")
        status, body, _ = call("POST", "/change-password", {
            "current_password": "not the right one",
            "new_password": NEW_PASSWORD,
        }, token=good_token)
        check("wrong current -> 401", status == 401, str(status))

        status, body, _ = call("POST", "/change-password", {
            "current_password": PASSWORD, "new_password": "short",
        }, token=good_token)
        check("weak new -> 400", status == 400, str(status))

        status, body, _ = call("POST", "/change-password", {
            "current_password": PASSWORD, "new_password": NEW_PASSWORD,
        }, token=good_token)
        check("valid change -> 204", status == 204, str(status))

        status, body, _ = call("POST", "/login",
                               {"email": EMAIL, "password": NEW_PASSWORD})
        check("new password works", status == 200, str(status))
        status, body, _ = call("POST", "/login",
                               {"email": EMAIL, "password": PASSWORD})
        check("old password rejected", status == 401, str(status))

        print("Errors")
        status, body, _ = call("GET", "/nope")
        check("404 is JSON", status == 404 and body["error"]["code"] == "not_found")
        status, body, _ = call("GET", "/register")
        check("405 is JSON", status == 405 and body["error"]["code"] == "method_not_allowed")

        print("Logout")
        fresh = None
        status, body, _ = call("POST", "/login",
                               {"email": EMAIL, "password": NEW_PASSWORD})
        fresh = body["token"]
        status, _, _ = call("POST", "/logout", token=fresh)
        check("logout -> 204", status == 204, str(status))

    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()

    print("\n" + ("ALL SMOKE CHECKS PASSED" if ok else "SMOKE CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
