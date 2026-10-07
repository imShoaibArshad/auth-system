# Auth System — Password Hashing, Sessions & Account Lockout

A complete authentication layer: registration, login, logout, session tokens,
password change, **PBKDF2 password hashing**, **account lockout with
exponential backoff**, per-IP rate limiting, and a deliberate defence against
**user enumeration**.

```bash
pip install -r requirements.txt
python run.py                 # http://127.0.0.1:5001
python -m pytest tests -q     # 74 tests
python smoke.py               # 24 checks against the real server
python run.py --reset         # wipe the local user DB
```

## Endpoints

| Method | Path | Auth | Success |
| --- | --- | --- | --- |
| POST | `/api/register` | – | `201` + token |
| POST | `/api/login` | – | `200` + token |
| POST | `/api/logout` | Bearer | `204` |
| GET | `/api/me` | Bearer | `200` |
| POST | `/api/change-password` | Bearer | `204` |

Every token is returned **both** as a JSON body (for API clients) and as an
`httpOnly; SameSite=Lax` cookie (for browsers).

## Password hashing

Storage format — self-describing, so cost can be raised later without a reset:

```
pbkdf2_sha256$260000$<salt_b64>$<hash_b64>
```

- **PBKDF2-HMAC-SHA256** from the standard library — no native dependency to
  audit, no bcrypt/libsodium build step on Windows.
- **16-byte random salt per password**, generated with `secrets`. Two
  identical passwords never produce the same hash.
- **260,000 iterations** (OWASP's 2023 floor for PBKDF2-SHA256 is 600k; this
  is a deliberate responsiveness/robustness trade, documented as such).
  `needs_rehash()` detects weaker hashes and `authenticate()` **rehashes
  transparently on successful login**, so raising the cost never forces a
  password reset.
- **`hmac.compare_digest`** for verification — a plain `==` leaks the hash
  byte-by-byte through timing.
- **Verification never raises.** A corrupt, truncated or foreign-format row
  returns `False`; a broken database must not become a 500.

### Password policy

Minimum 8 characters, plus checks for common passwords, obvious sequences
(`12345678`, `abcdefgh`) and too-few-distinct-characters. Deliberately **no
composition rules** — "must contain a symbol" pushes everyone to
`Passw0rd!`, and length beats complexity.

## The bug worth reading about

While writing the smoke test I hit a failure on:

> `unknown user -> identical body -> no user enumeration`

The cause was worse than a cosmetic mismatch. To avoid revealing that an
account doesn't exist, the unknown-user branch burned comparable CPU time by
calling `hash_password(password)`. But `hash_password()` **enforces
registration policy**. So:

| Request | Result |
| --- | --- |
| weak password (`short`) vs **real** account | `401 invalid_credentials` |
| weak password (`short`) vs **non-existent** account | **`500`** (unhandled `PasswordError`) |
| `password` vs non-existent account | **`500`** |

The branch built specifically to *hide* whether a user exists became a
**user-enumeration oracle** — and a crash at the same time. Fixed by adding
`_burn_time()`, which runs raw PBKDF2 with no policy check.
`test_weak_password_login_does_not_500_on_unknown_user` pins all five
combinations to the identical `AuthError("wrong email or password")`.

The smoke test also caught its own bug: the "no credentials" check was
inheriting the session cookie from `register`, so it passed for the wrong
reason. `call(..., send_cookie=False)` now makes the check honest.

## User enumeration defence

- **One generic message**: `wrong email or password` for unknown email, wrong
  password, and malformed input alike. `test_login_unknown_user_gives_identical_error`
  asserts the two response bodies are `==`, not merely both 401.
- **Timing**: unknown users still pay a full PBKDF2 derivation.
- **Registration** *does* reveal duplicates (`409 email_taken`) — unavoidable
  for a usable signup form, and a known, accepted trade-off.
- **Lockout** reveals a countdown (`423`), but an attacker can lock any
  address, so it isn't an existence oracle on its own.

## Account lockout

- **5 consecutive failures** → locked.
- **Exponential backoff**: 1 min → 2 → 4 → 8 … capped at 1 hour.
- Reset to 0 on any successful login.
- Locked **per account**, not per IP, so one victim's lockout can't be used to
  deny service to an attacker's *other* targets... and the per-IP limiter
  (**30 attempts / 10 min, sliding window**) covers the case where no account
  exists yet.
- The generic 401 stays generic; only the lockout state is revealed, with a
  clear message for the legitimate user.

## Session tokens

Format: `<payload_b64url>.<hmac_sha256_b64url>` — a compact, stateless,
tamper-evident token.

- Payload carries `uid`, `iat`, `exp` and a random nonce; **the signature
  covers the payload**, so editing the expiry or swapping the user id
  invalidates it (`test_parse_rejects_tampered_payload` does exactly this).
- **Signature is verified before the payload is trusted** — a forged `exp` can
  never be read as legitimate.
- **Signature compared with `hmac.compare_digest`.**
- Rejects: expired, future-issued, malformed, wrong-secret, oversized (>4KB)
  and zero/negative-TTL tokens.
- `SECRET_KEY` is **not** silently defaulted in production — `run.py` prints a
  warning that sessions will be invalidated on restart if it isn't set.

## API surface

Errors are always JSON: `{"error": {"code": "...", "message": "..."}}`.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_email` / `weak_password` / `invalid_request` | bad input |
| 401 | `invalid_credentials` / `unauthenticated` | auth failed |
| 409 | `email_taken` | duplicate registration |
| 415 | `unsupported_media_type` | non-JSON body |
| 423 | `account_locked` | lockout in effect |
| 429 | `rate_limited` | per-IP window exceeded |
| 404 / 405 | `not_found` / `method_not_allowed` | routing |

`change-password` **re-verifies the current password** before applying the new
one — a stolen token alone must not let an attacker lock the real owner out.

## Layout

```
auth-system/
├── run.py                # CLI: --host --port --db --reset
├── smoke.py              # 24 end-to-end checks over real HTTP
├── app/
│   ├── passwords.py      # PBKDF2 hashing + policy  ← core
│   ├── tokens.py         # HMAC-signed expiring sessions
│   ├── store.py          # SQLite users, lockout, attempt log
│   └── api.py            # Flask routes + rate limiting
└── tests/                # 74 tests (hashing/tokens + full API)
```

## Testing

```bash
python -m pytest tests -q   # 74 passed
python smoke.py             # 24 checks, boots the real server
```

Coverage highlights: salt uniqueness, no-plaintext-leak, garbage-input
`False` (never an exception), weak-password rejection, rehash-on-login,
token tampering/expiry/forgery, identical enumeration responses, lockout after
5 failures, lockout not affecting other accounts, per-IP rate limiting, and
attempt history ordering (the `at` column is second-granularity, so
`ORDER BY at DESC, id DESC` — a test caught the ambiguous tie).

## Limitations

- **No token revocation list.** Tokens are stateless, so logout clears the
  cookie but an already-stolen bearer token stays valid until it expires
  (12h default). Real systems need a denylist or short-lived tokens + refresh.
- **`SECRET_KEY` restarts invalidate sessions** unless supplied via env.
- **`secure` cookie flag is off** so `http://localhost` works — must be
  enabled behind HTTPS in production (noted in `api.py`).
- **No email verification, password reset, or 2FA.**
- **Single SQLite file**, not built for multi-process deployment; the store's
  `threading.Lock` covers threads, not separate workers.
- **`change-password` reaches into `store._conn`** instead of going through a
  store method — acceptable at this size, but it should be a `store.set_password()`
  before the store grows a second caller.

## Tech

Python · Flask · SQLite (stdlib) · `hashlib` / `hmac` / `secrets` (stdlib) · pytest
