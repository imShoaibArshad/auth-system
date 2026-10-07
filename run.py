"""Run the auth API.

    python run.py                       # http://127.0.0.1:5001
    python run.py --port 8080 --debug
    python run.py --reset               # wipe the local user database
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import create_app  # noqa: E402

DB_PATH = Path(__file__).resolve().parent / "users.db"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authentication API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5001)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--db", default=str(DB_PATH), help="path to the SQLite database")
    p.add_argument("--reset", action="store_true",
                   help="delete the database file and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.reset:
        target = Path(args.db)
        if target.exists():
            target.unlink()
            print(f"deleted {target}")
        else:
            print(f"nothing to delete at {target}")
        return 0

    # A real deployment must supply SECRET_KEY; defaulting silently to a
    # random value would invalidate every session on restart without saying so.
    if not os.environ.get("SECRET_KEY"):
        print("note: SECRET_KEY is not set — using a random key, so all "
              "sessions will be invalidated on restart.\n"
              "      export SECRET_KEY=... before running in production.\n")

    app = create_app({
        "SECRET_KEY": os.environ.get("SECRET_KEY") or app_secret(),
        "DATABASE": args.db,
    })

    print(f"Auth API on http://{args.host}:{args.port}")
    print("  POST /api/register  POST /api/login  POST /api/logout")
    print("  GET  /api/me        POST /api/change-password")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def app_secret() -> str:
    from app.tokens import new_secret
    return new_secret()


if __name__ == "__main__":
    sys.exit(main())
