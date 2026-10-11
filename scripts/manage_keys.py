"""
Issue, list and revoke API keys in the SQLite key store ($API_KEYS_DB).

Usage:
    uv run python scripts/manage_keys.py issue --name ops-admin --profile admin
    uv run python scripts/manage_keys.py issue --name fluentbit --profile ingest-service --ttl-days 30
    uv run python scripts/manage_keys.py list [--all]
    uv run python scripts/manage_keys.py revoke <key_id>
    uv run python scripts/manage_keys.py profiles

Use this to create the first admin key; after that, `POST /admin/keys` works too.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.key_store import PROFILES, get_key_store  # noqa: E402


def _fmt(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    issue = sub.add_parser("issue", help="issue a new key")
    issue.add_argument("--name", required=True, help="who or what the key is for")
    issue.add_argument("--profile", required=True, choices=sorted(PROFILES))
    issue.add_argument("--ttl-days", type=int, default=None, help="override the profile's default lifetime")

    ls = sub.add_parser("list", help="list keys (never shows secrets)")
    ls.add_argument("--all", action="store_true", help="include revoked keys")

    rv = sub.add_parser("revoke", help="revoke a key by id")
    rv.add_argument("key_id")

    sub.add_parser("profiles", help="show profiles and their scopes")

    args = parser.parse_args()
    store = get_key_store()

    if args.cmd == "issue":
        try:
            raw_key, rec = store.issue(args.name, args.profile, args.ttl_days)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"key_id:  {rec.key_id}")
        print(f"profile: {rec.profile}  scopes: {' '.join(sorted(rec.scopes))}")
        print(f"expires: {_fmt(rec.expires_at)}")
        print("API key (shown once, store it in a secret manager):")
        print(raw_key)
        return 0

    if args.cmd == "list":
        for rec in store.list(include_revoked=args.all):
            status = "revoked" if rec.revoked_at else "active"
            print(f"{rec.key_id}  {status:<7}  {rec.profile:<14}  {rec.name:<20}  "
                  f"expires={_fmt(rec.expires_at)}  last_used={_fmt(rec.last_used_at)}")
        return 0

    if args.cmd == "revoke":
        if not store.revoke(args.key_id):
            print("error: key not found or already revoked", file=sys.stderr)
            return 1
        print(f"revoked {args.key_id}")
        return 0

    for name, (scopes, ttl) in sorted(PROFILES.items()):
        print(f"{name:<14}  ttl={ttl or 'none'}d  scopes: {' '.join(sorted(scopes))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
