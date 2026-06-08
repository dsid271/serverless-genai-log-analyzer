"""
CLI utility to generate bcrypt-hashed API keys for api_keys.yaml.

Usage:
    uv run python scripts/generate_key.py "my-secret-key"
    uv run python scripts/generate_key.py           # auto-generates a random key
"""

from __future__ import annotations

import secrets
import sys

from passlib.hash import bcrypt


def main() -> None:
    if len(sys.argv) > 1:
        raw_key = sys.argv[1]
    else:
        raw_key = secrets.token_urlsafe(32)
        print(f"Generated key: {raw_key}")

    hashed = bcrypt.hash(raw_key)
    print(f"Hash (paste into api_keys.yaml): {hashed}")


if __name__ == "__main__":
    main()
