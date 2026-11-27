"""Back up the analyzer's local state to a folder or any rclone remote (free tiers: R2, B2, a USB drive).

  uv run python scripts/backup.py --dest D:\\backups\\gla            # local folder
  uv run python scripts/backup.py --dest r2:my-bucket/gla           # rclone remote (rclone config first)
  uv run python scripts/backup.py --dest D:\\backups\\gla --dry-run  # show what would run

What is copied (paths follow the same env vars as the app):
  sqlite/        every SQLite file, via SQLite's online backup API, so a file in use is copied consistently
                 (incidents, API keys, learned PII and PII rules)
  delta-lake/    Delta tables, data files first and `_delta_log` last, so the copy never lists a missing file
  chroma/        copied as-is. Chroma's index files are not snapshot-safe: stop the api first for a
                 consistent copy, or accept that a copy taken during writes may need a re-index
Extra directories (for example the Spark volume exported to a host path): --extra NAME=PATH, repeatable.
Restore: stop the stack, copy the folders back to the same paths, start it again.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from typing import Dict, List

LOG_ONLY = ["--filter", "+ **/_delta_log/**", "--filter", "- *"]
NO_LOG = ["--exclude", "**/_delta_log/**"]


def state_paths() -> Dict[str, str]:
    return {
        "incidents": os.getenv("INCIDENTS_DB", "./data/incidents.sqlite3"),
        "api_keys": os.getenv("API_KEYS_DB", "./data/api_keys.sqlite3"),
        "learned_pii": os.getenv("PII_LEARNED_DB", "./data/learned_pii.sqlite3"),
    }


def sqlite_snapshot(src: str, dst: str) -> None:
    """Consistent copy of a live SQLite database (WAL or not)."""
    source = sqlite3.connect(f"file:{os.path.abspath(src)}?mode=ro", uri=True)
    try:
        target = sqlite3.connect(dst)
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()


def plan(dest: str, staging: str, delta: str, chroma: str, extras: Dict[str, str], skip_chroma: bool) -> List[List[str]]:
    """rclone commands in run order. Delta data goes before its log; see the module docstring."""
    d = dest.rstrip("/\\")
    cmds = [["rclone", "sync", staging, f"{d}/sqlite"]]
    if os.path.isdir(delta):
        cmds += [["rclone", "sync", delta, f"{d}/delta-lake", *NO_LOG],
                 ["rclone", "sync", delta, f"{d}/delta-lake", *LOG_ONLY]]
    if not skip_chroma and os.path.isdir(chroma):
        cmds.append(["rclone", "sync", chroma, f"{d}/chroma"])
    for name, path in extras.items():
        if os.path.isdir(path):
            cmds += [["rclone", "sync", path, f"{d}/{name}", *NO_LOG], ["rclone", "sync", path, f"{d}/{name}", *LOG_ONLY]]
    return cmds


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dest", required=True, help="local folder or rclone remote:path")
    p.add_argument("--extra", action="append", default=[], metavar="NAME=PATH", help="extra directory to back up")
    p.add_argument("--skip-chroma", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the rclone commands and stop")
    args = p.parse_args()

    from dotenv import load_dotenv
    load_dotenv()
    extras = dict(e.split("=", 1) for e in args.extra)
    delta = os.getenv("DELTA_LAKE_PATH", "./data/delta-lake")
    chroma = os.getenv("CHROMA_PATH", "./data/chroma")
    if not args.dry_run and shutil.which("rclone") is None:
        print("rclone is not installed (https://rclone.org/install/). Use --dry-run to see the plan.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="gla-backup-") as staging:
        for name, path in state_paths().items():
            if os.path.exists(path):
                sqlite_snapshot(path, os.path.join(staging, f"{name}.sqlite3"))
                print(f"snapshot {name}: {path}")
            else:
                print(f"skip {name}: {path} does not exist")
        if not args.skip_chroma and os.path.isdir(chroma):
            print("note: chroma is copied while the api may be writing; stop the api for a consistent copy")
        for cmd in plan(args.dest, staging, delta, chroma, extras, args.skip_chroma):
            print("+ " + " ".join(cmd))
            if not args.dry_run and subprocess.run(cmd).returncode != 0:
                print("backup FAILED: rclone returned an error", file=sys.stderr)
                return 1
    print("dry run only" if args.dry_run else "backup finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
