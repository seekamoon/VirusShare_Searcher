#!/usr/bin/env python3
"""Look up one MD5 in the local VirusShare SQLite database."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sqlite3
import sys


DEFAULT_DB = Path(__file__).with_name("virusshare.sqlite3")
MD5_RE = re.compile(r"[0-9a-fA-F]{32}\Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="Find the VirusShare archive containing an MD5 hash")
    parser.add_argument("md5", help="32-character hexadecimal MD5 hash")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    args = parser.parse_args()
    md5 = args.md5.strip()
    if not MD5_RE.fullmatch(md5):
        parser.error("MD5 must contain exactly 32 hexadecimal characters")
    if not args.db.is_file():
        print(f"Database not found: {args.db}; run update_db.py first", file=sys.stderr)
        return 2
    try:
        with sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True) as db:
            rows = db.execute(
                "SELECT a.name FROM samples AS s JOIN archives AS a "
                "ON a.number = s.archive_number "
                "WHERE s.md5 = ? AND a.published = 1 ORDER BY a.number",
                (bytes.fromhex(md5),),
            ).fetchall()
            if rows:
                for (name,) in rows:
                    print(name)
                return 0
            imported = db.execute("SELECT COUNT(*) FROM archives WHERE published = 1").fetchone()[0]
            row = db.execute("SELECT value FROM metadata WHERE key = 'published_list_count'").fetchone()
            published = int(row[0]) if row else 0
            print(f"Not found (indexed {imported}/{published} discovered lists locally)")
            return 1
    except (sqlite3.Error, ValueError) as exc:
        print(f"Query failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
