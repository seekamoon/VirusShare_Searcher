#!/usr/bin/env python3
"""Incrementally download VirusShare MD5 lists into a local SQLite database."""

from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import io
from pathlib import Path
import re
import sqlite3
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


INDEX_URL = "https://virusshare.com/hashes"
DEFAULT_DB = Path(__file__).with_name("virusshare.sqlite3")
LINK_RE = re.compile(r"^/hashfiles/VirusShare_(\d{5,})\.md5$")
MD5_RE = re.compile(rb"^[0-9a-fA-F]{32}$")
USER_AGENT = "VirusShare-Searcher/1.0 (hash-list indexer)"
BATCH_SIZE = 2000
TIMEOUT = 45
RETRIES = 3


class HashLinkParser(HTMLParser):
    def __init__(self, index_url: str):
        super().__init__()
        self.index_url = index_url
        self.links: dict[int, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if not href:
            return
        url = urljoin(self.index_url, href)
        parsed = urlparse(url)
        index = urlparse(self.index_url)
        if (parsed.scheme, parsed.netloc) != (index.scheme, index.netloc):
            return
        match = LINK_RE.fullmatch(parsed.path)
        if match and not parsed.query and not parsed.fragment:
            number = int(match.group(1))
            previous = self.links.get(number)
            if previous is not None and previous != url:
                raise ValueError(f"Archive {number} has conflicting download links")
            self.links[number] = url


def open_url(url: str, *, method: str = "GET"):
    request = Request(url, headers={"User-Agent": USER_AGENT}, method=method)
    return urlopen(request, timeout=TIMEOUT)


def retry_open(url: str, *, method: str = "GET"):
    for attempt in range(RETRIES):
        try:
            return open_url(url, method=method)
        except HTTPError as exc:
            if exc.code not in (408, 429, 500, 502, 503, 504) or attempt == RETRIES - 1:
                raise
        except (URLError, TimeoutError):
            if attempt == RETRIES - 1:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


def download_list(url: str) -> bytes:
    """Download one complete list; retry transient network and short-read errors."""
    for attempt in range(RETRIES):
        try:
            with open_url(url) as response:
                content_length = response.headers.get("Content-Length")
                payload = response.read()
            if content_length is not None and len(payload) != int(content_length):
                raise OSError(f"Received only {len(payload)}/{content_length} bytes")
            if not payload:
                raise OSError("Download is empty")
            return payload
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            if isinstance(exc, HTTPError) and exc.code not in (408, 429, 500, 502, 503, 504):
                raise
            if attempt == RETRIES - 1:
                raise
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def discover_lists() -> dict[int, str]:
    with retry_open(INDEX_URL) as response:
        html = response.read().decode("utf-8")
    parser = HashLinkParser(INDEX_URL)
    parser.feed(html)
    if not parser.links:
        raise ValueError("No VirusShare MD5 list links found on the index page")

    # The site can expose a new .md5 file before adding its link to /hashes.
    # Only probe consecutive numbers after the largest linked file.
    next_number = max(parser.links) + 1
    while True:
        url = urljoin(INDEX_URL, f"/hashfiles/VirusShare_{next_number:05d}.md5")
        try:
            with retry_open(url, method="HEAD") as response:
                if response.status != 200:
                    raise ValueError(f"Probe for {url} returned HTTP {response.status}")
        except HTTPError as exc:
            if exc.code == 404:
                break
            raise
        parser.links[next_number] = url
        next_number += 1
    return dict(sorted(parser.links.items()))


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA cache_size=-131072")  # 128 MiB for the large MD5 index.
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS archives (
            number INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            source_url TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            imported_at TEXT NOT NULL,
            published INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS samples (
            md5 BLOB NOT NULL CHECK(length(md5) = 16),
            archive_number INTEGER NOT NULL REFERENCES archives(number),
            PRIMARY KEY (md5, archive_number)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    return db


def mark_published(db: sqlite3.Connection, links: dict[int, str]) -> None:
    with db:
        db.execute("UPDATE archives SET published = 0")
        db.executemany(
            "UPDATE archives SET published = 1 WHERE number = ? AND source_url = ?",
            ((number, url) for number, url in links.items()),
        )
        db.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (
                ("source_checked_at", datetime.now(timezone.utc).isoformat()),
                ("published_list_count", str(len(links))),
            ),
        )


def import_list(db: sqlite3.Connection, number: int, url: str, payload: bytes | None = None) -> int:
    name = f"VirusShare_{number:05d}.zip"
    for attempt in range(RETRIES):
        try:
            source = open_url(url) if payload is None else io.BytesIO(payload)
            with source as response, db:
                count = 0
                received_bytes = 0
                content_length = (
                    response.headers.get("Content-Length") if payload is None else str(len(payload))
                )
                batch: list[tuple[bytes, int]] = []
                # Insert the parent first; the whole archive is committed atomically.
                db.execute(
                    "INSERT INTO archives(number, name, source_url, sample_count, imported_at, published) "
                    "VALUES (?, ?, ?, 0, ?, 1)",
                    (number, name, url, datetime.now(timezone.utc).isoformat()),
                )
                for line_number, raw_line in enumerate(response, 1):
                    received_bytes += len(raw_line)
                    value = raw_line.strip()
                    if not value or value.startswith(b"#"):
                        continue
                    if not MD5_RE.fullmatch(value):
                        raise ValueError(f"{name} line {line_number} is not a valid MD5 hash")
                    batch.append((bytes.fromhex(value.decode("ascii")), number))
                    count += 1
                    if len(batch) >= BATCH_SIZE:
                        db.executemany(
                            "INSERT OR IGNORE INTO samples(md5, archive_number) VALUES (?, ?)", batch
                        )
                        batch.clear()
                if batch:
                    db.executemany(
                        "INSERT OR IGNORE INTO samples(md5, archive_number) VALUES (?, ?)", batch
                    )
                if count == 0:
                    raise ValueError(f"{name} contains no MD5 hashes; import rolled back")
                if content_length is not None and received_bytes != int(content_length):
                    raise ValueError(
                        f"{name} received only {received_bytes}/{content_length} bytes; import rolled back"
                    )
                db.execute("UPDATE archives SET sample_count = ? WHERE number = ?", (count, number))
            return count
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            if isinstance(exc, HTTPError) and exc.code not in (408, 429, 500, 502, 503, 504):
                raise
            if attempt == RETRIES - 1:
                raise
            print(f"{name} download failed; retry {attempt + 1}/{RETRIES - 1}: {exc}", file=sys.stderr)
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description="Update the local VirusShare MD5 index")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    parser.add_argument("--workers", type=int, default=3, help="Concurrent downloads (default: 3)")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be greater than zero")
    try:
        links = discover_lists()
        print(f"Found {len(links)} lists, numbered {min(links)}-{max(links)}", flush=True)
        with connect(args.db) as db:
            mark_published(db, links)
            existing = {
                row[0]: row[1]
                for row in db.execute("SELECT number, source_url FROM archives WHERE published = 1")
            }
            pending = [(n, url) for n, url in links.items() if existing.get(n) != url]
            print(f"Already indexed: {len(links) - len(pending)}; pending: {len(pending)}", flush=True)
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                tasks: deque[tuple[int, str, Future[bytes]]] = deque()
                remaining = iter(pending)

                def schedule_next() -> None:
                    item = next(remaining, None)
                    if item is not None:
                        number, url = item
                        tasks.append((number, url, pool.submit(download_list, url)))

                for _ in range(args.workers):
                    schedule_next()
                for position in range(1, len(pending) + 1):
                    number, url, future = tasks.popleft()
                    schedule_next()
                    count = import_list(db, number, url, future.result())
                    print(
                        f"[{position}/{len(pending)}] VirusShare_{number:05d}.zip: {count} MD5 hashes",
                        flush=True,
                    )
            indexed = db.execute("SELECT COUNT(*) FROM archives WHERE published = 1").fetchone()[0]
            print(f"Done: {indexed}/{len(links)} lists indexed; database: {args.db}")
        return 0
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"Update failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
