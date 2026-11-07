"""Small, offline checks for parsing, atomic imports, and lookups."""

import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import update_db


class Response(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data))}


class SearcherTests(unittest.TestCase):
    def test_link_parser_only_accepts_matching_hashfiles(self):
        parser = update_db.HashLinkParser(update_db.INDEX_URL)
        parser.feed(
            '<a href="hashfiles/VirusShare_00027.md5">27</a>'
            '<a href="https://example.com/hashfiles/VirusShare_00028.md5">other</a>'
            '<a href="hashfiles/VirusShare_00029.zip">zip</a>'
        )
        self.assertEqual(list(parser.links), [27])

    def test_import_query_and_rollback(self):
        sample = "3d18ea8bb288e54e4ea3c129b40bf24b"
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "search.sqlite3"
            with update_db.connect(db_path) as db:
                update_db.mark_published(
                    db,
                    {
                        27: "https://virusshare.com/hashfiles/VirusShare_00027.md5",
                        28: "https://virusshare.com/hashfiles/VirusShare_00028.md5",
                        29: "https://virusshare.com/hashfiles/VirusShare_00029.md5",
                    },
                )
                good = (f"# comment\n{sample}\n" + "a" * 32 + "\n").encode()
                with patch.object(update_db, "open_url", return_value=Response(good)):
                    self.assertEqual(update_db.import_list(db, 27, "url27"), 2)
                with patch.object(update_db, "open_url", return_value=Response(good)):
                    update_db.import_list(db, 29, "url29")
                bad = (f"{sample}\nnot-an-md5\n").encode()
                with patch.object(update_db, "open_url", return_value=Response(bad)):
                    with self.assertRaises(ValueError):
                        update_db.import_list(db, 28, "url28")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM archives").fetchone()[0], 2)

            result = subprocess.run(
                [sys.executable, "query.py", sample, "--db", str(db_path)],
                cwd=Path(__file__).parent,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.splitlines(), ["VirusShare_00027.zip", "VirusShare_00029.zip"])
            missing = subprocess.run(
                [sys.executable, "query.py", "0" * 32, "--db", str(db_path)],
                cwd=Path(__file__).parent,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 1)
            self.assertIn("2/3", missing.stdout)


if __name__ == "__main__":
    unittest.main()
