# VirusShare MD5 Searcher

This tool uses Python's standard library and a local SQLite database to find the `VirusShare_XXXXX.zip` archive associated with an MD5 hash. It downloads public MD5 lists, not malware samples or ZIP archives.

## Usage

Python 3.10 or later and an internet connection are required to update the database. The first update downloads every available list and may take some time and several gigabytes of disk space.

```bash
python3 update_db.py
python3 query.py 3d18ea8bb288e54e4ea3c129b40bf24b
```

Example query output:

```text
VirusShare_00027.zip
```

Both scripts accept `--db /path/to/database.sqlite3`. By default, they use `virusshare.sqlite3` beside the scripts. The update script downloads up to three lists concurrently; use `--workers N` to change this limit. Subsequent updates import only newly discovered lists. To reimport an older list that the website has changed, delete the database and rebuild it.

Queries are offline. A `Not found` result means the hash was absent from the lists currently indexed in the local database; the output also shows how many discovered lists have been indexed.

The update script extracts links from [VirusShare Hashes](https://virusshare.com/hashes) and probes consecutive list numbers after the last linked one in case a new file is available before its link appears on the page. Each list is imported in a single transaction. An interrupted download, truncated response, or invalid MD5 line rolls back that list, so the next run can resume. If the same MD5 appears in multiple archives, the query prints every matching archive.

Exit codes: a query returns 0 for a match, 1 for no match, and 2 for invalid input or a database error. An update returns 0 on success and 1 on failure.
