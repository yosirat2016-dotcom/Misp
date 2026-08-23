"""Lightweight poll: checks every 5 min (via misp-csv-watch.timer) whether
sources.csv on GitHub has changed since last check. If so, triggers the
full sync (which is the expensive part - hits rate-limited sources like
NVD/gov.il). If unchanged, exits quietly without touching those sources.

This is deliberately separate from misp-github-sync.timer (every 3 days,
unconditional refresh) - that one exists so existing sources still pick
up new IOCs even when the CSV never changes; this one exists so a new
CSV row gets picked up fast without re-hitting rate-limited APIs on every
5-minute tick.

State (last-seen content hash) is stored in .state/sources_csv.sha256,
gitignored - each machine running this tracks its own "have I already
synced this version" independently.

Usage:
    python scripts/check_sources_csv_changed.py
"""
import hashlib
import os
import sys
import urllib.request
from pathlib import Path
from urllib.error import URLError

from dotenv import load_dotenv

REQUEST_TIMEOUT_SECONDS = 15
STATE_FILE = Path(".state/sources_csv.sha256")


def fetch_csv_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "misp-csv-watch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            return resp.read()
    except URLError as exc:
        raise ConnectionError(f"Could not fetch sources.csv from {url}: {exc}") from exc


def main():
    load_dotenv()
    sources_csv_url = os.environ.get("GITHUB_SOURCES_CSV_URL", "")
    if not sources_csv_url:
        print("GITHUB_SOURCES_CSV_URL not set in .env", file=sys.stderr)
        sys.exit(1)

    content = fetch_csv_bytes(sources_csv_url)
    current_hash = hashlib.sha256(content).hexdigest()

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    last_hash = STATE_FILE.read_text().strip() if STATE_FILE.exists() else None

    if current_hash == last_hash:
        print("sources.csv unchanged, nothing to do")
        return

    print(f"sources.csv changed ({last_hash or '(none)'} -> {current_hash}), triggering full sync ...")
    STATE_FILE.write_text(current_hash)

    import sync_github_to_misp

    sync_github_to_misp.main()


if __name__ == "__main__":
    main()
