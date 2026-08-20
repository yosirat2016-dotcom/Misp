"""Scheduled sync: pulls sources.csv from GitHub, regenerates every feed,
then uses the MISP API to auto-create (if needed) and fetch each Feed -
no manual "Add Feed" / "Fetch and store" clicks required.

This assumes:
  - data/misp_feed/ is being served over HTTP continuously by something
    else (see deploy/systemd/misp-feeds-http.service) - this script does
    NOT start that server itself.
  - MISP_URL, MISP_API_KEY, FEED_SERVE_BASE_URL, and GITHUB_SOURCES_CSV_URL
    are set in a .env file at the repo root (copy .env.example).

Usage:
    python scripts/sync_github_to_misp.py
"""
import csv
import io
import os
import sys
import urllib.request
from pathlib import Path
from urllib.error import URLError

from dotenv import load_dotenv

import run_feeds

REQUEST_TIMEOUT_SECONDS = 30


def download_sources_csv(url: str) -> list[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "misp-sync/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            text = resp.read().decode("utf-8")
    except URLError as exc:
        raise ConnectionError(f"Could not fetch sources.csv from {url}: {exc}") from exc
    return list(csv.DictReader(io.StringIO(text)))


def feed_url_for(out_dir: str, base_url: str) -> str:
    """out_dir looks like 'data/misp_feed/<slug>' - turn it into a URL under
    the always-on HTTP server, e.g. http://172.17.0.1:8000/<slug>/"""
    slug = Path(out_dir).name
    return f"{base_url.rstrip('/')}/{slug}/"


def ensure_feed_and_fetch(misp, name: str, feed_url: str):
    """Find a MISP Feed pointing at feed_url, creating it if it doesn't
    exist yet, then trigger a fetch. Returns a short status string."""
    from pymisp import MISPFeed

    existing_feeds = misp.feeds(pythonify=True)
    match = next(
        (f for f in existing_feeds if getattr(f, "url", "").rstrip("/") == feed_url.rstrip("/")),
        None,
    )

    if match is None:
        feed = MISPFeed()
        feed.from_dict(
            name=name,
            provider=name,
            url=feed_url,
            source_format="misp",
            input_source="network",
            enabled=True,
            caching_enabled=True,
        )
        created = misp.add_feed(feed, pythonify=True)
        if isinstance(created, dict) and created.get("errors"):
            raise RuntimeError(f"MISP rejected feed creation: {created['errors']}")
        feed_id = created.id
        status = "created"
    else:
        feed_id = match.id
        status = "existing"

    fetch_result = misp.fetch_feed(feed_id)
    if isinstance(fetch_result, dict) and fetch_result.get("errors"):
        raise RuntimeError(f"MISP rejected fetch trigger: {fetch_result['errors']}")

    return f"{status}, fetch triggered (feed id {feed_id})"


def main():
    load_dotenv()

    misp_url = os.environ.get("MISP_URL", "")
    misp_api_key = os.environ.get("MISP_API_KEY", "")
    feed_serve_base_url = os.environ.get("FEED_SERVE_BASE_URL", "")
    sources_csv_url = os.environ.get("GITHUB_SOURCES_CSV_URL", "")

    missing = [
        name for name, val in [
            ("MISP_URL", misp_url), ("MISP_API_KEY", misp_api_key),
            ("FEED_SERVE_BASE_URL", feed_serve_base_url), ("GITHUB_SOURCES_CSV_URL", sources_csv_url),
        ] if not val
    ]
    if missing:
        print(f"Missing required .env values: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching sources.csv from {sources_csv_url} ...")
    rows = download_sources_csv(sources_csv_url)
    print(f"  {len(rows)} source(s) listed")

    from pymisp import PyMISP

    ssl_verify = os.environ.get("MISP_VERIFY_TLS", "true").lower() != "false"
    misp = PyMISP(misp_url, misp_api_key, ssl_verify)
    print(f"Connected to MISP: {misp.misp_instance_version}")

    results = []
    for row in rows:
        name, url, parser_key = row["name"], row["url"], row["parser"].strip()
        handler = run_feeds.PARSERS.get(parser_key)
        print(f"\n=== {name} ({parser_key}) ===")
        if handler is None:
            print(f"  unknown parser '{parser_key}', skipping")
            results.append((name, "skipped", f"unknown parser '{parser_key}'"))
            continue
        try:
            summary = handler(name, url)
            feed_url = feed_url_for(summary["out_dir"], feed_serve_base_url)
            misp_status = ensure_feed_and_fetch(misp, name, feed_url)
            results.append((name, "ok", f"{summary['event_count']} events -> {feed_url} ({misp_status})"))
        except Exception as exc:
            print(f"  FAILED: {exc}")
            results.append((name, "failed", str(exc)))

    print("\n=== Summary ===")
    for name, status, detail in results:
        print(f"  {status:8s} {name:30s} {detail}")

    if any(status == "failed" for _, status, _ in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
