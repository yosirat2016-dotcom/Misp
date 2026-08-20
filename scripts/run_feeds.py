"""Generic runner: reads a CSV of sources and converts each one to a MISP
Feed by dispatching to the right converter.

CSV columns: name,url,parser
  name   - label used for the output folder (data/misp_feed/<name>/) and
           as the Orgc attribution
  url    - the source URL (for "nvd"/"govil-cve" this is informational;
           those converters hit fixed, source-specific API endpoints)
  parser - which converter to use:
             generic    -> feed_to_misp.py (auto-detects RSS/JSON/CSV/text)
             nvd        -> nvd_to_misp.py (NVD CVE API 2.0)
             govil-cve  -> govil_cve_to_misp.py (gov.il CVE advisories)
           Adding a new source that fits the generic converter needs no
           code change - just a new CSV row with parser=generic. A source
           that needs its own logic (like NVD or gov.il) needs a new
           dedicated script exposing a convert(...) function, registered
           in PARSERS below.

One source failing (network error, blocked, empty feed) does not stop the
others - each row is isolated and reported at the end.

Usage:
    python scripts/run_feeds.py
    python scripts/run_feeds.py --sources scripts/sources.csv
    python scripts/run_feeds.py --only cisa-kev,nvd-recent
"""
import argparse
import csv
import sys
from pathlib import Path

import feed_to_misp
import govil_cve_to_misp
import nvd_to_misp


def run_generic(name: str, url: str):
    return feed_to_misp.convert_url_to_feed(url, out_base="data/misp_feed", org=name)


def run_nvd(name: str, url: str):
    return nvd_to_misp.convert(out_base=f"data/misp_feed/{name}", org=name)


def run_govil_cve(name: str, url: str):
    return govil_cve_to_misp.convert(out_base=f"data/misp_feed/{name}", org=name)


PARSERS = {
    "generic": run_generic,
    "nvd": run_nvd,
    "govil-cve": run_govil_cve,
}


def load_sources(csv_path: Path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", default="scripts/sources.csv", help="CSV file listing sources")
    parser.add_argument("--only", help="Comma-separated list of source names to run (default: all)")
    args = parser.parse_args()

    rows = load_sources(Path(args.sources))
    if args.only:
        wanted = set(args.only.split(","))
        rows = [r for r in rows if r["name"] in wanted]

    results = []
    for row in rows:
        name, url, parser_key = row["name"], row["url"], row["parser"].strip()
        handler = PARSERS.get(parser_key)
        print(f"\n=== {name} ({parser_key}) ===")
        if handler is None:
            print(f"  unknown parser '{parser_key}', skipping. Known parsers: {list(PARSERS)}")
            results.append((name, "skipped", f"unknown parser '{parser_key}'"))
            continue
        try:
            summary = handler(name, url)
            results.append((name, "ok", f"{summary['event_count']} events, {summary['attribute_count']} attributes"))
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
