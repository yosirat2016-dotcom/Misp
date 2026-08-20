"""End-to-end run: URLhaus -> parse -> validate -> normalize -> dedup ->
MISP event -> push (dry-run by default).

Usage:
    python main.py                  # dry run, prints a summary, sends nothing
    python main.py --live           # actually pushes to MISP (needs MISP_URL
                                     # and MISP_API_KEY in .env)
    python main.py --limit 20
"""
import argparse
import logging
import os

from dotenv import load_dotenv

from collectors.urlhaus import UrlhausCollector
from deduplication.deduplicator import deduplicate
from misp.client import MispClient
from misp.event_builder import build_event
from normalizers.ioc_normalizer import normalize_ioc
from parsers.urlhaus_parser import parse_urlhaus_response
from validators.ioc_validator import validate_ioc

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def run(limit: int | None, live: bool):
    load_dotenv()

    cti_api_key = os.environ.get("CTI_API_KEY", "")
    collector = UrlhausCollector(api_key=cti_api_key, limit=limit)
    raw = collector.fetch()

    iocs = parse_urlhaus_response(raw)
    logger.info("%d indicators discovered", len(iocs))

    valid_iocs = []
    rejected_count = 0
    for ioc in iocs:
        ok, reason = validate_ioc(ioc)
        if ok:
            valid_iocs.append(ioc)
        else:
            rejected_count += 1
            logger.debug("rejected %s: %s", ioc.value, reason)
    logger.info("%d indicators validated, %d rejected", len(valid_iocs), rejected_count)

    normalized_iocs = [normalize_ioc(ioc) for ioc in valid_iocs]

    deduped_iocs = deduplicate(normalized_iocs)
    logger.info("%d duplicates removed", len(normalized_iocs) - len(deduped_iocs))
    logger.info("%d indicators ready for MISP", len(deduped_iocs))

    if not deduped_iocs:
        logger.info("Nothing to send - exiting")
        return

    event = build_event(deduped_iocs, info="URLhaus recent malicious URLs")

    misp_url = os.environ.get("MISP_URL", "")
    misp_api_key = os.environ.get("MISP_API_KEY", "")
    ssl_verify = os.environ.get("MISP_VERIFY_TLS", "true").lower() != "false"

    if live and (not misp_url or not misp_api_key):
        raise SystemExit("MISP_URL and MISP_API_KEY must be set in .env to use --live")

    if live:
        client = MispClient(url=misp_url, api_key=misp_api_key, ssl_verify=ssl_verify)
        client.test_connection()
        result = client.push_event(event, dry_run=False)
        logger.info("MISP event created: %s", result)
    else:
        client = MispClient(url=misp_url or "https://dry-run-placeholder", api_key=misp_api_key or "dry-run")
        result = client.push_event(event, dry_run=True)
        logger.info("Dry run complete: %s", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Max URLhaus entries to fetch")
    parser.add_argument("--live", action="store_true", help="Actually push to MISP instead of a dry run")
    args = parser.parse_args()
    run(limit=args.limit, live=args.live)


if __name__ == "__main__":
    main()
