"""Collector for abuse.ch URLhaus - recent malicious URLs feed.

API docs: https://urlhaus-api.abuse.ch/
Requires a free Auth-Key (register at https://auth.abuse.ch/), sent via
the `Auth-Key` HTTP header. Without it the API returns an auth error.
"""
import logging

import requests

from collectors.base import ThreatIntelCollector

logger = logging.getLogger(__name__)

RECENT_URLS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
REQUEST_TIMEOUT_SECONDS = 30


class UrlhausCollector(ThreatIntelCollector):
    def __init__(self, api_key: str, limit: int | None = None):
        if not api_key:
            raise ValueError("URLhaus Auth-Key is required (set CTI_API_KEY in .env)")
        self._api_key = api_key
        self._limit = limit

    def fetch(self) -> dict:
        url = RECENT_URLS_ENDPOINT
        if self._limit:
            url = f"{url}limit/{self._limit}/"

        logger.info("Feed request started: %s", url)
        try:
            response = requests.get(
                url,
                headers={"Auth-Key": self._api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.exceptions.Timeout as exc:
            raise ConnectionError(f"URLhaus request timed out: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise ConnectionError(f"Could not reach URLhaus: {exc}") from exc

        if response.status_code == 401:
            raise PermissionError("URLhaus rejected the Auth-Key (HTTP 401)")
        if response.status_code == 429:
            raise RuntimeError("URLhaus rate limit exceeded (HTTP 429)")
        response.raise_for_status()

        data = response.json()
        query_status = data.get("query_status")
        if query_status != "ok":
            logger.info("Feed response received: query_status=%s", query_status)
            return {"query_status": query_status, "urls": []}

        urls = data.get("urls", [])
        logger.info("Feed response received: %d indicators discovered", len(urls))
        return data


if __name__ == "__main__":
    import os

    from dotenv import load_dotenv

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    load_dotenv()

    api_key = os.environ.get("CTI_API_KEY", "")
    collector = UrlhausCollector(api_key=api_key, limit=10)
    result = collector.fetch()
    print(f"query_status: {result.get('query_status')}")
    for entry in result.get("urls", []):
        print(entry.get("url"), "|", entry.get("threat"), "|", entry.get("tags"))
