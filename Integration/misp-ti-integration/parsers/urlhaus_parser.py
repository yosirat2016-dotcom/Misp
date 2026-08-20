"""Converts raw URLhaus API responses into the internal IOC model."""
from datetime import datetime, timezone

from models.ioc import IOC, IocType


def parse_urlhaus_response(raw: dict) -> list[IOC]:
    """raw is UrlhausCollector.fetch()'s return value: {"query_status", "urls": [...]}."""
    iocs = []
    for entry in raw.get("urls", []):
        url = entry.get("url")
        if not url:
            continue

        try:
            first_seen = datetime.strptime(entry["date_added"], "%Y-%m-%d %H:%M:%S UTC").replace(
                tzinfo=timezone.utc
            )
        except (KeyError, ValueError):
            first_seen = None

        iocs.append(
            IOC(
                value=url,
                type=IocType.URL,
                source="urlhaus",
                first_seen=first_seen,
                description=entry.get("threat", ""),
                tags=list(entry.get("tags") or []),
                reference=entry.get("urlhaus_reference"),
            )
        )
    return iocs
