"""Drops repeat IOCs. Expects already-normalized IOCs (see
normalizers/ioc_normalizer.py) so equivalent values collapse to the same
key. Dedup key is (type, normalized value) - source/context can be folded
in later if we need to keep the same IOC distinct per-source."""
from models.ioc import IOC


def deduplicate(iocs: list[IOC]) -> list[IOC]:
    """First occurrence of each (type, value) wins; later duplicates are dropped."""
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc.type, ioc.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    return unique
