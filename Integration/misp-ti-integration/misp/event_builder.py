"""Builds a MISP Event dict from a list of internal IOCs. Mapping documented
inline - see spec section 16 (internal IOC type -> MISP attribute type)."""
import uuid
from datetime import datetime, timezone

from models.ioc import IOC, IocType

ATTRIBUTE_TYPE_BY_IOC_TYPE = {
    IocType.IP: "ip-dst",
    IocType.DOMAIN: "domain",
    IocType.URL: "url",
    IocType.MD5: "md5",
    IocType.SHA1: "sha1",
    IocType.SHA256: "sha256",
    IocType.EMAIL: "email-src",
}

CATEGORY_BY_IOC_TYPE = {
    IocType.IP: "Network activity",
    IocType.DOMAIN: "Network activity",
    IocType.URL: "Network activity",
    IocType.EMAIL: "Network activity",
    IocType.MD5: "Payload delivery",
    IocType.SHA1: "Payload delivery",
    IocType.SHA256: "Payload delivery",
}


def ioc_to_attribute(ioc: IOC) -> dict:
    return {
        "type": ATTRIBUTE_TYPE_BY_IOC_TYPE[ioc.type],
        "category": CATEGORY_BY_IOC_TYPE[ioc.type],
        "to_ids": True,
        "value": ioc.value,
        "comment": ioc.description or f"source:{ioc.source}",
    }


def build_event(iocs: list[IOC], info: str, org_name: str = "MISP-TI-Integration") -> dict:
    """Returns a {"Event": {...}} dict ready for PyMISP's add_event(), or for
    inspection in dry-run mode. Does not deduplicate or validate - callers
    are expected to have already run the ioc through that part of the
    pipeline (see main.py for the full order)."""
    now = datetime.now(timezone.utc)
    sources = sorted({ioc.source for ioc in iocs})
    all_tags = sorted({tag for ioc in iocs for tag in ioc.tags} | {f"source:{s}" for s in sources})

    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": info,
            "date": now.strftime("%Y-%m-%d"),
            "threat_level_id": "4",  # Undefined - no source-specific scoring at this stage
            "analysis": "0",  # Initial
            "distribution": "3",  # Your organisation only, until reviewed
            "published": False,  # left for a human to publish after review
            "Orgc": {"name": org_name},
            "Tag": [{"name": tag} for tag in all_tags],
            "Attribute": [ioc_to_attribute(ioc) for ioc in iocs],
        }
    }
