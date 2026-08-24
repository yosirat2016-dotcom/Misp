"""abuse.ch ThreatFox API -> MISP feed converter.

The /browse/ page (https://threatfox.abuse.ch/browse/) looks like a real
feed in a browser, but its table is populated client-side (DataTables) -
the raw HTML has no data, which is why the generic converter previously
captured literal "<!doctype html>" as junk. The real data comes from
ThreatFox's own API instead.

API docs: https://threatfox.abuse.ch/api/
Requires a free Auth-Key (same one as URLhaus - register at
https://auth.abuse.ch/), sent via the `Auth-Key` HTTP header.

Usage:
    python scripts/threatfox_to_misp.py --days 3
"""
import argparse
import json
import os
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

UUID_NAMESPACE = uuid.UUID("6f6b6e40-8f2e-4f8e-9b7a-2b1a6e8c9d40")
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
REQUEST_TIMEOUT_SECONDS = 30

# ThreatFox ioc_type -> MISP attribute type. "ip:port" maps to MISP's
# composite ip-dst|port type (value becomes "ip|port" instead of "ip:port").
ATTRIBUTE_TYPE_BY_IOC_TYPE = {
    "domain": "domain",
    "url": "url",
    "ip:port": "ip-dst|port",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}


def fetch_iocs(api_key: str, days: int) -> list[dict]:
    body = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={"Auth-Key": api_key, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        data = json.load(resp)

    if data.get("query_status") != "ok":
        return []
    return data.get("data", [])


def build_misp_event(ioc: dict, org_name: str):
    ioc_type = ioc.get("ioc_type", "")
    attr_type = ATTRIBUTE_TYPE_BY_IOC_TYPE.get(ioc_type, "text")
    value = ioc["ioc"]
    if attr_type == "ip-dst|port":
        value = value.replace(":", "|")

    first_seen = ioc.get("first_seen", "")
    try:
        pub_dt = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        pub_dt = datetime.now(timezone.utc)
    date_str = pub_dt.strftime("%Y-%m-%d")
    timestamp = str(int(pub_dt.timestamp()))

    attributes = [
        {
            "type": attr_type,
            "category": "Network activity" if attr_type != "text" else "External analysis",
            "to_ids": attr_type != "text",
            "value": value,
            "comment": ioc.get("threat_type_desc", ioc.get("threat_type", "")),
        }
    ]
    if ioc.get("reference"):
        attributes.append({
            "type": "link", "category": "External analysis",
            "to_ids": False, "value": ioc["reference"], "comment": "ThreatFox reference",
        })

    malware = ioc.get("malware_printable") or ioc.get("malware")
    tags = [{"name": "source:threatfox-abuse-ch"}]
    if malware:
        tags.append({"name": f"malware:{malware.lower()}"})
    for tag in ioc.get("tags") or []:
        tags.append({"name": f"tag:{tag}"})

    info = f"ThreatFox: {malware or ioc.get('threat_type', 'IOC')} - {value}"
    event_uuid = str(uuid.uuid5(UUID_NAMESPACE, f"threatfox-{ioc['id']}"))
    event = {
        "uuid": event_uuid,
        "info": info,
        "date": date_str,
        "timestamp": timestamp,
        "publish_timestamp": timestamp,
        "threat_level_id": "4",
        "analysis": "2",
        "distribution": "3",
        "published": True,
        "Orgc": {"name": org_name, "uuid": str(uuid.uuid5(UUID_NAMESPACE, org_name))},
        "Tag": tags,
        "Attribute": attributes,
    }
    return event_uuid, event


def write_feed(iocs, out_dir: Path, org_name: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for ioc in iocs:
        event_uuid, event = build_misp_event(ioc, org_name)
        (out_dir / f"{event_uuid}.json").write_text(
            json.dumps({"Event": event}, indent=2), encoding="utf-8"
        )
        manifest[event_uuid] = {
            "Orgc": event["Orgc"], "Tag": event["Tag"], "info": event["info"],
            "date": event["date"], "analysis": event["analysis"],
            "threat_level_id": event["threat_level_id"],
            "publish_timestamp": event["publish_timestamp"],
        }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return len(manifest)


def convert(out_base: str = "data/misp_feed/threatfox-abuse-ch", org: str = "Abuse.ch - ThreatFox",
            days: int = 3, api_key: str | None = None):
    """Fetch recent ThreatFox IOCs and write a MISP Feed. Returns a summary dict.
    Raises ValueError if no API key is available or no IOCs were found."""
    api_key = api_key or os.environ.get("ABUSECH_API_KEY", "")
    if not api_key:
        raise ValueError("ThreatFox Auth-Key required (set ABUSECH_API_KEY in .env)")

    print(f"Fetching ThreatFox IOCs from the last {days} day(s) ...")
    iocs = fetch_iocs(api_key, days)

    if not iocs:
        raise ValueError("No IOCs returned by ThreatFox.")

    out_dir = Path(out_base)
    count = write_feed(iocs, out_dir, org)
    total_attrs = sum(len(build_misp_event(i, org)[1]["Attribute"]) for i in iocs)
    print(f"Wrote {count} MISP event(s) ({total_attrs} attributes total) to {out_dir}/")
    return {"slug": "threatfox-abuse-ch", "out_dir": str(out_dir), "event_count": count, "attribute_count": total_attrs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=3, help="IOCs from the last N days (max 7)")
    parser.add_argument("--out", default="data/misp_feed/threatfox-abuse-ch", help="Output directory")
    parser.add_argument("--org", default="Abuse.ch - ThreatFox", help="Org name to attribute events to")
    args = parser.parse_args()

    try:
        convert(out_base=args.out, org=args.org, days=args.days)
    except ValueError as exc:
        print(exc)


if __name__ == "__main__":
    main()
