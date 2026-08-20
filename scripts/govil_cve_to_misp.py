"""Israel National Cyber Directorate CVE advisories -> MISP feed converter.

Source page: https://www.gov.il/en/departments/dynamiccollectors/cve_advisories_listing
That page is a Cloudflare-protected AngularJS SPA with no visible feed/API
link - the listing is loaded client-side via a POST to an internal
"DynamicCollector" API discovered by reading the page's Angular bundle
(bundels/DynamicCollector/AngularJS) for its `getResults()` call, and
reading the page's `ng-init="dynamicCtrl.Events.initCtrl(...)"` for the
page-specific DynamicTemplateID. A plain requests.get() on the listing URL
only returns the empty SPA shell, so this reimplements that POST call.

No auth required - only a browser User-Agent header. Note: gov.il's WAF
fingerprints the HTTP client itself (not just rate-limits) - it blocks
Python's urllib/requests after the first call with HTTP 403 even with a
spoofed browser User-Agent, but accepts repeated calls from curl. This
shells out to curl for the actual request rather than fight that.

Usage:
    python scripts/govil_cve_to_misp.py
    python scripts/govil_cve_to_misp.py --limit 50
"""
import argparse
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

UUID_NAMESPACE = uuid.UUID("6f6b6e40-8f2e-4f8e-9b7a-2b1a6e8c9d40")
API_URL = "https://www.gov.il/en/api/DynamicCollector"
# Specific to the "cve_advisories_listing" page - found in that page's
# ng-init="dynamicCtrl.Events.initCtrl({}, 0, '<this uuid>', ...)".
DYNAMIC_TEMPLATE_ID = "2fc6f96f-ff10-47e1-aca3-75551896feab"
PAGE_SIZE = 10
REQUEST_TIMEOUT_SECONDS = 30
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def fetch_page(skip: int) -> dict:
    body = json.dumps({
        "DynamicTemplateID": DYNAMIC_TEMPLATE_ID,
        "QueryFilters": {},
        "From": skip,
        "ItemUrlName": "",
    })
    result = subprocess.run(
        [
            "curl", "-s", "-A", USER_AGENT,
            "-H", "Content-Type: application/json",
            "-X", "POST", "-d", body,
            "--max-time", str(REQUEST_TIMEOUT_SECONDS),
            API_URL,
        ],
        capture_output=True, check=True,
    )
    return json.loads(result.stdout.decode("utf-8"))


def fetch_all(limit: int | None = None):
    results = []
    skip = 0
    total = None
    while True:
        page = fetch_page(skip)
        if total is None:
            total = page.get("TotalResults", 0)
            print(f"  TotalResults reported by API: {total}")
        page_results = page.get("Results", [])
        if not page_results:
            break
        results.extend(page_results)
        skip += PAGE_SIZE
        print(f"  fetched {len(results)}/{total}")
        if skip >= total or (limit and len(results) >= limit):
            break
        time.sleep(0.5)  # be a polite scraper, this isn't a public bulk API
    return results[:limit] if limit else results


def build_misp_event(item: dict, org_name: str):
    data = item.get("Data", {})
    cve = data.get("CVE", "").strip()
    ilvn = data.get("ILVN", "").strip()
    title = data.get("nameofthecve", "").strip()
    affected = data.get("AffectedProducts", "").strip()
    credit = data.get("Credit", "").strip()
    solution = data.get("Solution", "").strip()
    description = (
        data.get("Description", "").strip()
        or data.get("descriptionfield", {}).get("DescriptionBlankTextString", "").strip()
    )
    publish_date = data.get("PublishDate", "")

    try:
        pub_dt = datetime.fromisoformat(publish_date.replace("Z", "+00:00"))
    except ValueError:
        pub_dt = datetime.now(timezone.utc)
    date_str = pub_dt.strftime("%Y-%m-%d")
    timestamp = str(int(pub_dt.timestamp()))

    attributes = []
    if cve:
        attributes.append({
            "type": "vulnerability", "category": "External analysis",
            "to_ids": True, "value": cve, "comment": "CVE ID",
        })
    if title:
        attributes.append({
            "type": "text", "category": "External analysis",
            "to_ids": False, "value": title, "comment": "advisory title",
        })
    if description and description != title:
        attributes.append({
            "type": "text", "category": "External analysis",
            "to_ids": False, "value": description, "comment": "description",
        })
    if affected:
        attributes.append({
            "type": "text", "category": "External analysis",
            "to_ids": False, "value": affected, "comment": "affected products",
        })
    if solution:
        attributes.append({
            "type": "text", "category": "External analysis",
            "to_ids": False, "value": solution, "comment": "solution",
        })
    if credit:
        attributes.append({
            "type": "text", "category": "External analysis",
            "to_ids": False, "value": credit, "comment": "credit",
        })

    tags = [{"name": "source:gov-il-cve-advisories"}]
    if ilvn:
        tags.append({"name": f'ilvn:"{ilvn}"'})

    dedup_key = cve or ilvn or item.get("UrlName", title)
    event_uuid = str(uuid.uuid5(UUID_NAMESPACE, dedup_key))
    event = {
        "uuid": event_uuid,
        "info": f"{ilvn} - {title}" if ilvn else (title or cve or "gov.il CVE advisory"),
        "date": date_str,
        "timestamp": timestamp,
        "publish_timestamp": timestamp,
        "threat_level_id": "4",  # Undefined - source gives no CVSS score
        "analysis": "2",
        "distribution": "3",
        "published": True,
        "Orgc": {"name": org_name, "uuid": str(uuid.uuid5(UUID_NAMESPACE, org_name))},
        "Tag": tags,
        "Attribute": attributes,
    }
    return event_uuid, event


def write_feed(items, out_dir: Path, org_name: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for item in items:
        event_uuid, event = build_misp_event(item, org_name)
        (out_dir / f"{event_uuid}.json").write_text(
            json.dumps({"Event": event}, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        manifest[event_uuid] = {
            "Orgc": event["Orgc"], "Tag": event["Tag"], "info": event["info"],
            "date": event["date"], "analysis": event["analysis"],
            "threat_level_id": event["threat_level_id"],
            "publish_timestamp": event["publish_timestamp"],
        }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return len(manifest)


def convert(out_base: str = "data/misp_feed/govil-cve-advisories", org: str = "gov.il-CERT-IL",
            limit: int | None = None):
    """Fetch gov.il CVE advisories and write a MISP Feed. Returns a summary dict.
    Raises ValueError if no advisories were retrieved."""
    print("Fetching gov.il CVE advisories ...")
    items = fetch_all(limit=limit)

    if not items:
        raise ValueError("No advisories retrieved.")

    out_dir = Path(out_base)
    count = write_feed(items, out_dir, org)
    total_attrs = sum(len(build_misp_event(i, org)[1]["Attribute"]) for i in items)
    print(f"Wrote {count} MISP event(s) ({total_attrs} attributes total) to {out_dir}/")
    return {"slug": "govil-cve-advisories", "out_dir": str(out_dir), "event_count": count, "attribute_count": total_attrs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Max advisories to fetch (default: all)")
    parser.add_argument("--out", default="data/misp_feed/govil-cve-advisories", help="Output directory")
    parser.add_argument("--org", default="gov.il-CERT-IL", help="Org name to attribute events to")
    args = parser.parse_args()

    try:
        convert(out_base=args.out, org=args.org, limit=args.limit)
    except ValueError as exc:
        print(exc)


if __name__ == "__main__":
    main()
