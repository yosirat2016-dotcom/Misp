"""NVD CVE API 2.0 -> MISP feed converter.

The generic feed_to_misp.py can't handle this source: NVD nests every
useful field (description, CVSS metrics, references) under a `cve: {...}`
wrapper and inside lists, which the generic flat key/value scanner skips.
This is a dedicated parser for NVD's actual response shape.

API docs: https://nvd.nist.gov/developers/vulnerabilities
No API key required for light use (rate-limited without one).

Usage:
    python scripts/nvd_to_misp.py --days 7
    python scripts/nvd_to_misp.py --pub-start 2026-08-01 --pub-end 2026-08-20
"""
import argparse
import json
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

UUID_NAMESPACE = uuid.UUID("6f6b6e40-8f2e-4f8e-9b7a-2b1a6e8c9d40")
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 30
RESULTS_PER_PAGE = 2000


def fetch_cves(pub_start: str, pub_end: str):
    all_vulns = []
    start_index = 0
    while True:
        params = (
            f"?pubStartDate={pub_start}&pubEndDate={pub_end}"
            f"&resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
        )
        url = API_URL + params
        req = urllib.request.Request(url, headers={"User-Agent": "misp-ti-integration/1.0"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)

        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        print(f"  fetched {start_index}/{total}")
        if start_index >= total or not vulns:
            break
    return all_vulns


def _best_cvss(metrics: dict):
    """Prefer CVSS v3.1, then v3.0, then v2 - matches NVD's own priority."""
    for key, version_label in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0]["cvssData"]
            severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            return cvss_data["baseScore"], severity, version_label
    return None, None, None


def _threat_level_from_score(score):
    if score is None:
        return "4"  # Undefined
    if score >= 9:
        return "1"  # High
    if score >= 7:
        return "2"  # Medium
    return "3"  # Low


def build_misp_event(vuln: dict, org_name: str):
    cve = vuln["cve"]
    cve_id = cve["id"]

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc["value"]
            break

    score, severity, cvss_version = _best_cvss(cve.get("metrics", {}))
    references = [ref["url"] for ref in cve.get("references", []) if ref.get("url")]
    cwes = sorted({
        desc["value"]
        for weakness in cve.get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc.get("lang") == "en" and desc["value"].startswith("CWE-")
    })

    published = cve.get("published", "")
    try:
        pub_dt = datetime.fromisoformat(published)
    except ValueError:
        pub_dt = datetime.now(timezone.utc)
    date_str = pub_dt.strftime("%Y-%m-%d")
    timestamp = str(int(pub_dt.replace(tzinfo=pub_dt.tzinfo or timezone.utc).timestamp()))

    attributes = [
        {
            "type": "vulnerability",
            "category": "External analysis",
            "to_ids": True,
            "value": cve_id,
            "comment": "CVE ID",
        }
    ]
    if description:
        attributes.append({
            "type": "text",
            "category": "External analysis",
            "to_ids": False,
            "value": description,
            "comment": "NVD description",
        })
    if score is not None:
        attributes.append({
            "type": "float",
            "category": "External analysis",
            "to_ids": False,
            "value": str(score),
            "comment": f"CVSS v{cvss_version} base score",
        })
    for cwe in cwes:
        attributes.append({
            "type": "weakness",
            "category": "External analysis",
            "to_ids": False,
            "value": cwe,
            "comment": "CWE classification",
        })
    for ref in references:
        attributes.append({
            "type": "link",
            "category": "External analysis",
            "to_ids": False,
            "value": ref,
            "comment": "NVD reference",
        })

    tags = [{"name": "source:nvd"}]
    if severity:
        tags.append({"name": f"severity:{severity.lower()}"})
    if score is not None:
        tags.append({"name": f'cvss-score:"{score}"'})

    event_uuid = str(uuid.uuid5(UUID_NAMESPACE, cve_id))
    event = {
        "uuid": event_uuid,
        "info": f"{cve_id}: {description[:120]}" if description else cve_id,
        "date": date_str,
        "timestamp": timestamp,
        "publish_timestamp": timestamp,
        "threat_level_id": _threat_level_from_score(score),
        "analysis": "2",
        "distribution": "3",
        "published": True,
        "Orgc": {"name": org_name, "uuid": str(uuid.uuid5(UUID_NAMESPACE, org_name))},
        "Tag": tags,
        "Attribute": attributes,
    }
    return event_uuid, event


def write_feed(vulns, out_dir: Path, org_name: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for vuln in vulns:
        event_uuid, event = build_misp_event(vuln, org_name)
        (out_dir / f"{event_uuid}.json").write_text(
            json.dumps({"Event": event}, indent=2), encoding="utf-8"
        )
        manifest[event_uuid] = {
            "Orgc": event["Orgc"],
            "Tag": event["Tag"],
            "info": event["info"],
            "date": event["date"],
            "analysis": event["analysis"],
            "threat_level_id": event["threat_level_id"],
            "publish_timestamp": event["publish_timestamp"],
        }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return len(manifest)


def convert(out_base: str = "data/misp_feed/nvd-recent", org: str = "NVD", days: int = 7,
            pub_start: str | None = None, pub_end: str | None = None):
    """Fetch recent NVD CVEs and write a MISP Feed. Returns a summary dict.
    Raises ValueError if no CVEs were found in the date range."""
    if not (pub_start and pub_end):
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        pub_start = start.strftime("%Y-%m-%dT00:00:00.000")
        pub_end = end.strftime("%Y-%m-%dT00:00:00.000")

    print(f"Fetching NVD CVEs published {pub_start} .. {pub_end} ...")
    vulns = fetch_cves(pub_start, pub_end)

    if not vulns:
        raise ValueError("No CVEs found in this date range.")

    out_dir = Path(out_base)
    count = write_feed(vulns, out_dir, org)
    total_attrs = sum(len(build_misp_event(v, org)[1]["Attribute"]) for v in vulns)
    print(f"Wrote {count} MISP event(s) ({total_attrs} attributes total) to {out_dir}/")
    return {"slug": "nvd-recent", "out_dir": str(out_dir), "event_count": count, "attribute_count": total_attrs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=7, help="Pull CVEs published in the last N days")
    parser.add_argument("--pub-start", help="Override: explicit start date (YYYY-MM-DD)")
    parser.add_argument("--pub-end", help="Override: explicit end date (YYYY-MM-DD)")
    parser.add_argument("--out", default="data/misp_feed/nvd-recent", help="Output directory")
    parser.add_argument("--org", default="NVD", help="Org name to attribute events to")
    args = parser.parse_args()

    try:
        convert(out_base=args.out, org=args.org, days=args.days, pub_start=args.pub_start, pub_end=args.pub_end)
    except ValueError as exc:
        print(exc)


if __name__ == "__main__":
    main()
