"""Generic threat-intel feed -> MISP custom feed converter.

Usage:
    python scripts/feed_to_misp.py <url> [--out DIR] [--org NAME] [--per-item]

Given any feed URL (RSS/XML, JSON, CSV, or plain text), this:
  1. downloads the raw content into data/raw/<slug>.<ext>
  2. auto-detects the format
  3. auto-detects IOC/attribute types found in the content (hashes, IPs,
     domains, URLs, CVEs, emails)
  4. writes a MISP Feed (https://www.misp-project.org/feeds/) into
     data/misp_feed/<slug>/: manifest.json + one <event-uuid>.json per event

The output directory can be served over HTTP and added in MISP via
Sync Actions -> Feeds -> Add Feed (Source format: MISP Feed).
"""
import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import uuid
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

UUID_NAMESPACE = uuid.UUID("6f6b6e40-8f2e-4f8e-9b7a-2b1a6e8c9d40")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
MAX_ATTRIBUTES_PER_EVENT = 500
MIN_ATTRIBUTES_FOR_DISCOVERY = 5

# Curated allowlist of common TLDs used to gate the domain pattern below.
# Not exhaustive (no full IANA TLD list) - a pragmatic tradeoff to keep
# free-text domain scanning from matching prose like "String.prototype".
COMMON_TLDS = {
    "com", "net", "org", "io", "gov", "edu", "mil", "int", "info", "biz",
    "co", "us", "uk", "ru", "cn", "de", "fr", "jp", "in", "ai", "dev",
    "app", "xyz", "online", "tech", "cloud", "me", "tv", "cc", "nl", "br",
    "au", "ca", "eu", "top", "site", "id", "kr", "it", "es", "pl",
}

# Single source of truth for IOC patterns, most specific/longest first so a
# shorter pattern never gets a chance to shadow a longer one (e.g. sha256
# before md5). Both detect_type (exact match) and scan_iocs (free-text
# search) are derived from this one list.
_TYPE_PATTERN_BODIES = [
    ("vulnerability", r"CVE-\d{4}-\d{4,7}"),
    ("sha512", r"[a-fA-F0-9]{128}"),
    ("sha256", r"[a-fA-F0-9]{64}"),
    ("sha1", r"[a-fA-F0-9]{40}"),
    ("md5", r"[a-fA-F0-9]{32}"),
    ("ip-dst", r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"),
    ("email-src", r"[^@\s]+@[^@\s]+\.[^@\s]+"),
    ("url", r"https?://\S+"),
    ("domain", r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
]

TYPE_PATTERNS = [
    (attr_type, re.compile(rf"^{body}$", re.I)) for attr_type, body in _TYPE_PATTERN_BODIES
]
SCAN_PATTERNS = [
    (attr_type, re.compile(rf"\b{body}\b", re.I)) for attr_type, body in _TYPE_PATTERN_BODIES
]

IPV6_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F:]{3,}\b")


def _is_domain_ok(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1].lower()
    return tld in COMMON_TLDS


def _is_ipv6(value: str) -> bool:
    if ":" not in value:
        return False
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def detect_type(value: str):
    value = value.strip()
    if not value:
        return None
    if _is_ipv6(value):
        return "ip-dst"
    for attr_type, pattern in TYPE_PATTERNS:
        if pattern.match(value):
            if attr_type == "domain" and not _is_domain_ok(value):
                continue
            return attr_type
    return None


def scan_iocs(text: str):
    found = []
    for attr_type, pattern in SCAN_PATTERNS:
        for match in pattern.findall(text):
            if attr_type == "domain" and not _is_domain_ok(match):
                continue
            found.append((attr_type, match))
    for candidate in IPV6_CANDIDATE_RE.findall(text):
        if _is_ipv6(candidate):
            found.append(("ip-dst", candidate))
    return found


def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def slugify(url: str) -> str:
    netloc = urlparse(url).netloc or "feed"
    return re.sub(r"[^a-z0-9]+", "-", netloc.lower()).strip("-")


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content_type = resp.headers.get("Content-Type", "")
        raw = resp.read()
    return raw, content_type


def sniff_format(raw: bytes, content_type: str, url: str) -> str:
    head = raw.lstrip()[:300].decode("utf-8", errors="ignore").lower()
    if "xml" in content_type or head.startswith("<?xml") or "<rss" in head:
        return "rss"
    if "json" in content_type or head.startswith("{") or head.startswith("["):
        return "json"
    if "csv" in content_type or url.lower().endswith(".csv"):
        return "csv"
    if url.lower().endswith((".json",)):
        return "json"
    # Heuristic: scan further into the file (past any comment banner) for
    # several comma-separated fields on non-comment lines -> csv
    full_text = raw.decode("utf-8", errors="ignore")
    sample_lines = [
        line for line in full_text.splitlines() if line and not line.startswith("#")
    ][:5]
    if sample_lines and all(line.count(",") >= 2 for line in sample_lines):
        return "csv"
    return "text"


def _looks_like_html(raw: bytes) -> bool:
    head = raw.lstrip()[:300].decode("utf-8", errors="ignore").lower()
    return head.startswith("<!doctype") or "<html" in head


_LINK_ALT_RE = re.compile(r"<link\b[^>]*rel=[\"']alternate[\"'][^>]*>", re.I)
_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def _looks_like_feed_href(href: str) -> bool:
    path = href.split("?")[0].split("#")[0].lower()
    if path.endswith((".json", ".csv", ".xml", ".rss")):
        return True
    return bool(re.search(r"/(rss|feed|atom)(/|$)", path))


def discover_feed_links(raw: bytes, base_url: str, limit: int = 8):
    """Scan an HTML entry page for RSS/Atom autodiscovery <link> tags and
    plain <a href> links that look like a real feed/download (e.g. a
    government site's "Download JSON/CSV" link), resolved to absolute URLs.
    """
    html = raw.decode("utf-8", errors="ignore")
    hrefs = []
    for tag in _LINK_ALT_RE.findall(html):
        match = _HREF_RE.search(tag)
        if match:
            hrefs.append(match.group(1))
    for href in _HREF_RE.findall(html):
        if _looks_like_feed_href(href):
            hrefs.append(href)

    seen = set()
    resolved = []
    for href in hrefs:
        abs_url = urljoin(base_url, href)
        if abs_url in seen or abs_url == base_url:
            continue
        seen.add(abs_url)
        resolved.append(abs_url)
        if len(resolved) >= limit:
            break
    return resolved


# ---------------------------------------------------------------------------
# Per-format parsers. Each returns a list of "events":
#   {"info": str, "date": datetime, "tags": [str], "attributes": [(type, value, comment)]}
# ---------------------------------------------------------------------------

def _append_with_scan(attributes, value, comment):
    """Append a (type, value, comment) attribute. If the value doesn't match
    a concrete IOC type on its own, keep it as text but also mine any IOCs
    embedded inside it (e.g. a "notes" cell containing a URL or a hash)."""
    attr_type = detect_type(value)
    if attr_type:
        attributes.append((attr_type, value, comment))
        return
    attributes.append(("text", value, comment))
    for found_type, found_value in scan_iocs(value):
        attributes.append((found_type, found_value, f"extracted from {comment}"))

def parse_rss(raw: bytes):
    root = ET.fromstring(raw)
    events = []
    for item in root.findall("./channel/item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        guid = item.findtext("guid", link).strip() or link or title
        pub_date = item.findtext("pubDate", "").strip()
        description_raw = item.findtext("description", "") or ""
        clean_description = strip_html(description_raw)

        try:
            dt = parsedate_to_datetime(pub_date)
        except (TypeError, ValueError):
            dt = datetime.now(timezone.utc)

        attributes = []
        if link:
            attributes.append(("link", link, "item link"))
        if clean_description:
            attributes.append(("text", clean_description, "item description"))
        for attr_type, value in scan_iocs(title + " " + clean_description):
            attributes.append((attr_type, value, "extracted from item content"))

        events.append(
            {
                "info": title or guid,
                "date": dt,
                "guid": guid,
                "tags": [],
                "attributes": attributes,
            }
        )
    return events


def parse_json(raw: bytes):
    data = json.loads(raw)
    if isinstance(data, dict):
        matched = None
        for key in ("data", "results", "items", "objects", "events"):
            if isinstance(data.get(key), list):
                matched = data[key]
                break
        if matched is None:
            # Some APIs wrap their list under a domain-specific key (e.g.
            # CISA's KEV feed uses "vulnerabilities"). If there's exactly
            # one top-level list-of-dicts, it's an unambiguous pick; with
            # zero or multiple candidates, fall back to treating the whole
            # dict as a single item rather than guessing.
            list_candidates = [
                v for v in data.values()
                if isinstance(v, list) and v and all(isinstance(i, dict) for i in v)
            ]
            if len(list_candidates) == 1:
                matched = list_candidates[0]
        if matched is not None:
            data = matched
    items = data if isinstance(data, list) else [data]

    events = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            item = {"value": item}
        attributes = []
        for key, value in item.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            _append_with_scan(attributes, str(value), key)
        info = item.get("title") or item.get("name") or item.get("id")
        if not info:
            cve = next((v for t, v, _ in attributes if t == "vulnerability"), None)
            info = cve or f"item {idx}"
        info = str(info)
        events.append(
            {
                "info": info,
                "date": datetime.now(timezone.utc),
                "guid": json.dumps(item, sort_keys=True, default=str),
                "tags": [],
                "attributes": attributes,
            }
        )
    return events


def parse_csv(raw: bytes, feed_label: str):
    text = raw.decode("utf-8", errors="ignore")
    all_lines = text.splitlines()
    comment_lines = [line for line in all_lines if line.startswith("#")]
    data_lines = [line for line in all_lines if not line.startswith("#")]

    reader = csv.reader(io.StringIO("\n".join(data_lines)))
    rows = [row for row in reader if row and any(cell.strip() for cell in row)]
    if not rows:
        return []

    # Some feeds (e.g. URLhaus) put the real header in a "# col1,col2,..."
    # comment line rather than as the first data row. Prefer that if present
    # and none of its tokens look like an actual IOC value.
    header = None
    for candidate in reversed(comment_lines):
        candidate = candidate.lstrip("#").strip()
        tokens = [t.strip().lower() for t in candidate.split(",")]
        if len(tokens) == len(rows[0]) and not any(detect_type(t) for t in tokens):
            header = tokens
            break

    if header is None:
        looks_like_header = any(not detect_type(cell) for cell in rows[0])
        if looks_like_header:
            header = [h.strip().lower() for h in rows[0]]
            rows = rows[1:]
        else:
            header = [f"col{i}" for i in range(len(rows[0]))]

    data_rows = rows

    attributes = []
    for row in data_rows:
        for col_name, cell in zip(header, row):
            cell = cell.strip()
            if not cell:
                continue
            _append_with_scan(attributes, cell, col_name)

    return _chunk_into_events(attributes, feed_label)


def parse_text(raw: bytes, feed_label: str):
    text = raw.decode("utf-8", errors="ignore")
    attributes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _append_with_scan(attributes, line, "line entry")
    return _chunk_into_events(attributes, feed_label)


def _chunk_into_events(attributes, feed_label):
    if not attributes:
        return []
    events = []
    for i in range(0, len(attributes), MAX_ATTRIBUTES_PER_EVENT):
        chunk = attributes[i : i + MAX_ATTRIBUTES_PER_EVENT]
        part = i // MAX_ATTRIBUTES_PER_EVENT + 1
        events.append(
            {
                "info": f"{feed_label} import (part {part})",
                "date": datetime.now(timezone.utc),
                "guid": f"{feed_label}-part-{part}-{len(chunk)}",
                "tags": [],
                "attributes": chunk,
            }
        )
    return events


# ---------------------------------------------------------------------------
# MISP feed writer
# ---------------------------------------------------------------------------

def parse_by_format(fmt: str, raw: bytes, slug: str):
    if fmt == "rss":
        return parse_rss(raw)
    if fmt == "json":
        return parse_json(raw)
    if fmt == "csv":
        return parse_csv(raw, slug)
    return parse_text(raw, slug)


CATEGORY_BY_TYPE = {
    "link": "External analysis",
    "text": "External analysis",
    "vulnerability": "External analysis",
    "ip-dst": "Network activity",
    "domain": "Network activity",
    "url": "Network activity",
    "email-src": "Network activity",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "sha512": "Payload delivery",
}


def build_misp_event(raw_event, org_name, source_tag):
    event_uuid = str(uuid.uuid5(UUID_NAMESPACE, raw_event["guid"]))
    date_str = raw_event["date"].strftime("%Y-%m-%d")
    timestamp = str(int(raw_event["date"].timestamp()))

    misp_attributes = [
        {
            "type": attr_type,
            "category": CATEGORY_BY_TYPE.get(attr_type, "External analysis"),
            "to_ids": attr_type not in ("link", "text"),
            "value": value,
            "comment": comment,
        }
        for attr_type, value, comment in raw_event["attributes"]
    ]

    tags = [{"name": source_tag}] + [{"name": t} for t in raw_event["tags"]]

    event = {
        "uuid": event_uuid,
        "info": raw_event["info"],
        "date": date_str,
        "timestamp": timestamp,
        "publish_timestamp": timestamp,
        "threat_level_id": "4",  # Undefined; unknown without source-specific scoring
        "analysis": "2",
        "distribution": "3",
        "published": True,
        "Orgc": {"name": org_name, "uuid": str(uuid.uuid5(UUID_NAMESPACE, org_name))},
        "Tag": tags,
        "Attribute": misp_attributes,
    }
    return event_uuid, event


def write_feed(events, out_dir: Path, org_name: str, source_tag: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for raw_event in events:
        event_uuid, event = build_misp_event(raw_event, org_name, source_tag)
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
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return len(manifest)


def convert_url_to_feed(url: str, out_base: str = "data/misp_feed", org: str | None = None, fmt: str = "auto"):
    """Fetch `url`, auto-detect/parse it, and write a MISP Feed under
    `out_base`/<slug>/. Returns {"slug", "out_dir", "event_count", "attribute_count"}.
    Raises ValueError if no events/attributes could be extracted."""
    slug = slugify(url)
    org_name = org or urlparse(url).netloc or "unknown-source"

    print(f"Fetching {url} ...")
    raw, content_type = fetch(url)

    detected_fmt = fmt if fmt != "auto" else sniff_format(raw, content_type, url)
    print(f"Detected format: {detected_fmt} (Content-Type: {content_type or 'n/a'})")

    if fmt == "auto" and detected_fmt == "text" and _looks_like_html(raw):
        print("Page looks like an HTML entry point, not a feed - looking for a linked feed ...")
        discovered = None
        for candidate in discover_feed_links(raw, url):
            try:
                c_raw, c_content_type = fetch(candidate)
            except Exception as exc:
                print(f"  skip {candidate}: {exc}")
                continue
            c_fmt = sniff_format(c_raw, c_content_type, candidate)
            if c_fmt == "text":
                print(f"  skip {candidate}: also resolves to plain text/HTML")
                continue
            c_events = parse_by_format(c_fmt, c_raw, slugify(candidate))
            c_attr_count = sum(len(e["attributes"]) for e in c_events)
            if c_attr_count < MIN_ATTRIBUTES_FOR_DISCOVERY:
                print(f"  skip {candidate}: sniffed as {c_fmt} but only {c_attr_count} attribute(s) - too small to be the real feed")
                continue
            print(f"  found {c_fmt} feed at {candidate} ({c_attr_count} attributes)")
            discovered = (c_raw, c_content_type, c_fmt)
            break
        if discovered:
            raw, content_type, detected_fmt = discovered
        else:
            print(
                "No structured feed auto-discovered under this URL - the page may be "
                "JavaScript-rendered. Falling back to raw page content; results may be noisy."
            )

    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    ext = {"rss": "xml", "json": "json", "csv": "csv", "text": "txt"}[detected_fmt]
    raw_path = raw_dir / f"{slug}.{ext}"
    raw_path.write_bytes(raw)
    print(f"Saved raw feed to {raw_path}")

    events = parse_by_format(detected_fmt, raw, slug)

    if not events:
        raise ValueError(f"No events/attributes could be extracted from {url}")

    out_dir = Path(out_base) / slug
    source_tag = f"source:{slug}"
    count = write_feed(events, out_dir, org_name, source_tag)
    total_attrs = sum(len(e["attributes"]) for e in events)
    print(f"Wrote {count} MISP event(s) ({total_attrs} attributes total) to {out_dir}/")
    return {"slug": slug, "out_dir": str(out_dir), "event_count": count, "attribute_count": total_attrs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Feed URL (RSS/XML, JSON, CSV, or plain text)")
    parser.add_argument("--out", default="data/misp_feed", help="Output base directory")
    parser.add_argument("--org", default=None, help="Org name to attribute events to")
    parser.add_argument(
        "--format",
        choices=["auto", "rss", "json", "csv", "text"],
        default="auto",
        help="Force a specific parser instead of auto-detecting",
    )
    args = parser.parse_args()

    try:
        convert_url_to_feed(args.url, out_base=args.out, org=args.org, fmt=args.format)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
