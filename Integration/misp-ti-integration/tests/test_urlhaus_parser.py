from datetime import datetime, timezone

from models.ioc import IocType
from parsers.urlhaus_parser import parse_urlhaus_response

SAMPLE_RAW = {
    "query_status": "ok",
    "urls": [
        {
            "url": "http://45.61.49.78/razor/r4z0r.mips",
            "date_added": "2026-08-18 09:02:05 UTC",
            "threat": "malware_download",
            "tags": ["elf", "mirai"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
        },
        {
            "url": "https://bad-domain-example.net/payload/setup.exe",
            "date_added": "not-a-real-date",
            "threat": "malware_download",
            "tags": [],
        },
        {"threat": "malware_download"},  # missing url - should be skipped
    ],
}


def test_parses_valid_entries():
    iocs = parse_urlhaus_response(SAMPLE_RAW)
    assert len(iocs) == 2
    assert iocs[0].value == "http://45.61.49.78/razor/r4z0r.mips"
    assert iocs[0].type == IocType.URL
    assert iocs[0].source == "urlhaus"
    assert iocs[0].first_seen == datetime(2026, 8, 18, 9, 2, 5, tzinfo=timezone.utc)
    assert iocs[0].tags == ["elf", "mirai"]
    assert iocs[0].reference == "https://urlhaus.abuse.ch/url/223622/"


def test_skips_entry_without_url():
    iocs = parse_urlhaus_response(SAMPLE_RAW)
    assert all(ioc.value for ioc in iocs)


def test_unparseable_date_falls_back_to_none():
    iocs = parse_urlhaus_response(SAMPLE_RAW)
    assert iocs[1].first_seen is None


def test_empty_response():
    assert parse_urlhaus_response({"query_status": "no_results", "urls": []}) == []
