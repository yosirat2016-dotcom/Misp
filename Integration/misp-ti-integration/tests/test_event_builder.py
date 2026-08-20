from models.ioc import IOC, IocType
from misp.event_builder import build_event


def test_builds_event_with_correct_attribute_mapping():
    iocs = [
        IOC(value="1.2.3.4", type=IocType.IP, source="urlhaus", description="C2 IP"),
        IOC(value="44d88612fea8a8f36de82e1278abb02f", type=IocType.MD5, source="urlhaus"),
    ]
    event = build_event(iocs, info="test event")["Event"]

    assert event["info"] == "test event"
    assert event["published"] is False
    assert len(event["Attribute"]) == 2

    ip_attr = event["Attribute"][0]
    assert ip_attr["type"] == "ip-dst"
    assert ip_attr["category"] == "Network activity"
    assert ip_attr["to_ids"] is True
    assert ip_attr["comment"] == "C2 IP"

    hash_attr = event["Attribute"][1]
    assert hash_attr["type"] == "md5"
    assert hash_attr["category"] == "Payload delivery"
    assert hash_attr["comment"] == "source:urlhaus"


def test_tags_include_source_and_ioc_tags():
    iocs = [IOC(value="a.com", type=IocType.DOMAIN, source="urlhaus", tags=["malware:qakbot"])]
    event = build_event(iocs, info="test")["Event"]
    tag_names = {t["name"] for t in event["Tag"]}
    assert "source:urlhaus" in tag_names
    assert "malware:qakbot" in tag_names


def test_empty_iocs_produces_empty_attributes():
    event = build_event([], info="empty")["Event"]
    assert event["Attribute"] == []
