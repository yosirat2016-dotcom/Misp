from models.ioc import IOC, IocType
from deduplication.deduplicator import deduplicate


def _ioc(value, ioc_type=IocType.URL, source="src"):
    return IOC(value=value, type=ioc_type, source=source)


def test_removes_exact_duplicates():
    iocs = [_ioc("http://a.com"), _ioc("http://a.com"), _ioc("http://b.com")]
    result = deduplicate(iocs)
    assert [i.value for i in result] == ["http://a.com", "http://b.com"]


def test_first_occurrence_wins():
    first = _ioc("http://a.com", source="source-1")
    second = _ioc("http://a.com", source="source-2")
    result = deduplicate([first, second])
    assert len(result) == 1
    assert result[0].source == "source-1"


def test_same_value_different_type_not_deduped():
    iocs = [_ioc("1.2.3.4", IocType.IP), _ioc("1.2.3.4", IocType.DOMAIN)]
    result = deduplicate(iocs)
    assert len(result) == 2


def test_empty_list():
    assert deduplicate([]) == []
