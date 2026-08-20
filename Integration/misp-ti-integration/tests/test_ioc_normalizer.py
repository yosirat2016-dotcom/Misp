from models.ioc import IOC, IocType
from normalizers.ioc_normalizer import normalize_ioc

SOURCE = "test-source"


def _ioc(value, ioc_type):
    return IOC(value=value, type=ioc_type, source=SOURCE)


def test_url_scheme_lowercased_host_preserved():
    result = normalize_ioc(_ioc("HTTP://Example.COM/Path", IocType.URL))
    assert result.value == "http://Example.COM/Path"


def test_domain_lowercased_and_trailing_dot_stripped():
    result = normalize_ioc(_ioc(" Example.COM. ", IocType.DOMAIN))
    assert result.value == "example.com"


def test_hash_lowercased_but_not_otherwise_modified():
    result = normalize_ioc(_ioc("44D88612FEA8A8F36DE82E1278ABB02F", IocType.MD5))
    assert result.value == "44d88612fea8a8f36de82e1278abb02f"


def test_ip_whitespace_trimmed_value_untouched():
    result = normalize_ioc(_ioc("  1.2.3.4  ", IocType.IP))
    assert result.value == "1.2.3.4"


def test_normalize_does_not_mutate_original():
    original = _ioc("HTTP://EXAMPLE.COM", IocType.URL)
    normalize_ioc(original)
    assert original.value == "HTTP://EXAMPLE.COM"
