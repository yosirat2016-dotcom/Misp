from models.ioc import IOC, IocType
from validators.ioc_validator import validate_ioc

SOURCE = "test-source"


def _ioc(value, ioc_type):
    return IOC(value=value, type=ioc_type, source=SOURCE)


def test_valid_ipv4():
    ok, reason = validate_ioc(_ioc("8.8.8.8", IocType.IP))
    assert ok and reason is None


def test_invalid_ip_rejected():
    ok, reason = validate_ioc(_ioc("999.999.1.1", IocType.IP))
    assert not ok and "malformed IP" in reason


def test_private_ip_kept_by_default():
    ok, _ = validate_ioc(_ioc("192.168.1.1", IocType.IP))
    assert ok


def test_private_ip_rejected_when_configured():
    ok, reason = validate_ioc(_ioc("192.168.1.1", IocType.IP), reject_private_ips=True)
    assert not ok and "private" in reason


def test_valid_domain():
    ok, _ = validate_ioc(_ioc("example.com", IocType.DOMAIN))
    assert ok


def test_invalid_domain_rejected():
    ok, reason = validate_ioc(_ioc("not a domain", IocType.DOMAIN))
    assert not ok and "malformed domain" in reason


def test_valid_url():
    ok, _ = validate_ioc(_ioc("https://example.com/payload.exe", IocType.URL))
    assert ok


def test_url_without_scheme_rejected():
    ok, reason = validate_ioc(_ioc("example.com/payload.exe", IocType.URL))
    assert not ok and "malformed URL" in reason


def test_valid_md5():
    ok, _ = validate_ioc(_ioc("44d88612fea8a8f36de82e1278abb02f", IocType.MD5))
    assert ok


def test_md5_wrong_length_rejected():
    ok, reason = validate_ioc(_ioc("44d88612fea8a8f36de82e1278abb02", IocType.MD5))
    assert not ok and "malformed md5" in reason


def test_valid_sha256():
    value = "a" * 64
    ok, _ = validate_ioc(_ioc(value, IocType.SHA256))
    assert ok


def test_empty_value_rejected():
    ok, reason = validate_ioc(_ioc("   ", IocType.IP))
    assert not ok and "empty" in reason
