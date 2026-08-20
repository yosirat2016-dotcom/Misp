"""Rejects malformed IOCs before they reach normalization/dedup/MISP.

Private-IP handling is configurable (reject_private_ips), not hard-coded:
a private IP is not inherently malicious, and not inherently something to
discard - some environments care about internal C2 beaconing to RFC1918
space, others only want internet-facing indicators. Default is to keep
private IPs and let the caller opt into filtering them.
"""
import ipaddress
import re
from urllib.parse import urlparse

from models.ioc import IOC, IocType

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
_HASH_LENGTHS = {
    IocType.MD5: 32,
    IocType.SHA1: 40,
    IocType.SHA256: 64,
}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme) and parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_valid_hash(value: str, ioc_type: IocType) -> bool:
    expected_len = _HASH_LENGTHS.get(ioc_type)
    if expected_len is None:
        return False
    return len(value) == expected_len and bool(_HEX_RE.match(value))


def is_valid_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))


def validate_ioc(ioc: IOC, reject_private_ips: bool = False) -> tuple[bool, str | None]:
    """Returns (is_valid, reason_if_rejected)."""
    value = ioc.value.strip()
    if not value:
        return False, "empty value"

    if ioc.type == IocType.IP:
        if not is_valid_ip(value):
            return False, "malformed IP"
        if reject_private_ips and is_private_ip(value):
            return False, "private IP rejected by config"
        return True, None

    if ioc.type == IocType.DOMAIN:
        return (True, None) if is_valid_domain(value) else (False, "malformed domain")

    if ioc.type == IocType.URL:
        return (True, None) if is_valid_url(value) else (False, "malformed URL")

    if ioc.type in (IocType.MD5, IocType.SHA1, IocType.SHA256):
        return (True, None) if is_valid_hash(value, ioc.type) else (False, f"malformed {ioc.type.value}")

    if ioc.type == IocType.EMAIL:
        return (True, None) if is_valid_email(value) else (False, "malformed email")

    return False, f"unknown IOC type: {ioc.type}"
