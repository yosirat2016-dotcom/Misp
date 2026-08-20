"""Normalizes IOC values before dedup/MISP so equivalent indicators collapse
to one form (e.g. `HTTP://Example.COM` and `http://example.com`).

Hashes are never modified - their exact form matters for forensic lookups
and they're case-insensitive by definition anyway, but lowercasing is
applied for consistent dedup keys, not because the original casing was
"wrong".
"""
from dataclasses import replace

from models.ioc import IOC, IocType


def normalize_url(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        return value
    scheme, rest = value.split("://", 1)
    return f"{scheme.lower()}://{rest}"


def normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def normalize_ip(value: str) -> str:
    return value.strip()


def normalize_hash(value: str) -> str:
    return value.strip().lower()


def normalize_email(value: str) -> str:
    return value.strip().lower()


_NORMALIZERS = {
    IocType.URL: normalize_url,
    IocType.DOMAIN: normalize_domain,
    IocType.IP: normalize_ip,
    IocType.MD5: normalize_hash,
    IocType.SHA1: normalize_hash,
    IocType.SHA256: normalize_hash,
    IocType.EMAIL: normalize_email,
}


def normalize_ioc(ioc: IOC) -> IOC:
    """Returns a new IOC with a normalized value. The original value is not
    mutated in place, so callers that need the forensic-original form still
    have it on the source IOC."""
    normalize_fn = _NORMALIZERS.get(ioc.type)
    if normalize_fn is None:
        return ioc
    return replace(ioc, value=normalize_fn(ioc.value))
