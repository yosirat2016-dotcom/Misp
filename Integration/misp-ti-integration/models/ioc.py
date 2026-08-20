"""Internal IOC representation, independent of any source or destination
(MISP, Sentinel, ...) format."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class IocType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class IOC:
    value: str
    type: IocType
    source: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int | None = None  # 0-100
    description: str = ""
    malware: str | None = None
    tags: list[str] = field(default_factory=list)
    reference: str | None = None
