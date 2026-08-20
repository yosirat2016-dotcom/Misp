"""Base interface for CTI feed collectors."""
from abc import ABC, abstractmethod


class ThreatIntelCollector(ABC):
    """Fetches raw data from one CTI source. Subclasses handle auth,
    request shape, and any source-specific quirks; the return value is
    always the raw parsed response (e.g. a dict from JSON)."""

    @abstractmethod
    def fetch(self):
        ...
