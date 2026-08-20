"""Thin wrapper around PyMISP: connectivity test + event push, with a
dry-run mode that never touches the network on the write side (per spec
section 22/23 - dry-run and MISP test mode)."""
import logging

logger = logging.getLogger(__name__)


class MispClient:
    def __init__(self, url: str, api_key: str, ssl_verify: bool = True):
        if not url or not api_key:
            raise ValueError("MISP_URL and MISP_API_KEY are required")
        self._url = url
        self._api_key = api_key
        self._ssl_verify = ssl_verify
        self._pymisp = None

    def _get_pymisp(self):
        if self._pymisp is None:
            from pymisp import PyMISP  # imported lazily so dry-run never needs pymisp installed correctly configured

            self._pymisp = PyMISP(self._url, self._api_key, self._ssl_verify)
        return self._pymisp

    def test_connection(self) -> dict:
        """Raises on failure. Returns MISP's version info on success."""
        pymisp = self._get_pymisp()
        version = pymisp.misp_instance_version
        if not version:
            raise ConnectionError(f"Could not reach MISP at {self._url}")
        logger.info("MISP connectivity OK: %s", version)
        return version

    def push_event(self, event: dict, dry_run: bool = True) -> dict:
        """event is a {"Event": {...}} dict, e.g. from event_builder.build_event().
        In dry-run mode, nothing is sent - just returns a summary."""
        info = event["Event"]["info"]
        attr_count = len(event["Event"]["Attribute"])

        if dry_run:
            logger.info("[DRY RUN] Would create MISP event '%s' with %d attributes", info, attr_count)
            return {"dry_run": True, "info": info, "attribute_count": attr_count}

        pymisp = self._get_pymisp()
        result = pymisp.add_event(event["Event"], pythonify=False)
        if isinstance(result, dict) and result.get("errors"):
            raise RuntimeError(f"MISP rejected the event: {result['errors']}")
        logger.info("Created MISP event '%s' with %d attributes", info, attr_count)
        return result
