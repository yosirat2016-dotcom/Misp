from unittest.mock import MagicMock, patch

import pytest

from collectors.urlhaus import UrlhausCollector

SAMPLE_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "id": "223622",
            "url": "http://45.61.49.78/razor/r4z0r.mips",
            "url_status": "offline",
            "host": "45.61.49.78",
            "date_added": "2026-08-18 09:02:05 UTC",
            "threat": "malware_download",
            "tags": ["elf", "mirai"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
        },
        {
            "id": "223711",
            "url": "https://bad-domain-example.net/payload/setup.exe",
            "url_status": "online",
            "host": "bad-domain-example.net",
            "date_added": "2026-08-19 03:14:00 UTC",
            "threat": "malware_download",
            "tags": ["exe", "loader"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/223711/",
        },
    ],
}


def _mock_response(status_code=200, json_body=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_body or {}
    response.raise_for_status.return_value = None
    return response


def test_fetch_returns_parsed_urls():
    with patch("collectors.urlhaus.requests.get", return_value=_mock_response(json_body=SAMPLE_RESPONSE)) as mocked_get:
        collector = UrlhausCollector(api_key="fake-key-for-demo", limit=10)
        result = collector.fetch()

    assert result["query_status"] == "ok"
    assert len(result["urls"]) == 2
    assert result["urls"][0]["url"] == "http://45.61.49.78/razor/r4z0r.mips"

    args, kwargs = mocked_get.call_args
    assert args[0] == "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/10/"
    assert kwargs["headers"] == {"Auth-Key": "fake-key-for-demo"}


def test_fetch_handles_no_results():
    with patch("collectors.urlhaus.requests.get", return_value=_mock_response(json_body={"query_status": "no_results"})):
        collector = UrlhausCollector(api_key="fake-key-for-demo")
        result = collector.fetch()

    assert result == {"query_status": "no_results", "urls": []}


def test_fetch_raises_on_401():
    with patch("collectors.urlhaus.requests.get", return_value=_mock_response(status_code=401)):
        collector = UrlhausCollector(api_key="bad-key")
        with pytest.raises(PermissionError):
            collector.fetch()


def test_fetch_raises_on_429():
    with patch("collectors.urlhaus.requests.get", return_value=_mock_response(status_code=429)):
        collector = UrlhausCollector(api_key="fake-key-for-demo")
        with pytest.raises(RuntimeError):
            collector.fetch()


def test_missing_api_key_raises():
    with pytest.raises(ValueError):
        UrlhausCollector(api_key="")
