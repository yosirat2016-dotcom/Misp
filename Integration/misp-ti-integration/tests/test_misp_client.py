from unittest.mock import MagicMock, patch

import pytest

from misp.client import MispClient


def test_missing_credentials_raise():
    with pytest.raises(ValueError):
        MispClient(url="", api_key="")


def test_dry_run_push_never_touches_pymisp():
    client = MispClient(url="https://misp.example", api_key="fake-key")
    event = {"Event": {"info": "test event", "Attribute": [{}, {}]}}

    with patch("pymisp.PyMISP") as mocked_pymisp_cls:
        result = client.push_event(event, dry_run=True)

    mocked_pymisp_cls.assert_not_called()
    assert result == {"dry_run": True, "info": "test event", "attribute_count": 2}


def test_real_push_calls_pymisp_add_event():
    client = MispClient(url="https://misp.example", api_key="fake-key")
    event = {"Event": {"info": "test event", "Attribute": []}}

    mock_instance = MagicMock()
    mock_instance.add_event.return_value = {"Event": {"id": "123"}}
    with patch("pymisp.PyMISP", return_value=mock_instance) as mocked_pymisp_cls:
        result = client.push_event(event, dry_run=False)

    mocked_pymisp_cls.assert_called_once_with("https://misp.example", "fake-key", True)
    mock_instance.add_event.assert_called_once()
    assert result == {"Event": {"id": "123"}}


def test_real_push_raises_on_misp_error_response():
    client = MispClient(url="https://misp.example", api_key="fake-key")
    event = {"Event": {"info": "test event", "Attribute": []}}

    mock_instance = MagicMock()
    mock_instance.add_event.return_value = {"errors": "something went wrong"}
    with patch("pymisp.PyMISP", return_value=mock_instance):
        with pytest.raises(RuntimeError):
            client.push_event(event, dry_run=False)


def test_connection_test_raises_when_no_version():
    client = MispClient(url="https://misp.example", api_key="fake-key")
    mock_instance = MagicMock()
    mock_instance.misp_instance_version = None
    with patch("pymisp.PyMISP", return_value=mock_instance):
        with pytest.raises(ConnectionError):
            client.test_connection()
