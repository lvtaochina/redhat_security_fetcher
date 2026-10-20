#! /usr/bin/env python3

from unittest.mock import Mock, patch
from get_affected_cves import get_data, DataSuccess, DataFail, DataError
import requests

def test_get_data_success():
    endpoint = "/cve/CVE-2026-75020.json"

    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"threat_severity" : "Low", "public_date" : "2016-04-27T00:00:00Z"}
    
    with patch(
        "get_affected_cves.requests.get",
        return_value = fake_response
    ):
        result = get_data(endpoint)

    assert result.data == {"threat_severity" : "Low", "public_date" : "2016-04-27T00:00:00Z"}
    assert result.status_code == 200
    assert isinstance(result, DataSuccess)

def test_get_data_empty():
    endpoint = "/cve/CVE-2026-75020.json"

    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {}
    
    with patch(
        "get_affected_cves.requests.get",
        return_value = fake_response
    ):
        result = get_data(endpoint)

    assert result.status_code == 200
    assert result.error == DataError.NO_DATA
    assert isinstance(result, DataFail)

def test_get_data_non_200():
    endpoint = "/cve/CVE-2026-75020.json"

    fake_response = Mock()
    fake_response.status_code = 404
    
    with patch(
        "get_affected_cves.requests.get",
        return_value = fake_response
    ):
        result = get_data(endpoint)

    assert result.status_code == 404
    assert result.error == DataError.HTTP_ERROR
    assert isinstance(result, DataFail)

def test_get_data_req_exception():
    endpoint = "/cve/CVE-2026-75020.json"

    with patch(
        "get_affected_cves.requests.get",
        side_effect = requests.RequestException("Mock request failure")
    ):
        result = get_data(endpoint)

    assert result.error == DataError.REQUEST_EXCEPTION
    assert result.status_code is None
    assert isinstance(result, DataFail)

def test_get_data_json_exception():
    endpoint = "/cve/CVE-2026-75020.json"

    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.side_effect = ValueError("Mock JSON error")

    with patch(
        "get_affected_cves.requests.get",
        return_value = fake_response
    ):
        result = get_data(endpoint)

    assert result.error == DataError.INVALID_JSON
    assert result.status_code == 200
    assert isinstance(result, DataFail)

def main() -> None:
    test_get_data_success()
    test_get_data_empty()
    test_get_data_non_200()
    test_get_data_req_exception()
    test_get_data_json_exception()

if __name__ == "__main__":
    main()