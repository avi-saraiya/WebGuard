"""Request-contract tests: the API accepts only the documented, privacy-minimal signals."""

from typing import Any

import pytest
from fastapi.testclient import TestClient


def scan(client: TestClient, **extra: Any) -> Any:
    return client.post("/api/v1/scans", json={"url": "https://example.com/", **extra})


def test_minimal_request_explains_missing_inputs(client: TestClient) -> None:
    response = scan(client)
    assert response.status_code == 200
    assert len(response.json()["notices"]) == 2


def test_header_names_are_normalized_to_lowercase(client: TestClient) -> None:
    response = scan(
        client,
        headers={"status": "collected", "values": {"X-Content-Type-Options": "nosniff"}},
    )
    assert response.status_code == 200


@pytest.mark.parametrize("name", ["set-cookie", "cookie", "authorization", "x-custom"])
def test_non_allowlisted_headers_are_rejected(client: TestClient, name: str) -> None:
    response = scan(client, headers={"status": "collected", "values": {name: "secret"}})
    assert response.status_code == 422
    assert "secret" not in response.text


def test_oversized_header_value_is_rejected(client: TestClient) -> None:
    response = scan(
        client,
        headers={"status": "collected", "values": {"content-security-policy": "a" * 8193}},
    )
    assert response.status_code == 422


def test_insecure_resources_must_be_http(client: TestClient) -> None:
    resource = {"url": "https://cdn.example/app.js", "kind": "script", "source": "dom"}
    response = scan(client, mixed_content={"resources": [resource]})
    assert response.status_code == 422


def test_resource_list_is_capped(client: TestClient) -> None:
    resource = {"url": "http://cdn.example/a.js", "kind": "script", "source": "dom"}
    response = scan(client, mixed_content={"resources": [resource] * 51})
    assert response.status_code == 422


def test_unknown_resource_kind_is_rejected(client: TestClient) -> None:
    resource = {"url": "http://cdn.example/a.js", "kind": "keylogger", "source": "dom"}
    response = scan(client, mixed_content={"resources": [resource]})
    assert response.status_code == 422
