from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import EXTENSION_ORIGIN


def post_scan(client: TestClient, payload: Any) -> Any:
    return client.post("/api/v1/scans", json=payload)


def test_scan_returns_result_shape(client: TestClient) -> None:
    response = post_scan(client, {"url": "https://Example.com/path"})
    assert response.status_code == 200
    body = response.json()
    assert body["target"] == {
        "url": "https://example.com/path",
        "host": "example.com",
        "scheme": "https",
    }
    assert set(body) >= {
        "scan_id",
        "summary",
        "findings",
        "checks",
        "engine_version",
        "analyzed_at",
    }


def test_scan_strips_query_and_fragment(client: TestClient) -> None:
    response = post_scan(client, {"url": "https://example.com/a?token=secret#frag"})
    assert response.status_code == 200
    assert response.json()["target"]["url"] == "https://example.com/a"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "javascript:alert(1)",
        "chrome://settings",
        "https://",
        "https://user:pass@example.com/",
        "https://example.com/" + "a" * 2048,
        "",
    ],
)
def test_scan_rejects_invalid_urls(client: TestClient, url: str) -> None:
    response = post_scan(client, {"url": url})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_scan_rejects_unknown_fields(client: TestClient) -> None:
    response = post_scan(client, {"url": "https://example.com/", "cookies": "session=abc"})
    assert response.status_code == 422


def test_validation_errors_do_not_echo_input(client: TestClient) -> None:
    response = post_scan(client, {"url": "ftp://secret-value.example/"})
    assert "secret-value" not in response.text


def test_scan_rejects_oversized_body(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scans",
        content=b'{"url": "' + b"a" * 5000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_cors_allows_extension_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/scans",
        headers={"Origin": EXTENSION_ORIGIN, "Access-Control-Request-Method": "POST"},
    )
    assert response.headers.get("access-control-allow-origin") == EXTENSION_ORIGIN


def test_cors_rejects_web_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/scans",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in response.headers
