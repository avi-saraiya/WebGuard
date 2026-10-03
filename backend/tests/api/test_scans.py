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
        content=b'{"url": "' + b"a" * 70_000 + b'"}',
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


GOOD_SITE = {
    "url": "https://good.example/",
    "collector_version": "0.2.0",
    "headers": {
        "status": "collected",
        "http_status": 200,
        "values": {
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        },
    },
    "mixed_content": {"resources": []},
}

BAD_SITE = {
    "url": "https://bad.example/login",
    "headers": {
        "status": "collected",
        "http_status": 200,
        "values": {"strict-transport-security": "max-age=300", "referrer-policy": "unsafe-url"},
    },
    "mixed_content": {
        "resources": [
            {"url": "http://cdn.bad.example/jquery.js", "kind": "script", "source": "dom"},
            {"url": "http://bad.example/submit", "kind": "form", "source": "dom"},
        ]
    },
}


def test_full_scan_of_well_configured_site_has_no_findings(client: TestClient) -> None:
    body = post_scan(client, GOOD_SITE).json()

    assert body["findings"] == []
    assert body["partial"] is False
    assert body["notices"] == []
    assert {c["rule_id"]: c["status"] for c in body["checks"]} == {
        "WEB-001": "PASS",
        "WEB-002": "PASS",
        "WEB-003": "PASS",
        "WEB-004": "PASS",
        "WEB-005": "PASS",
        "WEB-006": "PASS",
        "WEB-007": "PASS",
        "WEB-008": "PASS",
    }


def test_full_scan_of_poorly_configured_site(client: TestClient) -> None:
    body = post_scan(client, BAD_SITE).json()

    assert [(f["id"], f["severity"]) for f in body["findings"]] == [
        ("WEB-001", "MEDIUM"),
        ("WEB-004", "MEDIUM"),
        ("WEB-002", "LOW"),
        ("WEB-003", "LOW"),
        ("WEB-005", "LOW"),
        ("WEB-006", "LOW"),
    ]
    assert body["summary"] == {
        "critical": 0,
        "high": 0,
        "medium": 2,
        "low": 4,
        "informational": 0,
    }
    statuses = {c["rule_id"]: c["status"] for c in body["checks"]}
    assert statuses["WEB-007"] == "PASS"
    assert statuses["WEB-008"] == "NOT_APPLICABLE"
    for finding in body["findings"]:
        assert finding["evidence"], f"{finding['id']} must carry evidence"
        assert finding["recommendation"]
        assert finding["references"]


def test_scan_with_uncollected_headers_is_partial_without_header_findings(
    client: TestClient,
) -> None:
    payload = {**GOOD_SITE, "headers": {"status": "unavailable"}}
    body = post_scan(client, payload).json()

    assert body["partial"] is True
    assert body["findings"] == []
    assert any("headers could not be collected" in n for n in body["notices"])
