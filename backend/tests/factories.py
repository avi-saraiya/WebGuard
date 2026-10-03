"""Builders for scan requests and contexts used across rule and engine tests."""

from datetime import UTC, datetime
from typing import Any

from app.analyzers.context import ScanContext
from app.schemas.scan import ScanRequest

# A response that passes every header check; tests remove or override individual headers.
GOOD_HEADERS: dict[str, str] = {
    "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}

_UNSET: Any = object()


def make_request(
    url: str = "https://example.com/",
    *,
    headers: dict[str, str] | None = _UNSET,
    headers_status: str = "collected",
    meta_csp: list[str] | None = None,
    meta_referrer: str | None = None,
    resources: list[dict[str, str]] | None = _UNSET,
    truncated: bool = False,
) -> ScanRequest:
    """Build a request. ``headers=None`` / ``resources=None`` mean "not collected"."""
    payload: dict[str, Any] = {
        "url": url,
        "meta": {"content_security_policy": meta_csp or [], "referrer": meta_referrer},
    }
    if headers is not None:
        payload["headers"] = {
            "status": headers_status,
            "http_status": 200,
            "values": dict(GOOD_HEADERS) if headers is _UNSET else headers,
        }
    if resources is not None:
        payload["mixed_content"] = {
            "resources": [] if resources is _UNSET else resources,
            "truncated": truncated,
        }
    return ScanRequest.model_validate(payload)


def make_context(url: str = "https://example.com/", **kwargs: Any) -> ScanContext:
    return ScanContext(request=make_request(url, **kwargs), scanned_at=datetime.now(UTC))


def headers_without(*names: str, **overrides: str) -> dict[str, str]:
    """GOOD_HEADERS minus ``names``, plus ``overrides`` (use underscores for dashes)."""
    headers = {k: v for k, v in GOOD_HEADERS.items() if k not in names}
    headers.update({k.replace("_", "-"): v for k, v in overrides.items()})
    return headers
