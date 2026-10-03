"""Scan request/response schemas for ``POST /api/v1/scans``.

The request carries only what the extension's in-page collector observes: an allowlist of security
response headers, ``<meta>`` policy tags, and insecure (``http:``) resource URLs. Query strings and
fragments are stripped from every URL; cookies, page content and form values are never accepted.
"""

from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.schemas.finding import CheckResult, Finding

MAX_URL_LENGTH = 2048
MAX_HEADER_VALUE_LENGTH = 8192
MAX_RESOURCES = 50
MAX_META_POLICIES = 5

# The only response headers the API accepts. Anything else is rejected, not ignored, so the
# extension cannot silently start sending more data than documented in docs/security.md.
ALLOWED_HEADERS = frozenset(
    {
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    }
)


def _normalize_url(value: str, allowed_schemes: tuple[str, ...]) -> str:
    parts = urlsplit(value)
    if parts.scheme not in allowed_schemes:
        raise ValueError(f"URL scheme must be one of: {', '.join(allowed_schemes)}")
    if not parts.hostname:
        raise ValueError("URL must include a host")
    if parts.username or parts.password:
        raise ValueError("URL must not contain credentials")
    # Defense in depth: the extension already strips these, but query strings and fragments can
    # carry tokens or personal data and are never needed for analysis.
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", "", ""))


def _normalize_page_url(value: str) -> str:
    return _normalize_url(value, ("http", "https"))


def _normalize_insecure_url(value: str) -> str:
    return _normalize_url(value, ("http",))


PageUrl = Annotated[
    str, Field(min_length=1, max_length=MAX_URL_LENGTH), AfterValidator(_normalize_page_url)
]
InsecureUrl = Annotated[
    str, Field(min_length=1, max_length=MAX_URL_LENGTH), AfterValidator(_normalize_insecure_url)
]
PolicyValue = Annotated[str, Field(max_length=MAX_HEADER_VALUE_LENGTH)]


class HeaderCollection(BaseModel):
    """Security response headers observed via the collector's same-origin re-fetch."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["collected", "unavailable"]
    source: Literal["refetch"] = "refetch"
    http_status: int | None = Field(default=None, ge=100, le=599)
    values: dict[str, PolicyValue] = Field(default_factory=dict)

    @field_validator("values")
    @classmethod
    def _allowlisted_names(cls, values: dict[str, str]) -> dict[str, str]:
        normalized = {name.lower(): value for name, value in values.items()}
        unexpected = set(normalized) - ALLOWED_HEADERS
        if unexpected:
            raise ValueError("Header is not in the WebGuard allowlist")
        return normalized


ResourceKind = Literal[
    "script", "stylesheet", "iframe", "object", "fetch", "font", "image", "media", "form", "other"
]


class InsecureResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: InsecureUrl
    kind: ResourceKind
    source: Literal["dom", "performance"]


class MixedContentCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resources: list[InsecureResource] = Field(default_factory=list, max_length=MAX_RESOURCES)
    truncated: bool = False


class MetaPolicies(BaseModel):
    """Policies delivered through ``<meta>`` tags rather than response headers."""

    model_config = ConfigDict(extra="forbid")

    content_security_policy: list[PolicyValue] = Field(
        default_factory=list, max_length=MAX_META_POLICIES
    )
    referrer: PolicyValue | None = None


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: PageUrl
    collector_version: str | None = Field(default=None, max_length=32)
    # ``None`` means "not collected" and makes dependent checks UNABLE_TO_DETERMINE.
    headers: HeaderCollection | None = None
    meta: MetaPolicies = Field(default_factory=MetaPolicies)
    mixed_content: MixedContentCollection | None = None


class ScanTarget(BaseModel):
    url: str
    host: str
    scheme: str


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ScanResponse(BaseModel):
    scan_id: UUID
    target: ScanTarget
    summary: SeveritySummary
    findings: list[Finding]
    checks: list[CheckResult]
    # True when at least one check could not be evaluated; see ``notices`` for why.
    partial: bool = False
    notices: list[str] = Field(default_factory=list)
    engine_version: str
    analyzed_at: datetime
