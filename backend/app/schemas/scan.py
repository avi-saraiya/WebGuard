"""Scan request/response schemas for ``POST /api/v1/scans``."""

from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.schemas.finding import CheckResult, Finding

MAX_URL_LENGTH = 2048


def _normalize_page_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https")
    if not parts.hostname:
        raise ValueError("URL must include a host")
    if parts.username or parts.password:
        raise ValueError("URL must not contain credentials")
    # Defense in depth: the extension already strips these, but query strings and fragments can
    # carry tokens or personal data and are never needed for analysis.
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", "", ""))


PageUrl = Annotated[
    str, Field(min_length=1, max_length=MAX_URL_LENGTH), AfterValidator(_normalize_page_url)
]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: PageUrl


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
    engine_version: str
    analyzed_at: datetime
