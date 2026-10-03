"""Finding and check-result schemas (spec §15, §3.1, §8)."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


# Lower rank = more severe; used for sorting findings.
SEVERITY_RANK: dict[Severity, int] = {severity: rank for rank, severity in enumerate(Severity)}


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CheckStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - not a password
    MISSING = "MISSING"
    WEAK = "WEAK"
    MISCONFIGURED = "MISCONFIGURED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNABLE_TO_DETERMINE = "UNABLE_TO_DETERMINE"


class Category(StrEnum):
    TRANSPORT = "TRANSPORT"
    HTTP_SECURITY = "HTTP_SECURITY"
    MIXED_CONTENT = "MIXED_CONTENT"


class Finding(BaseModel):
    """A single evidence-backed observation. ``id`` equals the rule ID that produced it."""

    id: str = Field(examples=["WEB-001"])
    rule_version: int
    category: Category
    title: str
    severity: Severity
    confidence: Confidence
    description: str = Field(description="What was detected.")
    location: str = Field(description="Where it was detected.")
    rationale: str = Field(description="Why it matters.")
    evidence: dict[str, Any]
    recommendation: str
    references: list[str] = Field(default_factory=list)
    detected_at: datetime


class CheckResult(BaseModel):
    """The outcome of one rule, whether or not it produced a finding."""

    rule_id: str
    name: str
    category: Category
    status: CheckStatus
    summary: str
