"""Base class for deterministic security rules.

A rule inspects a :class:`ScanContext` and returns a :class:`RuleOutcome`: a check status for the
UI, a one-line summary, and (only when there is evidence of a weakness) a :class:`Finding`.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from app.analyzers.context import ScanContext
from app.schemas.finding import Category, CheckStatus, Confidence, Finding, Severity


@dataclass(frozen=True)
class RuleOutcome:
    status: CheckStatus
    summary: str
    finding: Finding | None = None


class SecurityRule(ABC):
    id: ClassVar[str]
    version: ClassVar[int]
    category: ClassVar[Category]
    title: ClassVar[str]
    references: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def evaluate(self, ctx: ScanContext) -> RuleOutcome: ...

    def outcome(self, status: CheckStatus, summary: str) -> RuleOutcome:
        return RuleOutcome(status=status, summary=summary)

    def unable_to_determine(self, summary: str) -> RuleOutcome:
        return RuleOutcome(status=CheckStatus.UNABLE_TO_DETERMINE, summary=summary)

    def finding(
        self,
        ctx: ScanContext,
        *,
        status: CheckStatus,
        summary: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        location: str,
        rationale: str,
        evidence: dict[str, Any],
        recommendation: str,
        title: str | None = None,
    ) -> RuleOutcome:
        return RuleOutcome(
            status=status,
            summary=summary,
            finding=Finding(
                id=self.id,
                rule_version=self.version,
                category=self.category,
                title=title or self.title,
                severity=severity,
                confidence=confidence,
                description=description,
                location=location,
                rationale=rationale,
                evidence=evidence,
                recommendation=recommendation,
                references=list(self.references),
                detected_at=ctx.scanned_at,
            ),
        )
