"""Runs every registered rule against a scan request and assembles the response."""

import logging
import time
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

from app import __version__
from app.analyzers.context import ScanContext
from app.rules.base import RuleOutcome, SecurityRule
from app.rules.registry import RuleRegistry
from app.schemas.finding import SEVERITY_RANK, CheckResult, CheckStatus, Finding
from app.schemas.scan import ScanRequest, ScanResponse, ScanTarget, SeveritySummary

logger = logging.getLogger(__name__)


def _evaluate_safely(rule: SecurityRule, ctx: ScanContext) -> RuleOutcome:
    # One broken rule must never fail the whole scan (spec §46): record it and move on.
    try:
        return rule.evaluate(ctx)
    except Exception:
        logger.exception("Rule evaluation failed", extra={"rule_id": rule.id})
        return rule.unable_to_determine("This check failed to run; no conclusion was drawn.")


def _notices(request: ScanRequest) -> list[str]:
    notices = []
    if request.headers is None or request.headers.status != "collected":
        notices.append(
            "Response headers could not be collected, so header-based checks were not evaluated."
        )
    if request.mixed_content is None:
        notices.append("Page resources were not collected, so mixed content was not evaluated.")
    elif request.mixed_content.truncated:
        notices.append("The insecure resource list was truncated; more may exist.")
    return notices


def analyze(request: ScanRequest, registry: RuleRegistry) -> ScanResponse:
    started = time.perf_counter()
    ctx = ScanContext(request=request, scanned_at=datetime.now(UTC))

    findings: list[Finding] = []
    checks: list[CheckResult] = []
    for rule in registry.all():
        outcome = _evaluate_safely(rule, ctx)
        checks.append(
            CheckResult(
                rule_id=rule.id,
                title=rule.title,
                category=rule.category,
                status=outcome.status,
                summary=outcome.summary,
            )
        )
        if outcome.finding is not None:
            findings.append(outcome.finding)

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.id))
    counts = Counter(f.severity.value.lower() for f in findings)
    parts = urlsplit(request.url)

    logger.info(
        "scan analyzed",
        extra={
            "findings": len(findings),
            "rules": len(checks),
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    )
    return ScanResponse(
        scan_id=uuid4(),
        target=ScanTarget(url=request.url, host=parts.hostname or "", scheme=parts.scheme),
        summary=SeveritySummary(**counts),
        findings=findings,
        checks=checks,
        partial=any(c.status == CheckStatus.UNABLE_TO_DETERMINE for c in checks),
        notices=_notices(request),
        engine_version=__version__,
        analyzed_at=ctx.scanned_at,
    )
