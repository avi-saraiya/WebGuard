import pytest

from app.analyzers.context import ScanContext
from app.analyzers.engine import analyze
from app.rules import registry as builtin_registry
from app.rules.base import RuleOutcome, SecurityRule
from app.rules.registry import RuleRegistry
from app.schemas.finding import Category, CheckStatus, Confidence, Severity
from tests.factories import make_request


class PassingRule(SecurityRule):
    id = "WEB-901"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Always passes"

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        return self.outcome(CheckStatus.PASS, "ok")


def _failing_rule(rule_id: str, severity: Severity) -> type[SecurityRule]:
    class FailingRule(SecurityRule):
        id = rule_id
        version = 2
        category = Category.HTTP_SECURITY
        title = f"Fails {rule_id}"
        references = ("https://example.org/ref",)

        def evaluate(self, ctx: ScanContext) -> RuleOutcome:
            return self.finding(
                ctx,
                status=CheckStatus.MISSING,
                summary="missing",
                severity=severity,
                confidence=Confidence.HIGH,
                description="d",
                location=ctx.headers_location,
                rationale="r",
                evidence={"header": None},
                recommendation="fix",
            )

    return FailingRule


class CrashingRule(SecurityRule):
    id = "WEB-999"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Crashes"

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        raise RuntimeError("boom")


@pytest.fixture
def registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.register(PassingRule)
    reg.register(_failing_rule("WEB-902", Severity.LOW))
    reg.register(_failing_rule("WEB-903", Severity.HIGH))
    return reg


def test_findings_sorted_by_severity_and_counted(registry: RuleRegistry) -> None:
    result = analyze(make_request(), registry)

    assert [f.id for f in result.findings] == ["WEB-903", "WEB-902"]
    assert result.summary.high == 1
    assert result.summary.low == 1
    assert result.summary.medium == 0
    assert [c.rule_id for c in result.checks] == ["WEB-901", "WEB-902", "WEB-903"]
    assert result.partial is False


def test_finding_carries_rule_metadata(registry: RuleRegistry) -> None:
    finding = analyze(make_request(), registry).findings[0]

    assert finding.rule_version == 2
    assert finding.references == ["https://example.org/ref"]
    assert finding.location == "HTTP response headers of https://example.com/"


def test_crashing_rule_yields_partial_result_not_failure(registry: RuleRegistry) -> None:
    registry.register(CrashingRule)

    result = analyze(make_request(), registry)

    crashed = next(c for c in result.checks if c.rule_id == "WEB-999")
    assert crashed.status == CheckStatus.UNABLE_TO_DETERMINE
    assert result.partial is True
    assert len(result.findings) == 2  # other rules still ran


def test_notices_explain_missing_inputs(registry: RuleRegistry) -> None:
    result = analyze(make_request(headers=None, resources=None), registry)
    assert any("headers could not be collected" in n for n in result.notices)
    assert any("mixed content was not evaluated" in n for n in result.notices)


def test_registry_rejects_duplicates_and_bad_ids() -> None:
    reg = RuleRegistry()
    reg.register(PassingRule)
    with pytest.raises(ValueError, match="Duplicate"):
        reg.register(PassingRule)

    class BadId(PassingRule):
        id = "XSS-1"

    with pytest.raises(ValueError, match="Invalid rule id"):
        reg.register(BadId)


def test_builtin_rules_have_unique_complete_metadata() -> None:
    for rule in builtin_registry.all():
        assert rule.title
        assert rule.version >= 1
        assert rule.references, f"{rule.id} should cite at least one reference"
