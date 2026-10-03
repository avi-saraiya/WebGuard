from app.rules import registry
from app.schemas.finding import CheckStatus, Confidence, Severity
from tests.factories import make_context

rule = registry.get("WEB-004")


def resource(kind: str, url: str = "http://cdn.example/x", source: str = "dom") -> dict[str, str]:
    return {"url": url, "kind": kind, "source": source}


def test_no_insecure_resources_passes() -> None:
    outcome = rule.evaluate(make_context(resources=[]))
    assert outcome.status == CheckStatus.PASS
    assert outcome.finding is None


def test_active_mixed_content_is_medium() -> None:
    ctx = make_context(resources=[resource("script", "http://cdn.example/app.js")])
    outcome = rule.evaluate(ctx)
    assert outcome.status == CheckStatus.MISCONFIGURED
    finding = outcome.finding
    assert finding is not None
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.HIGH
    assert finding.evidence["counts"] == {"active": 1}
    assert finding.evidence["resources"][0]["url"] == "http://cdn.example/app.js"


def test_passive_only_is_low() -> None:
    ctx = make_context(resources=[resource("image"), resource("media")])
    outcome = rule.evaluate(ctx)
    assert outcome.finding is not None
    assert outcome.finding.severity == Severity.LOW
    assert outcome.finding.evidence["counts"] == {"passive": 2}


def test_insecure_form_target_is_medium() -> None:
    outcome = rule.evaluate(make_context(resources=[resource("form"), resource("image")]))
    assert outcome.finding is not None
    assert outcome.finding.severity == Severity.MEDIUM
    assert "1 passive" in outcome.summary
    assert "1 form" in outcome.summary


def test_truncation_is_reported_in_evidence() -> None:
    outcome = rule.evaluate(make_context(resources=[resource("image")], truncated=True))
    assert outcome.finding is not None
    assert outcome.finding.evidence["truncated"] is True


def test_http_page_is_not_applicable() -> None:
    outcome = rule.evaluate(make_context("http://example.com/", resources=[resource("script")]))
    assert outcome.status == CheckStatus.NOT_APPLICABLE
    assert outcome.finding is None


def test_not_collected_draws_no_conclusion() -> None:
    outcome = rule.evaluate(make_context(resources=None))
    assert outcome.status == CheckStatus.UNABLE_TO_DETERMINE
    assert outcome.finding is None
