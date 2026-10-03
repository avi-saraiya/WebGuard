import pytest

from app.rules import registry
from app.schemas.finding import CheckStatus, Confidence, Severity
from tests.factories import headers_without, make_context

https_rule = registry.get("WEB-007")
hsts_rule = registry.get("WEB-002")


class TestWeb007Https:
    def test_https_page_passes(self) -> None:
        outcome = https_rule.evaluate(make_context("https://example.com/"))
        assert outcome.status == CheckStatus.PASS
        assert outcome.finding is None

    def test_http_page_is_high_severity_finding(self) -> None:
        outcome = https_rule.evaluate(make_context("http://example.com/"))
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.id == "WEB-007"
        assert outcome.finding.severity == Severity.HIGH
        assert outcome.finding.confidence == Confidence.HIGH
        assert outcome.finding.evidence == {"url": "http://example.com/", "scheme": "http"}

    @pytest.mark.parametrize(
        "url", ["http://localhost:3000/", "http://127.0.0.1/", "http://app.localhost/"]
    )
    def test_local_hosts_are_not_applicable(self, url: str) -> None:
        outcome = https_rule.evaluate(make_context(url))
        assert outcome.status == CheckStatus.NOT_APPLICABLE
        assert outcome.finding is None


class TestWeb002Hsts:
    def test_long_max_age_passes(self) -> None:
        outcome = hsts_rule.evaluate(make_context())
        assert outcome.status == CheckStatus.PASS
        assert "includesubdomains" in outcome.summary

    def test_missing_header_is_medium_finding(self) -> None:
        ctx = make_context(headers=headers_without("strict-transport-security"))
        outcome = hsts_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.MEDIUM
        assert outcome.finding.evidence["value"] is None

    def test_short_max_age_is_weak(self) -> None:
        ctx = make_context(headers=headers_without(strict_transport_security="max-age=86400"))
        outcome = hsts_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.WEAK
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.LOW
        assert outcome.finding.evidence["max_age"] == 86400

    @pytest.mark.parametrize("value", ["max-age=0", "includeSubDomains", "max-age=abc"])
    def test_ineffective_values_are_misconfigured(self, value: str) -> None:
        ctx = make_context(headers=headers_without(strict_transport_security=value))
        outcome = hsts_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.MISCONFIGURED
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.MEDIUM

    def test_quoted_max_age_and_case_are_accepted(self) -> None:
        ctx = make_context(headers=headers_without(strict_transport_security='MAX-AGE="31536000"'))
        assert hsts_rule.evaluate(ctx).status == CheckStatus.PASS

    def test_only_first_of_repeated_headers_counts(self) -> None:
        ctx = make_context(
            headers=headers_without(strict_transport_security="max-age=60, max-age=31536000")
        )
        assert hsts_rule.evaluate(ctx).status == CheckStatus.WEAK

    def test_http_page_is_not_applicable(self) -> None:
        outcome = hsts_rule.evaluate(make_context("http://example.com/"))
        assert outcome.status == CheckStatus.NOT_APPLICABLE

    def test_headers_unavailable_draws_no_conclusion(self) -> None:
        outcome = hsts_rule.evaluate(make_context(headers={}, headers_status="unavailable"))
        assert outcome.status == CheckStatus.UNABLE_TO_DETERMINE
        assert outcome.finding is None
