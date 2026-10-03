from typing import Any

import pytest

from app.rules import registry
from app.rules.base import RuleOutcome, SecurityRule
from app.schemas.finding import CheckStatus, Confidence, Severity
from tests.factories import headers_without, make_context

csp_rule = registry.get("WEB-001")
xcto_rule = registry.get("WEB-003")
clickjacking_rule = registry.get("WEB-005")
referrer_rule = registry.get("WEB-006")
weak_csp_rule = registry.get("WEB-008")

UNAVAILABLE: dict[str, Any] = {"headers": {}, "headers_status": "unavailable"}

ALL_HEADER_RULES = [csp_rule, xcto_rule, clickjacking_rule, referrer_rule, weak_csp_rule]


@pytest.mark.parametrize("rule", ALL_HEADER_RULES, ids=lambda r: r.id)
def test_unavailable_headers_never_produce_findings(rule: SecurityRule) -> None:
    outcome = rule.evaluate(make_context(**UNAVAILABLE))
    assert outcome.status == CheckStatus.UNABLE_TO_DETERMINE
    assert outcome.finding is None


@pytest.mark.parametrize("rule", ALL_HEADER_RULES, ids=lambda r: r.id)
def test_well_configured_response_passes(rule: SecurityRule) -> None:
    outcome = rule.evaluate(make_context())
    assert outcome.status == CheckStatus.PASS
    assert outcome.finding is None


class TestWeb001MissingCsp:
    def test_missing_csp_is_medium_high(self) -> None:
        outcome = csp_rule.evaluate(
            make_context(headers=headers_without("content-security-policy"))
        )
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.MEDIUM
        assert outcome.finding.confidence == Confidence.HIGH
        assert outcome.finding.evidence["value"] is None

    def test_report_only_does_not_count_as_enforced(self) -> None:
        headers = headers_without(
            "content-security-policy", content_security_policy_report_only="default-src 'self'"
        )
        outcome = csp_rule.evaluate(make_context(headers=headers))
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.evidence["report_only_value"] == "default-src 'self'"
        assert "Report-Only" in outcome.finding.description

    def test_meta_csp_counts_as_enforced(self) -> None:
        ctx = make_context(
            headers=headers_without("content-security-policy"), meta_csp=["default-src 'self'"]
        )
        outcome = csp_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.PASS
        assert "<meta>" in outcome.summary

    def test_meta_csp_passes_even_without_headers(self) -> None:
        outcome = csp_rule.evaluate(make_context(**UNAVAILABLE, meta_csp=["default-src 'self'"]))
        assert outcome.status == CheckStatus.PASS


class TestWeb008WeakCsp:
    def _evaluate(self, *policies: str) -> RuleOutcome:
        headers = headers_without(content_security_policy=", ".join(policies))
        return weak_csp_rule.evaluate(make_context(headers=headers))

    @pytest.mark.parametrize(
        ("policy", "issue"),
        [
            ("script-src 'self' 'unsafe-inline'", "unsafe-inline"),
            ("default-src 'self' 'unsafe-eval'", "unsafe-eval"),
            ("script-src *", "broad-source"),
            ("script-src https:", "broad-source"),
            ("img-src 'self'", "no-script-restriction"),
        ],
    )
    def test_weak_policies_are_flagged(self, policy: str, issue: str) -> None:
        outcome = self._evaluate(policy)
        assert outcome.status == CheckStatus.WEAK
        finding = outcome.finding
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert finding.confidence == Confidence.MEDIUM
        assert issue in finding.evidence["issues"]

    @pytest.mark.parametrize(
        "policy",
        [
            "script-src 'self'",
            "script-src 'nonce-abc' 'unsafe-inline'",  # unsafe-inline ignored with a nonce
            "script-src 'sha256-xyz' 'unsafe-inline'",
            "script-src 'strict-dynamic' 'nonce-abc' https: 'unsafe-inline'",
            "default-src 'none'",
        ],
    )
    def test_strict_policies_pass(self, policy: str) -> None:
        assert self._evaluate(policy).status == CheckStatus.PASS

    def test_weakness_counts_only_if_every_policy_has_it(self) -> None:
        # The second policy blocks inline script, so the combined effect is not weak.
        outcome = self._evaluate("script-src 'self' 'unsafe-inline'", "script-src 'self'")
        assert outcome.status == CheckStatus.PASS

    def test_no_csp_is_not_applicable(self) -> None:
        ctx = make_context(headers=headers_without("content-security-policy"))
        assert weak_csp_rule.evaluate(ctx).status == CheckStatus.NOT_APPLICABLE

    def test_meta_policy_is_evaluated(self) -> None:
        ctx = make_context(
            headers=headers_without("content-security-policy"),
            meta_csp=["script-src 'unsafe-eval' 'self'"],
        )
        outcome = weak_csp_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.WEAK
        assert outcome.finding is not None
        assert outcome.finding.location == "<meta> CSP in page"


class TestWeb003ContentTypeOptions:
    def test_missing_is_low_finding(self) -> None:
        outcome = xcto_rule.evaluate(
            make_context(headers=headers_without("x-content-type-options"))
        )
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.LOW

    def test_wrong_value_is_misconfigured(self) -> None:
        ctx = make_context(headers=headers_without(x_content_type_options="sniff-please"))
        outcome = xcto_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.MISCONFIGURED
        assert outcome.finding is not None

    def test_value_is_case_insensitive(self) -> None:
        ctx = make_context(headers=headers_without(x_content_type_options="NoSniff"))
        assert xcto_rule.evaluate(ctx).status == CheckStatus.PASS


class TestWeb005Clickjacking:
    def test_neither_header_is_missing(self) -> None:
        headers = headers_without("x-frame-options", content_security_policy="default-src 'self'")
        outcome = clickjacking_rule.evaluate(make_context(headers=headers))
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.LOW
        assert outcome.finding.confidence == Confidence.MEDIUM

    def test_frame_ancestors_alone_passes(self) -> None:
        headers = headers_without("x-frame-options")  # GOOD_HEADERS CSP has frame-ancestors
        assert clickjacking_rule.evaluate(make_context(headers=headers)).status == CheckStatus.PASS

    @pytest.mark.parametrize("value", ["DENY", "sameorigin"])
    def test_xfo_alone_passes(self, value: str) -> None:
        headers = headers_without(
            content_security_policy="default-src 'self'", x_frame_options=value
        )
        assert clickjacking_rule.evaluate(make_context(headers=headers)).status == CheckStatus.PASS

    def test_allow_from_is_misconfigured(self) -> None:
        headers = headers_without(
            content_security_policy="default-src 'self'",
            x_frame_options="ALLOW-FROM https://partner.example",
        )
        outcome = clickjacking_rule.evaluate(make_context(headers=headers))
        assert outcome.status == CheckStatus.MISCONFIGURED

    def test_wildcard_frame_ancestors_does_not_protect(self) -> None:
        headers = headers_without("x-frame-options", content_security_policy="frame-ancestors *")
        outcome = clickjacking_rule.evaluate(make_context(headers=headers))
        assert outcome.status == CheckStatus.MISSING

    def test_meta_frame_ancestors_is_ignored(self) -> None:
        headers = headers_without("x-frame-options", "content-security-policy")
        ctx = make_context(headers=headers, meta_csp=["frame-ancestors 'none'"])
        assert clickjacking_rule.evaluate(ctx).status == CheckStatus.MISSING


class TestWeb006ReferrerPolicy:
    def test_missing_is_informational(self) -> None:
        outcome = referrer_rule.evaluate(make_context(headers=headers_without("referrer-policy")))
        assert outcome.status == CheckStatus.MISSING
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.INFORMATIONAL

    @pytest.mark.parametrize("value", ["unsafe-url", "no-referrer-when-downgrade"])
    def test_leaky_policies_are_weak(self, value: str) -> None:
        outcome = referrer_rule.evaluate(
            make_context(headers=headers_without(referrer_policy=value))
        )
        assert outcome.status == CheckStatus.WEAK
        assert outcome.finding is not None
        assert outcome.finding.severity == Severity.LOW

    def test_last_recognized_token_wins(self) -> None:
        headers = headers_without(referrer_policy="unsafe-url, made-up, strict-origin")
        assert referrer_rule.evaluate(make_context(headers=headers)).status == CheckStatus.PASS

    def test_unrecognized_value_is_misconfigured(self) -> None:
        headers = headers_without(referrer_policy="leak-everything")
        outcome = referrer_rule.evaluate(make_context(headers=headers))
        assert outcome.status == CheckStatus.MISCONFIGURED

    def test_meta_referrer_takes_precedence(self) -> None:
        ctx = make_context(headers=headers_without("referrer-policy"), meta_referrer="no-referrer")
        outcome = referrer_rule.evaluate(ctx)
        assert outcome.status == CheckStatus.PASS
        assert "<meta>" in outcome.summary
