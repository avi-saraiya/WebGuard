"""HTTP security header rules."""

from app.analyzers.context import ScanContext
from app.analyzers.csp import Policy
from app.rules.base import RuleOutcome, SecurityRule
from app.rules.registry import register
from app.schemas.finding import Category, CheckStatus, Confidence, Severity

MDN_HEADERS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
OWASP_CSP = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
)

HEADERS_UNAVAILABLE = "Response headers were not available."
# Truncate policy text placed into evidence so findings stay readable.
_EVIDENCE_MAX = 500


def _clip(value: str) -> str:
    return value if len(value) <= _EVIDENCE_MAX else value[:_EVIDENCE_MAX] + "…"


@register
class MissingCspRule(SecurityRule):
    id = "WEB-001"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Missing Content-Security-Policy"
    check_name = "Content-Security-Policy"
    references = (MDN_HEADERS + "Content-Security-Policy", OWASP_CSP)

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if ctx.header_csp_policies:
            return self.outcome(CheckStatus.PASS, "Enforced via response header.")
        if ctx.meta_csp_policies:
            return self.outcome(
                CheckStatus.PASS,
                "Enforced via <meta> tag only (frame-ancestors, sandbox and reporting "
                "directives don't work there).",
            )
        if not ctx.headers_available:
            return self.unable_to_determine(HEADERS_UNAVAILABLE)

        report_only = ctx.header("content-security-policy-report-only")
        description = "The response did not contain an enforced Content-Security-Policy."
        if report_only:
            description += (
                " A Content-Security-Policy-Report-Only header is present, which reports "
                "violations but does not block anything."
            )
        return self.finding(
            ctx,
            status=CheckStatus.MISSING,
            summary="No enforced policy" + (" (Report-Only present)." if report_only else "."),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=description,
            location=ctx.headers_location,
            rationale=(
                "A Content Security Policy restricts where scripts and other resources may load "
                "from. It is a defense-in-depth control: it doesn't fix injection flaws, but it "
                "can stop many of them from being exploitable. Its absence does not by itself "
                "mean the site is vulnerable."
            ),
            evidence={
                "header": "Content-Security-Policy",
                "value": None,
                "report_only_value": _clip(report_only) if report_only else None,
                "meta_policies": [],
            },
            recommendation=(
                "Define a CSP suited to the application's resources. Start with "
                "Content-Security-Policy-Report-Only to find breakage, then enforce it."
            ),
        )


def _script_weaknesses(policy: Policy) -> set[str]:
    sources = policy.script_sources()
    if sources is None:
        return {"no-script-restriction"}
    issues: set[str] = set()
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources
    )
    strict_dynamic = "'strict-dynamic'" in sources
    # Browsers ignore 'unsafe-inline' when a nonce/hash is present, and ignore host/scheme
    # allowlists when 'strict-dynamic' is present (CSP Level 3).
    if "'unsafe-inline'" in sources and not has_nonce_or_hash and not strict_dynamic:
        issues.add("unsafe-inline")
    if "'unsafe-eval'" in sources:
        issues.add("unsafe-eval")
    if not strict_dynamic and any(s in ("*", "http:", "https:", "data:") for s in sources):
        issues.add("broad-source")
    return issues


_WEAKNESS_TEXT = {
    "no-script-restriction": "no script-src or default-src directive, so scripts are unrestricted",
    "unsafe-inline": "'unsafe-inline' allows inline scripts without a nonce or hash",
    "unsafe-eval": "'unsafe-eval' allows eval() and similar string-to-code APIs",
    "broad-source": "a wildcard or scheme-only source (*, http:, https:, data:) allows scripts "
    "from almost anywhere",
}


@register
class WeakCspRule(SecurityRule):
    id = "WEB-008"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Content-Security-Policy allows risky script sources"
    check_name = "CSP script sources"
    references = (MDN_HEADERS + "Content-Security-Policy/script-src", OWASP_CSP)

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        policies = ctx.enforced_csp_policies
        if not policies:
            if not ctx.headers_available:
                return self.unable_to_determine(HEADERS_UNAVAILABLE)
            return self.outcome(CheckStatus.NOT_APPLICABLE, "No enforced CSP (see WEB-001).")

        # All enforced policies apply at once; a weakness is effective only if every policy has it.
        per_policy = [_script_weaknesses(policy) for policy in policies]
        effective = set.intersection(*per_policy)
        if not effective:
            return self.outcome(CheckStatus.PASS, "Script sources are restricted.")

        ordered = [key for key in _WEAKNESS_TEXT if key in effective]
        return self.finding(
            ctx,
            status=CheckStatus.WEAK,
            summary="Allows " + ", ".join(ordered) + ".",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            description="The enforced Content-Security-Policy has "
            + "; ".join(_WEAKNESS_TEXT[key] for key in ordered)
            + ".",
            location=ctx.headers_location if ctx.header_csp_policies else "<meta> CSP in page",
            rationale=(
                "These settings reduce how much protection the CSP gives against script "
                "injection. Some may be required by the application today; whether they matter "
                "depends on whether an injection point exists."
            ),
            evidence={
                "issues": ordered,
                "policies": [_clip(policy.raw) for policy in policies],
            },
            recommendation=(
                "Prefer nonce- or hash-based script-src with 'strict-dynamic', remove "
                "'unsafe-inline' and 'unsafe-eval' where possible, and avoid wildcard sources."
            ),
        )


@register
class ContentTypeOptionsRule(SecurityRule):
    id = "WEB-003"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Missing X-Content-Type-Options header"
    check_name = "X-Content-Type-Options"
    references = (MDN_HEADERS + "X-Content-Type-Options", OWASP_HEADERS)

    _rationale = (
        "`X-Content-Type-Options: nosniff` stops browsers from guessing (sniffing) a response's "
        "content type. Without it, a file served with the wrong type, such as user-uploaded "
        "content, might be interpreted as script or HTML."
    )

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if not ctx.headers_available:
            return self.unable_to_determine(HEADERS_UNAVAILABLE)
        value = ctx.header("x-content-type-options")
        if value is None:
            return self.finding(
                ctx,
                status=CheckStatus.MISSING,
                summary="Header not present.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="The response did not include an X-Content-Type-Options header.",
                location=ctx.headers_location,
                rationale=self._rationale,
                evidence={"header": "X-Content-Type-Options", "value": None},
                recommendation="Send `X-Content-Type-Options: nosniff` on all responses.",
            )
        if value.split(",")[0].strip().lower() != "nosniff":
            return self.finding(
                ctx,
                status=CheckStatus.MISCONFIGURED,
                summary=f"Unexpected value {value!r}.",
                title="Invalid X-Content-Type-Options value",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    f"X-Content-Type-Options is set to {value!r}; the only valid value is nosniff."
                ),
                location=ctx.headers_location,
                rationale=self._rationale,
                evidence={"header": "X-Content-Type-Options", "value": value},
                recommendation="Set the header value to exactly `nosniff`.",
            )
        return self.outcome(CheckStatus.PASS, "nosniff")


@register
class ClickjackingRule(SecurityRule):
    id = "WEB-005"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Missing clickjacking protection"
    check_name = "Clickjacking protection"
    references = (
        MDN_HEADERS + "Content-Security-Policy/frame-ancestors",
        MDN_HEADERS + "X-Frame-Options",
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    )

    _rationale = (
        "If other sites can embed this page in a frame, they may trick users into clicking "
        "controls they can't see (clickjacking). This matters mainly for pages with "
        "state-changing actions; static content is at low risk."
    )

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if not ctx.headers_available:
            return self.unable_to_determine(HEADERS_UNAVAILABLE)

        # frame-ancestors only works when delivered by header; it's ignored in <meta>.
        ancestors = [
            p.sources("frame-ancestors")
            for p in ctx.header_csp_policies
            if p.sources("frame-ancestors") is not None
        ]
        if ancestors and not all(sources == ["*"] for sources in ancestors):
            return self.outcome(CheckStatus.PASS, "CSP frame-ancestors restricts framing.")

        xfo = ctx.header("x-frame-options")
        xfo_token = xfo.split(",")[0].strip().upper() if xfo else None
        if xfo_token in ("DENY", "SAMEORIGIN"):
            return self.outcome(CheckStatus.PASS, f"X-Frame-Options: {xfo_token}.")

        evidence = {
            "x_frame_options": xfo,
            "csp_frame_ancestors": [" ".join(s or []) for s in ancestors] or None,
        }
        if xfo is not None:
            return self.finding(
                ctx,
                status=CheckStatus.MISCONFIGURED,
                summary=f"X-Frame-Options value {xfo!r} is not honored.",
                title="Ineffective X-Frame-Options value",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    f"X-Frame-Options is set to {xfo!r}. Modern browsers only honor DENY and "
                    "SAMEORIGIN (ALLOW-FROM is obsolete), and no CSP frame-ancestors directive "
                    "is present."
                ),
                location=ctx.headers_location,
                rationale=self._rationale,
                evidence=evidence,
                recommendation=(
                    "Use CSP `frame-ancestors 'self'` (or 'none'), optionally with "
                    "`X-Frame-Options: SAMEORIGIN` for older browsers."
                ),
            )
        return self.finding(
            ctx,
            status=CheckStatus.MISSING,
            summary="Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            description=(
                "The response sets neither X-Frame-Options nor a restrictive CSP frame-ancestors "
                "directive, so other sites may be able to embed this page in a frame."
            ),
            location=ctx.headers_location,
            rationale=self._rationale,
            evidence=evidence,
            recommendation=(
                "Add CSP `frame-ancestors 'self'` (or 'none' if the page is never framed). "
                "`X-Frame-Options: SAMEORIGIN` can be added for older browsers."
            ),
        )


REFERRER_TOKENS = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
WEAK_REFERRER_TOKENS = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


def _effective_referrer_policy(value: str) -> str | None:
    # Browsers use the last token they recognize, which allows fallback lists.
    recognized = [
        t.strip().lower() for t in value.split(",") if t.strip().lower() in REFERRER_TOKENS
    ]
    return recognized[-1] if recognized else None


@register
class ReferrerPolicyRule(SecurityRule):
    id = "WEB-006"
    version = 1
    category = Category.HTTP_SECURITY
    title = "Referrer-Policy not set"
    check_name = "Referrer-Policy"
    references = (MDN_HEADERS + "Referrer-Policy", OWASP_HEADERS)

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        meta = ctx.request.meta.referrer
        header = ctx.header("referrer-policy")
        if header is None and meta is None and not ctx.headers_available:
            return self.unable_to_determine(HEADERS_UNAVAILABLE)

        # A <meta name="referrer"> overrides the header for the document's own requests.
        source, value = ("<meta> tag", meta) if meta else ("header", header)
        if value is None:
            return self.finding(
                ctx,
                status=CheckStatus.MISSING,
                summary="Not set; browser default (strict-origin-when-cross-origin) applies.",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                description='No Referrer-Policy header or <meta name="referrer"> tag was found.',
                location=ctx.headers_location,
                rationale=(
                    "Modern browsers default to strict-origin-when-cross-origin, which is a "
                    "reasonable policy, so this is informational. Setting it explicitly makes "
                    "the behavior consistent across browsers and intentional."
                ),
                evidence={"header": "Referrer-Policy", "value": None, "meta": None},
                recommendation=(
                    "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter."
                ),
            )

        effective = _effective_referrer_policy(value)
        evidence = {"source": source, "value": value, "effective_policy": effective}
        if effective is None:
            return self.finding(
                ctx,
                status=CheckStatus.MISCONFIGURED,
                summary=f"Unrecognized value {value!r}; browser default applies.",
                title="Unrecognized Referrer-Policy value",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                description=(
                    f"The Referrer-Policy {source} is {value!r}, which browsers don't recognize, "
                    "so they fall back to their default policy."
                ),
                location=ctx.headers_location if source == "header" else "<meta> tag in page",
                rationale="An invalid policy is ignored, which is likely not what was intended.",
                evidence=evidence,
                recommendation="Use a valid value such as `strict-origin-when-cross-origin`.",
            )
        if effective in WEAK_REFERRER_TOKENS:
            return self.finding(
                ctx,
                status=CheckStatus.WEAK,
                summary=f"{effective} may leak full URLs to other sites.",
                title="Permissive Referrer-Policy",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    f"The effective Referrer-Policy is {effective}, which sends the full URL "
                    "(path and query string) to other origins"
                    + (", even over unencrypted HTTP." if effective == "unsafe-url" else ".")
                ),
                location=ctx.headers_location if source == "header" else "<meta> tag in page",
                rationale=(
                    "URLs can contain sensitive data such as identifiers, search terms or "
                    "tokens. Sending them to third parties can leak that data."
                ),
                evidence=evidence,
                recommendation="Use `strict-origin-when-cross-origin` or a stricter policy.",
            )
        return self.outcome(CheckStatus.PASS, f"{effective} (via {source}).")
