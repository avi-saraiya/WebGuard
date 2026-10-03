"""Transport security rules: HTTPS usage and HSTS."""

import re

from app.analyzers.context import ScanContext
from app.rules.base import RuleOutcome, SecurityRule
from app.rules.registry import register
from app.schemas.finding import Category, CheckStatus, Confidence, Severity

MDN_HSTS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
# 180 days: the commonly recommended minimum; HSTS preload lists require one year.
HSTS_MIN_MAX_AGE = 15_552_000
_MAX_AGE = re.compile(r'^max-age\s*=\s*"?(\d+)"?$', re.IGNORECASE)


@register
class HttpsRule(SecurityRule):
    id = "WEB-007"
    version = 1
    category = Category.TRANSPORT
    title = "Page not served over HTTPS"
    check_name = "HTTPS"
    references = (
        "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    )

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if ctx.is_https:
            return self.outcome(CheckStatus.PASS, "The page was loaded over HTTPS.")
        if ctx.is_local:
            return self.outcome(
                CheckStatus.NOT_APPLICABLE,
                "Local development host; HTTPS is not expected.",
            )
        return self.finding(
            ctx,
            status=CheckStatus.MISSING,
            summary="The page was loaded over unencrypted HTTP.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="The page was loaded over plain HTTP rather than HTTPS.",
            location=ctx.url,
            rationale=(
                "Traffic sent over HTTP is not encrypted or integrity-protected. Anyone on the "
                "network path can read it or modify it in transit, including injecting scripts "
                "into the page."
            ),
            evidence={"url": ctx.url, "scheme": ctx.scheme},
            recommendation=(
                "Serve the site over HTTPS, redirect HTTP requests to HTTPS, and then enable HSTS."
            ),
        )


def _parse_hsts(value: str) -> tuple[int | None, set[str]]:
    """Return (max-age or None if missing/invalid, other directive names)."""
    # Repeated headers are comma-joined; browsers honor only the first.
    first = value.split(",")[0]
    max_age: int | None = None
    flags: set[str] = set()
    for raw in first.split(";"):
        token = raw.strip()
        if not token:
            continue
        match = _MAX_AGE.match(token)
        if match:
            max_age = int(match.group(1))
        else:
            flags.add(token.lower())
    return max_age, flags


@register
class HstsRule(SecurityRule):
    id = "WEB-002"
    version = 1
    category = Category.TRANSPORT
    title = "Missing Strict-Transport-Security header"
    check_name = "Strict-Transport-Security"
    references = (
        MDN_HSTS,
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    )

    _rationale = (
        "HSTS tells browsers to connect only over HTTPS for a period of time. Without it, the "
        "first request to the site (for example, a typed URL or an old http:// link) can be made "
        "over HTTP, giving a network attacker a chance to intercept or downgrade the connection."
    )

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if not ctx.is_https:
            return self.outcome(
                CheckStatus.NOT_APPLICABLE,
                "Browsers ignore HSTS on HTTP responses (see WEB-007).",
            )
        if not ctx.headers_available:
            return self.unable_to_determine("Response headers were not available.")

        value = ctx.header("strict-transport-security")
        if value is None:
            return self.finding(
                ctx,
                status=CheckStatus.MISSING,
                summary="Header not present.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "The HTTPS response did not include a Strict-Transport-Security header."
                ),
                location=ctx.headers_location,
                rationale=self._rationale,
                evidence={"header": "Strict-Transport-Security", "value": None},
                recommendation=(
                    "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on "
                    "HTTPS responses once you're sure every subdomain supports HTTPS."
                ),
            )

        max_age, flags = _parse_hsts(value)
        evidence = {"header": "Strict-Transport-Security", "value": value, "max_age": max_age}
        if max_age is None or max_age == 0:
            reason = "has no valid max-age" if max_age is None else "sets max-age=0"
            return self.finding(
                ctx,
                status=CheckStatus.MISCONFIGURED,
                summary=f"Header {reason}, so HSTS is not in effect.",
                title="Ineffective Strict-Transport-Security header",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    f"The Strict-Transport-Security header {reason}. Browsers will not "
                    "enforce HTTPS-only connections based on it."
                ),
                location=ctx.headers_location,
                rationale=self._rationale,
                evidence=evidence,
                recommendation="Set a valid max-age of at least 15552000 seconds (180 days).",
            )
        if max_age < HSTS_MIN_MAX_AGE:
            return self.finding(
                ctx,
                status=CheckStatus.WEAK,
                summary=f"max-age={max_age} is shorter than 180 days.",
                title="Short Strict-Transport-Security max-age",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    f"HSTS is enabled, but max-age is {max_age} seconds "
                    f"(about {max_age // 86_400} days)."
                ),
                location=ctx.headers_location,
                rationale=(
                    "A short max-age means browsers forget the HTTPS-only policy quickly, which "
                    "reopens the window for downgrade attacks on users who visit infrequently. "
                    "Short values are sometimes used deliberately while rolling HSTS out."
                ),
                evidence=evidence,
                recommendation=(
                    "Once HTTPS is stable, increase max-age to at least 15552000 (180 days); "
                    "31536000 (1 year) is common."
                ),
            )

        extras = ", ".join(sorted(flags & {"includesubdomains", "preload"}))
        return self.outcome(
            CheckStatus.PASS,
            f"max-age={max_age}" + (f" ({extras})" if extras else "") + ".",
        )
