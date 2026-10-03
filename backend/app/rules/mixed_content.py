"""Mixed content: an HTTPS page referencing resources or form targets over plain HTTP."""

from collections import Counter

from app.analyzers.context import ScanContext
from app.rules.base import RuleOutcome, SecurityRule
from app.rules.registry import register
from app.schemas.finding import Category, CheckStatus, Confidence, Severity

# "Active" content can change the page's behavior if tampered with; browsers block it.
# "Passive" (display) content is auto-upgraded to HTTPS by modern browsers or shown with a warning.
ACTIVE_KINDS = frozenset({"script", "stylesheet", "iframe", "object", "fetch", "font"})
PASSIVE_KINDS = frozenset({"image", "media", "other"})


def _group(kind: str) -> str:
    if kind == "form":
        return "form"
    return "active" if kind in ACTIVE_KINDS else "passive"


@register
class MixedContentRule(SecurityRule):
    id = "WEB-004"
    version = 1
    category = Category.MIXED_CONTENT
    title = "Mixed content detected"
    check_name = "Mixed content"
    references = (
        "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
        "https://web.dev/articles/what-is-mixed-content",
    )

    def evaluate(self, ctx: ScanContext) -> RuleOutcome:
        if not ctx.is_https:
            return self.outcome(
                CheckStatus.NOT_APPLICABLE,
                "Mixed content only applies to HTTPS pages (see WEB-007).",
            )
        collected = ctx.mixed_content
        if collected is None:
            return self.unable_to_determine("Page resources were not collected.")
        if not collected.resources:
            return self.outcome(CheckStatus.PASS, "No http:// resources or form targets found.")

        counts = Counter(_group(r.kind) for r in collected.resources)
        has_active_or_form = counts["active"] > 0 or counts["form"] > 0
        parts = [f"{counts[g]} {g}" for g in ("active", "passive", "form") if counts[g]]
        return self.finding(
            ctx,
            status=CheckStatus.MISCONFIGURED,
            summary=", ".join(parts) + " insecure reference(s).",
            severity=Severity.MEDIUM if has_active_or_form else Severity.LOW,
            confidence=Confidence.HIGH,
            description=(
                "The HTTPS page references resources or form targets over unencrypted HTTP ("
                + ", ".join(parts)
                + ")."
            ),
            location=f"Page content of {ctx.url}",
            rationale=(
                "Content fetched over HTTP can be read or modified in transit. Modern browsers "
                "block active mixed content (scripts, styles, frames) and upgrade or flag passive "
                "content (images, media), so the practical impact is often broken functionality; "
                "older browsers may load it. Forms that submit to http:// send user input "
                "unencrypted."
            ),
            evidence={
                "counts": dict(counts),
                "resources": [r.model_dump() for r in collected.resources],
                "truncated": collected.truncated,
            },
            recommendation=(
                "Load every resource and submit every form over https://. Consider "
                "`Content-Security-Policy: upgrade-insecure-requests` as a transitional measure."
            ),
        )
