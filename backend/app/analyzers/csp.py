"""Minimal Content-Security-Policy parser (CSP Level 3 serialization rules).

A response may carry several policies (repeated headers are joined with ``,``), and the browser
enforces *all* of them: a resource loads only if every policy allows it. Callers must therefore
treat a weakness as effective only when every policy exhibits it.
"""

from dataclasses import dataclass, field

# Directive used for script loading, in fallback order.
SCRIPT_DIRECTIVES = ("script-src", "default-src")


@dataclass(frozen=True)
class Policy:
    raw: str
    directives: dict[str, list[str]] = field(default_factory=dict)

    def sources(self, directive: str) -> list[str] | None:
        return self.directives.get(directive)

    def script_sources(self) -> list[str] | None:
        """Effective script-src source list, or ``None`` if scripts are unrestricted."""
        for name in SCRIPT_DIRECTIVES:
            if name in self.directives:
                return self.directives[name]
        return None


def parse_policy(serialized: str) -> Policy:
    directives: dict[str, list[str]] = {}
    for token in serialized.split(";"):
        parts = token.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        # Per spec, only the first occurrence of a directive is honored.
        if name not in directives:
            directives[name] = [value.lower() for value in parts[1:]]
    return Policy(raw=serialized.strip(), directives=directives)


def parse_policies(header_value: str | None) -> list[Policy]:
    """Split a (possibly comma-joined) header value into individual policies."""
    if not header_value:
        return []
    policies = [parse_policy(part) for part in header_value.split(",")]
    return [policy for policy in policies if policy.directives]
