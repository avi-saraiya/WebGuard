"""Rule registry. Rules self-register with ``@register`` when their module is imported."""

import re

from app.rules.base import SecurityRule

RULE_ID_PATTERN = re.compile(r"^WEB-\d{3}$")


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}

    def register[R: type[SecurityRule]](self, rule_cls: R) -> R:
        rule_id = rule_cls.id
        if not RULE_ID_PATTERN.match(rule_id):
            raise ValueError(f"Invalid rule id {rule_id!r}; expected WEB-NNN")
        if rule_id in self._rules:
            raise ValueError(f"Duplicate rule id {rule_id}")
        self._rules[rule_id] = rule_cls()
        return rule_cls

    def all(self) -> list[SecurityRule]:
        return [self._rules[rule_id] for rule_id in sorted(self._rules)]

    def get(self, rule_id: str) -> SecurityRule:
        return self._rules[rule_id]


registry = RuleRegistry()
register = registry.register
