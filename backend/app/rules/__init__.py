"""Security rules. Importing this package registers every built-in rule."""

from app.rules import headers, mixed_content, transport  # noqa: F401  (registers rules)
from app.rules.registry import registry

__all__ = ["registry"]
