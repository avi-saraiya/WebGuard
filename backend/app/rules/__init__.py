"""Security rules. Importing this package registers every built-in rule."""

from app.rules.registry import registry

__all__ = ["registry"]
