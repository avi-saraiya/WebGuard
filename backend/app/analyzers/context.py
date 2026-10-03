"""Normalized, read-only view of a scan request that rules evaluate against."""

from dataclasses import dataclass
from datetime import datetime
from functools import cached_property
from urllib.parse import urlsplit

from app.analyzers.csp import Policy, parse_policies, parse_policy
from app.schemas.scan import MixedContentCollection, ScanRequest

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class ScanContext:
    request: ScanRequest
    scanned_at: datetime

    @property
    def url(self) -> str:
        return self.request.url

    @cached_property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @cached_property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def is_local(self) -> bool:
        return self.host in LOCAL_HOSTS or self.host.endswith(".localhost")

    @property
    def headers_available(self) -> bool:
        headers = self.request.headers
        return headers is not None and headers.status == "collected"

    def header(self, name: str) -> str | None:
        """Header value (lowercase name), or ``None`` when absent or headers weren't collected."""
        if not self.headers_available or self.request.headers is None:
            return None
        value = self.request.headers.values.get(name.lower())
        return value.strip() if value is not None and value.strip() else None

    @cached_property
    def header_csp_policies(self) -> list[Policy]:
        return parse_policies(self.header("content-security-policy"))

    @cached_property
    def meta_csp_policies(self) -> list[Policy]:
        policies = (parse_policy(value) for value in self.request.meta.content_security_policy)
        return [policy for policy in policies if policy.directives]

    @property
    def enforced_csp_policies(self) -> list[Policy]:
        """Every enforced policy, from headers and ``<meta>``; Report-Only is excluded."""
        return self.header_csp_policies + self.meta_csp_policies

    @property
    def mixed_content(self) -> MixedContentCollection | None:
        return self.request.mixed_content

    @property
    def headers_location(self) -> str:
        return f"HTTP response headers of {self.url}"
