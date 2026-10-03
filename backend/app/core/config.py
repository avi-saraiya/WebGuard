"""Application settings, loaded from environment variables prefixed with ``WEBGUARD_``."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

# Matches any unpacked or published Chrome extension origin (IDs are 32 chars, a-p).
# Production deployments should pin the exact published extension ID instead.
DEFAULT_CORS_ORIGIN_REGEX = r"^chrome-extension://[a-p]{32}$"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WEBGUARD_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    cors_origin_regex: str = DEFAULT_CORS_ORIGIN_REGEX
    # Scan payloads are small, structured summaries; anything larger is rejected early.
    max_request_body_bytes: int = 256 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
