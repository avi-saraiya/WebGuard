from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

EXTENSION_ORIGIN = "chrome-extension://" + "a" * 32


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", max_request_body_bytes=4096)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
