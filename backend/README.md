# WebGuard Backend

FastAPI service that runs WebGuard's deterministic security rules against the signals the extension collects.

```bash
uv sync                                         # install Python 3.12 + dependencies
uv run uvicorn app.main:app --reload --port 8000
uv run pytest
uv run ruff check . && uv run mypy app
```

Configuration comes from environment variables prefixed `WEBGUARD_` (see `app/core/config.py` and `.env.example`).
