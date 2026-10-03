# WebGuard Backend

FastAPI service that runs WebGuard's deterministic security rules against the signals the extension collects.

```bash
uv sync                                         # install Python 3.12 + dependencies
uv run uvicorn app.main:app --reload --port 8000
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy app tests
```

Configuration comes from environment variables prefixed `WEBGUARD_` (see `app/core/config.py` and `.env.example`).

## Endpoints
- `GET /api/v1/health`: liveness check and API version
- `POST /api/v1/scans`: analyze collected page signals. Returns findings, per-rule checks, a severity summary,
  `partial` and `notices`.

Interactive OpenAPI docs are at `/docs` when not running in production.

## Layout

| Path | Contents |
|---|---|
| `app/core/` | Settings, JSON logging, request-ID and body-size middleware, error envelope |
| `app/schemas/` | Pydantic request/response models |
| `app/analyzers/` | `ScanContext`, CSP parser, and the engine that runs every rule |
| `app/rules/` | `SecurityRule`, the registry, and rules WEB-001…008. See [`docs/rules.md`](../docs/rules.md) |
| `tests/` | Unit tests per rule (`tests/unit/rules/`), engine and parser tests, API contract tests |
