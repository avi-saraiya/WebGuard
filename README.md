# WebGuard

A Chrome extension and FastAPI backend that analyze the **observable security posture** of the website in the
active tab and report evidence-based findings with severity, confidence, and remediation guidance.

WebGuard does not label websites "safe" or "malicious". Each finding comes from an explicit, tested rule and
includes the evidence behind it.

> Status: early development (v0.1 skeleton). See the [project specification](docs/WebGuard_Project_Specification.md)
> for the full roadmap.

## Repository layout

```
extension/       Chrome extension (Manifest V3, TypeScript, React)
backend/         FastAPI analysis API (Python 3.12, uv)
infrastructure/  Docker and deployment configuration
tools/           Development utilities
docs/            Specification, architecture, and security documentation
```

## Quick start

Prerequisites: [uv](https://docs.astral.sh/uv/), Node.js 22+, and Chrome. Docker is optional.

```bash
make install        # backend (uv) + extension (npm) dependencies
make dev-backend    # API on http://localhost:8000
make build          # extension → extension/dist
```

Alternatively, run the backend in Docker:

```bash
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

Then load `extension/dist` in Chrome via `chrome://extensions` → **Developer mode** → **Load unpacked**.

## Development

```bash
make test           # pytest + vitest
make lint           # ruff, mypy, eslint, prettier, tsc
make format         # auto-format backend + extension
```

Further reading: [architecture](docs/architecture.md), [backend](backend/README.md), [extension](extension/README.md).
