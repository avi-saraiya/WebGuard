# WebGuard Architecture

> Status: v0.1 skeleton. The analysis engine and the in-page collector arrive in Milestone 1 (v0.2).

## Overview

```text
 ┌──────────────────────── Chrome ────────────────────────┐
 │                                                        │
 │  Popup (React)  ──message──▶  Service worker           │
 │       ▲                         │   │                  │
 │       └──────── result ─────────┘   │ executeScript    │
 │                                     ▼ (v0.2)           │
 │                              Collector (in page)       │
 └─────────────────────────────────────┼──────────────────┘
                                       │ HTTPS / JSON
                                       ▼
                        FastAPI  /api/v1/scans
                                       │
                                       ▼
                         Rule engine (v0.2) → findings
```

1. The user opens the popup. The popup reads the active tab URL, which the `activeTab` grant makes available.
2. **Run Scan** sends `RUN_SCAN` to the service worker. The worker owns the scan so it finishes even if the
   popup closes. The worker only accepts messages from the extension's own pages.
3. The worker sends the page's signals to the backend. In v0.1 that is just the URL, with query and fragment
   stripped.
4. The backend validates the request, runs the rules (a mock in v0.1) and returns findings and checks.
5. The worker caches the result per tab in `chrome.storage.session`, which is memory-only and cleared when
   the browser closes, and returns it to the popup.

## Components

### Extension (`extension/`)
| Piece | Responsibility |
|---|---|
| `src/popup/` | React UI: current site, scan state, results |
| `src/background/service-worker.ts` | Message routing, sender validation, cache cleanup |
| `src/background/scan.ts` | Scan orchestration: eligibility check → backend call → cache |
| `src/services/api.ts` | Typed backend client with timeout and error-envelope handling |
| `src/types/scan.ts` | TypeScript mirror of the backend schemas |

### Backend (`backend/`)
| Piece | Responsibility |
|---|---|
| `app/main.py` | App factory, router and middleware wiring |
| `app/core/config.py` | Settings from `WEBGUARD_*` env vars |
| `app/core/middleware.py` | Request IDs and access logs, body size limit |
| `app/core/errors.py` | Uniform `{"error": {...}}` responses that never echo input |
| `app/core/logging.py` | JSON structured logging |
| `app/schemas/` | Pydantic request/response models (Finding, CheckResult, ScanResponse) |

## Dependency decisions

| Dependency | Why |
|---|---|
| **FastAPI + Pydantic v2** | Typed request validation and an OpenAPI schema with very little boilerplate. Required by the spec. |
| **pydantic-settings** | Env-based config with validation, so no secrets live in code. |
| **uv** | One tool for the Python version, virtualenv and lockfile. Fast and reproducible in CI and Docker. |
| **httpx2** (dev) | The HTTP client that Starlette's `TestClient` now expects. |
| **ruff, mypy (strict)** | Lint, format and type safety for the backend. |
| **Vite (plain, multi-entry)** | Builds the popup and service worker without an extension-specific plugin. CRXJS was considered and rejected: the manifest is small and static, so one less dependency outweighs HMR convenience. |
| **React 19** | The spec asks for React, and 19 is the current stable release. |
| **Vitest + Testing Library + jsdom** | Share Vite's transform pipeline and test the UI the way users interact with it. |
| **ESLint (typescript-eslint, react-hooks) + Prettier** | Catches correctness problems and keeps formatting consistent. `no-eval`/`no-new-func` are enforced. |

## Infrastructure
- `infrastructure/docker/backend.Dockerfile`: a multi-stage build (uv build stage, slim runtime). The image runs
  as a non-root user, has a healthcheck, and starts in production mode by default, which disables `/docs`.
- `infrastructure/docker/docker-compose.yml`: the local stack. It binds to `127.0.0.1` only and runs with a
  read-only root filesystem, all capabilities dropped and `no-new-privileges`.
- `.github/workflows/ci.yml`: the backend job runs lint, types and tests. The extension job runs lint, tests,
  build and `npm audit`, then uploads `dist/` as an artifact. A third job builds the Docker image.
- `.github/dependabot.yml`: weekly updates for uv, npm, Docker and GitHub Actions.
