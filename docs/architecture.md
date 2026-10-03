# WebGuard Architecture

> Status: v0.2 (Milestone 1). The deterministic rule engine and in-page collector are implemented. There is no database yet.

## Overview

```text
 ┌──────────────────────── Chrome ────────────────────────┐
 │                                                        │
 │  Popup (React)  ──message──▶  Service worker           │
 │       ▲                         │   │                  │
 │       └──────── result ─────────┘   │ executeScript    │
 │                                     ▼                  │
 │                              Collector (in page)       │
 └─────────────────────────────────────┼──────────────────┘
                                       │ HTTPS / JSON
                                       ▼
                        FastAPI  /api/v1/scans
                                       │
                                       ▼
              Rule engine (WEB-001…008) → findings + checks
```

1. The user opens the popup. The popup reads the active tab URL, which the `activeTab` grant makes available.
2. **Run Scan** sends `RUN_SCAN` to the service worker. The worker owns the scan so it finishes even if the
   popup closes. The worker only accepts messages from the extension's own pages.
3. The worker injects `collectPageSignals` into the tab with `chrome.scripting.executeScript`. The collector
   gathers:
   - allowlisted security headers, via a cookieless same-origin HEAD re-fetch
   - `<meta>` CSP and referrer tags
   - `http:` resource URLs, with query strings stripped

   It sends progress updates ("collecting", then "analyzing") to the popup. If injection fails, the scan
   continues with the URL only.
4. The worker POSTs the URL and signals to the backend. The backend validates them, builds a `ScanContext`,
   and runs every registered rule. Each rule returns a check status and, only when there is evidence, a
   finding. If a rule crashes, its check becomes `UNABLE_TO_DETERMINE` and the rest of the scan continues
   (partial results).
5. The worker caches the result per tab in `chrome.storage.session`, which is memory-only and cleared when
   the browser closes, and returns it to the popup.

## Components

### Extension (`extension/`)
| Piece | Responsibility |
|---|---|
| `src/popup/` | React UI: current site, scan state, results |
| `src/background/service-worker.ts` | Message routing, sender validation, cache cleanup |
| `src/background/scan.ts` | Scan orchestration: eligibility check → inject collector → backend call → cache |
| `src/collector/collectPageSignals.ts` | Self-contained function injected into the page; reads headers, meta policies, insecure URLs |
| `src/popup/pages/` | Results page (summary, findings, checks) and finding detail view |
| `src/components/` | Severity summary and badges, finding cards, checks list, evidence view, inline code text |
| `src/services/messaging.ts` | Typed popup ↔ service worker messages, including scan progress updates |
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
| `app/schemas/` | Pydantic request/response models (ScanRequest, Finding, CheckResult, ScanResponse) |
| `app/analyzers/context.py` | `ScanContext`: a normalized, read-only view of the request that rules evaluate |
| `app/analyzers/csp.py` | CSP parser that handles multiple policies |
| `app/analyzers/engine.py` | Runs every rule in isolation, sorts findings, counts severities, adds notices |
| `app/rules/` | `SecurityRule` base class, `@register` registry, and the rules themselves (see [rules.md](rules.md)) |

## Rule engine

The spec schedules the rule engine for v0.5. It was built early so that analyzers never need restructuring.
Each rule is a small class with an ID (`WEB-NNN`), a version, a category, references, a problem-phrased
`title` (used for its finding) and a neutral `check_name` (used in the checks list). It implements
`evaluate(ctx) -> RuleOutcome`. Rules never perform I/O; they only interpret the collected
signals. That keeps them deterministic and easy to test.

The collector runs in the browser and not on the server for three reasons:
- **No SSRF:** the backend never fetches arbitrary URLs.
- **Accurate data:** the analysis uses what the user's browser actually received, including `<meta>`
  policies and the resources the page actually loaded.
- **Narrow permissions:** `activeTab` scopes access to the page the user chose to scan.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness check and API version |
| `POST` | `/api/v1/scans` | Analyze collected signals; returns findings, checks, severity summary, `partial` and `notices` |

The request schema is `ScanRequest` in `backend/app/schemas/scan.py`, mirrored in `extension/src/types/scan.ts`.
Every error uses the shape `{"error": {"code", "message", "request_id", "details?"}}`. OpenAPI docs are served
at `/docs` outside production.

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
