# WebGuard — Project Context

WebGuard is a Chrome extension (Manifest V3, TypeScript, React) plus a FastAPI backend that analyzes the
**observable security posture** of the website in the active tab and returns evidence-based findings with
severity, confidence and remediation. It is a portfolio project. It is **not** an antivirus and never declares
a site "safe" or "malicious".

Source of truth for scope and roadmap: [`docs/WebGuard_Project_Specification.md`](docs/WebGuard_Project_Specification.md).
Approved implementation plan for the current phase: `/root/.claude/plans/assume-the-role-of-eager-ladybug.md`.

## Core principles
- **Deterministic detection first; AI explanation second.** Rules decide findings; AI (from v1.1) only explains.
- **Every finding needs evidence.** Never invent a finding. If data is missing, the check is `UNABLE_TO_DETERMINE`.
- **Severity and confidence are separate fields.**
- **No headline score or safe/unsafe verdict.** Show counts by severity.
- **Privacy:** send the minimum to the backend. Never send cookies, form values, page content, tokens or query strings.
- **Least privilege:** don't add Chrome permissions without a documented reason in `docs/security.md`.
- **No secrets in the extension source**, ever. Backend secrets come from env vars.

## Agent rules (spec §51)
1. Don't overbuild: finish the current version before starting features from later versions.
2. Fit new code into the existing architecture.
3. Every analyzer/rule gets positive **and** negative tests before moving on.
4. Never invent security findings.
5. Keep detection (rule engine) separate from explanation (AI).
6. Minimize permissions.
7. Never expose secrets.
8. Document why each significant dependency or architectural component exists (`docs/architecture.md`).
9. Don't break existing analyzers or API contracts unnecessarily.
10. Treat WebGuard itself as security-sensitive software.

## Decisions log
- Monorepo at the repo root: `extension/`, `backend/`, `infrastructure/`, `tools/`, `docs/`.
- Backend: Python 3.12 managed by **uv** (`backend/pyproject.toml` + `uv.lock`). FastAPI, Pydantic v2, pydantic-settings.
- Extension: **plain Vite** with multiple inputs (popup + service worker); no CRXJS. React 19, TS strict,
  Vitest + Testing Library, ESLint + Prettier. `src/test/setup.ts` provides an in-memory `chrome` mock.
- The service worker owns scanning (survives popup close) and only accepts messages from our own extension pages.
- Page data collection: the service worker injects a self-contained collector via
  `chrome.scripting.executeScript({ func })`, authorized by `activeTab`. Headers come from a cookieless
  same-origin `HEAD` re-fetch (GET fallback). Only allowlisted security headers are sent. URLs have query and
  fragment stripped. No `<all_urls>`, no `webRequest`.
- Record the reason for every new significant dependency in the table in `docs/architecture.md`.
- Backend is **stateless** (no DB) until the persistence phase (v0.6). No `GET /scans/{id}` yet.
- The rule registry exists from day one (spec puts it at v0.5, pulled forward to avoid a refactor).

## Conventions
- Rule IDs are `WEB-NNN`, catalogued in `docs/rules.md`. A finding's `id` equals its rule ID (one finding per rule per scan).
- Finding fields: `id, rule_version, category, title, severity, confidence, description, location, rationale, evidence, recommendation, references, detected_at`.
- Severity: `CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL`. Confidence: `HIGH | MEDIUM | LOW`.
- Check status: `PASS | MISSING | WEAK | MISCONFIGURED | NOT_APPLICABLE | UNABLE_TO_DETERMINE`.
- Use cautious language in finding text ("potential", "may"). A detected pattern is not a proven vulnerability.
- One commit per implementation step, with a tag per version (`v0.1.0`, `v0.2.0`, …).

## Git
- End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (attribution re-enabled
  from Milestone 1 onward; commits up to `v0.1.0` have none).
- Remote: `origin` = https://github.com/avi-saraiya/WebGuard (private). Push only when asked.
- CI (`.github/workflows/ci.yml`) runs on push to `main` and on PRs.

## Commands
Run from the repo root (see `Makefile`):
- `make install`: install backend (uv) and extension (npm) dependencies
- `make test` / `make lint` / `make format` / `make build`
- `docker compose -f infrastructure/docker/docker-compose.yml up --build`: backend in Docker on 127.0.0.1:8000
- `make dev-backend`: run the API on http://localhost:8000 (OpenAPI docs at /docs outside production)
- Extension only (from `extension/`): `npm test`, `npm run lint`, `npm run typecheck`, `npm run build` → load `extension/dist` unpacked.
- Backend only (from `backend/`): `uv run pytest`, `uv run ruff check .`, `uv run mypy app tests`. uv lives in `~/.local/bin`.

## Current status / next steps
Phase: v0.1.0 tagged. Next: Milestone 1 (≈ v0.2), starting at step 5.

- [x] 0. CLAUDE.md + `.claude/settings.json`
- [x] 1. Repo bootstrap (git init, .gitignore, .editorconfig, spec → docs/, README stub, Makefile)
- [x] 2. Backend skeleton (uv, FastAPI, config/logging/errors/middleware, health, mock POST /scans, pytest/ruff/mypy)
- [x] 3. Extension skeleton (Vite React TS, manifest, service worker, popup + Run Scan → mock backend, Vitest)
- [x] 4. Docker, CI, dependabot, architecture.md stub → tag v0.1.0
- [ ] 5. Rule engine + schemas
- [ ] 6. Rules WEB-001…008 with tests
- [ ] 7. Collector (`collectPageSignals`) with jsdom tests
- [ ] 8. Popup UI (summary, checks table, findings, detail, error/partial states)
- [ ] 9. Docs (rules.md, security.md, README) + fixture site → tag v0.2.0
