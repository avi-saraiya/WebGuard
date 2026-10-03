# WebGuard

A Chrome extension and FastAPI backend that analyze the **observable security posture** of the website in the
active tab and report evidence-based findings with severity, confidence and remediation guidance.

WebGuard does not label websites "safe" or "malicious", and it doesn't give a headline score. Every finding
comes from an explicit, tested rule and shows the evidence behind it.

> **Status: v0.2 (Milestone 1).** HTTPS, security headers and mixed content are analyzed. See the
> [project specification](docs/WebGuard_Project_Specification.md) for the roadmap.

## What it checks

| Rule | Check |
|---|---|
| WEB-001 | Content-Security-Policy present |
| WEB-002 | Strict-Transport-Security present and long-lived |
| WEB-003 | X-Content-Type-Options: nosniff |
| WEB-004 | Mixed content (http: scripts, styles, frames, images, form targets on HTTPS pages) |
| WEB-005 | Clickjacking protection (CSP frame-ancestors / X-Frame-Options) |
| WEB-006 | Referrer-Policy |
| WEB-007 | Page served over HTTPS |
| WEB-008 | Risky CSP script sources ('unsafe-inline', 'unsafe-eval', wildcards) |

Full logic, severities and rationale are in the [rule catalog](docs/rules.md).

## How it works

```text
Popup ─▶ Service worker ─▶ Collector (in page, via activeTab)
                 │            allowlisted headers · <meta> policies · http: resource URLs
                 ▼
          FastAPI /api/v1/scans ─▶ Rule engine ─▶ findings + per-rule checks ─▶ Popup
```

Only minimal, privacy-filtered data leaves the browser: no cookies, page content or form values, and query
strings are stripped. See the [security & privacy model](docs/security.md) and the
[architecture](docs/architecture.md).

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

Then load the extension:
1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select `extension/dist`.
4. Visit a site, click WebGuard, and press **Run Scan**.

### Try it on known configurations

`tools/fixture-site` serves pages with deliberately good and bad configurations. Each page states the findings
you should expect to see.

```bash
python3 tools/fixture-site/serve.py --https   # https://localhost:8443 (self-signed; click through the warning)
```

## Development

```bash
make test           # pytest + vitest
make lint           # ruff, mypy, eslint, prettier, tsc
make format         # auto-format backend + extension
```

Further reading: [backend](backend/README.md) · [extension](extension/README.md) · [rules](docs/rules.md) ·
[security](docs/security.md) · [architecture](docs/architecture.md).

## Limitations

- Headers come from a cookieless re-fetch of the page, which can differ from the logged-in response.
- Each scan covers the current page at one point in time. It isn't a site-wide crawl.
- No findings does **not** mean a site is secure. It only means these checks found nothing.

More detail: [docs/security.md](docs/security.md#known-limitations).
