# WebGuard Security & Privacy Model

WebGuard is a security tool, and it treats itself as security-sensitive software (spec §44). This document
covers:

- the permissions the extension requests
- what data it reads and sends
- how it is protected
- what it cannot tell you

## Extension permissions

| Permission                                  | Why it's needed                                                                                                                                                         |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `activeTab`                                 | Grants temporary access to the tab you're viewing **only after you click WebGuard**, so the collector can run on that page. It replaces broad `<all_urls>` host access. |
| `scripting`                                 | Lets the service worker inject the collector (`chrome.scripting.executeScript`) into that tab.                                                                          |
| `storage`                                   | Caches the last scan result per tab in `chrome.storage.session`. That storage is memory-only and cleared when the browser closes.                                       |
| `host_permissions: http://localhost:8000/*` | Lets the extension call the WebGuard backend. This is the only host it can reach on its own.                                                                            |

The extension deliberately does **not** request:

- **`<all_urls>`:** it never runs on pages you haven't asked it to scan.
- **`webRequest`:** it doesn't watch your browsing traffic.
- **`cookies`:** it doesn't read cookie values. Cookie analysis is planned for a later version and will need a
  separately justified permission.
- **`tabs`:** `activeTab` already provides the URL of the tab you clicked on.

The extension also sets its own strict CSP (`script-src 'self'; object-src 'none'; base-uri 'none'`). ESLint
forbids `eval` and `new Function` in product code; the one exception is a test that checks the collector can
be serialized.

## What data leaves the browser

When you click **Run Scan**, the collector runs once in the page and the following is sent to the backend:

| Sent                      | Detail                                                                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Page URL                  | Scheme, host, port and path. **The query string and fragment are removed** in the extension and again on the server.                                                                                                                        |
| Security response headers | Only these: `Content-Security-Policy`, `Content-Security-Policy-Report-Only`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. The API **rejects** any other header name. |
| `<meta>` policies         | The contents of CSP `http-equiv` tags and the `referrer` meta tag.                                                                                                                                                                          |
| Insecure resource URLs    | Only `http:` URLs, with query string and fragment removed, capped at 50, each labeled by type (script, image, form, …).                                                                                                                     |

**Never** read or sent: cookies, `localStorage`/`sessionStorage`, page text or HTML, form field values,
passwords, authentication tokens, or the full list of `https:` resources.

### How headers are obtained

The collector makes a **same-origin re-fetch** of the page URL:

- `HEAD`, falling back to `GET` if HEAD isn't allowed, in which case the body is discarded unread
- `credentials: "omit"`, so no cookies or auth headers are sent with it
- `cache: "no-store"`

Browsers expose every response header to same-origin `fetch` except `Set-Cookie`. The collector copies only
the allowlisted ones.

Side effects: this is one extra request to the site you're scanning. It never goes to any third party.

## Backend protections

- **Strict input validation** (Pydantic, `extra="forbid"`): every field has a type, a length limit and an
  allowlist. URLs must be http(s), may not contain credentials, and are normalized.
- **Request body limit** (256 KB by default), which also covers chunked uploads.
- **CORS:** only `chrome-extension://` origins are allowed. Production should pin the exact extension ID
  (`WEBGUARD_CORS_ORIGIN_REGEX`).
- **Error responses** use one consistent shape and **never echo the submitted input**.
- **Structured logs** carry request IDs and record paths only, never query strings or request bodies.
- **Configuration:** settings come from environment variables only, and no secrets are stored in either code
  base.
- **Container hardening:**
  - the process runs as a non-root user
  - the root filesystem is read-only
  - all Linux capabilities are dropped and `no-new-privileges` is set
  - in local compose, the port binds to loopback only
- **Production mode** disables the OpenAPI docs. The container also suppresses uvicorn's `Server` header.
- **Dependency hygiene:** Dependabot runs weekly for uv, npm, Docker and GitHub Actions, and CI runs
  `npm audit`.

## Threat model (Milestone 1)

| Threat                                                                                                               | Mitigation                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A malicious page tampers with what the collector reports, e.g. by overriding `fetch` or `document.querySelectorAll`. | The collector runs in Chrome's isolated world, so page scripts can't alter its globals. A page can still serve misleading markup to itself, so findings describe what was **observed**, not proof.                                       |
| A web page sends messages to the service worker to trigger scans.                                                    | The worker accepts messages only from the extension's own pages: `sender.id` must match and `sender.url` must be on the extension's origin. Content scripts and web pages are rejected. The popup checks progress messages the same way. |
| A backend response injects content into the popup.                                                                   | React escapes all text. No `dangerouslySetInnerHTML` is used. Reference links are rendered only for `http(s):` URLs, with `rel="noopener noreferrer"`.                                                                                   |
| A third party abuses the backend.                                                                                    | Only extension origins pass CORS. Request size and field lengths are capped. _Rate limiting is planned for a later milestone._                                                                                                           |
| Sensitive URL data leaks to the backend.                                                                             | Query strings and fragments are stripped twice, in the extension and on the server. Log lines include paths only.                                                                                                                        |
| Scan results persist after the session.                                                                              | Results live only in `chrome.storage.session`, and the backend is stateless (no database yet).                                                                                                                                           |

## Known limitations

- **Re-fetched headers may differ from the original response.** The cookieless re-fetch may get a different
  response than your logged-in page did, for example a redirect to a login page or different CDN behavior.
- **Point-in-time, single-page view.** Only the current page is checked. Other pages on the same site may be
  configured differently.
- **Only what's visible at scan time is reported.** Mixed content is detected from the DOM and the Performance
  timeline at the moment of the scan. Resources added later, or loaded inside cross-origin frames, are not
  seen.
- **Absence of a finding is not proof of security.** It only means these specific checks didn't detect an
  issue.
- **Pages Chrome protects** (`chrome://`, the Chrome Web Store, other extensions' pages) can't be scanned.
- **Over plain HTTP the backend URL is unencrypted.** Production deployments must serve the API over HTTPS
  and update `VITE_API_BASE_URL` and `host_permissions` to match.
