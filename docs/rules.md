# WebGuard Rule Catalog

Every finding comes from one of these deterministic rules (`backend/app/rules/`). Each rule has positive and
negative unit tests in `backend/tests/unit/rules/`.

**Severity** estimates potential impact if the weakness matters for this site. **Confidence** says how sure we
are that the observation is accurate and relevant. The two are reported separately.

Every rule also reports a **check status**:

| Status | Meaning |
|---|---|
| `PASS` | The control is present and looks reasonable. |
| `MISSING` | The control is absent. |
| `WEAK` | The control is present, but configured permissively. |
| `MISCONFIGURED` | The control is present, but invalid or ineffective. |
| `NOT_APPLICABLE` | The check doesn't apply, e.g. HSTS on an HTTP page. |
| `UNABLE_TO_DETERMINE` | The required data wasn't collected. **No finding is produced.** |

## Summary

| ID | Title | Category | Severity / Confidence |
|---|---|---|---|
| WEB-001 | Missing Content-Security-Policy | HTTP_SECURITY | MEDIUM / HIGH |
| WEB-002 | Missing Strict-Transport-Security header | TRANSPORT | MEDIUM / HIGH (missing or ineffective) · LOW / HIGH (short max-age) |
| WEB-003 | Missing X-Content-Type-Options header | HTTP_SECURITY | LOW / HIGH |
| WEB-004 | Mixed content detected | MIXED_CONTENT | MEDIUM / HIGH (active or form) · LOW / HIGH (passive only) |
| WEB-005 | Missing clickjacking protection | HTTP_SECURITY | LOW / MEDIUM |
| WEB-006 | Referrer-Policy not set | HTTP_SECURITY | INFORMATIONAL / HIGH (missing or invalid) · LOW / HIGH (leaky) |
| WEB-007 | Page not served over HTTPS | TRANSPORT | HIGH / HIGH |
| WEB-008 | Content-Security-Policy allows risky script sources | HTTP_SECURITY | LOW / MEDIUM |

## Rule details

### WEB-001: Missing Content-Security-Policy
- **PASS:**
  - An enforced `Content-Security-Policy` header is present, **or**
  - a `<meta http-equiv="Content-Security-Policy">` tag is present (noted, because meta CSP can't use
    `frame-ancestors`, `sandbox` or reporting directives).
- **MISSING:** neither exists. `Content-Security-Policy-Report-Only` alone still counts as missing, because it
  doesn't block anything. Its value is included in the evidence.
- **Why this severity:** CSP is defense in depth. Not having one doesn't make a site vulnerable by itself.

### WEB-002: Strict-Transport-Security
- **NOT_APPLICABLE** on HTTP pages, because browsers ignore HSTS sent over HTTP.
- **MISSING** (MEDIUM): no header.
- **MISCONFIGURED** (MEDIUM): `max-age` is missing, unparseable or `0`, so HSTS is not in effect.
- **WEAK** (LOW): `max-age` is below 15552000 (180 days).
- Only the first value counts when the header is repeated, matching browser behavior.

### WEB-003: X-Content-Type-Options
- **MISSING:** no header.
- **MISCONFIGURED:** the value isn't `nosniff` (case-insensitive).

### WEB-004: Mixed content
- **NOT_APPLICABLE** on HTTP pages.
- The collector reports `http:` URLs found in the DOM (`script`, `link[rel=stylesheet|icon]`, `iframe`, `img`,
  media, `object`/`embed`, `form[action]`, `[formaction]`) and in the Performance timeline.
- **Severity:**
  - **Active** content (scripts, styles, frames, objects, fetches, fonts) or **forms** that submit over HTTP →
    MEDIUM.
  - **Passive** content only (images, media) → LOW.
- Modern browsers block active mixed content and upgrade or flag passive content, so the practical impact is
  often broken functionality. The finding says so.
- At most 50 resources are reported. `truncated: true` in the evidence means more may exist.

### WEB-005: Clickjacking protection
- **PASS:**
  - a header-delivered CSP `frame-ancestors` that isn't just `*`, **or**
  - `X-Frame-Options: DENY|SAMEORIGIN`.
- **`frame-ancestors` in a `<meta>` CSP is ignored**, matching the CSP spec.
- **MISCONFIGURED:** `X-Frame-Options` has some other value, such as the obsolete `ALLOW-FROM`.
- **Why medium confidence:** the risk depends on whether the page has state-changing UI.

### WEB-006: Referrer-Policy
- **Policy sources:** a `<meta name="referrer">` overrides the header. When the value lists several tokens,
  the last recognized token is the one in effect, as in browsers.
- **MISSING** (INFORMATIONAL): browsers default to `strict-origin-when-cross-origin`, which is reasonable.
- **MISCONFIGURED** (INFORMATIONAL): no recognized token, so the browser default applies.
- **WEAK** (LOW): `unsafe-url` or `no-referrer-when-downgrade`, which send full URLs to other origins.

### WEB-007: HTTPS
- **PASS:** the page is HTTPS.
- **NOT_APPLICABLE:** `localhost`, `127.0.0.1`, `::1` and `*.localhost`.
- **MISSING** (HIGH): any other HTTP page.

### WEB-008: Weak CSP script sources
- Evaluates every enforced policy, from the header and from `<meta>`. The browser enforces **all** policies,
  so a weakness is reported only if **every** policy has it.
- **Issues detected:**
  - **no-script-restriction:** no `script-src` and no `default-src`.
  - **unsafe-inline:** `'unsafe-inline'` with no nonce or hash. Browsers ignore it when a nonce or hash is
    present, or when `'strict-dynamic'` is set.
  - **unsafe-eval:** `'unsafe-eval'` is present.
  - **broad-source:** `*`, `http:`, `https:` or `data:` is allowed. Not reported when `'strict-dynamic'` is
    set, because browsers then ignore host and scheme allowlists.
- **NOT_APPLICABLE:** there's no enforced CSP (WEB-001 covers that case).

## Adding a rule
1. Subclass `SecurityRule` in a module under `backend/app/rules/`. Give it the next `WEB-NNN` ID, `version = 1`,
   a category, a title and at least one reference, then decorate it with `@register`.
2. Return `unable_to_determine(...)` whenever an input wasn't collected. Never guess.
3. Add positive and negative tests under `backend/tests/unit/rules/`.
4. Add the rule to this catalog. Bump `version` whenever the rule's logic changes.
