# WebGuard — Chrome Web Security Risk Analyzer

## 1. Project Overview

**Project name:** WebGuard  
**Project type:** Chrome Extension + Backend Security Analysis Platform  
**Primary goal:** Build a portfolio-grade Chrome extension that analyzes the security posture of websites and provides evidence-based, actionable findings to developers and security practitioners.

WebGuard should **not** attempt to act as a consumer antivirus product or claim that a website is definitively "safe" or "malicious." Instead, it should inspect observable web-security properties, identify potential weaknesses, explain the evidence behind each finding, and provide remediation guidance.

A central architectural principle is:

> **Deterministic security detection first; AI-assisted explanation second.**

The system should derive findings from explicit rules and observable evidence. AI may explain a finding in natural language, summarize results, or help generate remediation guidance, but AI should not be the sole mechanism deciding whether a security vulnerability exists.

---

# 2. Portfolio Objectives

The project should demonstrate strong software-engineering ability while leveraging cybersecurity knowledge.

## Software Engineering Skills

The finished project should demonstrate:

- TypeScript
- Chrome Extension APIs / Manifest V3
- React
- REST API design
- Python
- FastAPI
- PostgreSQL
- Authentication and authorization
- Asynchronous processing
- Caching
- Background jobs
- Automated testing
- CI/CD
- Docker
- Cloud deployment
- Logging and monitoring
- Error handling
- Data modeling
- API integration
- System architecture
- Documentation

## Cybersecurity Skills

The project should demonstrate practical knowledge of:

- HTTPS and TLS
- HTTP security headers
- Content Security Policy
- Cookie security
- Mixed content
- Third-party resources
- Web supply-chain security
- JavaScript security patterns
- Domain and IP reputation
- Technology fingerprinting
- CVE/vulnerability intelligence
- Security findings and severity
- Evidence-based security analysis
- False positives and confidence
- Security remediation

---

# 3. Product Philosophy

WebGuard should follow these principles throughout development.

## 3.1 Evidence over speculation

Every security finding should contain:

1. What was detected
2. Where it was detected
3. Why it matters
4. Evidence supporting the finding
5. Severity
6. Confidence
7. Recommended remediation

The system should avoid statements such as:

> "This website is dangerous."

Prefer:

> "The page contains a third-party script from an external domain. This increases the site's third-party attack surface."

## 3.2 Deterministic detection

Security findings should originate from explicit analyzers/rules.

Example:

```text
HTTP Response
      ↓
Header Analyzer
      ↓
CSP missing
      ↓
Finding
      ↓
Severity + Evidence
```

Not:

```text
HTTP Response
      ↓
LLM
      ↓
Security Score
```

## 3.3 AI is supplementary

AI can be used for:

- Explaining findings
- Summarizing reports
- Generating remediation explanations
- Answering questions about detected findings
- Translating technical findings into developer-friendly language

AI should not independently determine whether a security issue exists.

## 3.4 Security and privacy by design

The extension should collect the minimum information necessary.

Avoid sending:

- passwords
- form contents
- private page contents
- authentication tokens
- session cookies
- personal information

to the backend.

The system should clearly communicate what information is analyzed and what leaves the browser.

---

# 4. High-Level Architecture

```text
                         ┌──────────────────────┐
                         │      Chrome          │
                         │      Browser         │
                         └──────────┬───────────┘
                                    │
                                    ↓
                         ┌──────────────────────┐
                         │   Chrome Extension   │
                         │                      │
                         │ Popup UI             │
                         │ Content Script       │
                         │ Background Worker    │
                         │ Security Collectors  │
                         └──────────┬───────────┘
                                    │
                              HTTPS / REST
                                    │
                                    ↓
                         ┌──────────────────────┐
                         │     FastAPI API      │
                         └──────────┬───────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 ↓                  ↓                  ↓
        ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
        │ Analysis Engine│ │ PostgreSQL     │ │ External APIs  │
        │                │ │                │ │                │
        │ Header Rules   │ │ Users          │ │ Threat Intel   │
        │ Cookie Rules   │ │ Scans          │ │ CVE/NVD       │
        │ JS Rules       │ │ Findings       │ │ Technology DB  │
        │ Domain Rules   │ │ Technologies   │ │ Reputation     │
        └────────────────┘ └────────────────┘ └────────────────┘
                                    │
                                    ↓
                         ┌──────────────────────┐
                         │  Web Dashboard / UI  │
                         │                      │
                         │ Findings             │
                         │ History              │
                         │ Reports              │
                         │ Trends               │
                         └──────────────────────┘
```

---

# 5. Major System Components

## 5.1 Chrome Extension

The extension is the primary user interface.

Responsibilities:

- Detect the active tab
- Determine the current URL
- Collect browser-observable security information
- Inspect page resources
- Communicate with the backend
- Display scan status
- Display findings
- Display explanations
- Store minimal local state
- Trigger scans

The extension should use **Manifest V3**.

Recommended implementation:

```text
TypeScript
React
Chrome Extension APIs
Manifest V3
```

---

# 6. Extension UI

The extension should eventually contain the following screens.

## 6.1 Popup Dashboard

Example:

```text
WebGuard
────────────────────────────

example.com

Security Findings

🔴 1 High
🟠 2 Medium
🟡 3 Low
🟢 8 Informational

HTTP Security      4/6
Cookies            8/10
Third Parties      7/10
Transport          10/10

[View Findings]
[Run Full Scan]
```

## 6.2 Finding Details

Example:

```text
Missing Content-Security-Policy

Severity: Medium
Confidence: High

What was detected?
The response did not contain a CSP header.

Why does this matter?
A Content Security Policy can restrict where
scripts and other resources are allowed to load
from.

Evidence
Content-Security-Policy header: absent

Recommendation
Implement a CSP appropriate to the application's
resource requirements.

[Explain with AI]
```

## 6.3 Scan History

Example:

```text
Scan History

Oct 03   78   3 findings
Oct 02   74   5 findings
Oct 01   72   6 findings
```

## 6.4 Settings

Settings should eventually include:

- Backend URL
- Automatic scan preference
- AI explanation preference
- Data-sharing/privacy controls
- Theme
- Notification preferences
- Account
- API status

---

# 7. Security Analysis Modules

The final product should contain several independent analyzers.

---

## 7.1 HTTPS / Transport Security Analyzer

Checks:

- Whether the page uses HTTPS
- HTTP-to-HTTPS redirection
- Mixed content
- HSTS
- Secure cookie usage
- Transport-related configuration

Example finding:

```text
Mixed Content Detected

Severity: Medium
Confidence: High

The HTTPS page requested a resource over HTTP.

Evidence:
http://example.com/script.js
```

---

# 8. HTTP Security Header Analyzer

Analyze at minimum:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

The analyzer should distinguish between:

- Present
- Missing
- Weak
- Potentially misconfigured
- Not applicable
- Unable to determine

Example:

```text
HTTP Security Headers

✓ Strict-Transport-Security
✓ X-Content-Type-Options
⚠ Content-Security-Policy
✓ Referrer-Policy
✗ X-Frame-Options
```

The system should avoid claiming that a missing header automatically means the site is vulnerable.

---

# 9. Cookie Security Analyzer

Analyze cookie attributes where browser APIs make them observable.

Important properties:

- Secure
- HttpOnly
- SameSite
- Domain
- Path
- Expiration
- First-party vs third-party context

Example:

```text
session_id

✓ Secure
✓ HttpOnly
⚠ SameSite not explicitly configured
```

The analyzer should explain that the actual risk depends on how the cookie is used.

---

# 10. Third-Party Resource Analyzer

Identify external resources such as:

- JavaScript
- CSS
- Images
- Frames
- Fonts
- API requests
- Analytics
- Advertising
- CDNs

Example:

```text
Third-Party Resources

23 total
11 external domains

Categories:
Analytics       3
Advertising     4
CDN             2
Other           2
```

The analyzer should produce a domain/resource inventory.

---

# 11. JavaScript Analyzer

The JavaScript analyzer should initially focus on **static indicators**, not exploit attempts.

Potential checks:

- Dangerous DOM APIs
- `innerHTML`
- `outerHTML`
- `document.write`
- `eval`
- dynamic script creation
- inline scripts
- external scripts
- exposed source maps
- suspicious resource loading patterns

Important:

A detected pattern must not automatically be labeled an exploitable vulnerability.

Example:

```text
Potential DOM Injection Pattern

File:
https://example.com/js/app.js

Pattern:
innerHTML

Severity:
Informational / Low

Confidence:
Medium

Explanation:
The application uses innerHTML. This API can become
security-sensitive when user-controlled data is inserted
without appropriate sanitization.
```

---

# 12. Technology Fingerprinting

Identify technologies used by the site.

Possible categories:

- Frontend frameworks
- Backend frameworks
- JavaScript libraries
- CDNs
- Analytics
- Web servers
- Cloud providers
- CMS platforms

Example:

```text
Detected Technologies

Frontend
React
Next.js

Infrastructure
Cloudflare

Analytics
Google Analytics
```

Technology detection should be evidence-based using observable indicators.

---

# 13. Vulnerability Intelligence

Once technology and versions can be identified, the backend may query vulnerability databases.

Potential data sources:

- NVD
- Vendor advisories
- Official security advisories
- Other reputable vulnerability databases

The system should associate:

```text
Technology
     ↓
Version
     ↓
Known vulnerability
     ↓
CVE
     ↓
Finding
```

Important:

The system should distinguish:

- Confirmed version
- Inferred version
- Unknown version

It should not report a CVE as applicable solely because a technology family was detected.

---

# 14. Threat Intelligence

The backend may eventually integrate domain/IP reputation services.

Potential workflow:

```text
Observed Domain
       ↓
Normalize Domain
       ↓
Threat Intelligence API
       ↓
Reputation Result
       ↓
Finding
```

Possible results:

- No known indicators
- Known malicious indicator
- Suspicious
- Unknown
- Service unavailable

"Unknown" must not be interpreted as "safe."

---

# 15. Security Finding Data Model

Every finding should use a consistent structure.

Example:

```json
{
  "id": "WEB-001",
  "category": "HTTP_SECURITY",
  "title": "Missing Content-Security-Policy",
  "severity": "MEDIUM",
  "confidence": "HIGH",
  "description": "...",
  "evidence": {
    "header": "Content-Security-Policy",
    "value": null
  },
  "recommendation": "...",
  "detected_at": "..."
}
```

Severity values:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFORMATIONAL
```

Confidence values:

```text
HIGH
MEDIUM
LOW
```

Severity and confidence must remain separate.

---

# 16. Security Scoring

A score may be included as a secondary visualization.

Do not make the score the primary product output.

Prefer:

```text
1 High
2 Medium
3 Low
8 Informational
```

over:

```text
Website Security: 73/100
```

If a score is implemented, document:

- Exact scoring formula
- Categories
- Weighting
- Severity weights
- Confidence handling
- Unknown data
- Missing data
- Limitations

The score must not imply that a website has been proven safe or unsafe.

---

# 17. AI Explanation Layer

AI should be introduced after deterministic scanning is reliable.

Input:

```json
{
  "finding": "...",
  "evidence": "...",
  "technology": "...",
  "severity": "...",
  "confidence": "..."
}
```

AI output:

```text
What was detected?

Why does it matter?

What could cause the issue?

What should developers consider doing?

What are the limitations of this finding?
```

The AI should never invent evidence.

The prompt should explicitly tell the model:

- Use only supplied evidence
- Do not claim exploitation
- Do not invent vulnerabilities
- State uncertainty
- Distinguish potential weakness from confirmed vulnerability

---

# 18. Reporting

The final system should generate reports.

Example report structure:

```text
WebGuard Security Assessment

Target:
example.com

Scan Date:
October 3, 2026

Summary
────────────────────
1 High
2 Medium
3 Low
8 Informational

Findings
────────────────────

WEB-001
Missing CSP
Severity: Medium
Confidence: High

Evidence:
...

Recommendation:
...

WEB-002
...
```

Potential export formats:

- JSON
- CSV
- PDF
- HTML

---

# 19. Historical Analysis

The backend should retain scan results for authenticated users.

Example:

```text
example.com

Security Findings Over Time

Oct 1    6
Oct 2    5
Oct 3    3
```

The user should be able to compare scans.

Example:

```text
Previous Scan
────────────────
6 findings

Current Scan
────────────────
3 findings

Resolved:
WEB-002
WEB-004
WEB-007

New:
WEB-009
```

---

# 20. Authentication

Authentication should not be required for the initial MVP.

Introduce authentication once persistent scan history is implemented.

Possible implementation:

- Email/password
- OAuth
- JWT/session-based authentication

Security requirements:

- Password hashing
- Secure session management
- HTTPS
- CSRF protection where applicable
- Rate limiting
- Input validation
- Authorization checks

---

# 21. Database

Recommended database:

**PostgreSQL**

Initial entities:

```text
users
scans
findings
technologies
domains
scan_technologies
scan_resources
```

Potential relationships:

```text
User
  │
  └── Scan
        │
        ├── Finding
        ├── Resource
        └── Technology
```

---

# 22. Backend API

Potential endpoints:

```text
POST /api/v1/scans
GET  /api/v1/scans/{id}
GET  /api/v1/scans/{id}/findings
GET  /api/v1/scans/{id}/technologies

GET  /api/v1/domains/{domain}

POST /api/v1/findings/{id}/explain

POST /api/v1/reports
GET  /api/v1/reports/{id}
```

Authentication endpoints can be added later.

The API should use:

- Request validation
- Typed schemas
- Consistent error responses
- Authentication middleware
- Rate limiting
- Logging

---

# 23. MVP Definition

## MVP Goal

The MVP should prove the core concept:

> A Chrome extension can analyze a website's observable security configuration and return useful, evidence-based findings.

The MVP should be small enough to build reliably but substantial enough to demonstrate engineering ability.

## MVP Features

### Extension

- Manifest V3
- TypeScript
- React UI
- Active-tab URL detection
- Scan button
- Scan progress state
- Findings display
- Finding details

### Security analysis

Implement:

1. HTTPS detection
2. Mixed-content detection
3. Basic HTTP security-header analysis
4. Basic cookie analysis
5. Third-party resource enumeration
6. Basic technology detection

### Backend

- FastAPI
- REST API
- Request validation
- Analysis engine
- PostgreSQL optional for first MVP; SQLite may be used during local development

### Output

Each finding contains:

- Title
- Severity
- Confidence
- Description
- Evidence
- Recommendation

### MVP should NOT include

- AI
- User accounts
- Payments
- Complex threat intelligence
- Automated vulnerability exploitation
- Large-scale crawling
- Automatic background scanning
- Full PDF reports
- Complex scoring

The objective is to get a trustworthy scanning pipeline working first.

---

# 24. Version Roadmap

## Version 0.1 — Project Skeleton

### Objective

Establish the architecture and development environment.

### Features

- Monorepo
- Chrome extension
- React
- TypeScript
- FastAPI
- Basic API endpoint
- Docker development environment
- Basic CI pipeline
- README
- Unit-test framework

### Behavior

Clicking the extension should show:

```text
WebGuard

Current Site:
example.com

[Run Scan]
```

The button can initially return mock data.

---

# 25. Version 0.2 — First Real Scanner

### Features

- Active URL detection
- HTTPS detection
- Basic security headers
- Mixed-content detection
- Findings UI
- Severity
- Confidence
- Evidence

### Behavior

```text
Run Scan
   ↓
Collect website information
   ↓
Send to backend
   ↓
Run security rules
   ↓
Return findings
   ↓
Display findings
```

This should be the first genuinely functional release.

---

# 26. Version 0.3 — Cookie and Resource Analysis

### Features

- Cookie analyzer
- Third-party resource analyzer
- Resource inventory
- Cookie security attributes
- Domain grouping

UI:

```text
Cookies
12 detected

Third-Party Resources
23 detected
11 external domains
```

---

# 27. Version 0.4 — Technology Detection

### Features

- Framework detection
- Library detection
- CDN detection
- Analytics detection
- Basic version detection where reliably observable

Example:

```text
Technologies

React
Next.js
Cloudflare
Google Analytics
```

Technology detection should include evidence.

---

# 28. Version 0.5 — Improved Rule Engine

Refactor security checks into a reusable rule-engine architecture.

Example:

```python
class SecurityRule:
    id
    category
    title
    severity
    confidence

    def evaluate(context):
        ...
```

This allows new rules to be added without modifying the entire scanner.

Add:

- Rule registry
- Rule metadata
- Rule tests
- Versioned rules
- Finding IDs

Example:

```text
WEB-001 Missing CSP
WEB-002 Missing HSTS
WEB-003 Missing X-Content-Type-Options
WEB-004 Mixed Content
```

---

# 29. Version 0.6 — Authentication and Scan History

### Features

- User accounts
- Authentication
- PostgreSQL
- Persistent scans
- Scan history
- Domain history

Dashboard:

```text
My Scans

example.com
Oct 3 — 3 findings

github.com
Oct 3 — 1 finding

example.org
Oct 2 — 7 findings
```

---

# 30. Version 0.7 — Threat Intelligence

### Features

- Domain reputation
- IP reputation where appropriate
- Threat intelligence integration
- External API caching
- API error handling
- Rate limiting

Important states:

```text
Known malicious
Known clean / no known indicators
Suspicious
Unknown
Unavailable
```

Do not collapse all results into safe/unsafe.

---

# 31. Version 0.8 — Vulnerability Intelligence

### Features

- CVE integration
- Technology → version → vulnerability mapping
- CVSS information
- Vendor advisory references
- Confidence handling

Example:

```text
Detected:
Library X 1.2.3

Potential advisory:
CVE-XXXX-XXXXX

Applicability:
Potential

Reason:
The detected version appears to match the
affected version range.

Verification:
Required
```

---

# 32. Version 0.9 — JavaScript Static Analysis

### Features

- Script inventory
- Inline script detection
- External script detection
- Dangerous API pattern detection
- Source-map detection
- Dynamic script patterns

The system must use cautious language.

Example:

```text
Potential Security-Sensitive Pattern

innerHTML detected.

This does NOT prove that the application is
vulnerable to XSS.
```

---

# 33. Version 1.0 — Production MVP / Portfolio Release

Version 1.0 should represent the first polished portfolio release.

### Features

- Chrome Extension
- React
- TypeScript
- FastAPI
- PostgreSQL
- Authentication
- Security rule engine
- Header analysis
- Cookie analysis
- Third-party analysis
- Technology detection
- Threat intelligence
- Vulnerability intelligence
- JavaScript static indicators
- Scan history
- Finding details
- Strong error handling
- Automated tests
- CI/CD
- Cloud deployment
- Documentation

### Quality requirements

- No hardcoded secrets
- Secure API communication
- Input validation
- Rate limiting
- Structured logging
- Unit tests
- Integration tests
- Extension tests
- Backend tests
- Database migrations
- Production configuration

---

# 34. Version 1.1 — AI Security Explanations

Introduce AI only after the deterministic scanner is stable.

### Features

- Explain finding
- Explain evidence
- Explain remediation
- Generate summary
- Ask questions about scan findings

Example:

```text
Why is this finding important?

[AI explanation]
```

AI should receive structured findings rather than unrestricted page content.

---

# 35. Version 1.2 — Professional Security Reports

### Features

- HTML reports
- PDF reports
- JSON export
- CSV export
- Executive summary
- Technical findings
- Evidence
- Recommendations
- Scan metadata

---

# 36. Version 1.3 — Scan Comparison

### Features

Compare scans:

```text
Previous → Current

Resolved
3

New
1

Unchanged
4
```

Add:

- Finding lifecycle
- First detected
- Last detected
- Resolved date
- Regression detection

---

# 37. Version 1.4 — Security Dashboard

Create a full web dashboard.

Dashboard components:

```text
Security Overview
────────────────────────

Sites Monitored       12
Open Findings         18
High Severity          2
Medium Severity        7

Recent Scans
...

Security Trends
...
```

Add graphs for:

- Findings over time
- Severity distribution
- Technology distribution
- Domain activity

---

# 38. Version 1.5 — Continuous Monitoring

Introduce optional scheduled monitoring.

Example:

```text
Monitor example.com

Frequency:
Daily

Notify when:
☑ New high-severity finding
☑ Security header changes
☑ Technology version changes
☑ New third-party domain
```

Architecture:

```text
Scheduler
   ↓
Scan Queue
   ↓
Worker
   ↓
Analysis Engine
   ↓
Database
   ↓
Notification
```

This introduces asynchronous distributed-system concepts.

---

# 39. Version 1.6 — Notification System

Support:

- Email
- In-app notifications
- Optional webhook

Example:

```text
WebGuard Alert

example.com changed.

New finding:
Missing security header

Detected:
Oct 3, 2026
```

---

# 40. Version 1.7 — Advanced Supply-Chain Analysis

Expand third-party analysis.

Features:

- Third-party dependency inventory
- Domain relationships
- Script origins
- Resource changes
- Unexpected third-party resources
- Subresource Integrity detection
- SRI-related findings where applicable

Visualization:

```text
example.com
│
├── First Party
│   ├── app.js
│   └── styles.css
│
└── Third Party
    ├── analytics.com
    ├── cdn.com
    └── ads.com
```

---

# 41. Version 1.8 — Security Posture Profiles

Allow different scan profiles.

## Developer Profile

Focus on:

- Security headers
- Cookies
- JavaScript patterns
- Dependencies

## Privacy Profile

Focus on:

- Third-party domains
- Trackers
- Cookies
- External resources

## Security Analyst Profile

Focus on:

- Threat intelligence
- Technologies
- Vulnerability intelligence
- Historical changes

---

# 42. Version 2.0 — Full Security Intelligence Platform

The final version should transform WebGuard from a browser extension into a broader security intelligence platform.

The Chrome extension becomes the **collection and interactive analysis interface**, while the backend becomes the central security analysis platform.

Final architecture:

```text
                         Chrome Extension
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
          Browser Analysis              User Interface
                 │                           │
                 └─────────────┬─────────────┘
                               │
                             API
                               │
                    ┌──────────┴──────────┐
                    │                     │
              Analysis Platform       PostgreSQL
                    │
       ┌────────────┼─────────────┐
       ↓            ↓             ↓
   Rule Engine  Threat Intel  Vulnerability DB
       │            │             │
       └────────────┼─────────────┘
                    ↓
             Finding Correlation
                    ↓
              Risk Dashboard
                    ↓
          Reports / Alerts / AI
```

Final capabilities:

- Browser security analysis
- HTTP security analysis
- Cookie analysis
- Third-party analysis
- JavaScript static indicators
- Technology fingerprinting
- Vulnerability intelligence
- Threat intelligence
- Scan history
- Scan comparison
- Continuous monitoring
- Alerts
- Security reports
- AI explanations
- Security dashboards
- Configurable scan profiles
- Supply-chain visibility

---

# 43. Testing Strategy

Testing should be treated as a major feature, not an afterthought.

## Unit Tests

Test every security rule independently.

Example:

```text
Given:
CSP header absent

Expected:
WEB-001
Severity: MEDIUM
Confidence: HIGH
```

## Integration Tests

Test:

```text
Extension
   ↓
API
   ↓
Analysis Engine
   ↓
Database
```

## API Tests

Test:

- Valid requests
- Invalid requests
- Authentication
- Authorization
- Rate limiting
- API failures
- External service failures

## Browser Tests

Use browser automation where appropriate.

Test:

- Extension loading
- Popup
- Scan workflow
- Findings
- Error states

---

# 44. Security Requirements for WebGuard

WebGuard itself must be secure.

Requirements:

- HTTPS everywhere in production
- Secrets stored in environment/secret management
- No API keys in extension source
- Strong authentication
- Password hashing
- Input validation
- Output encoding
- Rate limiting
- CORS restrictions
- Secure cookies where applicable
- Dependency scanning
- Container scanning
- Logging
- Dependency updates
- Least-privilege extension permissions

---

# 45. Chrome Extension Permission Philosophy

Request the minimum permissions necessary.

Avoid requesting broad permissions without a clear reason.

Document every permission:

```text
Permission:
activeTab

Purpose:
Analyze the currently active website.

Permission:
storage

Purpose:
Store local user preferences.
```

The project should explicitly justify permissions in its documentation.

---

# 46. Error Handling

Every component should have graceful failure behavior.

Example:

```text
Threat Intelligence API unavailable

Status:
Unable to determine reputation.

The scan will continue using locally
available security checks.
```

An external API failing should not cause the entire scan to fail.

The system should support partial results.

---

# 47. Observability

The backend should eventually provide:

- Structured logs
- Request IDs
- Error tracking
- Metrics
- API latency
- Scan duration
- External API latency
- Failure rates

Potential metrics:

```text
scans_total
scan_duration_seconds
analysis_errors_total
external_api_errors_total
findings_generated_total
```

---

# 48. Recommended Repository Structure

```text
webguard/
│
├── extension/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── analyzers/
│   │   └── types/
│   ├── public/
│   ├── manifest.json
│   └── package.json
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── analyzers/
│   │   ├── rules/
│   │   └── core/
│   ├── tests/
│   └── requirements.txt
│
├── infrastructure/
│   ├── docker/
│   └── deployment/
│
├── docs/
│
├── .github/
│   └── workflows/
│
└── README.md
```

---

# 49. Development Order

Do not attempt to build Version 2.0 immediately.

Recommended sequence:

```text
Phase 1
Project skeleton
        ↓
Phase 2
Chrome extension
        ↓
Phase 3
Basic scanner
        ↓
Phase 4
Security rule engine
        ↓
Phase 5
Backend + database
        ↓
Phase 6
Technology detection
        ↓
Phase 7
Threat intelligence
        ↓
Phase 8
Vulnerability intelligence
        ↓
Phase 9
Authentication + history
        ↓
Phase 10
AI explanations
        ↓
Phase 11
Reports
        ↓
Phase 12
Monitoring + alerts
        ↓
Phase 13
Advanced supply-chain analysis
        ↓
Version 2.0
```

---

# 50. Definition of Done for Each Release

A version should not be considered complete merely because the feature works once.

Every release should have:

- Implementation
- Unit tests
- Integration tests where appropriate
- Error handling
- Documentation
- Updated API schemas
- Updated database migrations where necessary
- Updated UI
- Security review
- README updates
- Git commit/tag
- CI passing

---

# 51. AI Agent Instructions

The AI coding agent working on this project should follow these rules.

## Rule 1 — Do not overbuild

Implement the current version before introducing features from future versions.

## Rule 2 — Preserve architecture

New functionality should fit the existing architecture rather than creating unrelated implementations.

## Rule 3 — Test before expanding

A security analyzer should have tests covering both positive and negative cases.

## Rule 4 — Never invent security findings

A finding requires evidence.

## Rule 5 — Separate detection from explanation

The rule engine determines the finding.

AI explains the finding.

## Rule 6 — Minimize permissions

Do not add Chrome permissions unless required.

## Rule 7 — Never expose secrets

Never place API keys or credentials inside the extension source code.

## Rule 8 — Explain architectural decisions

When introducing a significant dependency or architectural component, document why it is needed.

## Rule 9 — Preserve backwards compatibility

Existing analyzers and API contracts should not break unnecessarily.

## Rule 10 — Security first

Treat WebGuard itself as security-sensitive software.

---

# 52. Final Portfolio Presentation

The final GitHub repository should contain:

## README

Include:

- Project overview
- Screenshots
- Architecture diagram
- Features
- Tech stack
- Installation
- Development instructions
- Security model
- Limitations
- Roadmap

## Architecture Documentation

Explain:

- Extension
- API
- Analysis engine
- Database
- External APIs
- Background jobs

## Security Documentation

Explain:

- Permissions
- Data collection
- Privacy
- Threat model
- Known limitations

## Demo

The final project should have a short demo showing:

```text
1. Visit website
2. Open WebGuard
3. Run scan
4. View findings
5. Open finding
6. Inspect evidence
7. Request AI explanation
8. Compare with previous scan
9. Generate report
```

---

# 53. Final Product Vision

The finished product should feel like:

> **"A lightweight browser-based security assessment platform for understanding the observable security posture of modern websites."**

It should not feel like:

> "A Chrome popup that gives websites a random security score."

The strongest version of the project combines:

```text
Chrome Extension
        +
Web Security
        +
Backend Engineering
        +
Security Rule Engine
        +
Threat Intelligence
        +
Vulnerability Intelligence
        +
Database
        +
Cloud Infrastructure
        +
AI Explanation
```

That combination provides a substantial software-engineering portfolio project while giving the developer multiple opportunities to demonstrate both engineering depth and cybersecurity knowledge.

---

# 54. Suggested Initial Milestone

The first implementation milestone should be intentionally small:

### Milestone 1

Build:

```text
Chrome Extension
       ↓
Current URL
       ↓
FastAPI
       ↓
Security Header Analyzer
       ↓
JSON Findings
       ↓
React Popup
```

Implement only:

- HTTPS check
- HSTS check
- CSP check
- X-Content-Type-Options check
- X-Frame-Options check
- Referrer-Policy check
- Basic mixed-content check

Once this works reliably, introduce the cookie and third-party-resource analyzers.

Do not introduce AI, threat intelligence, authentication, CVEs, monitoring, or reports until the deterministic scanner is working and tested.

This gives the AI coding agent a clear first target and prevents the project from becoming an oversized, untestable codebase at the beginning.
