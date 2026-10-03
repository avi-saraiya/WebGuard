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

## Development

Installation and development instructions will be added as the components land.
