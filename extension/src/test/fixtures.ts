import type { Finding, ScanResponse } from "../types/scan";

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "WEB-001",
    rule_version: 1,
    category: "HTTP_SECURITY",
    title: "Missing Content-Security-Policy",
    severity: "MEDIUM",
    confidence: "HIGH",
    description: "The response did not contain an enforced Content-Security-Policy.",
    location: "HTTP response headers of https://example.com/",
    rationale: "A Content Security Policy restricts where scripts may load from.",
    evidence: { header: "Content-Security-Policy", value: null },
    recommendation: "Define a CSP suited to the application's resources.",
    references: ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"],
    detected_at: "2026-10-03T00:00:00Z",
    ...overrides,
  };
}

export function makeScanResponse(overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    scan_id: "00000000-0000-0000-0000-000000000000",
    target: { url: "https://example.com/", host: "example.com", scheme: "https" },
    summary: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    findings: [],
    checks: [],
    partial: false,
    notices: [],
    engine_version: "0.2.0",
    analyzed_at: "2026-10-03T00:00:00Z",
    ...overrides,
  };
}
