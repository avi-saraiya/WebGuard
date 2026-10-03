// Mirrors backend/app/schemas/{finding,scan}.py. Keep in sync with the API contract.

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export type CheckStatus =
  "PASS" | "MISSING" | "WEAK" | "MISCONFIGURED" | "NOT_APPLICABLE" | "UNABLE_TO_DETERMINE";

export type Category = "TRANSPORT" | "HTTP_SECURITY" | "MIXED_CONTENT";

export interface Finding {
  id: string;
  rule_version: number;
  category: Category;
  title: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  location: string;
  rationale: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  references: string[];
  detected_at: string;
}

export interface CheckResult {
  rule_id: string;
  title: string;
  category: Category;
  status: CheckStatus;
  summary: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface ScanResponse {
  scan_id: string;
  target: { url: string; host: string; scheme: string };
  summary: SeveritySummary;
  findings: Finding[];
  checks: CheckResult[];
  partial: boolean;
  notices: string[];
  engine_version: string;
  analyzed_at: string;
}

// ---- Request: what the in-page collector observes (mirrors app/schemas/scan.py) ----

export interface HeaderCollection {
  status: "collected" | "unavailable";
  source: "refetch";
  http_status: number | null;
  /** Lowercase allowlisted header name → value. */
  values: Record<string, string>;
}

export type ResourceKind =
  "script" | "stylesheet" | "iframe" | "object" | "fetch" | "font" | "image" | "media" | "form" | "other";

export interface InsecureResource {
  url: string;
  kind: ResourceKind;
  source: "dom" | "performance";
}

export interface MixedContentCollection {
  resources: InsecureResource[];
  truncated: boolean;
}

export interface MetaPolicies {
  content_security_policy: string[];
  referrer: string | null;
}

export interface CollectedSignals {
  collector_version: string;
  headers: HeaderCollection;
  meta: MetaPolicies;
  mixed_content: MixedContentCollection;
}

export interface ScanRequest extends Partial<CollectedSignals> {
  url: string;
}
