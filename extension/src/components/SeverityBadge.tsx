import type { Confidence, Severity } from "../types/scan";

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFORMATIONAL: "Info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge--${severity.toLowerCase()}`}>
      <span className="visually-hidden">Severity: </span>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function ConfidenceLabel({ confidence }: { confidence: Confidence }) {
  return <span className="confidence">{confidence.toLowerCase()} confidence</span>;
}
