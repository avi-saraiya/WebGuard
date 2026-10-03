import type { Severity, SeveritySummary as Summary } from "../types/scan";

const ROWS: { severity: Severity; key: keyof Summary; label: string }[] = [
  { severity: "CRITICAL", key: "critical", label: "Critical" },
  { severity: "HIGH", key: "high", label: "High" },
  { severity: "MEDIUM", key: "medium", label: "Medium" },
  { severity: "LOW", key: "low", label: "Low" },
  { severity: "INFORMATIONAL", key: "informational", label: "Informational" },
];

export function SeveritySummary({ summary }: { summary: Summary }) {
  return (
    <ul className="severity-summary" aria-label="Findings by severity">
      {ROWS.map(({ severity, key, label }) => (
        <li key={severity} className="severity-summary__row">
          <span className={`severity-dot severity-dot--${severity.toLowerCase()}`} aria-hidden="true" />
          <span className="severity-summary__count">{summary[key]}</span>
          <span>{label}</span>
        </li>
      ))}
    </ul>
  );
}
