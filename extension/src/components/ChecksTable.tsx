import type { CheckResult, CheckStatus } from "../types/scan";

const STATUS_DISPLAY: Record<CheckStatus, { icon: string; label: string; tone: string }> = {
  PASS: { icon: "✓", label: "Pass", tone: "pass" },
  MISSING: { icon: "✗", label: "Missing", tone: "fail" },
  WEAK: { icon: "⚠", label: "Weak", tone: "warn" },
  MISCONFIGURED: { icon: "⚠", label: "Misconfigured", tone: "warn" },
  NOT_APPLICABLE: { icon: "–", label: "Not applicable", tone: "muted" },
  UNABLE_TO_DETERMINE: { icon: "?", label: "Unable to determine", tone: "muted" },
};

interface ChecksTableProps {
  checks: CheckResult[];
  findingIds: Set<string>;
  onOpenFinding: (id: string) => void;
}

export function ChecksTable({ checks, findingIds, onOpenFinding }: ChecksTableProps) {
  return (
    <ul className="checks" aria-label="Security checks">
      {checks.map((check) => {
        const status = STATUS_DISPLAY[check.status];
        const hasFinding = findingIds.has(check.rule_id);
        return (
          <li key={check.rule_id} className="check">
            <span className={`check__icon check__icon--${status.tone}`} aria-hidden="true">
              {status.icon}
            </span>
            <span className="check__body">
              {hasFinding ? (
                <button type="button" className="link-button" onClick={() => onOpenFinding(check.rule_id)}>
                  {check.title}
                </button>
              ) : (
                <span>{check.title}</span>
              )}
              <span className="check__summary">
                <span className="visually-hidden">{status.label}: </span>
                {check.summary}
              </span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}
