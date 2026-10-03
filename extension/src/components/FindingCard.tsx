import type { Finding } from "../types/scan";
import { ConfidenceLabel, SeverityBadge } from "./SeverityBadge";

export function FindingCard({ finding, onOpen }: { finding: Finding; onOpen: (id: string) => void }) {
  return (
    <li>
      <button type="button" className="finding-card" onClick={() => onOpen(finding.id)}>
        <SeverityBadge severity={finding.severity} />
        <span className="finding-card__body">
          <span className="finding-card__title">{finding.title}</span>
          <span className="finding-card__meta">
            {finding.id} · <ConfidenceLabel confidence={finding.confidence} />
          </span>
        </span>
        <span className="finding-card__chevron" aria-hidden="true">
          ›
        </span>
      </button>
    </li>
  );
}
