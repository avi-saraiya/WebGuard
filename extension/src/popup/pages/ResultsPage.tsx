import { ChecksTable } from "../../components/ChecksTable";
import { FindingCard } from "../../components/FindingCard";
import { SeveritySummary } from "../../components/SeveritySummary";
import type { ScanResponse } from "../../types/scan";

export function ResultsPage({
  result,
  onOpenFinding,
}: {
  result: ScanResponse;
  onOpenFinding: (id: string) => void;
}) {
  const findingIds = new Set(result.findings.map((f) => f.id));
  const analyzedAt = new Date(result.analyzed_at).toLocaleString();

  return (
    <div className="results">
      {result.notices.length > 0 && (
        <div className="notice notice--partial" role="status">
          <strong>Partial results.</strong>
          <ul>
            {result.notices.map((notice) => (
              <li key={notice}>{notice}</li>
            ))}
          </ul>
        </div>
      )}

      <section aria-labelledby="summary-heading">
        <h2 id="summary-heading" className="section-title">
          Security findings
        </h2>
        <SeveritySummary summary={result.summary} />
      </section>

      <section aria-labelledby="findings-heading">
        <h2 id="findings-heading" className="section-title">
          Findings ({result.findings.length})
        </h2>
        {result.findings.length === 0 ? (
          <p className="muted">
            No findings from the checks that ran. This does not mean the site is secure, only that these
            specific checks did not detect an issue.
          </p>
        ) : (
          <ul className="findings">
            {result.findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} onOpen={onOpenFinding} />
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="checks-heading">
        <h2 id="checks-heading" className="section-title">
          Checks
        </h2>
        <ChecksTable checks={result.checks} findingIds={findingIds} onOpenFinding={onOpenFinding} />
      </section>

      <p className="muted small">
        Scanned {analyzedAt} · engine {result.engine_version}
      </p>
    </div>
  );
}
