import { EvidenceView } from "../../components/EvidenceView";
import { SeverityBadge } from "../../components/SeverityBadge";
import type { Finding } from "../../types/scan";

// Defense in depth: references come from the backend, so only ever link to http(s) URLs.
function isWebUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

export function FindingDetail({ finding, onBack }: { finding: Finding; onBack: () => void }) {
  const references = finding.references.filter(isWebUrl);
  return (
    <article className="detail" aria-labelledby="finding-title">
      <button type="button" className="link-button back" onClick={onBack}>
        ‹ All findings
      </button>

      <header className="detail__header">
        <h2 id="finding-title">{finding.title}</h2>
        <p className="muted">
          {finding.id} · rule v{finding.rule_version}
        </p>
        <dl className="detail__ratings">
          <div>
            <dt>Severity</dt>
            <dd>
              <SeverityBadge severity={finding.severity} />
            </dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{finding.confidence.charAt(0) + finding.confidence.slice(1).toLowerCase()}</dd>
          </div>
        </dl>
      </header>

      <section>
        <h3>What was detected?</h3>
        <p>{finding.description}</p>
      </section>
      <section>
        <h3>Where?</h3>
        <p className="detail__location">{finding.location}</p>
      </section>
      <section>
        <h3>Why does this matter?</h3>
        <p>{finding.rationale}</p>
      </section>
      <section>
        <h3>Evidence</h3>
        <EvidenceView evidence={finding.evidence} />
      </section>
      <section>
        <h3>Recommendation</h3>
        <p>{finding.recommendation}</p>
      </section>
      {references.length > 0 && (
        <section>
          <h3>References</h3>
          <ul className="references">
            {references.map((url) => (
              <li key={url}>
                <a href={url} target="_blank" rel="noopener noreferrer">
                  {new URL(url).hostname}
                  {new URL(url).pathname}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </article>
  );
}
