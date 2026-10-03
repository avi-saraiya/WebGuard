/** Renders a finding's evidence object as a readable key/value list. All values render as text. */
export function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence);
  if (entries.length === 0) return <p className="muted">No structured evidence.</p>;
  return (
    <dl className="evidence">
      {entries.map(([key, value]) => (
        <div key={key} className="evidence__row">
          <dt>{humanize(key)}</dt>
          <dd>
            <EvidenceValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function EvidenceValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="muted">absent</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">none</span>;
    return (
      <ul className="evidence__list">
        {value.map((item, index) => (
          <li key={index}>
            <EvidenceValue value={item} />
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    return (
      <span className="evidence__inline">
        {Object.entries(value as Record<string, unknown>)
          .map(([k, v]) => `${humanize(k)}: ${String(v)}`)
          .join(" · ")}
      </span>
    );
  }
  return <code className="evidence__code">{String(value)}</code>;
}

const ACRONYMS: Record<string, string> = { url: "URL", csp: "CSP", http: "HTTP" };

function humanize(key: string): string {
  const text = key
    .split("_")
    .map((word) => ACRONYMS[word] ?? word)
    .join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
