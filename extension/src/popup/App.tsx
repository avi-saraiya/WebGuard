import { useCallback, useEffect, useState } from "react";
import { SeveritySummary } from "../components/SeveritySummary";
import { sendMessage, type ScanOutcome } from "../services/messaging";
import { checkScanEligibility } from "../services/url";
import type { ScanResponse } from "../types/scan";

type ActiveTab = { id: number; url: string | undefined };

type ViewState =
  | { kind: "loading" }
  | { kind: "unscannable"; reason: string }
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "done"; result: ScanResponse }
  | { kind: "error"; message: string; requestId: string | null };

async function getActiveTab(): Promise<ActiveTab | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id === undefined ? null : { id: tab.id, url: tab.url };
}

export function App() {
  const [tab, setTab] = useState<ActiveTab | null>(null);
  const [view, setView] = useState<ViewState>({ kind: "loading" });

  useEffect(() => {
    void (async () => {
      const active = await getActiveTab();
      const eligibility = checkScanEligibility(active?.url);
      if (!active || !eligibility.scannable) {
        setView({
          kind: "unscannable",
          reason: eligibility.scannable ? "No active tab." : eligibility.reason,
        });
        return;
      }
      setTab(active);
      const cached = await sendMessage({
        type: "GET_CACHED_SCAN",
        tabId: active.id,
        url: eligibility.url.href,
      });
      setView(cached?.result ? { kind: "done", result: cached.result } : { kind: "idle" });
    })();
  }, []);

  const runScan = useCallback(async () => {
    if (!tab) return;
    setView({ kind: "scanning" });
    const outcome: ScanOutcome | undefined = await sendMessage({ type: "RUN_SCAN", tabId: tab.id });
    if (!outcome) {
      setView({
        kind: "error",
        message: "No response from the WebGuard background worker.",
        requestId: null,
      });
    } else if (outcome.ok) {
      setView({ kind: "done", result: outcome.result });
    } else {
      setView({ kind: "error", message: outcome.error.message, requestId: outcome.error.requestId });
    }
  }, [tab]);

  const host = tab?.url ? new URL(tab.url).host : null;

  return (
    <main className="popup">
      <header className="popup__header">
        <h1>WebGuard</h1>
      </header>

      {view.kind === "loading" && <p className="muted">Loading…</p>}

      {view.kind === "unscannable" && (
        <p className="notice" role="status">
          {view.reason}
        </p>
      )}

      {host && (
        <section className="site">
          <span className="site__label">Current site</span>
          <span className="site__host">{host}</span>
        </section>
      )}

      {view.kind === "done" && (
        <section aria-label="Scan results">
          <SeveritySummary summary={view.result.summary} />
          <p className="muted">
            {view.result.findings.length} finding{view.result.findings.length === 1 ? "" : "s"} · engine{" "}
            {view.result.engine_version}
          </p>
        </section>
      )}

      {view.kind === "error" && (
        <div className="error" role="alert">
          <p>{view.message}</p>
          {view.requestId && <p className="muted">Request ID: {view.requestId}</p>}
        </div>
      )}

      {tab && (
        <button className="button" type="button" onClick={runScan} disabled={view.kind === "scanning"}>
          {view.kind === "scanning" ? "Scanning…" : view.kind === "done" ? "Scan again" : "Run Scan"}
        </button>
      )}
    </main>
  );
}
