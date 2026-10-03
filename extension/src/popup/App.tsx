import { useCallback, useEffect, useState } from "react";
import { sendMessage, type ScanProgressMessage, type ScanStage } from "../services/messaging";
import { checkScanEligibility } from "../services/url";
import type { ScanResponse } from "../types/scan";
import { FindingDetail } from "./pages/FindingDetail";
import { ResultsPage } from "./pages/ResultsPage";

type ActiveTab = { id: number; url: string };

type ViewState =
  | { kind: "loading" }
  | { kind: "unscannable"; reason: string }
  | { kind: "idle" }
  | { kind: "scanning"; stage: ScanStage | "starting" }
  | { kind: "done"; result: ScanResponse }
  | { kind: "error"; message: string; requestId: string | null };

const STAGE_LABEL: Record<ScanStage | "starting", string> = {
  starting: "Starting scan…",
  collecting: "Collecting page signals…",
  analyzing: "Analyzing with security rules…",
};

async function getActiveTab(): Promise<{ id: number; url: string | undefined } | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id === undefined ? null : { id: tab.id, url: tab.url };
}

export function App() {
  const [tab, setTab] = useState<ActiveTab | null>(null);
  const [view, setView] = useState<ViewState>({ kind: "loading" });
  const [openFindingId, setOpenFindingId] = useState<string | null>(null);

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
      setTab({ id: active.id, url: eligibility.url.href });
      const cached = await sendMessage({
        type: "GET_CACHED_SCAN",
        tabId: active.id,
        url: eligibility.url.href,
      });
      setView(cached?.result ? { kind: "done", result: cached.result } : { kind: "idle" });
    })();
  }, []);

  useEffect(() => {
    if (!tab) return;
    const onProgress = (message: ScanProgressMessage, sender: chrome.runtime.MessageSender) => {
      if (sender.id !== chrome.runtime.id || message?.type !== "SCAN_PROGRESS" || message.tabId !== tab.id) {
        return;
      }
      setView((current) =>
        current.kind === "scanning" ? { kind: "scanning", stage: message.stage } : current,
      );
    };
    chrome.runtime.onMessage.addListener(onProgress);
    return () => chrome.runtime.onMessage.removeListener(onProgress);
  }, [tab]);

  const runScan = useCallback(async () => {
    if (!tab) return;
    setOpenFindingId(null);
    setView({ kind: "scanning", stage: "starting" });
    const outcome = await sendMessage({ type: "RUN_SCAN", tabId: tab.id });
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

  const host = tab ? new URL(tab.url).host : null;
  const openFinding =
    view.kind === "done" && openFindingId
      ? view.result.findings.find((finding) => finding.id === openFindingId)
      : undefined;

  if (openFinding) {
    return (
      <main className="popup">
        <FindingDetail finding={openFinding} onBack={() => setOpenFindingId(null)} />
      </main>
    );
  }

  return (
    <main className="popup">
      <header className="popup__header">
        <h1>WebGuard</h1>
        {host && (
          <p className="site__host" title={tab?.url}>
            {host}
          </p>
        )}
      </header>

      {view.kind === "loading" && <p className="muted">Loading…</p>}

      {view.kind === "unscannable" && (
        <p className="notice" role="status">
          {view.reason}
        </p>
      )}

      {view.kind === "idle" && (
        <p className="muted">
          Check this page's observable security configuration: HTTPS, security headers and mixed content.
        </p>
      )}

      {view.kind === "scanning" && (
        <p className="progress" role="status" aria-live="polite">
          <span className="spinner" aria-hidden="true" />
          {STAGE_LABEL[view.stage]}
        </p>
      )}

      {view.kind === "error" && (
        <div className="error" role="alert">
          <p>{view.message}</p>
          {view.requestId && <p className="small">Request ID: {view.requestId}</p>}
        </div>
      )}

      {tab && (
        <button className="button" type="button" onClick={runScan} disabled={view.kind === "scanning"}>
          {view.kind === "scanning" ? "Scanning…" : view.kind === "done" ? "Scan again" : "Run Scan"}
        </button>
      )}

      {view.kind === "done" && <ResultsPage result={view.result} onOpenFinding={setOpenFindingId} />}

      {tab && (
        <details className="privacy">
          <summary>What is sent to the backend?</summary>
          <p>
            Only the page URL without its query string or fragment, a fixed list of security response headers,
            Content-Security-Policy and referrer <code>&lt;meta&gt;</code> tags, and the addresses of
            resources loaded over insecure <code>http://</code>. Cookies, page text, form values and storage
            never leave your browser.
          </p>
        </details>
      )}
    </main>
  );
}
