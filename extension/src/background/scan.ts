import { collectPageSignals } from "../collector/collectPageSignals";
import { ApiError, createScan } from "../services/api";
import type { CachedScanOutcome, ScanOutcome, ScanStage } from "../services/messaging";
import { checkScanEligibility, stripQueryAndFragment } from "../services/url";
import type { CollectedSignals, ScanResponse } from "../types/scan";

interface CachedScan {
  url: string;
  result: ScanResponse;
}

const cacheKey = (tabId: number) => `scan:${tabId}`;

function reportProgress(tabId: number, stage: ScanStage): void {
  // The popup may have closed; a missing receiver is expected and harmless.
  chrome.runtime.sendMessage({ type: "SCAN_PROGRESS", tabId, stage }).catch(() => undefined);
}

/** Injects the collector into the tab. Returns null if the page can't be inspected. */
async function collectSignals(tabId: number): Promise<CollectedSignals | null> {
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: collectPageSignals,
    });
    return (injection?.result as CollectedSignals | undefined) ?? null;
  } catch (err) {
    console.warn("WebGuard collector could not run on this page", err);
    return null;
  }
}

export async function runScan(tabId: number): Promise<ScanOutcome> {
  const tab = await chrome.tabs.get(tabId);
  const eligibility = checkScanEligibility(tab.url);
  if (!eligibility.scannable) {
    return { ok: false, error: { code: "NOT_SCANNABLE", message: eligibility.reason, requestId: null } };
  }

  const url = stripQueryAndFragment(eligibility.url.href);
  reportProgress(tabId, "collecting");
  // If collection fails we still scan the URL; the backend marks dependent checks as undetermined.
  const signals = await collectSignals(tabId);
  reportProgress(tabId, "analyzing");
  try {
    const result = await createScan({ url, ...signals });
    const entry: CachedScan = { url, result };
    // Session storage lives in memory only and is cleared when the browser closes.
    await chrome.storage.session.set({ [cacheKey(tabId)]: entry });
    return { ok: true, result };
  } catch (err) {
    if (err instanceof ApiError) {
      return { ok: false, error: { code: err.code, message: err.message, requestId: err.requestId } };
    }
    console.error("WebGuard scan failed", err);
    return {
      ok: false,
      error: { code: "UNEXPECTED", message: "The scan failed unexpectedly.", requestId: null },
    };
  }
}

export async function getCachedScan(tabId: number, tabUrl: string): Promise<CachedScanOutcome> {
  const key = cacheKey(tabId);
  const stored = (await chrome.storage.session.get(key))[key] as CachedScan | undefined;
  const matches = stored !== undefined && stored.url === stripQueryAndFragment(tabUrl);
  return { result: matches ? stored.result : null };
}

export async function clearCachedScan(tabId: number): Promise<void> {
  await chrome.storage.session.remove(cacheKey(tabId));
}
