import type { ScanResponse } from "../types/scan";

// Popup → service worker messages. The worker owns scanning so a scan survives the popup closing.
export type RunScanMessage = { type: "RUN_SCAN"; tabId: number };
export type GetCachedScanMessage = { type: "GET_CACHED_SCAN"; tabId: number; url: string };
export type ExtensionMessage = RunScanMessage | GetCachedScanMessage;

export type ScanOutcome =
  | { ok: true; result: ScanResponse }
  | { ok: false; error: { code: string; message: string; requestId: string | null } };

export type CachedScanOutcome = { result: ScanResponse | null };

export function sendMessage(message: RunScanMessage): Promise<ScanOutcome>;
export function sendMessage(message: GetCachedScanMessage): Promise<CachedScanOutcome>;
export function sendMessage(message: ExtensionMessage): Promise<unknown> {
  return chrome.runtime.sendMessage(message);
}
