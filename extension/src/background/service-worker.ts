import type { ExtensionMessage } from "../services/messaging";
import { clearCachedScan, getCachedScan, runScan } from "./scan";

export function isTrustedSender(sender: chrome.runtime.MessageSender): boolean {
  // Only our own extension pages (e.g. the popup) may drive scans. Content scripts share our
  // extension ID but report the web page's URL, so checking the sender URL's origin excludes them.
  return sender.id === chrome.runtime.id && (sender.url ?? "").startsWith(chrome.runtime.getURL(""));
}

chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  if (!isTrustedSender(sender)) {
    return false;
  }

  switch (message.type) {
    case "RUN_SCAN":
      void runScan(message.tabId).then(sendResponse);
      return true; // keep the channel open for the async response
    case "GET_CACHED_SCAN":
      void getCachedScan(message.tabId, message.url).then(sendResponse);
      return true;
    default:
      return false;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void clearCachedScan(tabId);
});
