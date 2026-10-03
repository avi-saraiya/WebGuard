import type { ExtensionMessage } from "../services/messaging";
import { clearCachedScan, getCachedScan, runScan } from "./scan";

function isTrustedSender(sender: chrome.runtime.MessageSender): boolean {
  // Only our own extension pages (the popup) may drive scans; never web pages or content scripts.
  return sender.id === chrome.runtime.id && sender.tab === undefined;
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
