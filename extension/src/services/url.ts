// Chrome blocks script injection on these hosts regardless of permissions.
const RESTRICTED_HOSTS = new Set(["chrome.google.com", "chromewebstore.google.com"]);

/** Returns the URL without query string or fragment, which may carry tokens or personal data. */
export function stripQueryAndFragment(url: string): string {
  const parsed = new URL(url);
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

export type ScanEligibility = { scannable: true; url: URL } | { scannable: false; reason: string };

export function checkScanEligibility(url: string | undefined): ScanEligibility {
  if (!url) {
    return { scannable: false, reason: "WebGuard can't read this tab's address." };
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { scannable: false, reason: "This tab's address isn't a valid URL." };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { scannable: false, reason: "WebGuard can only scan http:// and https:// pages." };
  }
  if (RESTRICTED_HOSTS.has(parsed.hostname)) {
    return { scannable: false, reason: "Chrome doesn't allow extensions to inspect this page." };
  }
  return { scannable: true, url: parsed };
}
