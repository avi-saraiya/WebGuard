import type {
  CollectedSignals,
  HeaderCollection,
  InsecureResource,
  MetaPolicies,
  MixedContentCollection,
} from "../types/scan";

/**
 * Runs INSIDE the inspected page via `chrome.scripting.executeScript({ func })`.
 *
 * Chrome serializes this function with `toString()`, so it must be fully self-contained: no
 * imports, no references to module-level values. Every helper and constant lives inside it.
 * `collectPageSignals.test.ts` enforces this by re-evaluating the source in an isolated scope.
 *
 * Privacy contract (see docs/security.md): only allowlisted security headers, <meta> policy tags,
 * and http: resource URLs with query strings and fragments removed. No cookies, storage, page
 * text or form values are read.
 */
export async function collectPageSignals(): Promise<CollectedSignals> {
  const COLLECTOR_VERSION = "0.2.0";
  const FETCH_TIMEOUT_MS = 8000;
  const MAX_RESOURCES = 50;
  const MAX_META_POLICIES = 5;
  const MAX_VALUE_LENGTH = 8192;
  const ALLOWED_HEADERS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
  ];

  const clip = (value: string) => value.slice(0, MAX_VALUE_LENGTH);

  /** Resolve against the document, require http:, and drop query + fragment. */
  const insecureUrl = (raw: string | null | undefined): string | null => {
    if (!raw) return null;
    try {
      const url = new URL(raw, document.baseURI);
      if (url.protocol !== "http:") return null;
      url.search = "";
      url.hash = "";
      return url.href;
    } catch {
      return null;
    }
  };

  async function collectHeaders(): Promise<HeaderCollection> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    // Cookieless same-origin re-fetch: the browser exposes all response headers except Set-Cookie.
    const init: RequestInit = {
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      signal: controller.signal,
    };
    try {
      let response = await fetch(location.href, { ...init, method: "HEAD" });
      if (response.status === 405 || response.status === 501) {
        response = await fetch(location.href, { ...init, method: "GET" });
        void response.body?.cancel(); // headers are all we need
      }
      const values: Record<string, string> = {};
      for (const name of ALLOWED_HEADERS) {
        const value = response.headers.get(name);
        if (value !== null) values[name] = clip(value);
      }
      return { status: "collected", source: "refetch", http_status: response.status, values };
    } catch {
      return { status: "unavailable", source: "refetch", http_status: null, values: {} };
    } finally {
      clearTimeout(timer);
    }
  }

  function collectMeta(): MetaPolicies {
    const csp = Array.from(document.querySelectorAll<HTMLMetaElement>("meta[http-equiv]"))
      .filter((m) => m.httpEquiv.trim().toLowerCase() === "content-security-policy" && m.content.trim())
      .slice(0, MAX_META_POLICIES)
      .map((m) => clip(m.content));
    const referrerTags = Array.from(document.querySelectorAll<HTMLMetaElement>("meta[name]")).filter(
      (m) => m.name.trim().toLowerCase() === "referrer",
    );
    const lastReferrer = referrerTags.at(-1)?.content.trim();
    return { content_security_policy: csp, referrer: lastReferrer ? clip(lastReferrer) : null };
  }

  function collectMixedContent(): MixedContentCollection {
    const found = new Map<string, InsecureResource>();
    let truncated = false;
    const add = (
      raw: string | null | undefined,
      kind: InsecureResource["kind"],
      source: InsecureResource["source"],
    ) => {
      const url = insecureUrl(raw);
      if (!url) return;
      const key = `${kind} ${url}`;
      if (found.has(key)) return;
      if (found.size >= MAX_RESOURCES) {
        truncated = true;
        return;
      }
      found.set(key, { url, kind, source });
    };

    const domSources: [string, string, InsecureResource["kind"]][] = [
      ["script[src]", "src", "script"],
      ["iframe[src], frame[src]", "src", "iframe"],
      ["img[src]", "src", "image"],
      ["audio[src], video[src], audio > source[src], video > source[src]", "src", "media"],
      ["video[poster]", "poster", "media"],
      ["object[data]", "data", "object"],
      ["embed[src]", "src", "object"],
      ["form[action]", "action", "form"],
      ["button[formaction], input[formaction]", "formaction", "form"],
    ];
    for (const [selector, attribute, kind] of domSources) {
      document.querySelectorAll(selector).forEach((el) => add(el.getAttribute(attribute), kind, "dom"));
    }
    document.querySelectorAll<HTMLLinkElement>("link[href]").forEach((link) => {
      const rel = link.rel.toLowerCase().split(/\s+/);
      if (rel.includes("stylesheet")) add(link.getAttribute("href"), "stylesheet", "dom");
      else if (rel.includes("icon")) add(link.getAttribute("href"), "image", "dom");
    });

    const initiatorKinds: Record<string, InsecureResource["kind"]> = {
      script: "script",
      css: "stylesheet",
      link: "stylesheet",
      img: "image",
      image: "image",
      iframe: "iframe",
      frame: "iframe",
      video: "media",
      audio: "media",
      xmlhttprequest: "fetch",
      fetch: "fetch",
      beacon: "fetch",
      object: "object",
      embed: "object",
    };
    for (const entry of performance.getEntriesByType("resource") as PerformanceResourceTiming[]) {
      add(entry.name, initiatorKinds[entry.initiatorType] ?? "other", "performance");
    }

    return { resources: Array.from(found.values()), truncated };
  }

  const isHttps = location.protocol === "https:";
  return {
    collector_version: COLLECTOR_VERSION,
    headers: await collectHeaders(),
    meta: collectMeta(),
    // Mixed content is only meaningful on HTTPS pages.
    mixed_content: isHttps ? collectMixedContent() : { resources: [], truncated: false },
  };
}
