import { collectPageSignals } from "./collectPageSignals";

const PAGE_URL = "https://example.test/account/page?token=secret#frag";

let fetchMock: ReturnType<typeof vi.fn>;

function headersResponse(headers: Record<string, string>, status = 200): Response {
  return new Response(null, { status, headers });
}

beforeEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
  fetchMock = vi.fn(async () => headersResponse({}));
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(performance, "getEntriesByType").mockReturnValue([]);
});

describe("collectPageSignals: headers", () => {
  it("re-fetches the page with HEAD, no credentials and no cache", async () => {
    await collectPageSignals();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(PAGE_URL);
    expect(init).toMatchObject({ method: "HEAD", credentials: "omit", cache: "no-store" });
  });

  it("returns only allowlisted security headers", async () => {
    fetchMock.mockResolvedValue(
      headersResponse({
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Powered-By": "Express",
        Server: "nginx/1.2.3",
        "X-Debug-Token": "abc",
      }),
    );

    const { headers } = await collectPageSignals();

    expect(headers).toEqual({
      status: "collected",
      source: "refetch",
      http_status: 200,
      values: {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
      },
    });
  });

  it("falls back to GET when HEAD is not allowed", async () => {
    fetchMock
      .mockResolvedValueOnce(headersResponse({}, 405))
      .mockResolvedValueOnce(headersResponse({ "X-Frame-Options": "DENY" }));

    const { headers } = await collectPageSignals();

    expect(fetchMock.mock.calls.map(([, init]) => (init as RequestInit).method)).toEqual(["HEAD", "GET"]);
    expect(headers.values).toEqual({ "x-frame-options": "DENY" });
  });

  it("reports headers as unavailable when the fetch fails", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    const { headers } = await collectPageSignals();

    expect(headers).toEqual({ status: "unavailable", source: "refetch", http_status: null, values: {} });
  });
});

describe("collectPageSignals: meta policies", () => {
  it("collects CSP and referrer meta tags case-insensitively", async () => {
    document.head.innerHTML = `
      <meta http-equiv="Content-Security-Policy" content="script-src 'self'">
      <meta http-equiv="content-security-policy" content="img-src *">
      <meta http-equiv="refresh" content="5">
      <meta name="Referrer" content="origin">
      <meta name="referrer" content="no-referrer">
      <meta name="description" content="private page text">`;

    const { meta } = await collectPageSignals();

    expect(meta).toEqual({
      content_security_policy: ["script-src 'self'", "img-src *"],
      referrer: "no-referrer", // last tag wins
    });
  });

  it("returns empty values when no meta policies exist", async () => {
    expect((await collectPageSignals()).meta).toEqual({ content_security_policy: [], referrer: null });
  });
});

describe("collectPageSignals: mixed content", () => {
  it("finds http: references in the DOM and strips query strings", async () => {
    document.body.innerHTML = `
      <script src="http://cdn.example/app.js?v=1&session=abc"></script>
      <script src="https://cdn.example/safe.js"></script>
      <script src="/relative.js"></script>
      <link rel="stylesheet" href="http://cdn.example/site.css">
      <link rel="preconnect" href="http://cdn.example/">
      <img src="http://img.example/a.png#x">
      <iframe src="http://widgets.example/embed"></iframe>
      <form action="http://example.test/login?next=/account"></form>
      <video poster="http://media.example/poster.jpg"><source src="http://media.example/v.mp4"></video>`;

    const { mixed_content } = await collectPageSignals();

    expect(mixed_content.truncated).toBe(false);
    expect(mixed_content.resources).toEqual(
      expect.arrayContaining([
        { url: "http://cdn.example/app.js", kind: "script", source: "dom" },
        { url: "http://cdn.example/site.css", kind: "stylesheet", source: "dom" },
        { url: "http://img.example/a.png", kind: "image", source: "dom" },
        { url: "http://widgets.example/embed", kind: "iframe", source: "dom" },
        { url: "http://example.test/login", kind: "form", source: "dom" },
        { url: "http://media.example/poster.jpg", kind: "media", source: "dom" },
        { url: "http://media.example/v.mp4", kind: "media", source: "dom" },
      ]),
    );
    expect(mixed_content.resources).toHaveLength(7);
    expect(JSON.stringify(mixed_content)).not.toMatch(/session|next=|v=1/);
  });

  it("includes insecure network requests from the performance timeline", async () => {
    vi.mocked(performance.getEntriesByType).mockReturnValue([
      { name: "http://api.example/data?id=7", initiatorType: "fetch" },
      { name: "http://fonts.example/f.woff2", initiatorType: "css" },
      { name: "http://x.example/beacon", initiatorType: "something-new" },
      { name: "https://api.example/secure", initiatorType: "fetch" },
    ] as unknown as PerformanceEntryList);

    const { mixed_content } = await collectPageSignals();

    expect(mixed_content.resources).toEqual([
      { url: "http://api.example/data", kind: "fetch", source: "performance" },
      { url: "http://fonts.example/f.woff2", kind: "stylesheet", source: "performance" },
      { url: "http://x.example/beacon", kind: "other", source: "performance" },
    ]);
  });

  it("deduplicates and caps the resource list", async () => {
    const images = Array.from({ length: 60 }, (_, i) => `<img src="http://img.example/${i}.png">`);
    document.body.innerHTML = images.join("") + `<img src="http://img.example/0.png?dup=1">`;

    const { mixed_content } = await collectPageSignals();

    expect(mixed_content.resources).toHaveLength(50);
    expect(mixed_content.truncated).toBe(true);
  });
});

describe("collectPageSignals: injection safety", () => {
  it("is self-contained so chrome.scripting can serialize it", async () => {
    // Re-create the function from its source text alone, as Chrome does when injecting it.
    // Any reference to module-scope values would throw a ReferenceError here.
    // eslint-disable-next-line no-new-func
    const isolated = new Function(`return (${collectPageSignals.toString()})`)() as typeof collectPageSignals;
    document.body.innerHTML = `<script src="http://cdn.example/app.js"></script>`;

    const result = await isolated();

    expect(result.collector_version).toBe("0.2.0");
    expect(result.mixed_content.resources).toHaveLength(1);
  });
});
