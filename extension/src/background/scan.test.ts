import { installChromeMock, type ChromeMock } from "../test/setup";
import type { ScanResponse } from "../types/scan";
import { getCachedScan, runScan } from "./scan";

const RESULT: ScanResponse = {
  scan_id: "00000000-0000-0000-0000-000000000000",
  target: { url: "https://example.com/page", host: "example.com", scheme: "https" },
  summary: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  findings: [],
  checks: [],
  engine_version: "0.1.0-mock",
  analyzed_at: "2026-10-03T00:00:00Z",
};

let chromeMock: ChromeMock;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  chromeMock = installChromeMock();
  fetchMock = vi.fn(async () => new Response(JSON.stringify(RESULT), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
});

function givenTab(url: string) {
  chromeMock.tabs.get.mockResolvedValue({ id: 7, url } as chrome.tabs.Tab);
}

describe("runScan", () => {
  it("sends only the stripped URL to the backend and caches the result", async () => {
    givenTab("https://example.com/page?session=abc#top");

    const outcome = await runScan(7);

    expect(outcome).toEqual({ ok: true, result: RESULT });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/scans$/);
    expect(JSON.parse(init.body as string)).toEqual({ url: "https://example.com/page" });
    expect(init.credentials).toBe("omit");
    expect(await getCachedScan(7, "https://example.com/page?other=1")).toEqual({ result: RESULT });
  });

  it("refuses restricted pages without calling the backend", async () => {
    givenTab("chrome://settings");

    const outcome = await runScan(7);

    expect(outcome).toMatchObject({ ok: false, error: { code: "NOT_SCANNABLE" } });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports an unreachable backend", async () => {
    givenTab("https://example.com/");
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    const outcome = await runScan(7);

    expect(outcome).toMatchObject({ ok: false, error: { code: "NETWORK_ERROR" } });
  });

  it("surfaces the backend error envelope", async () => {
    givenTab("https://example.com/");
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: "VALIDATION_ERROR", message: "Request validation failed.", request_id: "r1" },
        }),
        { status: 422 },
      ),
    );

    const outcome = await runScan(7);

    expect(outcome).toEqual({
      ok: false,
      error: { code: "VALIDATION_ERROR", message: "Request validation failed.", requestId: "r1" },
    });
  });
});

describe("getCachedScan", () => {
  it("ignores a cached result for a different page", async () => {
    givenTab("https://example.com/page");
    await runScan(7);

    expect(await getCachedScan(7, "https://example.com/other")).toEqual({ result: null });
  });
});
