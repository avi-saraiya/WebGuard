import { makeScanResponse } from "../test/fixtures";
import { installChromeMock, type ChromeMock } from "../test/setup";
import type { CollectedSignals } from "../types/scan";
import { getCachedScan, runScan } from "./scan";

const RESULT = makeScanResponse({
  target: { url: "https://example.com/page", host: "example.com", scheme: "https" },
});

const SIGNALS: CollectedSignals = {
  collector_version: "0.2.0",
  headers: {
    status: "collected",
    source: "refetch",
    http_status: 200,
    values: { "x-content-type-options": "nosniff" },
  },
  meta: { content_security_policy: [], referrer: null },
  mixed_content: { resources: [], truncated: false },
};

let chromeMock: ChromeMock;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  chromeMock = installChromeMock();
  chromeMock.scripting.executeScript.mockResolvedValue([{ result: SIGNALS }]);
  fetchMock = vi.fn(async () => new Response(JSON.stringify(RESULT), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
});

function givenTab(url: string) {
  chromeMock.tabs.get.mockResolvedValue({ id: 7, url } as chrome.tabs.Tab);
}

function sentPayload(): Record<string, unknown> {
  const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

describe("runScan", () => {
  it("collects page signals and sends them with the stripped URL", async () => {
    givenTab("https://example.com/page?session=abc#top");

    const outcome = await runScan(7);

    expect(outcome).toEqual({ ok: true, result: RESULT });
    expect(chromeMock.scripting.executeScript).toHaveBeenCalledWith(
      expect.objectContaining({ target: { tabId: 7 } }),
    );
    expect(sentPayload()).toEqual({ url: "https://example.com/page", ...SIGNALS });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/scans$/);
    expect(init.credentials).toBe("omit");
  });

  it("still scans the URL when the collector can't run", async () => {
    givenTab("https://example.com/");
    chromeMock.scripting.executeScript.mockRejectedValue(new Error("Cannot access contents of the page"));

    const outcome = await runScan(7);

    expect(outcome.ok).toBe(true);
    expect(sentPayload()).toEqual({ url: "https://example.com/" });
  });

  it("reports progress stages to the popup", async () => {
    givenTab("https://example.com/");

    await runScan(7);

    const stages = chromeMock.runtime.sendMessage.mock.calls.map(([m]) => (m as { stage: string }).stage);
    expect(stages).toEqual(["collecting", "analyzing"]);
  });

  it("caches the result for the same page", async () => {
    givenTab("https://example.com/page");
    await runScan(7);

    expect(await getCachedScan(7, "https://example.com/page?other=1")).toEqual({ result: RESULT });
    expect(await getCachedScan(7, "https://example.com/other")).toEqual({ result: null });
  });

  it("refuses restricted pages without injecting or calling the backend", async () => {
    givenTab("chrome://settings");

    const outcome = await runScan(7);

    expect(outcome).toMatchObject({ ok: false, error: { code: "NOT_SCANNABLE" } });
    expect(chromeMock.scripting.executeScript).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports an unreachable backend", async () => {
    givenTab("https://example.com/");
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    expect(await runScan(7)).toMatchObject({ ok: false, error: { code: "NETWORK_ERROR" } });
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

    expect(await runScan(7)).toEqual({
      ok: false,
      error: { code: "VALIDATION_ERROR", message: "Request validation failed.", requestId: "r1" },
    });
  });
});
