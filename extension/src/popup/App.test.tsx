import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { makeFinding, makeScanResponse } from "../test/fixtures";
import { installChromeMock, type ChromeMock } from "../test/setup";
import type { ScanResponse } from "../types/scan";
import { App } from "./App";

const CSP_FINDING = makeFinding();
const HSTS_FINDING = makeFinding({
  id: "WEB-002",
  title: "Short Strict-Transport-Security max-age",
  severity: "LOW",
  confidence: "HIGH",
  evidence: { header: "Strict-Transport-Security", value: "max-age=300", max_age: 300 },
  references: [
    "javascript:alert(1)",
    "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
  ],
});

const RESULT = makeScanResponse({
  summary: { critical: 0, high: 0, medium: 1, low: 1, informational: 0 },
  findings: [CSP_FINDING, HSTS_FINDING],
  checks: [
    {
      rule_id: "WEB-001",
      title: "Missing Content-Security-Policy",
      category: "HTTP_SECURITY",
      status: "MISSING",
      summary: "No enforced policy.",
    },
    {
      rule_id: "WEB-003",
      title: "Missing X-Content-Type-Options header",
      category: "HTTP_SECURITY",
      status: "PASS",
      summary: "nosniff",
    },
    {
      rule_id: "WEB-004",
      title: "Mixed content detected",
      category: "MIXED_CONTENT",
      status: "UNABLE_TO_DETERMINE",
      summary: "Page resources were not collected.",
    },
  ],
});

let chromeMock: ChromeMock;

beforeEach(() => {
  chromeMock = installChromeMock();
});

function givenActiveTab(url: string) {
  chromeMock.tabs.query.mockResolvedValue([{ id: 3, url } as chrome.tabs.Tab]);
}

function givenMessages(handlers: {
  cached?: ScanResponse | null;
  scan?: unknown | (() => Promise<unknown>);
}) {
  chromeMock.runtime.sendMessage.mockImplementation(async (message: unknown) => {
    if ((message as { type: string }).type === "GET_CACHED_SCAN") return { result: handlers.cached ?? null };
    return typeof handlers.scan === "function" ? (handlers.scan as () => Promise<unknown>)() : handlers.scan;
  });
}

async function renderAndScan() {
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Run Scan" }));
}

describe("App: before scanning", () => {
  it("shows the current host and a Run Scan button", async () => {
    givenActiveTab("https://example.com/some/page?q=1");
    givenMessages({});

    render(<App />);

    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Scan" })).toBeEnabled();
  });

  it("explains when a page can't be scanned", async () => {
    givenActiveTab("chrome://extensions");
    givenMessages({});

    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent("http:// and https://");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("restores a cached result without rescanning", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({ cached: RESULT });

    render(<App />);

    expect(await screen.findByLabelText("Findings by severity")).toBeInTheDocument();
    expect(chromeMock.runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "RUN_SCAN" }),
    );
  });

  it("explains what data leaves the browser", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({});

    render(<App />);

    expect(await screen.findByText("What is sent to the backend?")).toBeInTheDocument();
    expect(screen.getByText(/Cookies, page text, form values and storage never leave/)).toBeInTheDocument();
  });
});

describe("App: scanning", () => {
  it("shows progress stages broadcast by the service worker", async () => {
    givenActiveTab("https://example.com/");
    let finish: (value: unknown) => void = () => undefined;
    givenMessages({ scan: () => new Promise((resolve) => (finish = resolve)) });

    await renderAndScan();
    expect(screen.getByRole("status")).toHaveTextContent("Starting scan");
    expect(screen.getByRole("button", { name: "Scanning…" })).toBeDisabled();

    const [listener] = chromeMock.runtime.onMessage.addListener.mock.calls.at(-1) as [
      (message: unknown, sender: { id: string }) => void,
    ];
    act(() => listener({ type: "SCAN_PROGRESS", tabId: 3, stage: "analyzing" }, { id: "test-extension-id" }));
    expect(screen.getByRole("status")).toHaveTextContent("Analyzing with security rules");

    // Messages from other tabs or other extensions are ignored.
    act(() =>
      listener({ type: "SCAN_PROGRESS", tabId: 99, stage: "collecting" }, { id: "test-extension-id" }),
    );
    act(() => listener({ type: "SCAN_PROGRESS", tabId: 3, stage: "collecting" }, { id: "other-extension" }));
    expect(screen.getByRole("status")).toHaveTextContent("Analyzing with security rules");

    await act(async () => finish({ ok: true, result: RESULT }));
    expect(await screen.findByRole("button", { name: "Scan again" })).toBeEnabled();
  });

  it("shows backend errors with the request ID", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({
      scan: {
        ok: false,
        error: { code: "NETWORK_ERROR", message: "Couldn't reach the WebGuard backend.", requestId: "abc" },
      },
    });

    await renderAndScan();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Couldn't reach the WebGuard backend.");
    expect(alert).toHaveTextContent("Request ID: abc");
  });
});

describe("App: results", () => {
  beforeEach(() => {
    givenActiveTab("https://example.com/");
  });

  it("shows severity counts, findings in order and check statuses", async () => {
    givenMessages({ scan: { ok: true, result: RESULT } });

    await renderAndScan();

    const summary = await screen.findByLabelText("Findings by severity");
    expect(within(summary).getByText("Medium").previousSibling).toHaveTextContent("1");
    const findingButtons = within(
      screen.getByRole("heading", { name: /Findings \(2\)/ }).parentElement!,
    ).getAllByRole("button");
    expect(findingButtons.map((b) => b.textContent)).toEqual([
      expect.stringContaining("Missing Content-Security-Policy"),
      expect.stringContaining("Short Strict-Transport-Security max-age"),
    ]);
    const checks = screen.getByLabelText("Security checks");
    expect(within(checks).getByText("Pass:", { exact: false })).toBeInTheDocument();
    expect(within(checks).getByText("Unable to determine:", { exact: false })).toBeInTheDocument();
  });

  it("does not claim a site is secure when there are no findings", async () => {
    givenMessages({ scan: { ok: true, result: makeScanResponse() } });

    await renderAndScan();

    expect(await screen.findByText(/This does not mean the site is secure/)).toBeInTheDocument();
  });

  it("shows a partial-results banner with the backend's notices", async () => {
    givenMessages({
      scan: {
        ok: true,
        result: { ...RESULT, partial: true, notices: ["Response headers could not be collected."] },
      },
    });

    await renderAndScan();

    const banner = await screen.findByText("Partial results.");
    expect(banner.parentElement).toHaveTextContent("Response headers could not be collected.");
  });

  it("opens finding details with evidence and safe references, and goes back", async () => {
    givenMessages({ scan: { ok: true, result: RESULT } });
    await renderAndScan();

    await userEvent.click(await screen.findByRole("button", { name: /Short Strict-Transport-Security/ }));

    expect(
      screen.getByRole("heading", { name: "Short Strict-Transport-Security max-age" }),
    ).toBeInTheDocument();
    for (const heading of [
      "What was detected?",
      "Where?",
      "Why does this matter?",
      "Evidence",
      "Recommendation",
    ]) {
      expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    }
    expect(screen.getByText("max-age=300")).toBeInTheDocument();
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1); // the javascript: reference is dropped
    expect(links[0]).toHaveAttribute("href", expect.stringMatching(/^https:\/\/developer\.mozilla\.org/));
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");

    await userEvent.click(screen.getByRole("button", { name: /All findings/ }));
    expect(screen.getByLabelText("Findings by severity")).toBeInTheDocument();
  });

  it("opens a finding from the checks list", async () => {
    givenMessages({ scan: { ok: true, result: RESULT } });
    await renderAndScan();

    const checks = await screen.findByLabelText("Security checks");
    await userEvent.click(within(checks).getByRole("button", { name: "Missing Content-Security-Policy" }));

    expect(screen.getByRole("heading", { name: "What was detected?" })).toBeInTheDocument();
  });
});
