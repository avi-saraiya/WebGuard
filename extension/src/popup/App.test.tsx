import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { installChromeMock, type ChromeMock } from "../test/setup";
import { makeScanResponse } from "../test/fixtures";
import type { ScanResponse } from "../types/scan";
import { App } from "./App";

const RESULT = makeScanResponse({ summary: { critical: 0, high: 1, medium: 2, low: 0, informational: 0 } });

let chromeMock: ChromeMock;

beforeEach(() => {
  chromeMock = installChromeMock();
});

function givenActiveTab(url: string) {
  chromeMock.tabs.query.mockResolvedValue([{ id: 3, url } as chrome.tabs.Tab]);
}

function givenMessages(handlers: { cached?: ScanResponse | null; scan?: unknown }) {
  chromeMock.runtime.sendMessage.mockImplementation(async (message: unknown) =>
    (message as { type: string }).type === "GET_CACHED_SCAN"
      ? { result: handlers.cached ?? null }
      : handlers.scan,
  );
}

describe("App", () => {
  it("shows the current site and a Run Scan button", async () => {
    givenActiveTab("https://example.com/some/page?q=1");
    givenMessages({});

    render(<App />);

    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Scan" })).toBeEnabled();
  });

  it("runs a scan and shows the severity summary", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({ scan: { ok: true, result: RESULT } });

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Run Scan" }));

    expect(await screen.findByLabelText("Findings by severity")).toBeInTheDocument();
    expect(chromeMock.runtime.sendMessage).toHaveBeenCalledWith({ type: "RUN_SCAN", tabId: 3 });
    expect(screen.getByRole("button", { name: "Scan again" })).toBeInTheDocument();
  });

  it("shows a cached result without rescanning", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({ cached: RESULT });

    render(<App />);

    expect(await screen.findByLabelText("Findings by severity")).toBeInTheDocument();
    expect(chromeMock.runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "RUN_SCAN" }),
    );
  });

  it("shows backend errors with the request ID", async () => {
    givenActiveTab("https://example.com/");
    givenMessages({
      scan: {
        ok: false,
        error: { code: "NETWORK_ERROR", message: "Couldn't reach the WebGuard backend.", requestId: "abc" },
      },
    });

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Run Scan" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't reach the WebGuard backend.");
    expect(screen.getByRole("alert")).toHaveTextContent("Request ID: abc");
  });

  it("explains when a page can't be scanned", async () => {
    givenActiveTab("chrome://extensions");
    givenMessages({});

    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent("http:// and https://");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
