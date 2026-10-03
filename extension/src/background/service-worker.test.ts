import { installChromeMock } from "../test/setup";

beforeEach(() => {
  installChromeMock();
});

async function loadWorker() {
  vi.resetModules();
  return import("./service-worker");
}

describe("isTrustedSender", () => {
  it("accepts the extension's own pages", async () => {
    const { isTrustedSender } = await loadWorker();
    expect(
      isTrustedSender({ id: "test-extension-id", url: "chrome-extension://test-extension-id/popup.html" }),
    ).toBe(true);
  });

  it.each([
    ["a content script (our ID, web page URL)", { id: "test-extension-id", url: "https://evil.example/" }],
    ["another extension", { id: "other-extension", url: "chrome-extension://other-extension/popup.html" }],
    ["a sender without a URL", { id: "test-extension-id" }],
    ["a look-alike URL", { id: "test-extension-id", url: "https://chrome-extension.test-extension-id/" }],
  ])("rejects %s", async (_label, sender) => {
    const { isTrustedSender } = await loadWorker();
    expect(isTrustedSender(sender)).toBe(false);
  });
});

describe("message routing", () => {
  it("ignores messages from untrusted senders", async () => {
    await loadWorker();
    const [listener] = vi.mocked(chrome.runtime.onMessage.addListener).mock.calls.at(-1) as unknown as [
      (message: unknown, sender: chrome.runtime.MessageSender, sendResponse: () => void) => boolean,
    ];
    const sendResponse = vi.fn();

    const keepOpen = listener(
      { type: "RUN_SCAN", tabId: 1 },
      { id: "test-extension-id", url: "https://evil.example/" },
      sendResponse,
    );

    expect(keepOpen).toBe(false);
    expect(chrome.tabs.get).not.toHaveBeenCalled();
  });
});
