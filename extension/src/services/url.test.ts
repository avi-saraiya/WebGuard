import { checkScanEligibility, stripQueryAndFragment } from "./url";

describe("stripQueryAndFragment", () => {
  it("removes query strings and fragments", () => {
    expect(stripQueryAndFragment("https://example.com/a/b?token=secret#section")).toBe(
      "https://example.com/a/b",
    );
  });

  it("leaves clean URLs unchanged", () => {
    expect(stripQueryAndFragment("https://example.com/")).toBe("https://example.com/");
  });
});

describe("checkScanEligibility", () => {
  it.each(["https://example.com/", "http://localhost:3000/page"])("accepts %s", (url) => {
    expect(checkScanEligibility(url).scannable).toBe(true);
  });

  it.each([
    undefined,
    "",
    "not a url",
    "chrome://settings",
    "chrome-extension://abc/popup.html",
    "file:///etc/passwd",
    "https://chromewebstore.google.com/detail/x",
    "https://chrome.google.com/webstore",
  ])("rejects %s", (url) => {
    const result = checkScanEligibility(url);
    expect(result.scannable).toBe(false);
    if (!result.scannable) expect(result.reason).not.toHaveLength(0);
  });
});
