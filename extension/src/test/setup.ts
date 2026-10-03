import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

/** Minimal in-memory stand-in for the chrome.* APIs WebGuard uses. Tests override pieces with vi.fn(). */
export function createChromeMock() {
  let session: Record<string, unknown> = {};
  return {
    runtime: {
      id: "test-extension-id",
      getURL: (path: string) => `chrome-extension://test-extension-id/${path}`,
      sendMessage: vi.fn(async (_message: unknown): Promise<unknown> => undefined),
      onMessage: { addListener: vi.fn(), removeListener: vi.fn() },
    },
    scripting: { executeScript: vi.fn(async (_injection: unknown): Promise<{ result?: unknown }[]> => []) },
    tabs: {
      query: vi.fn(async () => [] as chrome.tabs.Tab[]),
      get: vi.fn(),
      onRemoved: { addListener: vi.fn() },
    },
    storage: {
      session: {
        get: vi.fn(async (key: string) => (key in session ? { [key]: session[key] } : {})),
        set: vi.fn(async (items: Record<string, unknown>) => {
          session = { ...session, ...items };
        }),
        remove: vi.fn(async (key: string) => {
          delete session[key];
        }),
      },
    },
  };
}

export type ChromeMock = ReturnType<typeof createChromeMock>;

export function installChromeMock(): ChromeMock {
  const mock = createChromeMock();
  vi.stubGlobal("chrome", mock);
  return mock;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
