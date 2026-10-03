import type { ScanRequest, ScanResponse } from "../types/scan";

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly code: string,
    readonly requestId: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string; request_id?: string };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      credentials: "omit",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: { "Content-Type": "application/json", ...init.headers },
    });
  } catch (err) {
    const timedOut = err instanceof DOMException && err.name === "TimeoutError";
    throw new ApiError(
      timedOut
        ? "The WebGuard backend took too long to respond."
        : "Couldn't reach the WebGuard backend. Is it running?",
      null,
      timedOut ? "TIMEOUT" : "NETWORK_ERROR",
    );
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ErrorEnvelope;
    throw new ApiError(
      body.error?.message ?? `Backend returned HTTP ${response.status}.`,
      response.status,
      body.error?.code ?? "HTTP_ERROR",
      body.error?.request_id ?? response.headers.get("x-request-id"),
    );
  }
  return (await response.json()) as T;
}

export function createScan(payload: ScanRequest): Promise<ScanResponse> {
  return request<ScanResponse>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
