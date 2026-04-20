/**
 * Shared HTTP fetch utilities with optional undici connection pooling.
 *
 * Rationale:
 *   A scan can issue hundreds of sequential HTTPS requests (OSV detail fetches,
 *   EPSS batches). Opening a fresh TCP/TLS handshake per request is expensive.
 *   Routing the hot paths through a pooled undici Agent with keep-alive reuses
 *   the underlying sockets and cuts latency significantly.
 *
 *   The dispatcher is loaded lazily via dynamic import so the optional
 *   dependency is truly optional — if `undici` isn't resolvable we transparently
 *   fall back to the global fetch. Either way, every request still flows through
 *   the validation layer (size, timeout, content-type, JSON parsing).
 */
import { safeJsonParse } from './sanitize.js';

type UndiciAgentLike = {
  close?: () => Promise<void>;
  destroy?: () => Promise<void>;
};

let pooledDispatcher: UndiciAgentLike | null = null;
let dispatcherInitialized = false;

/**
 * Lazily create (or return cached) undici Agent for pooled keep-alive.
 *
 * Returns null when undici is unavailable or fails to load. Callers must be
 * prepared to receive null and fall back to the global fetch.
 */
export async function getPooledDispatcher(): Promise<UndiciAgentLike | null> {
  if (dispatcherInitialized) return pooledDispatcher;
  dispatcherInitialized = true;
  try {
    // Dynamic import so the dependency stays truly optional at runtime.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod: any = await import('undici');
    const AgentCtor = mod?.Agent;
    if (typeof AgentCtor !== 'function') return null;
    pooledDispatcher = new AgentCtor({
      keepAliveTimeout: 30_000,
      keepAliveMaxTimeout: 60_000,
      connections: 20,
    }) as UndiciAgentLike;
    return pooledDispatcher;
  } catch {
    pooledDispatcher = null;
    return null;
  }
}

/**
 * Close and release the pooled dispatcher. Safe to call when no pool exists.
 * Primarily used for tests and graceful shutdown.
 */
export async function closeFetchPool(): Promise<void> {
  if (pooledDispatcher) {
    try {
      if (typeof pooledDispatcher.close === 'function') {
        await pooledDispatcher.close();
      } else if (typeof pooledDispatcher.destroy === 'function') {
        await pooledDispatcher.destroy();
      }
    } catch {
      // Ignore shutdown errors.
    }
  }
  pooledDispatcher = null;
  dispatcherInitialized = false;
}

/**
 * For tests only: reset the internal dispatcher state so the next
 * getPooledDispatcher() call re-imports and re-initializes.
 */
export function resetFetchPoolForTests(): void {
  pooledDispatcher = null;
  dispatcherInitialized = false;
}

export type FetchValidationOptions = {
  /** Max response bytes (both Content-Length and body). Defaults to 50 MB. */
  maxSize?: number;
  /** Override the per-request abort timeout in ms. Defaults to 30_000. */
  timeoutMs?: number;
  /** Expected content-type substring. Defaults to 'application/json'. */
  expectedContentType?: string | null;
  /** Opt-in to the pooled undici dispatcher. Falls back silently if unavailable. */
  pool?: boolean;
};

const DEFAULT_MAX_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Fetch `url` with size, timeout, and content-type validation. Returns the
 * raw Response after validating headers, but DOES NOT read the body — callers
 * that only need a Response should use this. Body-reading callers should use
 * fetchJsonWithValidation instead.
 */
export async function fetchWithValidation(
  url: string,
  init: RequestInit = {},
  options: FetchValidationOptions = {},
): Promise<Response> {
  const {
    maxSize = DEFAULT_MAX_SIZE,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    expectedContentType = 'application/json',
    pool = false,
  } = options;

  // Only create an AbortSignal.timeout if the caller didn't already provide one.
  const signal = init.signal ?? AbortSignal.timeout(timeoutMs);

  // Build the fetch init, conditionally adding the pooled dispatcher.
  // Using `any` here so we can safely forward `dispatcher` — TypeScript's
  // lib.dom RequestInit doesn't know about Node's undici extension.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fetchInit: any = { ...init, signal };

  if (pool) {
    const dispatcher = await getPooledDispatcher();
    if (dispatcher) fetchInit.dispatcher = dispatcher;
  }

  const response = await fetch(url, fetchInit);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  if (expectedContentType) {
    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes(expectedContentType)) {
      throw new Error(
        `Unexpected Content-Type: ${contentType}. Expected ${expectedContentType}.`,
      );
    }
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new Error(`Response too large: ${contentLength} bytes (max ${maxSize})`);
  }

  return response;
}

/**
 * Fetch `url` and return its parsed JSON body, enforcing size, timeout,
 * content-type, and safe-JSON-parse checks. Strips prototype-pollution keys.
 */
export async function fetchJsonWithValidation<T = unknown>(
  url: string,
  init: RequestInit = {},
  options: FetchValidationOptions = {},
): Promise<T> {
  const { maxSize = DEFAULT_MAX_SIZE } = options;
  const response = await fetchWithValidation(url, init, options);

  const text = await response.text();
  if (text.length > maxSize) {
    throw new Error(`Response body too large: ${text.length} chars (max ${maxSize})`);
  }

  return safeJsonParse<T>(text);
}
