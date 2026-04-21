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
  /** Alias for maxSize, matching the legacy C-agent API. Defaults to 50 MB. */
  maxBytes?: number;
  /** Override the per-request abort timeout in ms. Defaults to 30_000. */
  timeoutMs?: number;
  /** Expected content-type substring. Defaults to 'application/json'. */
  expectedContentType?: string | null;
  /** Alias for expectedContentType, matching the legacy C-agent API. */
  contentType?: string | null;
  /** Opt-in to the pooled undici dispatcher. Falls back silently if unavailable. */
  pool?: boolean;
};

export type FetchValidationErrorKind =
  | 'timeout'
  | 'oversize'
  | 'content-type'
  | 'http-status'
  | 'network'
  | 'html-body';

export class FetchValidationError extends Error {
  kind: FetchValidationErrorKind;
  constructor(kind: FetchValidationErrorKind, message: string) {
    super(message);
    this.name = 'FetchValidationError';
    this.kind = kind;
  }
}

const DEFAULT_MAX_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Type guard: detect whether the 2nd arg is actually options (legacy 2-arg
 * call shape used by some callers/tests) rather than a RequestInit.
 */
function looksLikeOptions(obj: unknown): obj is FetchValidationOptions {
  if (!obj || typeof obj !== 'object') return false;
  const keys = ['maxSize', 'maxBytes', 'timeoutMs', 'expectedContentType', 'contentType', 'pool'] as const;
  for (const k of keys) {
    if (k in (obj as Record<string, unknown>)) return true;
  }
  return false;
}

/**
 * Fetch `url` with size, timeout, and content-type validation. Accepts
 * either the 3-arg form (url, init, options) or the 2-arg form (url, options)
 * — the legacy C-agent tests pass options as the 2nd arg.
 */
export async function fetchWithValidation(
  url: string,
  initOrOptions: RequestInit | FetchValidationOptions = {},
  maybeOptions: FetchValidationOptions = {},
): Promise<Response> {
  const usingLegacy2Arg = looksLikeOptions(initOrOptions) && Object.keys(maybeOptions).length === 0;
  const init: RequestInit = usingLegacy2Arg ? {} : (initOrOptions as RequestInit);
  const options: FetchValidationOptions = usingLegacy2Arg
    ? (initOrOptions as FetchValidationOptions)
    : maybeOptions;
  const maxSize = options.maxSize ?? options.maxBytes ?? DEFAULT_MAX_SIZE;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const expectedContentType =
    options.expectedContentType !== undefined
      ? options.expectedContentType
      : (options.contentType ?? 'application/json');
  const pool = options.pool ?? false;

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

  let response: Response;
  try {
    response = await fetch(url, fetchInit);
  } catch (err) {
    if (err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError')) {
      throw new FetchValidationError(
        'timeout',
        `Request aborted: timed out after ${timeoutMs}ms`,
      );
    }
    const msg = err instanceof Error ? err.message : String(err);
    throw new FetchValidationError('network', `Network error: ${msg}`);
  }

  if (!response.ok) {
    throw new FetchValidationError('http-status', `HTTP ${response.status}: ${response.statusText}`);
  }

  if (expectedContentType) {
    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes(expectedContentType)) {
      throw new FetchValidationError(
        'content-type',
        `Unexpected Content-Type: ${contentType}. Expected ${expectedContentType}.`,
      );
    }
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new FetchValidationError(
      'oversize',
      `Response too large: ${contentLength} bytes (max ${maxSize})`,
    );
  }

  // When expecting JSON we stream-read the body with a running byte count
  // so we can enforce maxSize even when content-length is absent, and sniff
  // the body start for HTML/XML to catch CDN/captive-portal error pages.
  // The buffered body is rewrapped in a fresh Response for downstream callers.
  if (expectedContentType === 'application/json' && response.body) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    let sniffed = false;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.byteLength;
        if (total > maxSize) {
          try { await reader.cancel(); } catch { /* ignore */ }
          throw new FetchValidationError(
            'oversize',
            `Response body exceeded max size (${maxSize}); aborted at ${total} bytes`,
          );
        }
        chunks.push(value);
        if (!sniffed && total >= 16) {
          sniffed = true;
          const head = new TextDecoder('utf-8').decode(chunks[0]).slice(0, 64).trimStart().toLowerCase();
          if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<?xml')) {
            try { await reader.cancel(); } catch { /* ignore */ }
            throw new FetchValidationError(
              'html-body',
              'Response body starts with HTML/XML markup despite JSON content-type',
            );
          }
        }
      }
    } finally {
      try { reader.releaseLock(); } catch { /* ignore */ }
    }
    // Coalesce chunks into a single Uint8Array then into a fresh Response.
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      combined.set(c, offset);
      offset += c.byteLength;
    }
    return new Response(combined, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }

  return response;
}

/**
 * Fetch `url` and return its parsed JSON body, enforcing size, timeout,
 * content-type, and safe-JSON-parse checks. Strips prototype-pollution keys.
 */
export async function fetchJsonWithValidation<T = unknown>(
  url: string,
  initOrOptions: RequestInit | FetchValidationOptions = {},
  maybeOptions: FetchValidationOptions = {},
): Promise<T> {
  const usingLegacy2Arg = looksLikeOptions(initOrOptions) && Object.keys(maybeOptions).length === 0;
  const init: RequestInit = usingLegacy2Arg ? {} : (initOrOptions as RequestInit);
  const options: FetchValidationOptions = usingLegacy2Arg
    ? (initOrOptions as FetchValidationOptions)
    : maybeOptions;
  const maxSize = options.maxSize ?? options.maxBytes ?? DEFAULT_MAX_SIZE;

  const response = await fetchWithValidation(url, init, options);

  // Stream the body and enforce size so callers can't be OOM'd by
  // responses that omit content-length.
  const body = response.body;
  if (!body) {
    return safeJsonParse<T>(await response.text());
  }
  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8');
  let total = 0;
  let text = '';
  let sniffed = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxSize) {
          try { await reader.cancel(); } catch { /* ignore */ }
          throw new FetchValidationError(
            'oversize',
            `Response body exceeded max size (${maxSize}); aborted at ${total} bytes`,
          );
        }
        text += decoder.decode(value, { stream: true });
        if (!sniffed && text.length >= 16) {
          sniffed = true;
          const head = text.slice(0, 16).trimStart().toLowerCase();
          if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<?xml')) {
            try { await reader.cancel(); } catch { /* ignore */ }
            throw new FetchValidationError(
              'html-body',
              'Response body starts with HTML/XML markup despite JSON content-type',
            );
          }
        }
      }
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
  text += decoder.decode();
  return safeJsonParse<T>(text);
}
