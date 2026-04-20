/**
 * Hardened fetch wrapper used for all outbound HTTP to third-party advisory
 * services (OSV, FIRST.org EPSS, CISA KEV, npm registry, etc).
 *
 * A compromised or misbehaving upstream can otherwise:
 *   - Serve a gigantic response and OOM the scanner (CI/Action).
 *   - Swap content-type to HTML (e.g. a captive portal / error page) and
 *     cause the JSON parser to throw on unexpected markup.
 *   - Hang forever without a timeout.
 *
 * `fetchWithValidation` enforces:
 *   - Request timeout via AbortController (default 30s).
 *   - Non-OK HTTP status rejection.
 *   - Content-Type prefix/regex match.
 *   - Content-Length upfront reject when > maxBytes.
 *   - Running-count size check while streaming the body — kills the connection
 *     as soon as the limit is exceeded (never buffers the full body first).
 *   - HTML sniff on the first bytes (defence against servers that claim JSON
 *     but return an error page).
 *
 * Errors are raised as `FetchValidationError` with a machine-readable `kind`.
 */

export type FetchValidationKind =
  | 'timeout'
  | 'oversize'
  | 'content-type'
  | 'http-status'
  | 'network'
  | 'html-body';

export class FetchValidationError extends Error {
  readonly kind: FetchValidationKind;
  readonly url: string;
  readonly status?: number;

  constructor(kind: FetchValidationKind, url: string, message: string, status?: number) {
    super(message);
    this.name = 'FetchValidationError';
    this.kind = kind;
    this.url = url;
    this.status = status;
  }
}

export type FetchValidationOptions = RequestInit & {
  /** Hard byte cap for the response body. Required. */
  maxBytes: number;
  /** Request timeout in milliseconds. Defaults to 30_000. */
  timeoutMs?: number;
  /**
   * Expected response content-type. Either a string prefix
   * (e.g. `application/json`) or a RegExp matched against the
   * raw Content-Type header value. Required.
   */
  contentType: string | RegExp;
};

const HTML_SNIFF_PREFIXES = ['<!doctype html', '<html', '<?xml'];
const HTML_SNIFF_LENGTH = 32;

function contentTypeMatches(actual: string, expected: string | RegExp): boolean {
  if (!actual) return false;
  const lowered = actual.toLowerCase();
  if (typeof expected === 'string') {
    return lowered.startsWith(expected.toLowerCase());
  }
  return expected.test(actual);
}

function startsWithHtml(prefix: string): boolean {
  const trimmed = prefix.trimStart().toLowerCase();
  return HTML_SNIFF_PREFIXES.some((p) => trimmed.startsWith(p));
}

/**
 * Fetch `url` and return the response body as a string if and only if it
 * passes every validation gate. On any violation, throws `FetchValidationError`.
 */
export async function fetchWithValidation(
  url: string,
  options: FetchValidationOptions,
): Promise<string> {
  const { maxBytes, timeoutMs = 30_000, contentType, signal: externalSignal, ...init } = options;

  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    throw new FetchValidationError('oversize', url, `Invalid maxBytes: ${maxBytes}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // Chain an external signal if caller passed one.
  const externalAbort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', externalAbort, { once: true });
  }

  let response: Response;
  try {
    response = await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener('abort', externalAbort);
    const name = (err as { name?: string } | null)?.name;
    if (name === 'AbortError' || name === 'TimeoutError') {
      throw new FetchValidationError('timeout', url, `Request timed out after ${timeoutMs}ms`);
    }
    throw new FetchValidationError(
      'network',
      url,
      `Network failure: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  try {
    if (!response.ok) {
      throw new FetchValidationError(
        'http-status',
        url,
        `HTTP ${response.status}: ${response.statusText}`,
        response.status,
      );
    }

    const rawCt = response.headers.get('content-type') ?? '';
    if (!contentTypeMatches(rawCt, contentType)) {
      throw new FetchValidationError(
        'content-type',
        url,
        `Unexpected Content-Type: ${rawCt || '(missing)'}. Expected ${String(contentType)}.`,
      );
    }

    const clHeader = response.headers.get('content-length');
    if (clHeader !== null) {
      const declared = Number.parseInt(clHeader, 10);
      if (Number.isFinite(declared) && declared > maxBytes) {
        throw new FetchValidationError(
          'oversize',
          url,
          `Response too large (Content-Length ${declared} > ${maxBytes})`,
        );
      }
    }

    const body = response.body;
    if (!body) {
      // No stream — read text defensively but still apply the cap.
      const text = await response.text();
      if (text.length > maxBytes) {
        throw new FetchValidationError(
          'oversize',
          url,
          `Response body too large (${text.length} > ${maxBytes} bytes)`,
        );
      }
      if (startsWithHtml(text.slice(0, HTML_SNIFF_LENGTH))) {
        throw new FetchValidationError(
          'html-body',
          url,
          'Response body starts with HTML markup despite JSON content-type',
        );
      }
      return text;
    }

    const reader = body.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    let received = 0;
    let sniffed = false;
    let sniffBuf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      received += value.byteLength;
      if (received > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // best-effort; body is already over-limit
        }
        throw new FetchValidationError(
          'oversize',
          url,
          `Response body exceeded ${maxBytes} bytes during streaming (read ${received})`,
        );
      }

      const piece = decoder.decode(value, { stream: true });
      chunks.push(piece);

      if (!sniffed) {
        sniffBuf += piece;
        if (sniffBuf.length >= HTML_SNIFF_LENGTH || sniffBuf.trimStart().length >= HTML_SNIFF_LENGTH) {
          if (startsWithHtml(sniffBuf.slice(0, HTML_SNIFF_LENGTH + 8))) {
            try {
              await reader.cancel();
            } catch {
              // best-effort
            }
            throw new FetchValidationError(
              'html-body',
              url,
              'Response body starts with HTML markup despite JSON content-type',
            );
          }
          sniffed = true;
          sniffBuf = '';
        }
      }
    }

    // Flush any remaining multi-byte sequences.
    chunks.push(decoder.decode());

    // Late HTML sniff if the entire body was too short to trip the inline check.
    if (!sniffed && startsWithHtml(chunks.join('').slice(0, HTML_SNIFF_LENGTH))) {
      throw new FetchValidationError(
        'html-body',
        url,
        'Response body starts with HTML markup despite JSON content-type',
      );
    }

    return chunks.join('');
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener('abort', externalAbort);
  }
}

/**
 * Convenience wrapper that parses the validated body as JSON.
 */
export async function fetchJsonWithValidation<T = unknown>(
  url: string,
  options: FetchValidationOptions,
): Promise<T> {
  const body = await fetchWithValidation(url, options);
  try {
    return JSON.parse(body) as T;
  } catch (err) {
    throw new FetchValidationError(
      'content-type',
      url,
      `Response body failed to parse as JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
