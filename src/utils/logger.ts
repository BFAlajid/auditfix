/**
 * Structured logger with verbosity levels and token redaction.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

// Patterns to redact from all log output
const TOKEN_PATTERNS = [
  /gh[ps]_[A-Za-z0-9_]{36,}/g,
  /github_pat_[A-Za-z0-9_]{82,}/g,
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /Authorization:\s*[^\s]+/gi,
];

function redact(message: string): string {
  let result = message;
  for (const pattern of TOKEN_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

let currentLevel: LogLevel = 'info';

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}

export function debug(message: string): void {
  if (shouldLog('debug')) {
    console.error(redact(`[debug] ${message}`));
  }
}

export function info(message: string): void {
  if (shouldLog('info')) {
    console.error(redact(`[info] ${message}`));
  }
}

export function warn(message: string): void {
  if (shouldLog('warn')) {
    console.error(redact(`[warn] ${message}`));
  }
}

export function error(message: string): void {
  if (shouldLog('error')) {
    console.error(redact(`[error] ${message}`));
  }
}
