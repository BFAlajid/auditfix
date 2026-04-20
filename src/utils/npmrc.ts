/**
 * Minimal .npmrc parser for registry and auth-token configuration.
 *
 * Supports the subset of npm config needed to reach private registries:
 *   - `registry=<url>`                 default registry
 *   - `@scope:registry=<url>`          per-scope registry
 *   - `//host/path/:_authToken=<tok>`  bearer token keyed by registry URL
 *   - `${VAR}` env-var expansion (common for token security)
 *
 * Precedence (first hit wins — earlier files override later ones):
 *   1. <projectDir>/.npmrc
 *   2. ~/.npmrc
 *   3. /etc/npmrc
 *
 * Malformed lines are skipped with a debug log; the parser never throws.
 */
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import * as logger from './logger.js';

export type NpmrcConfig = {
  /** Default registry URL (normalized, trailing slash preserved if present). */
  defaultRegistry: string;
  /** Map of `@scope` -> registry URL. Keys include the leading `@`. */
  scopeRegistries: Record<string, string>;
  /** Map of registry URL (protocol-stripped, with leading //) -> bearer token. */
  authTokens: Record<string, string>;
};

const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';

/** Reference to npm's public registry — used when no override configured. */
export function defaultNpmrcConfig(): NpmrcConfig {
  return {
    defaultRegistry: DEFAULT_REGISTRY,
    scopeRegistries: {},
    authTokens: {},
  };
}

/**
 * Load and merge .npmrc files in npm's precedence order.
 * Missing files are treated as empty (silent). Malformed lines skipped.
 */
export async function loadNpmrc(projectDir: string): Promise<NpmrcConfig> {
  const paths = [
    resolve(projectDir, '.npmrc'),
    join(homedir(), '.npmrc'),
    '/etc/npmrc',
  ];

  const merged = defaultNpmrcConfig();

  // Walk in reverse precedence (low-priority first) so later reads override.
  // Precedence order is [project, home, etc]; reverse to [etc, home, project].
  for (const p of [...paths].reverse()) {
    const parsed = await readAndParse(p);
    if (!parsed) continue;
    if (parsed.defaultRegistry) {
      merged.defaultRegistry = parsed.defaultRegistry;
    }
    Object.assign(merged.scopeRegistries, parsed.scopeRegistries);
    Object.assign(merged.authTokens, parsed.authTokens);
  }

  return merged;
}

/** Read a file and parse it; return null on any read error. */
async function readAndParse(path: string): Promise<NpmrcConfig | null> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return null;
  }
  try {
    return parseNpmrc(text);
  } catch (err) {
    logger.debug(
      `Failed to parse .npmrc at ${path}: ${err instanceof Error ? err.message : String(err)}`
    );
    return null;
  }
}

/**
 * Parse raw .npmrc text. Exported for testing.
 * Unknown/malformed lines are dropped silently (npm's own behavior).
 */
export function parseNpmrc(text: string): NpmrcConfig {
  const out = defaultNpmrcConfig();
  // Ensure default isn't populated unless the file sets it.
  out.defaultRegistry = '';

  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;

    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;

    const keyRaw = line.slice(0, eqIdx).trim();
    const valueRaw = line.slice(eqIdx + 1).trim();
    if (!keyRaw || !valueRaw) continue;

    const value = expandEnv(stripQuotes(valueRaw));
    if (!value) continue;

    // Scope registry: @scope:registry=<url>
    const scopeMatch = keyRaw.match(/^(@[^:]+):registry$/);
    if (scopeMatch) {
      out.scopeRegistries[scopeMatch[1]] = value;
      continue;
    }

    // Auth token: //host/path/:_authToken=<token>
    // Also support :_auth and :username/:_password combos lightly.
    if (keyRaw.startsWith('//')) {
      const colonIdx = keyRaw.lastIndexOf(':');
      if (colonIdx === -1) continue;
      const prefix = keyRaw.slice(0, colonIdx); // "//host/path/"
      const subKey = keyRaw.slice(colonIdx + 1);
      if (subKey === '_authToken') {
        out.authTokens[prefix] = value;
      }
      continue;
    }

    // Default registry
    if (keyRaw === 'registry') {
      out.defaultRegistry = value;
      continue;
    }

    // Other keys (always-auth, email, prefix, etc.) are ignored for our purposes.
  }

  if (!out.defaultRegistry) {
    out.defaultRegistry = DEFAULT_REGISTRY;
  }
  return out;
}

/** Strip wrapping quotes if present. */
function stripQuotes(v: string): string {
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    return v.slice(1, -1);
  }
  return v;
}

/**
 * Expand ${VAR} references against process.env. Missing vars resolve to ''.
 * Supports both ${VAR} and $VAR forms — npm accepts only ${VAR}, we match that.
 */
export function expandEnv(value: string): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name) => {
    return process.env[name] ?? '';
  });
}

/**
 * Resolve the registry URL that should be used to look up `packageName`.
 * Scoped packages route to their scope's registry if configured.
 */
export function registryForPackage(
  packageName: string,
  config: NpmrcConfig
): string {
  if (packageName.startsWith('@')) {
    const slash = packageName.indexOf('/');
    if (slash !== -1) {
      const scope = packageName.slice(0, slash);
      const scoped = config.scopeRegistries[scope];
      if (scoped) return scoped;
    }
  }
  return config.defaultRegistry;
}

/**
 * Find the bearer token whose key (e.g. `//host/path/`) is a prefix of the
 * registry URL's authority+path. Strips protocol when matching so a token
 * stored as `//npm.example.com/` matches `https://npm.example.com/`.
 *
 * Returns null if no matching token is configured.
 */
export function tokenForRegistry(
  registryUrl: string,
  config: NpmrcConfig
): string | null {
  const stripped = stripProtocol(registryUrl);
  let best: { key: string; token: string } | null = null;

  for (const [key, token] of Object.entries(config.authTokens)) {
    const keyStripped = stripProtocol(key);
    if (!keyStripped) continue;
    if (stripped.startsWith(keyStripped)) {
      // Prefer the longest prefix match.
      if (!best || keyStripped.length > stripProtocol(best.key).length) {
        best = { key, token };
      }
    }
  }
  return best?.token ?? null;
}

/** Drop scheme so `https://host/path` and `//host/path` compare equal. */
function stripProtocol(url: string): string {
  return url.replace(/^[a-z]+:/i, '');
}
