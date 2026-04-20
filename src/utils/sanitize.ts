/**
 * Input sanitization utilities.
 * Strips prototype pollution keys, validates package names and versions.
 */
import yaml from 'js-yaml';

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** JSON.parse with reviver that strips __proto__, constructor, prototype keys */
export function safeJsonParse<T>(content: string): T {
  return JSON.parse(stripBom(content), (key, value) => {
    if (DANGEROUS_KEYS.has(key)) return undefined;
    return value;
  }) as T;
}

/** Strip UTF-8 BOM from file content */
export function stripBom(content: string): string {
  return content.replace(/^\uFEFF/, '');
}

/** Validate npm package name against strict regex */
const PACKAGE_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

export function isValidPackageName(name: string): boolean {
  return PACKAGE_NAME_RE.test(name) && name.length <= 214;
}

/** Validate lockfile path key — no traversal, no null bytes */
export function isValidLockfilePath(pathKey: string): boolean {
  if (pathKey === '') return true; // root entry
  if (pathKey.includes('\0')) return false;
  if (pathKey.includes('\\')) return false;
  if (pathKey.includes('..')) return false;
  return true;
}

/** Validate advisory ID format */
const GHSA_RE = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const MAL_RE = /^MAL-\d{4}-\d+$/;

export function isValidAdvisoryId(id: string): boolean {
  return GHSA_RE.test(id) || CVE_RE.test(id) || MAL_RE.test(id) || id.startsWith('PYSEC-') || id.startsWith('RUSTSEC-');
}

/**
 * Recursively remove `__proto__`, `constructor`, `prototype` keys from any object graph.
 * Safe against cycles via a visited WeakSet. Mutates nested object/array nodes in place.
 *
 * Used to neutralise prototype-pollution payloads smuggled through YAML inputs
 * (js-yaml's default schema preserves these keys as own-properties rather than
 * discarding them the way our JSON reviver does).
 */
export function stripProtoKeys<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value === null || typeof value !== 'object') return value;
  const node = value as unknown as object;
  if (seen.has(node)) return value;
  seen.add(node);

  if (Array.isArray(value)) {
    for (const item of value) stripProtoKeys(item, seen);
    return value;
  }

  for (const key of Object.keys(value as Record<string, unknown>)) {
    if (DANGEROUS_KEYS.has(key)) {
      delete (value as Record<string, unknown>)[key];
      continue;
    }
    stripProtoKeys((value as Record<string, unknown>)[key], seen);
  }
  return value;
}

/**
 * Safe YAML parser using js-yaml v4+ (no !!js/function RCE).
 *
 * All YAML inputs (policy files, pnpm-lock.yaml, yarn-berry yarn.lock, pnpm-workspace.yaml)
 * flow through this function. We strip prototype-pollution keys after parsing so every
 * downstream caller (src/core/lockfile/pnpm.ts, src/core/lockfile/yarn-berry.ts,
 * src/core/workspace/detector.ts, src/core/config.ts, src/core/policy/loader.ts)
 * automatically receives sanitized output — no per-site change needed.
 */
export function safeYamlParse(content: string): unknown {
  const parsed = yaml.load(stripBom(content), {
    schema: yaml.DEFAULT_SCHEMA,
    json: true,
  });
  return stripProtoKeys(parsed);
}
