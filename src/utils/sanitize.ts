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

/** Safe YAML parser using js-yaml v4+ (no !!js/function RCE). */
export function safeYamlParse(content: string): unknown {
  return yaml.load(stripBom(content), {
    schema: yaml.DEFAULT_SCHEMA,
    json: true,
  });
}
