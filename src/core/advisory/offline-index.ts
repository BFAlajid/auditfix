/**
 * Bundled offline advisory index.
 * Ships a static snapshot of high-severity npm advisories so auditfix
 * can produce results even with zero network access.
 *
 * The index is intentionally small — only critical/high severity advisories
 * for the top 200 npm packages. It's a last-resort fallback, not a primary source.
 *
 * Update: run `npm run build:index` to regenerate from OSV bulk export.
 */
import type { Advisory } from '../../types/advisory.js';
import semver from 'semver';
import * as logger from '../../utils/logger.js';

export type OfflineEntry = {
  id: string;
  pkg: string;
  range: string;          // affected semver range
  fix: string | null;     // fix version or null
  severity: string;       // CVSS vector
  summary: string;
};

/**
 * Try to load the auto-generated index from the OSV bulk export.
 * Falls back to the hardcoded index if the generated file does not exist.
 *
 * Distinguish "module not present" (expected on fresh installs) from
 * "load threw an error" (worth retrying on the next call).
 */
let generatedIndex: OfflineEntry[] | null = null;
let generatedLoaded = false;

const MODULE_NOT_FOUND_CODES = new Set(['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND']);

function isModuleNotFound(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: unknown }).code;
  return typeof code === 'string' && MODULE_NOT_FOUND_CODES.has(code);
}

/**
 * Default loader — dynamic-imports the generated index. Swappable for tests
 * via `__testable.setLoader`.
 */
type GeneratedIndexLoader = () => Promise<OfflineEntry[] | null>;

const defaultLoader: GeneratedIndexLoader = async () => {
  // @ts-expect-error — generated file may not exist; handled by caller
  const mod = await import('./offline-index.generated.js');
  if (Array.isArray(mod.GENERATED_INDEX) && mod.GENERATED_INDEX.length > 0) {
    return mod.GENERATED_INDEX as OfflineEntry[];
  }
  return null;
};

let activeLoader: GeneratedIndexLoader = defaultLoader;

async function loadGeneratedIndex(): Promise<OfflineEntry[] | null> {
  if (generatedLoaded) return generatedIndex;
  try {
    const loaded = await activeLoader();
    if (loaded) generatedIndex = loaded;
    generatedLoaded = true;
  } catch (err) {
    // Missing generated file is the expected fresh-install path — accept
    // the hardcoded fallback and never retry.
    if (isModuleNotFound(err)) {
      generatedLoaded = true;
      return generatedIndex;
    }
    // Any other failure is transient (e.g. FS flake, permissions). Keep
    // `generatedLoaded` false so the next call re-attempts the import.
    logger.debug(
      `offline-index: generated load failed (will retry): ${err instanceof Error ? err.message : String(err)}`,
    );
    throw err;
  }
  return generatedIndex;
}

/**
 * Test-only seam. NOT part of the public API. Lets tests inject a custom
 * loader to exercise retry paths without resorting to import-mocking tricks.
 */
export const __testable = {
  setLoader(loader: GeneratedIndexLoader): void {
    activeLoader = loader;
  },
  resetLoader(): void {
    activeLoader = defaultLoader;
  },
};

/** Reset the generated-index load state. Intended for tests. */
export function resetOfflineIndexState(): void {
  generatedIndex = null;
  generatedLoaded = false;
  indexReady = null;
  indexLoadFailures = 0;
  BUILTIN_INDEX = HARDCODED_INDEX;
}

/**
 * Built-in advisory index — hardcoded last-resort fallback.
 * This is a curated subset of high-impact advisories.
 */
const HARDCODED_INDEX: OfflineEntry[] = [
  { id: 'GHSA-35jh-r3h4-6jhm', pkg: 'lodash', range: '<4.17.21', fix: '4.17.21', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', summary: 'Prototype Pollution in lodash' },
  { id: 'GHSA-jf85-cpcp-j695', pkg: 'lodash', range: '<4.17.12', fix: '4.17.12', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', summary: 'Prototype Pollution in lodash' },
  { id: 'GHSA-4xc9-xhrj-v574', pkg: 'minimist', range: '<1.2.6', fix: '1.2.6', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', summary: 'Prototype Pollution in minimist' },
  { id: 'GHSA-c2qf-rxjj-qqgw', pkg: 'semver', range: '>=7.0.0 <7.5.2', fix: '7.5.2', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'ReDoS in semver' },
  { id: 'GHSA-952p-6rrq-rcjv', pkg: 'jsonwebtoken', range: '<9.0.0', fix: '9.0.0', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', summary: 'Insecure default algorithm in jsonwebtoken' },
  { id: 'GHSA-36fh-84j7-cv5h', pkg: 'express', range: '<4.19.2', fix: '4.19.2', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', summary: 'Open redirect in express' },
  { id: 'GHSA-rv95-896h-c2vc', pkg: 'express', range: '<4.20.0', fix: '4.20.0', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'ReDoS via content-type parsing in express' },
  { id: 'GHSA-qw6h-vgh9-j6wx', pkg: 'node-fetch', range: '<2.6.7', fix: '2.6.7', severity: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', summary: 'Exposure of sensitive information in node-fetch' },
  { id: 'GHSA-wf5p-g6vw-rhxx', pkg: 'axios', range: '>=0.8.1 <1.6.0', fix: '1.6.0', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', summary: 'SSRF in axios' },
  { id: 'GHSA-8hc4-vh64-cxmj', pkg: 'kind-of', range: '>=6.0.0 <6.0.3', fix: '6.0.3', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', summary: 'Type confusion in kind-of' },
  { id: 'GHSA-p8p7-x288-28g6', pkg: 'http-cache-semantics', range: '<4.1.1', fix: '4.1.1', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'ReDoS in http-cache-semantics' },
  { id: 'GHSA-3xgq-45jj-v275', pkg: 'tough-cookie', range: '<4.1.3', fix: '4.1.3', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'Prototype pollution in tough-cookie' },
  { id: 'GHSA-72xf-g2v4-qvf3', pkg: 'ini', range: '<1.3.6', fix: '1.3.6', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', summary: 'Prototype pollution in ini' },
  { id: 'GHSA-93q8-gq69-wqmw', pkg: 'qs', range: '>=6.7.0 <6.7.3', fix: '6.7.3', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'Prototype pollution in qs' },
  { id: 'GHSA-hrpp-h998-j3pp', pkg: 'qs', range: '>=6.5.0 <6.5.3', fix: '6.5.3', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'Prototype pollution in qs' },
  { id: 'GHSA-cph5-m8f7-6c5x', pkg: 'got', range: '<11.8.5', fix: '11.8.5', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', summary: 'Open redirect in got' },
  { id: 'GHSA-pfrx-2q88-qq97', pkg: 'json5', range: '<2.2.2', fix: '2.2.2', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', summary: 'Prototype pollution in json5' },
  { id: 'GHSA-9c47-m6qq-7p4h', pkg: 'json-schema', range: '<0.4.0', fix: '0.4.0', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', summary: 'Prototype pollution in json-schema' },
  { id: 'GHSA-8225-6cvr-8pqp', pkg: 'node-forge', range: '<1.3.0', fix: '1.3.0', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', summary: 'URL parsing vulnerability in node-forge' },
  { id: 'GHSA-2fc9-xpp8-2g9h', pkg: 'postcss', range: '<8.4.31', fix: '8.4.31', severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', summary: 'Line return parsing issue in postcss' },
];

/**
 * The effective index: generated (if available) merged with hardcoded fallback.
 * Generated index takes precedence; hardcoded entries are appended only if
 * their id+pkg combination is not already present in the generated set.
 */
function buildEffectiveIndex(gen: OfflineEntry[] | null): OfflineEntry[] {
  if (gen === null) {
    return HARDCODED_INDEX;
  }
  const seen = new Set(gen.map((e) => `${e.id}:${e.pkg}`));
  const extras = HARDCODED_INDEX.filter((e) => !seen.has(`${e.id}:${e.pkg}`));
  return [...gen, ...extras];
}

// Synchronous fallback used immediately; enriched lazily
let BUILTIN_INDEX: OfflineEntry[] = HARDCODED_INDEX;

// Attempt to load generated index on first async call.
//
// If the in-flight load rejects we must clear `indexReady` so the next caller
// re-runs the load. Otherwise one transient failure (FS hiccup, permissions
// race on first bundle extract) silently disables the generated index for
// the entire process lifetime. After MAX_INDEX_LOAD_FAILURES consecutive
// failures we stop retrying — the hardcoded fallback stays in place so
// scans keep working.
let indexReady: Promise<void> | null = null;
let indexLoadFailures = 0;
const MAX_INDEX_LOAD_FAILURES = 3;

function ensureIndex(): Promise<void> {
  if (indexReady) return indexReady;

  // Once we give up retrying we resolve immediately with the hardcoded
  // fallback that's already in BUILTIN_INDEX.
  if (indexLoadFailures >= MAX_INDEX_LOAD_FAILURES) {
    indexReady = Promise.resolve();
    return indexReady;
  }

  indexReady = (async () => {
    try {
      const gen = await loadGeneratedIndex();
      BUILTIN_INDEX = buildEffectiveIndex(gen);
      indexLoadFailures = 0;
    } catch (err) {
      indexLoadFailures += 1;
      logger.debug(
        `offline-index: load attempt ${indexLoadFailures} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      // Clear the cached promise so the next caller retries, unless we've
      // now hit the ceiling.
      if (indexLoadFailures < MAX_INDEX_LOAD_FAILURES) {
        indexReady = null;
      } else {
        logger.warn(
          `offline-index: generated load failed ${indexLoadFailures} times; using hardcoded fallback`,
        );
      }
      // Scanning must never abort because the *optional* generated index
      // could not be loaded — resolve successfully with whatever
      // BUILTIN_INDEX currently is (hardcoded fallback).
    }
  })();

  return indexReady;
}

/**
 * Query the offline index for advisories affecting a specific package + version.
 */
export function queryOfflineIndex(
  packageName: string,
  version: string,
): Advisory[] {
  const results: Advisory[] = [];

  for (const entry of BUILTIN_INDEX) {
    if (entry.pkg !== packageName) continue;

    try {
      if (semver.satisfies(version, entry.range, { includePrerelease: true })) {
        results.push({
          id: entry.id,
          aliases: [],
          summary: entry.summary,
          details: '',
          severity: [{ type: 'CVSS_V3', score: entry.severity }],
          affectedRange: entry.range,
          fixVersion: entry.fix,
          publishedAt: '',
          modifiedAt: '',
          references: [{ type: 'ADVISORY', url: `https://github.com/advisories/${entry.id}` }],
          source: 'offline-index',
        });
      }
    } catch {
      // Invalid semver — skip
    }
  }

  return results;
}

/**
 * Query the offline index for all packages in a dependency graph.
 * Returns advisories keyed by package name.
 */
export async function queryOfflineIndexBatch(
  graph: import('../../types/package.js').DependencyGraph,
): Promise<Map<string, Advisory[]>> {
  await ensureIndex();
  const result = new Map<string, Advisory[]>();
  const checked = new Set<string>();

  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (checked.has(key)) continue;
    checked.add(key);

    const advisories = queryOfflineIndex(node.name, node.version);
    if (advisories.length > 0) {
      const existing = result.get(node.name) ?? [];
      existing.push(...advisories);
      result.set(node.name, existing);
    }
  }

  return result;
}

/** Number of advisories in the bundled index */
export function getOfflineIndexSize(): number {
  return BUILTIN_INDEX.length;
}
