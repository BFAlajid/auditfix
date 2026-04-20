/**
 * Main analysis pipeline.
 * Orchestrates: lockfile parsing -> reachability -> advisory resolve -> matching -> scoring
 */
import type { AuditReport, ScanMetadata, ConfidenceLevel, RiskScore } from '../types/report.js';
import { detectAndParseLockfile } from './lockfile/parser.js';
import { computeDependencyPaths } from './graph/reachability.js';
import { resolveAdvisories, resolveAdvisoriesWithCache, AdvisoryResolutionError } from './advisory/resolver.js';
import { matchAdvisories } from './advisory/matcher.js';
import { scoreAllMatches } from './advisory/scorer.js';
import type { ScorerContext } from './advisory/scorer.js';
import { fetchEpssScores, fetchKevCatalog, extractCveIds } from './advisory/epss.js';
import { loadLocalAllowList, applyAllowList } from './allowlist/local.js';
import { detectWorkspaces, mapDepsToWorkspaces } from './workspace/detector.js';
import { scanImportChains, isDirectlyImported } from './graph/import-chain.js';
import * as logger from '../utils/logger.js';

export type AnalyzeOptions = {
  projectDir: string;
  productionOnly: boolean;
  severityThreshold?: RiskScore['label'];
  workspace?: string; // filter to a specific workspace
  noCache?: boolean;  // bypass advisory cache
};

export async function analyze(options: AnalyzeOptions): Promise<AuditReport> {
  const startTime = Date.now();

  // 1. Parse lockfile
  logger.info('Detecting and parsing lockfile...');
  const lockfileResult = detectAndParseLockfile(options.projectDir);
  logger.info(`Parsed ${lockfileResult.packageCount} packages (${lockfileResult.type})`);

  if (lockfileResult.skipped.length > 0) {
    logger.debug(`Skipped ${lockfileResult.skipped.length} entries: ${lockfileResult.skipped.map(s => `${s.key} (${s.reason})`).join(', ')}`);
  }

  // 2. Detect workspaces
  const wsConfig = detectWorkspaces(options.projectDir);
  let depToWorkspaces: Map<string, Set<string>> | undefined;
  if (wsConfig.isMonorepo) {
    logger.info(`Monorepo detected: ${wsConfig.workspaces.length} workspaces`);
    depToWorkspaces = mapDepsToWorkspaces(lockfileResult.graph, wsConfig.workspaces);
  }

  // 2b. Scan import chains for reachability analysis
  const importedPackages = scanImportChains(options.projectDir);

  // 3. Compute dependency paths
  computeDependencyPaths(lockfileResult.graph);

  // 4. Resolve advisories (three-tier fallback: OSV → cache → npm)
  let advisorySource: string;
  let confidence: ConfidenceLevel;
  let advisoryCount: number;
  let advisories: Map<string, import('../types/advisory.js').Advisory[]>;

  try {
    const resolved = await resolveAdvisoriesWithCache(lockfileResult.graph, { noCache: options.noCache });
    advisories = resolved.advisories;
    // TODO(resolver-sourceId): prefer `resolved.sourceId` for any downstream
    // logic that needs to branch on origin (telemetry, confidence rules, etc.).
    // The `source` string is retained for human-readable display only.
    advisorySource = resolved.source;
    confidence = resolved.confidence;
    advisoryCount = countAdvisories(advisories);

    if (resolved.errors.length > 0) {
      for (const err of resolved.errors) {
        logger.warn(err);
      }
    }
  } catch (err) {
    if (err instanceof AdvisoryResolutionError) {
      // All sources failed — exit 2
      for (const e of err.errors) {
        logger.warn(e);
      }
      logger.error(err.message);

      return {
        vulnerabilities: [],
        metadata: {
          totalPackages: lockfileResult.packageCount,
          skippedPackages: lockfileResult.skipped.length,
          skippedReasons: lockfileResult.skipped.map((s) => ({ key: s.key, reason: s.reason })),
          advisorySource: 'None (all sources failed)',
          advisoryCount: 0,
          confidence: 'UNRELIABLE',
          scanDurationMs: Date.now() - startTime,
          lockfileType: lockfileResult.type,
        },
        ignored: [],
      };
    }
    throw err;
  }

  // 5. Match advisories to installed packages
  logger.info('Matching advisories...');
  const allMatches = matchAdvisories(lockfileResult.graph, advisories);

  // Annotate matches with workspace info and import-chain reachability in a
  // single pass. Merged from two separate loops — the work is O(1) per match
  // so there's no reason to iterate the list twice.
  for (const match of allMatches) {
    if (depToWorkspaces) {
      const graphKey = `${match.package}@${match.installedVersion}`;
      const ws = depToWorkspaces.get(graphKey);
      if (ws && ws.size > 0) {
        match.workspaces = [...ws];
      }
    }
    match.isDirectlyImported = isDirectlyImported(match.package, importedPackages);
  }

  logger.info(`Found ${allMatches.length} vulnerability matches`);

  // 6. Apply allow-list
  const allowList = loadLocalAllowList(options.projectDir);
  const { kept: matches, ignored } = applyAllowList(allMatches, allowList);

  if (ignored.length > 0) {
    logger.info(`${ignored.length} vulnerabilities suppressed by allow-list`);
  }

  // 7. Fetch EPSS + KEV data for exploit scoring
  const allCveIds = new Set<string>();
  for (const m of matches) {
    for (const cve of extractCveIds(m.advisory.aliases ?? [])) {
      allCveIds.add(cve);
    }
  }

  let scorerCtx: ScorerContext = {};
  if (allCveIds.size > 0) {
    logger.info(`Fetching EPSS/KEV data for ${allCveIds.size} CVEs...`);
    const [epssScores, kevSet] = await Promise.all([
      fetchEpssScores([...allCveIds]).catch(() => new Map()),
      fetchKevCatalog().catch(() => new Set<string>()),
    ]);
    scorerCtx = { epssScores, kevSet };
    logger.debug(`EPSS: ${epssScores.size} scores, KEV: ${kevSet.size} entries`);
  }

  // 8. Score, sort, and filter in single pass
  const severityRank: Record<RiskScore['label'], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const minRank = (options.severityThreshold && options.severityThreshold !== 'info')
    ? (severityRank[options.severityThreshold] ?? 0)
    : 0;

  let scored = scoreAllMatches(matches, scorerCtx).filter((s) => {
    if (options.workspace && !(s.match.workspaces?.includes(options.workspace!) ?? false)) return false;
    if (options.productionOnly && !s.match.isProduction) return false;
    if (minRank > 0 && severityRank[s.risk.label] < minRank) return false;
    return true;
  });

  // Determine confidence based on skip rate (can only degrade, not upgrade)
  const skipRate = lockfileResult.skipped.length / Math.max(lockfileResult.packageCount, 1);
  if (skipRate > 0.1) {
    confidence = 'UNRELIABLE';
  } else if (skipRate > 0.05 && confidence === 'HIGH') {
    confidence = 'MEDIUM';
  }

  const metadata: ScanMetadata = {
    totalPackages: lockfileResult.packageCount,
    skippedPackages: lockfileResult.skipped.length,
    skippedReasons: lockfileResult.skipped.map((s) => ({ key: s.key, reason: s.reason })),
    advisorySource,
    advisoryCount,
    confidence,
    scanDurationMs: Date.now() - startTime,
    workspaceCount: wsConfig.isMonorepo ? wsConfig.workspaces.length : undefined,
    lockfileType: lockfileResult.type,
  };

  return {
    vulnerabilities: scored,
    metadata,
    ignored,
  };
}

function countAdvisories(advisories: Map<string, import('../types/advisory.js').Advisory[]>): number {
  let count = 0;
  for (const [, list] of advisories) {
    count += list.length;
  }
  return count;
}
