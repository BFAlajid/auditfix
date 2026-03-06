/**
 * Main analysis pipeline.
 * Orchestrates: lockfile parsing -> reachability -> advisory resolve -> matching -> scoring
 */
import type { AuditReport, ScanMetadata, ConfidenceLevel, RiskScore } from '../types/report.js';
import { detectAndParseLockfile } from './lockfile/parser.js';
import { computeDependencyPaths } from './graph/reachability.js';
import { resolveAdvisories, AdvisoryResolutionError } from './advisory/resolver.js';
import { matchAdvisories } from './advisory/matcher.js';
import { scoreAllMatches } from './advisory/scorer.js';
import { loadLocalAllowList, applyAllowList } from './allowlist/local.js';
import * as logger from '../utils/logger.js';

export type AnalyzeOptions = {
  projectDir: string;
  productionOnly: boolean;
  severityThreshold?: RiskScore['label'];
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

  // 2. Compute dependency paths
  computeDependencyPaths(lockfileResult.graph);

  // 3. Resolve advisories (three-tier fallback: OSV → cache → npm)
  let advisorySource: string;
  let confidence: ConfidenceLevel;
  let advisoryCount: number;
  let advisories: Map<string, import('../types/advisory.js').Advisory[]>;

  try {
    const resolved = await resolveAdvisories(lockfileResult.graph);
    advisories = resolved.advisories;
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
        },
        ignored: [],
      };
    }
    throw err;
  }

  // 4. Match advisories to installed packages
  logger.info('Matching advisories...');
  const allMatches = matchAdvisories(lockfileResult.graph, advisories);
  logger.info(`Found ${allMatches.length} vulnerability matches`);

  // 5. Apply allow-list
  const allowList = loadLocalAllowList(options.projectDir);
  const { kept: matches, ignored } = applyAllowList(allMatches, allowList);

  if (ignored.length > 0) {
    logger.info(`${ignored.length} vulnerabilities suppressed by allow-list`);
  }

  // 6. Score and sort
  let scored = scoreAllMatches(matches);

  // Filter production-only if requested
  if (options.productionOnly) {
    scored = scored.filter((s) => s.match.isProduction);
  }

  // Filter by severity threshold
  if (options.severityThreshold && options.severityThreshold !== 'info') {
    const severityRank: Record<RiskScore['label'], number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };
    const minRank = severityRank[options.severityThreshold] ?? 0;
    scored = scored.filter((s) => severityRank[s.risk.label] >= minRank);
  }

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
