/**
 * Risk scoring engine.
 * Combines CVSS + production reachability + exploit status + fix availability.
 */
import type { AdvisoryMatch } from '../../types/advisory.js';
import type { RiskScore, ScoredVulnerability } from '../../types/report.js';
import { parseCvssVector, cvssToSeverity } from './cvss.js';

/**
 * Score a single advisory match.
 */
export function scoreMatch(match: AdvisoryMatch): ScoredVulnerability {
  const { advisory } = match;

  // Parse CVSS vector from severity data
  let cvssScore = 0;
  let cvssVector = '';
  if (advisory.severity && advisory.severity.length > 0) {
    // Prefer CVSS_V3
    const v3 = advisory.severity.find((s) => s.type === 'CVSS_V3');
    const severity = v3 ?? advisory.severity[0];
    const parsed = parseCvssVector(severity.score);
    cvssScore = parsed.score;
    cvssVector = parsed.vector;
  }

  const fixAvailable = advisory.fixVersion !== null;
  const directDependency = match.dependencyPath.length <= 1;
  const depth = match.dependencyPath.length;

  // Check for known exploit references
  const exploitAvailable = hasExploitIndicator(advisory.references?.map(r => r.url) ?? []);

  // Compute composite score (0-100)
  const score = computeCompositeScore({
    cvssScore,
    isProduction: match.isProduction,
    isDirectlyImported: match.isDirectlyImported ?? false,
    exploitAvailable,
    fixAvailable,
    depth,
    directDependency,
  });

  // Determine label based on production reachability + CVSS
  const label = determineLabel({
    cvssScore,
    isProduction: match.isProduction,
    exploitAvailable,
  });

  const risk: RiskScore = {
    score,
    label,
    factors: {
      cvssScore,
      cvssVector,
      productionReachable: match.isProduction,
      directlyImported: match.isDirectlyImported ?? false,
      exploitAvailable,
      fixAvailable,
      fixVersion: advisory.fixVersion,
      depth,
      directDependency,
    },
  };

  return { match, risk };
}

/**
 * Score all matches and sort by risk (highest first).
 */
export function scoreAllMatches(matches: AdvisoryMatch[]): ScoredVulnerability[] {
  return matches
    .map(scoreMatch)
    .sort((a, b) => b.risk.score - a.risk.score);
}

function computeCompositeScore(factors: {
  cvssScore: number;
  isProduction: boolean;
  isDirectlyImported: boolean;
  exploitAvailable: boolean;
  fixAvailable: boolean;
  depth: number;
  directDependency: boolean;
}): number {
  let score = 0;

  // CVSS base: 0-10 mapped to 0-40
  score += factors.cvssScore * 4;

  // Production reachability: massive weight (the key differentiator)
  if (factors.isProduction) {
    score += 30;
  }

  // Directly imported by application code: stronger reachability signal
  if (factors.isDirectlyImported) {
    score += 10;
  }

  // Exploit available: significant boost
  if (factors.exploitAvailable) {
    score += 15;
  }

  // No fix available: slight boost (harder to remediate)
  if (!factors.fixAvailable) {
    score += 5;
  }

  // Direct dependency: slight boost (easier to fix)
  if (factors.directDependency) {
    score += 5;
  }

  // Depth penalty: deeper = slightly less urgent
  score -= Math.min(factors.depth, 5);

  return Math.max(0, Math.min(100, Math.round(score)));
}

function determineLabel(factors: {
  cvssScore: number;
  isProduction: boolean;
  exploitAvailable: boolean;
}): RiskScore['label'] {
  // Architecture spec scoring formula:
  if (factors.isProduction && factors.exploitAvailable && factors.cvssScore >= 7) {
    return 'critical';
  }
  if (factors.isProduction && factors.cvssScore >= 7) {
    return 'high';
  }
  if (factors.isProduction && factors.cvssScore >= 4) {
    return 'medium';
  }
  if (!factors.isProduction) {
    return 'low'; // dev-only = low regardless of CVSS
  }
  if (factors.cvssScore >= 4) {
    return 'medium';
  }
  return 'low';
}

/** Check references for known exploit databases / PoC indicators */
function hasExploitIndicator(urls: string[]): boolean {
  const exploitPatterns = [
    'exploit-db.com',
    'packetstormsecurity.com',
    '/cisa.gov/known-exploited',
  ];

  return urls.some((url) =>
    exploitPatterns.some((pattern) => url.includes(pattern))
  );
}
