/**
 * Parse CVSS v3.1 vector strings to numeric scores.
 * Manual implementation — no library needed.
 *
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */

const METRIC_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    N: 0.85, // unchanged scope
    L: 0.62, // unchanged scope
    H: 0.27, // unchanged scope
  },
  PR_CHANGED: {
    N: 0.85,
    L: 0.68,
    H: 0.50,
  },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 0, C: 1 }, // 0=unchanged, 1=changed
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

export type CvssResult = {
  score: number;
  vector: string;
};

/**
 * Parse a CVSS v3.1 vector string and compute the base score.
 * Returns score 0.0 if parsing fails.
 */
export function parseCvssVector(vector: string): CvssResult {
  if (!vector || !vector.startsWith('CVSS:3')) {
    return { score: 0, vector: vector ?? '' };
  }

  try {
    const metrics = parseMetrics(vector);
    const score = computeBaseScore(metrics);
    return { score, vector };
  } catch {
    return { score: 0, vector };
  }
}

function parseMetrics(vector: string): Record<string, string> {
  const parts = vector.split('/');
  const metrics: Record<string, string> = {};

  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value) {
      metrics[key] = value;
    }
  }

  return metrics;
}

function computeBaseScore(m: Record<string, string>): number {
  const av = METRIC_WEIGHTS.AV[m.AV] ?? 0;
  const ac = METRIC_WEIGHTS.AC[m.AC] ?? 0;
  const ui = METRIC_WEIGHTS.UI[m.UI] ?? 0;
  const scopeChanged = m.S === 'C';

  const prWeights = scopeChanged ? METRIC_WEIGHTS.PR_CHANGED : METRIC_WEIGHTS.PR;
  const pr = prWeights[m.PR] ?? 0;

  const c = METRIC_WEIGHTS.C[m.C] ?? 0;
  const i = METRIC_WEIGHTS.I[m.I] ?? 0;
  const a = METRIC_WEIGHTS.A[m.A] ?? 0;

  // Impact Sub Score
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

  let impact: number;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  if (impact <= 0) return 0;

  // Exploitability
  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore: number;
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }

  // Round up to 1 decimal place (CVSS spec)
  return Math.ceil(baseScore * 10) / 10;
}

/**
 * Map a CVSS numeric score to a severity label.
 */
export function cvssToSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
