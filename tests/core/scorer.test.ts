import { describe, it, expect } from 'vitest';
import { scoreMatch } from '../../src/core/advisory/scorer.js';
import { parseCvssVector, cvssToSeverity } from '../../src/core/advisory/cvss.js';
import type { AdvisoryMatch, Advisory } from '../../src/types/advisory.js';

function makeMatch(overrides: Partial<{
  isProduction: boolean;
  cvssVector: string;
  fixVersion: string | null;
  depth: number;
}>): AdvisoryMatch {
  const advisory: Advisory = {
    id: 'GHSA-test-test-test',
    aliases: ['CVE-2024-1234'],
    summary: 'Test vulnerability',
    details: '',
    severity: overrides.cvssVector
      ? [{ type: 'CVSS_V3', score: overrides.cvssVector }]
      : [],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: 'fixVersion' in overrides ? overrides.fixVersion! : '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
  };

  return {
    advisory,
    package: 'test-pkg',
    installedVersion: '1.5.0',
    dependencyPath: Array(overrides.depth ?? 1).fill('pkg'),
    isProduction: overrides.isProduction ?? true,
  };
}

describe('risk scoring', () => {
  it('scores production + high CVSS + exploit as critical', () => {
    const match = makeMatch({
      isProduction: true,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });
    // Add exploit reference
    match.advisory.references = [{ type: 'WEB', url: 'https://exploit-db.com/exploits/12345' }];

    const result = scoreMatch(match);
    expect(result.risk.label).toBe('critical');
    expect(result.risk.score).toBeGreaterThan(70);
  });

  it('scores production + high CVSS without exploit as high', () => {
    const match = makeMatch({
      isProduction: true,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });

    const result = scoreMatch(match);
    expect(result.risk.label).toBe('high');
  });

  it('scores dev-only as low regardless of CVSS', () => {
    const match = makeMatch({
      isProduction: false,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });

    const result = scoreMatch(match);
    expect(result.risk.label).toBe('low');
  });

  it('scores no fix available higher than fix available', () => {
    const withFix = scoreMatch(makeMatch({
      fixVersion: '2.0.0',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    }));
    const noFix = scoreMatch(makeMatch({
      fixVersion: null,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    }));

    expect(noFix.risk.score).toBeGreaterThanOrEqual(withFix.risk.score);
    expect(noFix.risk.factors.fixAvailable).toBe(false);
    expect(withFix.risk.factors.fixAvailable).toBe(true);
  });
});

describe('CVSS parsing', () => {
  it('parses a critical CVSS vector', () => {
    const result = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.score).toBeGreaterThanOrEqual(9.0);
  });

  it('parses a medium CVSS vector', () => {
    const result = parseCvssVector('CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N');
    expect(result.score).toBeGreaterThanOrEqual(3.0);
    expect(result.score).toBeLessThan(7.0);
  });

  it('returns 0 for invalid vector', () => {
    const result = parseCvssVector('not-a-vector');
    expect(result.score).toBe(0);
  });

  it('returns 0 for empty string', () => {
    const result = parseCvssVector('');
    expect(result.score).toBe(0);
  });
});

describe('cvssToSeverity', () => {
  it('maps scores to correct labels', () => {
    expect(cvssToSeverity(9.8)).toBe('critical');
    expect(cvssToSeverity(7.5)).toBe('high');
    expect(cvssToSeverity(5.0)).toBe('medium');
    expect(cvssToSeverity(2.0)).toBe('low');
    expect(cvssToSeverity(0)).toBe('info');
  });
});
