import { describe, it, expect } from 'vitest';
import {
  osvToOfflineEntries,
  isRecentlyModified,
  convertOsvBatch,
} from '../../src/core/advisory/osv-to-offline.js';
import type { OsvVulnerability } from '../../src/types/advisory.js';

function makeVuln(overrides: Partial<OsvVulnerability> = {}): OsvVulnerability {
  return {
    id: 'GHSA-test-1234-abcd',
    summary: 'Test vulnerability in test-pkg',
    details: 'A test vulnerability for unit testing.',
    aliases: ['CVE-2024-12345'],
    modified: '2025-06-15T00:00:00Z',
    published: '2025-01-01T00:00:00Z',
    affected: [
      {
        package: { ecosystem: 'npm', name: 'test-pkg' },
        ranges: [
          {
            type: 'SEMVER',
            events: [
              { introduced: '1.0.0' },
              { fixed: '1.5.0' },
            ],
          },
        ],
      },
    ],
    severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    ],
    references: [
      { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-test-1234-abcd' },
    ],
    ...overrides,
  };
}

describe('osvToOfflineEntries', () => {
  it('converts a standard OSV vulnerability to an OfflineEntry', () => {
    const vuln = makeVuln();
    const entries = osvToOfflineEntries(vuln);

    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({
      id: 'GHSA-test-1234-abcd',
      pkg: 'test-pkg',
      range: '>=1.0.0 <1.5.0',
      fix: '1.5.0',
      severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      summary: 'Test vulnerability in test-pkg',
    });
  });

  it('skips non-npm ecosystems', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'PyPI', name: 'test-pkg' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '1.0.0' }, { fixed: '1.5.0' }],
            },
          ],
        },
      ],
    });

    expect(osvToOfflineEntries(vuln)).toHaveLength(0);
  });

  it('handles case-insensitive npm ecosystem check', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'NPM', name: 'test-pkg' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '0' }, { fixed: '2.0.0' }],
            },
          ],
        },
      ],
    });

    const entries = osvToOfflineEntries(vuln);
    expect(entries).toHaveLength(1);
    expect(entries[0].range).toBe('>=0.0.0 <2.0.0');
  });

  it('skips entries with no fix version', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'npm', name: 'test-pkg' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '1.0.0' }], // no fixed event
            },
          ],
        },
      ],
    });

    expect(osvToOfflineEntries(vuln)).toHaveLength(0);
  });

  it('skips entries with only GIT ranges (no semver range)', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'npm', name: 'test-pkg' },
          ranges: [
            {
              type: 'GIT',
              events: [{ introduced: 'abc123' }, { fixed: 'def456' }],
            },
          ],
        },
      ],
    });

    expect(osvToOfflineEntries(vuln)).toHaveLength(0);
  });

  it('produces multiple entries for multiple affected npm packages', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'npm', name: 'pkg-a' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '1.0.0' }, { fixed: '1.1.0' }],
            },
          ],
        },
        {
          package: { ecosystem: 'npm', name: 'pkg-b' },
          ranges: [
            {
              type: 'ECOSYSTEM',
              events: [{ introduced: '0' }, { fixed: '3.0.0' }],
            },
          ],
        },
      ],
    });

    const entries = osvToOfflineEntries(vuln);
    expect(entries).toHaveLength(2);
    expect(entries[0].pkg).toBe('pkg-a');
    expect(entries[1].pkg).toBe('pkg-b');
  });

  it('returns empty for null/undefined affected array', () => {
    const vuln = makeVuln({ affected: undefined as unknown as OsvVulnerability['affected'] });
    expect(osvToOfflineEntries(vuln)).toHaveLength(0);
  });

  it('returns empty for missing id', () => {
    const vuln = makeVuln({ id: '' });
    expect(osvToOfflineEntries(vuln)).toHaveLength(0);
  });

  it('uses summary fallback to id when summary is missing', () => {
    const vuln = makeVuln({ summary: undefined });
    const entries = osvToOfflineEntries(vuln);
    expect(entries).toHaveLength(1);
    expect(entries[0].summary).toBe('GHSA-test-1234-abcd');
  });

  it('prefers CVSS_V3 over other severity types', () => {
    const vuln = makeVuln({
      severity: [
        { type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' },
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
      ],
    });

    const entries = osvToOfflineEntries(vuln);
    expect(entries[0].severity).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
  });

  it('falls back to CVSS_V4 when no CVSS_V3', () => {
    const vuln = makeVuln({
      severity: [
        { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N' },
      ],
    });

    const entries = osvToOfflineEntries(vuln);
    expect(entries[0].severity).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N');
  });

  it('returns empty severity string when no severity data', () => {
    const vuln = makeVuln({ severity: undefined });
    const entries = osvToOfflineEntries(vuln);
    expect(entries[0].severity).toBe('');
  });

  it('handles multiple ranges in a single affected entry', () => {
    const vuln = makeVuln({
      affected: [
        {
          package: { ecosystem: 'npm', name: 'multi-range-pkg' },
          ranges: [
            {
              type: 'SEMVER',
              events: [
                { introduced: '1.0.0' },
                { fixed: '1.5.0' },
              ],
            },
            {
              type: 'ECOSYSTEM',
              events: [
                { introduced: '2.0.0' },
                { fixed: '2.3.0' },
              ],
            },
          ],
        },
      ],
    });

    const entries = osvToOfflineEntries(vuln);
    expect(entries).toHaveLength(1);
    expect(entries[0].range).toBe('>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0');
    // Fix version comes from first non-GIT range
    expect(entries[0].fix).toBe('1.5.0');
  });
});

describe('isRecentlyModified', () => {
  it('returns true for vulnerability modified after cutoff', () => {
    const vuln = makeVuln({ modified: '2025-06-01T00:00:00Z' });
    const cutoff = new Date('2024-01-01T00:00:00Z');
    expect(isRecentlyModified(vuln, cutoff)).toBe(true);
  });

  it('returns false for vulnerability modified before cutoff', () => {
    const vuln = makeVuln({ modified: '2020-01-01T00:00:00Z' });
    const cutoff = new Date('2024-01-01T00:00:00Z');
    expect(isRecentlyModified(vuln, cutoff)).toBe(false);
  });

  it('returns true when modified exactly at cutoff', () => {
    const vuln = makeVuln({ modified: '2024-01-01T00:00:00Z' });
    const cutoff = new Date('2024-01-01T00:00:00Z');
    expect(isRecentlyModified(vuln, cutoff)).toBe(true);
  });

  it('returns false for missing modified date', () => {
    const vuln = makeVuln({ modified: '' });
    const cutoff = new Date('2024-01-01T00:00:00Z');
    expect(isRecentlyModified(vuln, cutoff)).toBe(false);
  });
});

describe('convertOsvBatch', () => {
  it('filters by recency and converts', () => {
    const cutoff = new Date('2024-01-01T00:00:00Z');

    const recentVuln = makeVuln({
      id: 'GHSA-recent-0001',
      modified: '2025-03-01T00:00:00Z',
    });

    const oldVuln = makeVuln({
      id: 'GHSA-old-0001',
      modified: '2020-01-01T00:00:00Z',
    });

    const entries = convertOsvBatch([recentVuln, oldVuln], cutoff);
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe('GHSA-recent-0001');
  });

  it('deduplicates by id+pkg', () => {
    const cutoff = new Date('2020-01-01T00:00:00Z');

    const vuln1 = makeVuln({ id: 'GHSA-dupe-0001', modified: '2025-01-01T00:00:00Z' });
    const vuln2 = makeVuln({ id: 'GHSA-dupe-0001', modified: '2025-02-01T00:00:00Z' });

    const entries = convertOsvBatch([vuln1, vuln2], cutoff);
    expect(entries).toHaveLength(1);
  });

  it('allows same id with different packages', () => {
    const cutoff = new Date('2020-01-01T00:00:00Z');

    const vuln1 = makeVuln({
      id: 'GHSA-multi-0001',
      modified: '2025-01-01T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'pkg-a' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
        },
      ],
    });

    const vuln2 = makeVuln({
      id: 'GHSA-multi-0001',
      modified: '2025-01-01T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'pkg-b' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
        },
      ],
    });

    const entries = convertOsvBatch([vuln1, vuln2], cutoff);
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.pkg).sort()).toEqual(['pkg-a', 'pkg-b']);
  });

  it('returns empty array for empty input', () => {
    const cutoff = new Date('2024-01-01T00:00:00Z');
    expect(convertOsvBatch([], cutoff)).toEqual([]);
  });

  it('skips vulns without fix versions even if recent', () => {
    const cutoff = new Date('2020-01-01T00:00:00Z');

    const noFixVuln = makeVuln({
      id: 'GHSA-nofix-0001',
      modified: '2025-01-01T00:00:00Z',
      affected: [
        {
          package: { ecosystem: 'npm', name: 'no-fix-pkg' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }] }],
        },
      ],
    });

    const entries = convertOsvBatch([noFixVuln], cutoff);
    expect(entries).toHaveLength(0);
  });
});
