import { describe, it, expect } from 'vitest';
import { extractCveIds, computeExploitScore } from '../../src/core/advisory/epss.js';
import type { EpssScore } from '../../src/core/advisory/epss.js';

describe('extractCveIds', () => {
  it('filters CVE-prefixed aliases', () => {
    const result = extractCveIds(['CVE-2024-1234', 'GHSA-xxxx', 'CVE-2023-5678']);
    expect(result).toEqual(['CVE-2024-1234', 'CVE-2023-5678']);
  });

  it('returns empty for no CVEs', () => {
    expect(extractCveIds(['GHSA-xxxx'])).toEqual([]);
    expect(extractCveIds([])).toEqual([]);
  });
});

describe('computeExploitScore', () => {
  it('returns 20 for CVE in KEV catalog', () => {
    const kevSet = new Set(['CVE-2024-1234']);
    const result = computeExploitScore(['CVE-2024-1234'], new Map(), kevSet);
    expect(result.score).toBe(20);
    expect(result.inKev).toBe(true);
  });

  it('returns 20 for very high EPSS (>=0.5)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.6, percentile: 0.98 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(20);
    expect(result.inKev).toBe(false);
    expect(result.epssMax).toBe(0.6);
  });

  it('returns 15 for high EPSS (>=0.1)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.15, percentile: 0.9 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(15);
  });

  it('returns 8 for moderate EPSS (>=0.01)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.05, percentile: 0.7 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(8);
  });

  it('returns 2 for low EPSS (<0.01)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.005, percentile: 0.3 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(2);
  });

  it('returns 0 when no data available', () => {
    const result = computeExploitScore(['CVE-2024-1234'], new Map(), new Set());
    expect(result.score).toBe(0);
    expect(result.epssMax).toBeNull();
  });

  it('picks highest EPSS across multiple CVEs', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1', { cve: 'CVE-2024-1', epss: 0.02, percentile: 0.5 }],
      ['CVE-2024-2', { cve: 'CVE-2024-2', epss: 0.2, percentile: 0.92 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1', 'CVE-2024-2'], epss, new Set());
    expect(result.epssMax).toBe(0.2);
    expect(result.score).toBe(15);
  });
});
