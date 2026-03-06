import { describe, it, expect } from 'vitest';
import { eventsToSemverRange, extractFixVersion, affectedToSemverRange } from '../../src/core/advisory/osv-ranges.js';
import type { OsvAffected } from '../../src/types/advisory.js';

describe('eventsToSemverRange', () => {
  it('converts introduced + fixed pair', () => {
    const result = eventsToSemverRange([
      { introduced: '1.0.0' },
      { fixed: '1.0.5' },
    ]);
    expect(result).toBe('>=1.0.0 <1.0.5');
  });

  it('converts "0" sentinel to "0.0.0"', () => {
    const result = eventsToSemverRange([
      { introduced: '0' },
      { fixed: '2.0.0' },
    ]);
    expect(result).toBe('>=0.0.0 <2.0.0');
  });

  it('handles last_affected (inclusive upper bound)', () => {
    const result = eventsToSemverRange([
      { introduced: '1.0.0' },
      { last_affected: '1.5.0' },
    ]);
    expect(result).toBe('>=1.0.0 <=1.5.0');
  });

  it('handles unpaired introduced (no fix)', () => {
    const result = eventsToSemverRange([
      { introduced: '3.0.0' },
    ]);
    expect(result).toBe('>=3.0.0');
  });

  it('handles multiple ranges joined with ||', () => {
    const result = eventsToSemverRange([
      { introduced: '1.0.0' },
      { fixed: '1.0.5' },
      { introduced: '2.0.0' },
      { fixed: '2.1.0' },
    ]);
    expect(result).toBe('>=1.0.0 <1.0.5 || >=2.0.0 <2.1.0');
  });

  it('handles empty events array', () => {
    const result = eventsToSemverRange([]);
    expect(result).toBe('');
  });

  it('handles mixed fixed and last_affected', () => {
    const result = eventsToSemverRange([
      { introduced: '0' },
      { fixed: '1.0.0' },
      { introduced: '2.0.0' },
      { last_affected: '2.5.0' },
    ]);
    expect(result).toBe('>=0.0.0 <1.0.0 || >=2.0.0 <=2.5.0');
  });
});

describe('extractFixVersion', () => {
  it('returns fixed version when present', () => {
    expect(extractFixVersion([
      { introduced: '1.0.0' },
      { fixed: '1.0.5' },
    ])).toBe('1.0.5');
  });

  it('returns null when no fix', () => {
    expect(extractFixVersion([
      { introduced: '1.0.0' },
    ])).toBeNull();
  });

  it('returns first fix version with multiple fixes', () => {
    expect(extractFixVersion([
      { introduced: '1.0.0' },
      { fixed: '1.0.5' },
      { introduced: '2.0.0' },
      { fixed: '2.1.0' },
    ])).toBe('1.0.5');
  });
});

describe('affectedToSemverRange', () => {
  it('combines multiple ranges from affected entry', () => {
    const affected: OsvAffected = {
      package: { ecosystem: 'npm', name: 'test-pkg' },
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
            { fixed: '2.1.0' },
          ],
        },
      ],
    };

    const result = affectedToSemverRange(affected);
    expect(result).toBe('>=1.0.0 <1.5.0 || >=2.0.0 <2.1.0');
  });

  it('skips GIT range types', () => {
    const affected: OsvAffected = {
      package: { ecosystem: 'npm', name: 'test-pkg' },
      ranges: [
        {
          type: 'GIT',
          events: [{ introduced: 'abc123' }],
        },
        {
          type: 'SEMVER',
          events: [
            { introduced: '1.0.0' },
            { fixed: '1.5.0' },
          ],
        },
      ],
    };

    const result = affectedToSemverRange(affected);
    expect(result).toBe('>=1.0.0 <1.5.0');
  });
});
