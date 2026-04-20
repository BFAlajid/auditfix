import { describe, it, expect } from 'vitest';
import {
  isValidVersion,
  satisfies,
} from '../../src/utils/semver.js';

describe('isValidVersion', () => {
  it('returns true for valid semver versions', () => {
    expect(isValidVersion('1.0.0')).toBe(true);
    expect(isValidVersion('0.0.1')).toBe(true);
    expect(isValidVersion('10.20.30')).toBe(true);
  });

  it('returns true for prerelease versions', () => {
    expect(isValidVersion('1.0.0-alpha.1')).toBe(true);
    expect(isValidVersion('1.0.0-beta.2')).toBe(true);
    expect(isValidVersion('1.0.0-rc.1')).toBe(true);
    expect(isValidVersion('2.0.0-0')).toBe(true);
  });

  it('returns true for versions with build metadata', () => {
    expect(isValidVersion('1.0.0+build.123')).toBe(true);
    expect(isValidVersion('1.0.0-alpha+001')).toBe(true);
  });

  it('returns false for invalid version strings', () => {
    expect(isValidVersion('not-a-version')).toBe(false);
    expect(isValidVersion('abc')).toBe(false);
    expect(isValidVersion('1.2')).toBe(false);
    expect(isValidVersion('latest')).toBe(false);
  });

  it('accepts v-prefixed versions (node-semver coerces v prefix)', () => {
    // node-semver treats 'v1.0.0' as valid via semver.valid()
    expect(isValidVersion('v1.0.0')).toBe(true);
  });

  it('returns false for empty string', () => {
    expect(isValidVersion('')).toBe(false);
  });

  it('returns false for versions exceeding max length', () => {
    const longVersion = '1.0.0-' + 'a'.repeat(260);
    expect(isValidVersion(longVersion)).toBe(false);
  });
});

describe('satisfies', () => {
  it('returns true when version satisfies a basic range', () => {
    expect(satisfies('1.5.0', '>=1.0.0 <2.0.0')).toBe(true);
    expect(satisfies('1.0.0', '^1.0.0')).toBe(true);
    expect(satisfies('1.9.9', '~1.9.0')).toBe(true);
  });

  it('returns false when version does not satisfy the range', () => {
    expect(satisfies('2.0.0', '>=1.0.0 <2.0.0')).toBe(false);
    expect(satisfies('0.9.0', '^1.0.0')).toBe(false);
    expect(satisfies('2.0.0', '~1.9.0')).toBe(false);
  });

  it('includes prerelease versions in range checks', () => {
    // This is the critical behavior: includePrerelease must be true
    expect(satisfies('1.5.0-beta.1', '>=1.0.0 <2.0.0')).toBe(true);
    expect(satisfies('2.0.0-rc.1', '>=1.0.0 <3.0.0')).toBe(true);
  });

  it('returns false for invalid version input', () => {
    expect(satisfies('not-a-version', '>=1.0.0')).toBe(false);
    expect(satisfies('', '>=1.0.0')).toBe(false);
  });

  it('returns false for invalid range input', () => {
    expect(satisfies('1.0.0', 'not-a-range!!!')).toBe(false);
  });

  it('returns false for version exceeding max length', () => {
    const longVersion = '1.0.0-' + 'a'.repeat(260);
    expect(satisfies(longVersion, '>=1.0.0')).toBe(false);
  });
});
