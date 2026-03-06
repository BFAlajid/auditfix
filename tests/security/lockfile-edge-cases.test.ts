import { describe, it, expect } from 'vitest';
import { parseNpmLockfile } from '../../src/core/lockfile/npm.js';

describe('lockfile edge cases', () => {
  it('handles scoped packages correctly', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/@babel/core': {
          version: '7.23.0',
          resolved: 'https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz',
          integrity: 'sha512-test',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    const node = result.graph.get('@babel/core@7.23.0');
    expect(node).toBeDefined();
    expect(node!.name).toBe('@babel/core');
  });

  it('handles npm aliased packages (name field != path key)', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/my-lodash': {
          name: 'lodash',
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-test',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    // Must be keyed by real name (lodash), not alias (my-lodash)
    expect(result.graph.has('lodash@4.17.21')).toBe(true);
    expect(result.graph.has('my-lodash@4.17.21')).toBe(false);
  });

  it('skips linked dependencies', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/linked-pkg': {
          version: '1.0.0',
          link: true,
          resolved: 'packages/linked-pkg',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].reason).toBe('local-file');
  });

  it('handles BOM in lockfile content', () => {
    const lockfile = '\uFEFF' + JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/test': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/test/-/test-1.0.0.tgz',
          integrity: 'sha512-test',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(1);
  });

  it('handles empty lockfile (only root)', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
    expect(result.skipped).toHaveLength(0);
  });

  it('rejects path keys with traversal attempts', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/../etc/passwd': {
          version: '1.0.0',
          resolved: 'https://evil.com',
          integrity: 'sha512-evil',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
    expect(result.skipped.some(s => s.reason === 'unparseable')).toBe(true);
  });

  it('handles lockfileVersion 2 (v2)', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/pkg': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
          integrity: 'sha512-test',
        },
      },
      dependencies: {
        pkg: { version: '1.0.0' },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.type).toBe('npm-v2');
    expect(result.graph.size).toBe(1);
  });

  it('handles same package at multiple versions', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/semver': {
          version: '7.5.4',
          resolved: 'https://registry.npmjs.org/semver/-/semver-7.5.4.tgz',
          integrity: 'sha512-test1',
        },
        'node_modules/old-pkg/node_modules/semver': {
          version: '5.7.2',
          resolved: 'https://registry.npmjs.org/semver/-/semver-5.7.2.tgz',
          integrity: 'sha512-test2',
          dev: true,
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.has('semver@7.5.4')).toBe(true);
    expect(result.graph.has('semver@5.7.2')).toBe(true);
  });
});
