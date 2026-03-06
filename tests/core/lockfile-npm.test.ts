import { describe, it, expect } from 'vitest';
import { parseNpmLockfile } from '../../src/core/lockfile/npm.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(import.meta.dirname, '..', 'fixtures', 'npm-basic');

describe('npm lockfile v3 parser', () => {
  it('parses a basic npm lockfile v3', () => {
    const content = readFileSync(join(FIXTURE_DIR, 'package-lock.json'), 'utf-8');
    const result = parseNpmLockfile(content);

    expect(result.type).toBe('npm-v3');
    expect(result.graph.size).toBeGreaterThan(0);
  });

  it('correctly identifies production vs dev dependencies', () => {
    const content = readFileSync(join(FIXTURE_DIR, 'package-lock.json'), 'utf-8');
    const result = parseNpmLockfile(content);

    // express is production
    const express = result.graph.get('express@4.17.1');
    expect(express).toBeDefined();
    expect(express!.isProduction).toBe(true);
    expect(express!.isDev).toBe(false);

    // qs is production (transitive via express)
    const qs = result.graph.get('qs@6.5.2');
    expect(qs).toBeDefined();
    expect(qs!.isProduction).toBe(true);

    // jest is dev-only
    const jest = result.graph.get('jest@29.7.0');
    expect(jest).toBeDefined();
    expect(jest!.isDev).toBe(true);
    expect(jest!.isProduction).toBe(false);

    // semver is dev-only (transitive via jest)
    const semver = result.graph.get('semver@5.7.1');
    expect(semver).toBeDefined();
    expect(semver!.isDev).toBe(true);
    expect(semver!.isProduction).toBe(false);
  });

  it('extracts correct package names', () => {
    const content = readFileSync(join(FIXTURE_DIR, 'package-lock.json'), 'utf-8');
    const result = parseNpmLockfile(content);

    const names = Array.from(result.graph.values()).map((n) => n.name);
    expect(names).toContain('express');
    expect(names).toContain('body-parser');
    expect(names).toContain('qs');
  });

  it('calculates correct depth', () => {
    const content = readFileSync(join(FIXTURE_DIR, 'package-lock.json'), 'utf-8');
    const result = parseNpmLockfile(content);

    const express = result.graph.get('express@4.17.1');
    expect(express!.depth).toBe(1);
  });

  it('rejects lockfile v1', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {},
    });

    expect(() => parseNpmLockfile(lockfile)).toThrow('lockfileVersion 2 or 3');
  });

  it('handles empty packages field', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 'root', version: '1.0.0' } },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
  });

  it('skips file: protocol dependencies', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/local-pkg': {
          version: '1.0.0',
          resolved: 'file:../local-pkg',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].reason).toBe('local-file');
  });

  it('skips git dependencies', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/git-pkg': {
          version: '1.0.0',
          resolved: 'git+https://github.com/user/repo.git#abc123',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);
    expect(result.graph.size).toBe(0);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].reason).toBe('git-dep');
  });

  it('resolves multi-version dependency edges correctly', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/pkg-a': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz',
          integrity: 'sha512-a',
          dependencies: { semver: '^5.0.0' },
        },
        'node_modules/pkg-b': {
          version: '2.0.0',
          resolved: 'https://registry.npmjs.org/pkg-b/-/pkg-b-2.0.0.tgz',
          integrity: 'sha512-b',
          dependencies: { semver: '^7.0.0' },
        },
        'node_modules/semver': {
          version: '7.5.4',
          resolved: 'https://registry.npmjs.org/semver/-/semver-7.5.4.tgz',
          integrity: 'sha512-s1',
        },
        'node_modules/pkg-a/node_modules/semver': {
          version: '5.7.2',
          resolved: 'https://registry.npmjs.org/semver/-/semver-5.7.2.tgz',
          integrity: 'sha512-s2',
        },
      },
    });

    const result = parseNpmLockfile(lockfile);

    // Both versions should exist
    expect(result.graph.has('semver@7.5.4')).toBe(true);
    expect(result.graph.has('semver@5.7.2')).toBe(true);

    // pkg-a depends on semver ^5.0.0 → should resolve to 5.7.2
    const pkgA = result.graph.get('pkg-a@1.0.0')!;
    expect(pkgA.dependencies).toContain('semver@5.7.2');
    expect(pkgA.dependencies).not.toContain('semver@7.5.4');

    // pkg-b depends on semver ^7.0.0 → should resolve to 7.5.4
    const pkgB = result.graph.get('pkg-b@2.0.0')!;
    expect(pkgB.dependencies).toContain('semver@7.5.4');
    expect(pkgB.dependencies).not.toContain('semver@5.7.2');
  });

  it('uses name field for aliased packages', () => {
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
    const node = result.graph.get('lodash@4.17.21');
    expect(node).toBeDefined();
    expect(node!.name).toBe('lodash');
  });
});
