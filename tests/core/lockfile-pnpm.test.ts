import { describe, it, expect } from 'vitest';
import { parsePnpmLockfile } from '../../src/core/lockfile/pnpm.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(__dirname, '../fixtures/pnpm-basic');

function readFixture(file: string): string {
  return readFileSync(join(FIXTURE_DIR, file), 'utf-8');
}

describe('pnpm lockfile parser', () => {
  it('parses pnpm-lock.yaml v9 and produces correct graph', () => {
    const content = readFixture('pnpm-lock.yaml');
    const { type, graph } = parsePnpmLockfile(content);

    expect(type).toBe('pnpm-v9');
    expect(graph.size).toBeGreaterThanOrEqual(5);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('semver@5.7.1')).toBe(true);
  });

  it('classifies production dependencies from importers', () => {
    const content = readFixture('pnpm-lock.yaml');
    const { graph } = parsePnpmLockfile(content);

    const lodash = graph.get('lodash@4.17.20')!;
    expect(lodash.isProduction).toBe(true);

    const express = graph.get('express@4.17.1')!;
    expect(express.isProduction).toBe(true);
  });

  it('classifies dev dependencies with dev: true flag', () => {
    const content = readFixture('pnpm-lock.yaml');
    const { graph } = parsePnpmLockfile(content);

    const semver = graph.get('semver@5.7.1')!;
    expect(semver.isDev).toBe(true);
  });

  it('resolves dependency edges', () => {
    const content = readFixture('pnpm-lock.yaml');
    const { graph } = parsePnpmLockfile(content);

    const express = graph.get('express@4.17.1')!;
    expect(express.dependencies).toContain('accepts@1.3.8');
    expect(express.dependencies).toContain('body-parser@1.19.0');
  });

  it('propagates production through transitive deps', () => {
    const content = readFixture('pnpm-lock.yaml');
    const { graph } = parsePnpmLockfile(content);

    const accepts = graph.get('accepts@1.3.8')!;
    expect(accepts.isProduction).toBe(true);
  });

  it('throws on unsupported lockfile version', () => {
    const content = `lockfileVersion: 3\npackages: {}`;
    expect(() => parsePnpmLockfile(content)).toThrow('Unsupported pnpm lockfile version');
  });

  it('throws on missing packages field', () => {
    const content = `lockfileVersion: '9.0'`;
    expect(() => parsePnpmLockfile(content)).toThrow('missing "packages"');
  });

  it('parses v6 format with slash-prefixed keys', () => {
    const content = `
lockfileVersion: 6

packages:
  /lodash/4.17.20:
    resolution: {integrity: sha512-abc}
  /express/4.17.1:
    resolution: {integrity: sha512-def}
    dependencies:
      lodash: 4.17.20
  /@scope/pkg/1.0.0:
    resolution: {integrity: sha512-ghi}
`;
    const { type, graph } = parsePnpmLockfile(content);
    expect(type).toBe('pnpm-v6');
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('@scope/pkg@1.0.0')).toBe(true);
  });

  it('skips workspace entries', () => {
    const content = `
lockfileVersion: '9.0'

packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-abc}
  my-workspace@1.0.0:
    resolution: {type: directory, directory: packages/my-workspace}
`;
    const { graph, skipped } = parsePnpmLockfile(content);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(skipped.some(s => s.reason === 'workspace')).toBe(true);
  });

  it('parses pnpm monorepo with multiple importers', () => {
    const content = `
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      shared-lib:
        specifier: ^1.0.0
        version: 1.0.0
  packages/app:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.0
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.0.0
  packages/utils:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  shared-lib@1.0.0:
    resolution: {integrity: sha512-shared}

  express@4.18.0:
    resolution: {integrity: sha512-express}

  vitest@1.0.0:
    resolution: {integrity: sha512-vitest}
    dev: true

  lodash@4.17.21:
    resolution: {integrity: sha512-lodash}
`;
    const { graph } = parsePnpmLockfile(content);

    const express = graph.get('express@4.18.0')!;
    expect(express).toBeDefined();
    expect(express.isProduction).toBe(true);

    const vitest = graph.get('vitest@1.0.0')!;
    expect(vitest).toBeDefined();
    expect(vitest.isProduction).toBe(false);

    const lodash = graph.get('lodash@4.17.21')!;
    expect(lodash).toBeDefined();
    expect(lodash.isProduction).toBe(true);

    const sharedLib = graph.get('shared-lib@1.0.0')!;
    expect(sharedLib).toBeDefined();
    expect(sharedLib.isProduction).toBe(true);
  });
});
