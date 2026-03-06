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
});
