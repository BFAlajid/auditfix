import { describe, it, expect } from 'vitest';
import { parseYarnBerryLockfile } from '../../src/core/lockfile/yarn-berry.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(__dirname, '../fixtures/yarn-berry');

function readFixture(file: string): string {
  return readFileSync(join(FIXTURE_DIR, file), 'utf-8');
}

function readManifest() {
  return JSON.parse(readFixture('package.json'));
}

describe('Yarn Berry lockfile parser', () => {
  it('parses Berry yarn.lock and produces correct graph', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    expect(graph.size).toBeGreaterThanOrEqual(5);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('semver@5.7.1')).toBe(true);
  });

  it('classifies production dependencies', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    const lodash = graph.get('lodash@4.17.20')!;
    expect(lodash.isProduction).toBe(true);
    expect(lodash.isDev).toBe(false);
  });

  it('classifies dev dependencies', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    const semver = graph.get('semver@5.7.1')!;
    expect(semver.isDev).toBe(true);
    expect(semver.isProduction).toBe(false);
  });

  it('resolves dependency edges', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    const express = graph.get('express@4.17.1')!;
    expect(express.dependencies).toContain('accepts@1.3.8');
    expect(express.dependencies).toContain('body-parser@1.19.0');
  });

  it('skips workspace entries', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph, skipped } = parseYarnBerryLockfile(content, manifest);

    // The root workspace entry should be skipped
    expect(skipped.some(s => s.reason === 'workspace')).toBe(true);
    // Workspace entries should not appear in the graph
    for (const node of graph.values()) {
      expect(node.resolved).not.toContain('@workspace:');
    }
  });

  it('skips __metadata key', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    for (const node of graph.values()) {
      expect(node.name).not.toBe('__metadata');
    }
  });

  it('marks transitive deps of prod as production', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnBerryLockfile(content, manifest);

    const accepts = graph.get('accepts@1.3.8')!;
    expect(accepts.isProduction).toBe(true);
  });

  it('handles scoped packages with @npm: protocol', () => {
    const content = `
__metadata:
  version: 6

"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
  checksum: sha512-abc123
`;
    const { graph } = parseYarnBerryLockfile(content, {
      dependencies: { '@scope/pkg': '^1.0.0' },
    });
    expect(graph.has('@scope/pkg@1.2.3')).toBe(true);
  });
});
