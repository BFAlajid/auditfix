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

  // M-S3: oversized request key is skipped, parse still succeeds.
  it('skips oversized request keys (>MAX_KEY_LENGTH) with warning', () => {
    const longRange = '^' + '1.'.repeat(800) + '0';
    const content = `
__metadata:
  version: 6

"lodash@npm:^4.17.20":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  checksum: sha512-abc

"huge-pkg@npm:${longRange}":
  version: 1.0.0
  resolution: "huge-pkg@npm:1.0.0"
  checksum: sha512-huge
`;
    const { graph, skipped } = parseYarnBerryLockfile(content, {
      dependencies: { lodash: '^4.17.20' },
    });
    // Real package still parsed.
    expect(graph.has('lodash@4.17.20')).toBe(true);
    // Oversized-keyed entry was skipped.
    expect(graph.has('huge-pkg@1.0.0')).toBe(false);
    expect(skipped.some(s => s.reason === 'unparseable')).toBe(true);
  });

  // C-B4 mirror: optionalDependencies must NOT be marked as production.
  it('does not mark optionalDependencies as production', () => {
    const content = `
__metadata:
  version: 6

"fsevents@npm:^2.3.0":
  version: 2.3.3
  resolution: "fsevents@npm:2.3.3"
  checksum: sha512-fake
`;
    const { graph } = parseYarnBerryLockfile(content, {
      optionalDependencies: { fsevents: '^2.3.0' },
    });
    const fsevents = graph.get('fsevents@2.3.3')!;
    expect(fsevents).toBeDefined();
    expect(fsevents.isOptional).toBe(true);
    expect(fsevents.isProduction).toBe(false);
  });

  // Fix 6: resolveRoot returns null when exact range misses — no longer
  // falls back to arbitrary first graph entry with matching name.
  it('returns null when manifest range does not match any lockfile entry', () => {
    const content = `
__metadata:
  version: 6

"express@npm:^4.17.1":
  version: 4.17.1
  resolution: "express@npm:4.17.1"
  checksum: sha512-ex
`;
    // Manifest declares express@^5.0.0; lockfile only has the ^4.17.1 range.
    const { graph } = parseYarnBerryLockfile(content, {
      dependencies: { express: '^5.0.0' },
    });
    const express = graph.get('express@4.17.1')!;
    expect(express).toBeDefined();
    // Resolution missed → express falls back to dev classification.
    expect(express.isProduction).toBe(false);
    expect(express.isDev).toBe(true);
  });
});
