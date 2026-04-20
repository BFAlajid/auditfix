import { describe, it, expect } from 'vitest';
import { parseYarnClassicLockfile } from '../../src/core/lockfile/yarn-classic.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(__dirname, '../fixtures/yarn-classic');

function readFixture(file: string): string {
  return readFileSync(join(FIXTURE_DIR, file), 'utf-8');
}

function readManifest() {
  return JSON.parse(readFixture('package.json'));
}

describe('Yarn Classic lockfile parser', () => {
  it('parses basic yarn.lock and produces correct graph', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph, skipped } = parseYarnClassicLockfile(content, manifest);

    expect(graph.size).toBeGreaterThanOrEqual(5);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('semver@5.7.1')).toBe(true);
  });

  it('correctly classifies production dependencies', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnClassicLockfile(content, manifest);

    const lodash = graph.get('lodash@4.17.20')!;
    expect(lodash.isProduction).toBe(true);
    expect(lodash.isDev).toBe(false);

    const express = graph.get('express@4.17.1')!;
    expect(express.isProduction).toBe(true);
  });

  it('correctly classifies dev dependencies', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnClassicLockfile(content, manifest);

    const semver = graph.get('semver@5.7.1')!;
    expect(semver.isDev).toBe(true);
    expect(semver.isProduction).toBe(false);
  });

  it('resolves transitive dependency edges', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnClassicLockfile(content, manifest);

    const express = graph.get('express@4.17.1')!;
    expect(express.dependencies).toContain('accepts@1.3.8');
    expect(express.dependencies).toContain('body-parser@1.19.0');
  });

  it('marks transitive deps of prod deps as production', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnClassicLockfile(content, manifest);

    const accepts = graph.get('accepts@1.3.8')!;
    expect(accepts.isProduction).toBe(true);
  });

  it('assigns depth via BFS', () => {
    const content = readFixture('yarn.lock');
    const manifest = readManifest();
    const { graph } = parseYarnClassicLockfile(content, manifest);

    const express = graph.get('express@4.17.1')!;
    expect(express.depth).toBe(1);

    const accepts = graph.get('accepts@1.3.8')!;
    expect(accepts.depth).toBe(2);
  });

  it('throws on invalid format', () => {
    expect(() =>
      parseYarnClassicLockfile('<<<< merge conflict', readManifest())
    ).toThrow();
  });

  it('skips git dependencies', () => {
    const content = `
git-pkg@^1.0.0:
  version "1.0.0"
  resolved "git+https://github.com/test/pkg.git#abc123"
`;
    const { graph, skipped } = parseYarnClassicLockfile(content, {});
    expect(graph.size).toBe(0);
    expect(skipped.some(s => s.reason === 'git-dep')).toBe(true);
  });

  it('handles scoped packages', () => {
    const content = `
"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"
  integrity sha512-abc123
`;
    const { graph } = parseYarnClassicLockfile(content, {
      dependencies: { '@scope/pkg': '^1.0.0' },
    });
    expect(graph.has('@scope/pkg@1.2.3')).toBe(true);
    expect(graph.get('@scope/pkg@1.2.3')!.isProduction).toBe(true);
  });

  // C-B4: optionalDependencies must NOT be marked as production.
  it('does not mark optionalDependencies as production', () => {
    const content = `
fsevents@^2.3.0:
  version "2.3.3"
  resolved "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz"
  integrity sha512-fake
`;
    const { graph } = parseYarnClassicLockfile(content, {
      optionalDependencies: { fsevents: '^2.3.0' },
    });
    const fsevents = graph.get('fsevents@2.3.3')!;
    expect(fsevents).toBeDefined();
    expect(fsevents.isOptional).toBe(true);
    expect(fsevents.isProduction).toBe(false);
  });

  // Fix 6: resolveRoot must return null when no entry matches both name AND range.
  // Previously it fell back to "first entry matching name", which silently
  // pointed at the wrong version.
  it('returns null (does not classify) when manifest range does not match any lockfile entry', () => {
    const content = `
express@^4.17.1:
  version "4.17.1"
  resolved "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
  integrity sha512-ex
`;
    // Manifest declares express@^5.0.0, but lockfile has 4.17.1 under range ^4.17.1.
    // No exact range match → root resolution fails → express should remain dev
    // (fallback classification for unreached nodes).
    const { graph } = parseYarnClassicLockfile(content, {
      dependencies: { express: '^5.0.0' },
    });
    const express = graph.get('express@4.17.1')!;
    expect(express).toBeDefined();
    // Because root could not be resolved, express is NOT classified production.
    expect(express.isProduction).toBe(false);
    expect(express.isDev).toBe(true);
  });
});
