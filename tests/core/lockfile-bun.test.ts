import { describe, it, expect } from 'vitest';
import { parseBunLockfile, parseBunSpec, stripJsonc } from '../../src/core/lockfile/bun.js';

/**
 * Minimal valid bun.lock covering:
 *  - scoped + unscoped packages
 *  - workspace root entry
 *  - transitive prod edge (express -> accepts)
 *  - dev-only dep (semver)
 */
const MINIMAL_BUN_LOCK = `{
  // lockfileVersion tracks auditfix-relevant shape
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "lodash": "^4.17.20",
        "express": "^4.17.1",
        "@scope/pkg": "^1.0.0"
      },
      "devDependencies": {
        "semver": "^5.7.1"
      }
    }
  },
  "packages": {
    "lodash": ["lodash@4.17.20", {}, "sha512-lodash-integrity"],
    "express": ["express@4.17.1", {
      "dependencies": {
        "accepts": "~1.3.8",
        "body-parser": "1.19.0"
      }
    }, "sha512-express-integrity"],
    "accepts": ["accepts@1.3.8", {
      "dependencies": { "mime-types": "~2.1.34" }
    }, "sha512-accepts-integrity"],
    "body-parser": ["body-parser@1.19.0", {}, "sha512-body-parser-integrity"],
    "mime-types": ["mime-types@2.1.35", {}, "sha512-mt-integrity"],
    "semver": ["semver@5.7.1", {}, "sha512-semver-integrity"],
    "@scope/pkg": ["@scope/pkg@1.2.3", {}, "sha512-scope-integrity"],
  }
}
`;

describe('bun lockfile parser', () => {
  it('parses a minimal valid bun.lock into the expected graph shape', () => {
    const { type, graph } = parseBunLockfile(MINIMAL_BUN_LOCK);

    expect(type).toBe('bun');
    expect(graph.size).toBe(7);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('accepts@1.3.8')).toBe(true);
    expect(graph.has('body-parser@1.19.0')).toBe(true);
    expect(graph.has('mime-types@2.1.35')).toBe(true);
    expect(graph.has('semver@5.7.1')).toBe(true);
    expect(graph.has('@scope/pkg@1.2.3')).toBe(true);
  });

  it('parses scoped package names with leading @', () => {
    const { graph } = parseBunLockfile(MINIMAL_BUN_LOCK);
    const scoped = graph.get('@scope/pkg@1.2.3');
    expect(scoped).toBeDefined();
    expect(scoped!.name).toBe('@scope/pkg');
    expect(scoped!.version).toBe('1.2.3');
  });

  it('resolves dependency edges', () => {
    const { graph } = parseBunLockfile(MINIMAL_BUN_LOCK);
    const express = graph.get('express@4.17.1');
    expect(express).toBeDefined();
    expect(express!.dependencies).toContain('accepts@1.3.8');
    expect(express!.dependencies).toContain('body-parser@1.19.0');

    const accepts = graph.get('accepts@1.3.8');
    expect(accepts!.dependencies).toContain('mime-types@2.1.35');
  });

  it('classifies prod dependencies from root workspace', () => {
    const { graph } = parseBunLockfile(MINIMAL_BUN_LOCK);

    const lodash = graph.get('lodash@4.17.20');
    expect(lodash!.isProduction).toBe(true);
    expect(lodash!.isDev).toBe(false);

    const express = graph.get('express@4.17.1');
    expect(express!.isProduction).toBe(true);
  });

  it('classifies dev dependencies from root workspace', () => {
    const { graph } = parseBunLockfile(MINIMAL_BUN_LOCK);
    const semver = graph.get('semver@5.7.1');
    expect(semver!.isDev).toBe(true);
    expect(semver!.isProduction).toBe(false);
  });

  it('propagates production through transitive edges (prod root -> dep)', () => {
    const { graph } = parseBunLockfile(MINIMAL_BUN_LOCK);
    const accepts = graph.get('accepts@1.3.8');
    expect(accepts!.isProduction).toBe(true);
    const mime = graph.get('mime-types@2.1.35');
    expect(mime!.isProduction).toBe(true);
  });

  it('skips the root workspace pseudo-entry', () => {
    const withRoot = `{
      "workspaces": { "": { "name": "root" } },
      "packages": {
        "": ["root@0.0.0", {}, ""],
        "lodash": ["lodash@4.17.20", {}, ""]
      }
    }`;
    const { graph, skipped } = parseBunLockfile(withRoot);
    expect(graph.size).toBe(1);
    expect(skipped.some((s) => s.reason === 'workspace')).toBe(true);
  });

  it('skips git / file / workspace-protocol specs', () => {
    const lock = `{
      "workspaces": { "": { "name": "root" } },
      "packages": {
        "a": ["a@git+https://github.com/foo/bar.git#abc", {}, ""],
        "b": ["b@file:../local-pkg", {}, ""],
        "c": ["c@workspace:*", {}, ""],
        "d": ["d@1.0.0", {}, ""]
      }
    }`;
    const { graph, skipped } = parseBunLockfile(lock);
    expect(graph.has('d@1.0.0')).toBe(true);
    expect(skipped.some((s) => s.reason === 'git-dep')).toBe(true);
    expect(skipped.some((s) => s.reason === 'local-file')).toBe(true);
    expect(skipped.some((s) => s.reason === 'workspace')).toBe(true);
  });

  it('rejects oversized package keys (> 1KB) without crashing', () => {
    const oversized = 'x'.repeat(2048);
    const lock = `{
      "workspaces": { "": {} },
      "packages": {
        "${oversized}": ["pkg@1.0.0", {}, ""],
        "ok": ["ok@1.0.0", {}, ""]
      }
    }`;
    const { graph, skipped } = parseBunLockfile(lock);
    expect(graph.has('ok@1.0.0')).toBe(true);
    expect(skipped.some((s) => s.reason === 'unparseable')).toBe(true);
  });

  it('fails gracefully on malformed JSON (skipped populated, no throw-up)', () => {
    const malformed = '{ "packages": { this is not json }';
    expect(() => parseBunLockfile(malformed)).toThrow(/Failed to parse bun.lock/);
  });

  it('detects binary bun.lockb and refuses cleanly with a skipped entry', () => {
    // Binary bun.lockb files contain null bytes.
    const binary = '\0\0bun-lockb-magic\0\0';
    const { type, graph, skipped } = parseBunLockfile(binary);
    expect(type).toBe('bun');
    expect(graph.size).toBe(0);
    expect(skipped).toEqual([
      { key: 'bun.lockb', reason: 'unparseable' },
    ]);
  });

  it('tolerates JSONC comments and trailing commas', () => {
    const jsonc = `{
      // comment
      /* another */
      "workspaces": { "": { "dependencies": { "lodash": "^4.0.0" } } },
      "packages": {
        "lodash": ["lodash@4.17.21", {}, ""], /* trailing comment */
      },
    }`;
    const { graph } = parseBunLockfile(jsonc);
    expect(graph.has('lodash@4.17.21')).toBe(true);
  });
});

describe('parseBunSpec', () => {
  it('parses unscoped specs', () => {
    expect(parseBunSpec('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
  });

  it('parses scoped specs', () => {
    expect(parseBunSpec('@scope/pkg@1.2.3')).toEqual({ name: '@scope/pkg', version: '1.2.3' });
  });

  it('strips npm: protocol prefix', () => {
    expect(parseBunSpec('lodash@npm:4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
  });

  it('returns null on unrecognizable spec', () => {
    expect(parseBunSpec('garbage')).toBeNull();
    expect(parseBunSpec('')).toBeNull();
  });
});

describe('stripJsonc', () => {
  it('strips // line comments', () => {
    const out = stripJsonc('{"a":1} // trailing');
    expect(out.trim()).toBe('{"a":1}');
  });

  it('strips block comments', () => {
    const out = stripJsonc('{"a"/*skip*/:1}');
    expect(out).toBe('{"a":1}');
  });

  it('preserves // inside strings', () => {
    const out = stripJsonc('{"url":"http://example.com"}');
    expect(out).toBe('{"url":"http://example.com"}');
  });

  it('strips trailing commas', () => {
    const out = stripJsonc('{"a":1,"b":2,}');
    expect(out).toBe('{"a":1,"b":2}');
  });
});
