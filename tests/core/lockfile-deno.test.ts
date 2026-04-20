import { describe, it, expect } from 'vitest';
import { parseDenoLockfile, parseDenoNpmKey } from '../../src/core/lockfile/deno.js';

/**
 * Minimal valid deno.lock v3 covering:
 *  - npm packages with deps
 *  - scoped package
 *  - peer-pinned dep edge ("name@1.0.0_peer@2.0.0")
 *  - workspace root with npm: specifier for prod classification
 */
const MINIMAL_DENO_LOCK_V3 = JSON.stringify(
  {
    version: '3',
    packages: {
      specifiers: {
        'npm:express@^4.17.1': 'npm:express@4.17.1',
        'npm:lodash@^4.17.20': 'npm:lodash@4.17.20',
        'npm:@scope/pkg@^1.0.0': 'npm:@scope/pkg@1.2.3',
      },
      npm: {
        'express@4.17.1': {
          integrity: 'sha512-express',
          dependencies: ['accepts@1.3.8', 'body-parser@1.19.0'],
        },
        'accepts@1.3.8': {
          integrity: 'sha512-accepts',
          dependencies: ['mime-types@2.1.35_foo@2.0.0'],
        },
        'body-parser@1.19.0': {
          integrity: 'sha512-bp',
          dependencies: [],
        },
        'mime-types@2.1.35': {
          integrity: 'sha512-mt',
          dependencies: [],
        },
        'lodash@4.17.20': { integrity: 'sha512-lodash', dependencies: [] },
        'transitive-dev@1.0.0': {
          integrity: 'sha512-td',
          dependencies: [],
        },
        '@scope/pkg@1.2.3': { integrity: 'sha512-scope', dependencies: [] },
      },
    },
    remote: {},
    workspace: {
      dependencies: [
        'npm:express@^4.17.1',
        'npm:lodash@^4.17.20',
        'npm:@scope/pkg@^1.0.0',
      ],
    },
  },
  null,
  2,
);

describe('deno lockfile parser', () => {
  it('parses a minimal valid deno.lock into the expected graph shape', () => {
    const { type, graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);

    expect(type).toBe('deno');
    expect(graph.size).toBe(7);
    expect(graph.has('express@4.17.1')).toBe(true);
    expect(graph.has('lodash@4.17.20')).toBe(true);
    expect(graph.has('@scope/pkg@1.2.3')).toBe(true);
  });

  it('parses scoped packages correctly', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const scoped = graph.get('@scope/pkg@1.2.3');
    expect(scoped).toBeDefined();
    expect(scoped!.name).toBe('@scope/pkg');
    expect(scoped!.version).toBe('1.2.3');
  });

  it('resolves dependency edges', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const express = graph.get('express@4.17.1');
    expect(express).toBeDefined();
    expect(express!.dependencies).toContain('accepts@1.3.8');
    expect(express!.dependencies).toContain('body-parser@1.19.0');
  });

  it('strips peer-pinned suffix from dep edge keys (name@ver_peer@ver -> name@ver)', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const accepts = graph.get('accepts@1.3.8');
    expect(accepts!.dependencies).toContain('mime-types@2.1.35');
    // Peer suffix should not bleed into the resolved key.
    expect(accepts!.dependencies).not.toContain('mime-types@2.1.35_foo@2.0.0');
  });

  it('classifies workspace npm: specifiers as production roots', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const lodash = graph.get('lodash@4.17.20');
    expect(lodash!.isProduction).toBe(true);

    const express = graph.get('express@4.17.1');
    expect(express!.isProduction).toBe(true);
  });

  it('propagates production through transitive edges', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const accepts = graph.get('accepts@1.3.8');
    expect(accepts!.isProduction).toBe(true);
    const mime = graph.get('mime-types@2.1.35');
    expect(mime!.isProduction).toBe(true);
  });

  it('classifies npm packages unreachable from roots as dev', () => {
    const { graph } = parseDenoLockfile(MINIMAL_DENO_LOCK_V3);
    const td = graph.get('transitive-dev@1.0.0');
    expect(td!.isDev).toBe(true);
    expect(td!.isProduction).toBe(false);
  });

  it('rejects oversized package keys (> 1KB)', () => {
    const oversized = 'x'.repeat(2048);
    const lock = JSON.stringify({
      version: '3',
      packages: {
        npm: {
          [`${oversized}@1.0.0`]: { integrity: '', dependencies: [] },
          'ok@1.0.0': { integrity: '', dependencies: [] },
        },
      },
    });
    const { graph, skipped } = parseDenoLockfile(lock);
    expect(graph.has('ok@1.0.0')).toBe(true);
    expect(skipped.some((s) => s.reason === 'unparseable')).toBe(true);
  });

  it('fails gracefully on malformed JSON', () => {
    expect(() => parseDenoLockfile('{not json')).toThrow(/Failed to parse deno.lock/);
  });

  it('throws on missing/too-low version', () => {
    const v1 = JSON.stringify({ version: '1', packages: { npm: {} } });
    expect(() => parseDenoLockfile(v1)).toThrow(/requires deno.lock version 3/);
  });

  it('supports v4 lockfile shape', () => {
    const v4 = JSON.stringify({
      version: '4',
      specifiers: {
        'npm:lodash@^4': 'npm:lodash@4.17.21',
      },
      npm: {
        'lodash@4.17.21': { integrity: 'sha512-lo', dependencies: [] },
      },
      workspace: {
        dependencies: ['npm:lodash@^4'],
      },
    });
    const { graph } = parseDenoLockfile(v4);
    expect(graph.has('lodash@4.17.21')).toBe(true);
    expect(graph.get('lodash@4.17.21')!.isProduction).toBe(true);
  });

  it('ignores JSR and remote entries', () => {
    const withJsr = JSON.stringify({
      version: '3',
      packages: {
        npm: {
          'lodash@4.17.21': { integrity: '', dependencies: [] },
        },
        jsr: {
          '@std/path@1.0.0': { integrity: '' },
        },
      },
      remote: {
        'https://deno.land/x/foo@1.0.0/mod.ts': 'sha-remote',
      },
    });
    const { graph } = parseDenoLockfile(withJsr);
    expect(graph.size).toBe(1);
    expect(graph.has('lodash@4.17.21')).toBe(true);
  });

  it('handles dependencies stored as Record (older v3 variant)', () => {
    const lock = JSON.stringify({
      version: '3',
      packages: {
        npm: {
          'a@1.0.0': {
            integrity: '',
            dependencies: { b: 'b@2.0.0' },
          },
          'b@2.0.0': { integrity: '', dependencies: [] },
        },
      },
      workspace: { dependencies: ['npm:a@^1'] },
    });
    const { graph } = parseDenoLockfile(lock);
    const a = graph.get('a@1.0.0');
    expect(a!.dependencies).toContain('b@2.0.0');
  });
});

describe('parseDenoNpmKey', () => {
  it('parses unscoped name@version', () => {
    expect(parseDenoNpmKey('lodash@4.17.21')).toEqual({
      name: 'lodash',
      version: '4.17.21',
    });
  });

  it('parses scoped @scope/name@version', () => {
    expect(parseDenoNpmKey('@scope/pkg@1.2.3')).toEqual({
      name: '@scope/pkg',
      version: '1.2.3',
    });
  });

  it('strips peer-pinned suffix (_peer@ver)', () => {
    expect(parseDenoNpmKey('lodash@4.17.21_other@2.0.0')).toEqual({
      name: 'lodash',
      version: '4.17.21',
    });
  });

  it('strips peer-pinned suffix on scoped packages', () => {
    expect(parseDenoNpmKey('@scope/pkg@1.0.0_peer@2.0.0')).toEqual({
      name: '@scope/pkg',
      version: '1.0.0',
    });
  });

  it('returns null on invalid inputs', () => {
    expect(parseDenoNpmKey('')).toBeNull();
    expect(parseDenoNpmKey('no-at-sign')).toBeNull();
    expect(parseDenoNpmKey('@scope-only')).toBeNull();
  });
});
