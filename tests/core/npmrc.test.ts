import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Must mock before importing the module under test so the hoisted mock
// replaces `os.homedir` for the resolver.
let currentHome = '';
vi.mock('node:os', async () => {
  const actual = await vi.importActual<typeof import('node:os')>('node:os');
  return {
    ...actual,
    homedir: () => currentHome || actual.homedir(),
  };
});

import {
  loadNpmrc,
  parseNpmrc,
  expandEnv,
  registryForPackage,
  tokenForRegistry,
  defaultNpmrcConfig,
} from '../../src/utils/npmrc.js';

describe('parseNpmrc', () => {
  it('parses default registry, scope registries, and auth tokens', () => {
    const text = [
      'registry=https://npm.example.com/',
      '//npm.example.com/:_authToken=TOKEN_DEFAULT',
      '@acme:registry=https://acme.example.com/',
      '//acme.example.com/:_authToken=TOKEN_ACME',
    ].join('\n');

    const config = parseNpmrc(text);

    expect(config.defaultRegistry).toBe('https://npm.example.com/');
    expect(config.scopeRegistries['@acme']).toBe('https://acme.example.com/');
    expect(config.authTokens['//npm.example.com/']).toBe('TOKEN_DEFAULT');
    expect(config.authTokens['//acme.example.com/']).toBe('TOKEN_ACME');
  });

  it('expands ${VAR} env references', () => {
    process.env.TEST_NPM_TOKEN = 'secret123';
    try {
      const config = parseNpmrc(
        '//npm.example.com/:_authToken=${TEST_NPM_TOKEN}'
      );
      expect(config.authTokens['//npm.example.com/']).toBe('secret123');
    } finally {
      delete process.env.TEST_NPM_TOKEN;
    }
  });

  it('skips comments and empty lines', () => {
    const config = parseNpmrc(
      '# comment\n\n; another\nregistry=https://r.example.com/'
    );
    expect(config.defaultRegistry).toBe('https://r.example.com/');
  });

  it('returns defaults when content is empty', () => {
    const config = parseNpmrc('');
    expect(config.defaultRegistry).toBe('https://registry.npmjs.org/');
    expect(config.scopeRegistries).toEqual({});
    expect(config.authTokens).toEqual({});
  });

  it('strips surrounding quotes from values', () => {
    const config = parseNpmrc(
      '//npm.example.com/:_authToken="quoted-token"'
    );
    expect(config.authTokens['//npm.example.com/']).toBe('quoted-token');
  });

  it('drops malformed lines silently', () => {
    const config = parseNpmrc(
      ['not-a-valid-line', 'registry=https://r.example.com/', ''].join('\n')
    );
    expect(config.defaultRegistry).toBe('https://r.example.com/');
  });
});

describe('expandEnv', () => {
  it('returns empty string for missing vars', () => {
    delete process.env.NOT_SET_VAR;
    expect(expandEnv('${NOT_SET_VAR}')).toBe('');
  });

  it('does not touch $VAR form (only ${VAR})', () => {
    process.env.TEST_X = 'val';
    try {
      expect(expandEnv('$TEST_X')).toBe('$TEST_X');
    } finally {
      delete process.env.TEST_X;
    }
  });
});

describe('registryForPackage', () => {
  it('routes scoped packages to their scope registry', () => {
    const config = defaultNpmrcConfig();
    config.scopeRegistries['@acme'] = 'https://acme.example.com/';
    expect(registryForPackage('@acme/foo', config)).toBe(
      'https://acme.example.com/'
    );
  });

  it('routes unscoped packages to the default registry', () => {
    const config = defaultNpmrcConfig();
    config.defaultRegistry = 'https://default.example.com/';
    expect(registryForPackage('foo', config)).toBe(
      'https://default.example.com/'
    );
  });

  it('falls back to default when scope is unknown', () => {
    const config = defaultNpmrcConfig();
    config.defaultRegistry = 'https://default.example.com/';
    expect(registryForPackage('@unknown/foo', config)).toBe(
      'https://default.example.com/'
    );
  });
});

describe('tokenForRegistry', () => {
  it('matches a token by host prefix, ignoring protocol', () => {
    const config = defaultNpmrcConfig();
    config.authTokens['//npm.example.com/'] = 'TOK';
    expect(
      tokenForRegistry('https://npm.example.com/', config)
    ).toBe('TOK');
  });

  it('returns null when no token matches', () => {
    const config = defaultNpmrcConfig();
    expect(tokenForRegistry('https://npm.example.com/', config)).toBeNull();
  });

  it('prefers the longest prefix match', () => {
    const config = defaultNpmrcConfig();
    config.authTokens['//npm.example.com/'] = 'SHORT';
    config.authTokens['//npm.example.com/nested/'] = 'LONG';
    expect(
      tokenForRegistry('https://npm.example.com/nested/', config)
    ).toBe('LONG');
  });
});

describe('loadNpmrc', () => {
  let tmpRoot: string;
  let projectDir: string;
  let fakeHome: string;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(join(tmpdir(), 'auditfix-npmrc-'));
    projectDir = join(tmpRoot, 'project');
    fakeHome = join(tmpRoot, 'home');
    await mkdir(projectDir, { recursive: true });
    await mkdir(fakeHome, { recursive: true });
    currentHome = fakeHome;
  });

  afterEach(async () => {
    currentHome = '';
    await rm(tmpRoot, { recursive: true, force: true });
  });

  it('returns defaults when no .npmrc files exist anywhere', async () => {
    const config = await loadNpmrc(projectDir);
    expect(config.defaultRegistry).toBe('https://registry.npmjs.org/');
  });

  it('project .npmrc overrides home .npmrc for same key', async () => {
    await writeFile(
      join(fakeHome, '.npmrc'),
      'registry=https://home.example.com/\n'
    );
    await writeFile(
      join(projectDir, '.npmrc'),
      'registry=https://project.example.com/\n'
    );
    const config = await loadNpmrc(projectDir);
    expect(config.defaultRegistry).toBe('https://project.example.com/');
  });

  it('merges disjoint scope registries from project and home', async () => {
    await writeFile(
      join(fakeHome, '.npmrc'),
      '@home:registry=https://home.example.com/\n'
    );
    await writeFile(
      join(projectDir, '.npmrc'),
      '@proj:registry=https://proj.example.com/\n'
    );
    const config = await loadNpmrc(projectDir);
    expect(config.scopeRegistries['@home']).toBe('https://home.example.com/');
    expect(config.scopeRegistries['@proj']).toBe('https://proj.example.com/');
  });

  it('expands env vars when loading', async () => {
    process.env.LOAD_TEST_TOKEN = 'loaded-token';
    try {
      await writeFile(
        join(projectDir, '.npmrc'),
        '//npm.example.com/:_authToken=${LOAD_TEST_TOKEN}\n'
      );
      const config = await loadNpmrc(projectDir);
      expect(config.authTokens['//npm.example.com/']).toBe('loaded-token');
    } finally {
      delete process.env.LOAD_TEST_TOKEN;
    }
  });

  it('skips a malformed file without throwing', async () => {
    // Completely unparseable content — should fall through to defaults.
    await writeFile(join(projectDir, '.npmrc'), '===???\n\n');
    const config = await loadNpmrc(projectDir);
    // Default registry should still resolve since parser tolerates garbage.
    expect(config.defaultRegistry).toBe('https://registry.npmjs.org/');
  });
});
