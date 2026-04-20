import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, symlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { SafeUpdate } from '../../src/core/fixer/safe-update.js';
import type { ScoredVulnerability } from '../../src/types/report.js';
import type { Advisory, AdvisoryMatch } from '../../src/types/advisory.js';

// Mutable mock for safeExec — tests can swap the implementation per test
const safeExecMock = vi.hoisted(() =>
  vi.fn<() => Promise<{ stdout: string; stderr: string; exitCode: number }>>().mockResolvedValue({
    stdout: '',
    stderr: '',
    exitCode: 0,
  }),
);

vi.mock('../../src/utils/shell.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/utils/shell.js')>();
  return {
    ...original,
    safeExec: safeExecMock,
  };
});

const { applyFixes } = await import('../../src/core/fixer/lockfile-writer.js');

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-test-test',
    aliases: ['CVE-2024-0001'],
    summary: 'Test advisory',
    details: '',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '1.5.1',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function makeMatch(overrides: Partial<AdvisoryMatch> = {}): AdvisoryMatch {
  return {
    advisory: makeAdvisory(),
    package: 'vulnerable-pkg',
    installedVersion: '1.5.0',
    dependencyPath: ['vulnerable-pkg'],
    isProduction: true,
    ...overrides,
  };
}

function makeVuln(): ScoredVulnerability {
  return {
    match: makeMatch(),
    risk: {
      score: 75,
      label: 'high',
      factors: {
        cvssScore: 9.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productionReachable: true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: true,
        fixVersion: '1.5.1',
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeSafeUpdate(overrides: Partial<SafeUpdate> = {}): SafeUpdate {
  return {
    vuln: makeVuln(),
    packageName: 'vulnerable-pkg',
    currentVersion: '1.5.0',
    fixVersion: '1.5.1',
    reason: 'within-parent-range',
    ...overrides,
  };
}

function makeTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'auditfix-writer-'));
}

function writePkgJson(dir: string, content: Record<string, unknown>): void {
  writeFileSync(join(dir, 'package.json'), JSON.stringify(content, null, 2) + '\n', 'utf-8');
}

// ---------------------------------------------------------------------------
// Input validation (preserved from original tests)
// ---------------------------------------------------------------------------

describe('applyFixes — validation', () => {
  beforeEach(() => {
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  it('returns empty applied and failed for empty updates array', async () => {
    const result = await applyFixes('/tmp/nonexistent', []);
    expect(result.applied).toHaveLength(0);
    expect(result.failed).toHaveLength(0);
  });

  it('fails validation before touching files for invalid package name', async () => {
    const maliciousUpdate = makeSafeUpdate({
      packageName: 'foo; rm -rf /',
      fixVersion: '1.0.0',
    });
    const result = await applyFixes('/tmp/nonexistent', [maliciousUpdate]);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toContain('Invalid package name');
    expect(safeExecMock).not.toHaveBeenCalled();
  });

  it('fails validation for invalid version string', async () => {
    const maliciousUpdate = makeSafeUpdate({
      packageName: 'lodash',
      fixVersion: '1.0.0 && curl evil.com',
    });
    const result = await applyFixes('/tmp/nonexistent', [maliciousUpdate]);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toContain('Invalid version string');
    expect(safeExecMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// npm happy path — overrides PERSIST (C-B5 fix)
// ---------------------------------------------------------------------------

describe('applyFixes — npm happy path (C-B5)', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes npm overrides and leaves them in package.json on install success', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0', dependencies: { 'vulnerable-pkg': '^1.5.0' } });
    const update = makeSafeUpdate({ packageName: 'vulnerable-pkg', fixVersion: '1.5.1' });

    const result = await applyFixes(dir, [update], 'npm-v3');

    expect(result.applied).toHaveLength(1);
    expect(result.failed).toHaveLength(0);

    // Overrides MUST remain in package.json (C-B5): without them, the lockfile
    // reverts on next `npm install`.
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    expect(pkg.overrides).toBeDefined();
    expect(pkg.overrides['vulnerable-pkg']).toBe('1.5.1');
  });

  it('writes a pending-overrides sentinel so downstream knows overrides are uncommitted', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const update = makeSafeUpdate({ packageName: 'vulnerable-pkg', fixVersion: '1.5.1' });

    await applyFixes(dir, [update], 'npm-v3');

    const sentinelPath = join(dir, '.auditfix', 'pending-overrides.json');
    expect(existsSync(sentinelPath)).toBe(true);
    const sentinel = JSON.parse(readFileSync(sentinelPath, 'utf-8'));
    expect(sentinel.schemaVersion).toBe(1);
    expect(sentinel.strategy).toBe('npm overrides');
    expect(sentinel.overrides['vulnerable-pkg']).toBe('1.5.1');
  });

  it('invokes npm install --package-lock-only', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    await applyFixes(dir, [makeSafeUpdate()], 'npm-v3');

    expect(safeExecMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = safeExecMock.mock.calls[0];
    expect(cmd).toBe('npm');
    expect(args).toEqual(['install', '--package-lock-only']);
  });
});

// ---------------------------------------------------------------------------
// Rollback on install failure
// ---------------------------------------------------------------------------

describe('applyFixes — install failure rollback', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reverts package.json when install fails — overrides must NOT persist', async () => {
    const original = { name: 'test', version: '1.0.0', dependencies: { foo: '^1.0.0' } };
    writePkgJson(dir, original);
    const originalBytes = readFileSync(join(dir, 'package.json'), 'utf-8');

    safeExecMock.mockResolvedValueOnce({ stdout: '', stderr: 'peer dep conflict', exitCode: 1 });

    const update = makeSafeUpdate({ packageName: 'vulnerable-pkg', fixVersion: '1.5.1' });
    const result = await applyFixes(dir, [update], 'npm-v3');

    expect(result.applied).toHaveLength(0);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toContain('peer dep conflict');

    // Package.json must be exactly reverted
    const afterBytes = readFileSync(join(dir, 'package.json'), 'utf-8');
    expect(afterBytes).toBe(originalBytes);

    // And NO sentinel should exist since the fix never succeeded
    expect(existsSync(join(dir, '.auditfix', 'pending-overrides.json'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Yarn Berry and Classic
// ---------------------------------------------------------------------------

describe('applyFixes — yarn Berry', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('uses yarn install --mode=update-lockfile (no node_modules mutation)', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const result = await applyFixes(dir, [makeSafeUpdate()], 'yarn-berry');

    expect(result.applied).toHaveLength(1);
    expect(safeExecMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = safeExecMock.mock.calls[0];
    expect(cmd).toBe('yarn');
    expect(args).toEqual(['install', '--mode=update-lockfile']);

    // Uses resolutions, not overrides
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    expect(pkg.resolutions).toBeDefined();
    expect(pkg.resolutions['vulnerable-pkg']).toBe('1.5.1');
  });
});

describe('applyFixes — yarn Classic', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('refuses to run without --yes and emits a skipped result', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const result = await applyFixes(dir, [makeSafeUpdate()], 'yarn-classic');

    expect(result.skipped).toBe(true);
    expect(result.skipReason).toMatch(/yes/i);
    expect(result.applied).toHaveLength(0);
    expect(safeExecMock).not.toHaveBeenCalled();

    // package.json must NOT have been mutated
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    expect(pkg.resolutions).toBeUndefined();
  });

  it('runs full yarn install when { yes: true } is passed', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const result = await applyFixes(dir, [makeSafeUpdate()], 'yarn-classic', { yes: true });

    expect(result.applied).toHaveLength(1);
    expect(safeExecMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = safeExecMock.mock.calls[0];
    expect(cmd).toBe('yarn');
    expect(args).toEqual(['install']);
  });
});

// ---------------------------------------------------------------------------
// TOCTOU: symlink inserted between pre-check and write
// ---------------------------------------------------------------------------

describe('applyFixes — TOCTOU symlink protection', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('rejects when package.json is a pre-existing symlink', async () => {
    const realTargetDir = makeTempDir();
    const realTarget = join(realTargetDir, 'real-pkg.json');
    writeFileSync(realTarget, JSON.stringify({ name: 'real' }), 'utf-8');

    const linkPath = join(dir, 'package.json');
    try {
      symlinkSync(realTarget, linkPath, 'file');
    } catch {
      // On Windows, creating symlinks may require elevation — skip in that case.
      rmSync(realTargetDir, { recursive: true, force: true });
      return;
    }

    const result = await applyFixes(dir, [makeSafeUpdate()], 'npm-v3');

    expect(result.applied).toHaveLength(0);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toContain('symlink');
    // Real target must be untouched
    const real = JSON.parse(readFileSync(realTarget, 'utf-8'));
    expect(real.overrides).toBeUndefined();

    rmSync(realTargetDir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// Oversized package.json guard
// ---------------------------------------------------------------------------

describe('applyFixes — oversized package.json', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('rejects when package.json exceeds configured max bytes', async () => {
    // Build a package.json > 1KB and set the limit to 1000 bytes
    const bigPkg: Record<string, unknown> = { name: 'test', version: '1.0.0', dependencies: {} };
    const deps = bigPkg.dependencies as Record<string, string>;
    for (let i = 0; i < 200; i++) {
      deps[`dep-${i}`] = '^1.0.0';
    }
    writePkgJson(dir, bigPkg);

    const result = await applyFixes(dir, [makeSafeUpdate()], 'npm-v3', { maxPackageJsonBytes: 1000 });

    expect(result.applied).toHaveLength(0);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].reason).toMatch(/oversized/i);
    expect(safeExecMock).not.toHaveBeenCalled();
  });

  it('accepts package.json under the configured max', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const result = await applyFixes(dir, [makeSafeUpdate()], 'npm-v3', { maxPackageJsonBytes: 10_000 });
    expect(result.applied).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Pnpm
// ---------------------------------------------------------------------------

describe('applyFixes — pnpm', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
    safeExecMock.mockClear();
    safeExecMock.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes pnpm.overrides and runs pnpm install --lockfile-only', async () => {
    writePkgJson(dir, { name: 'test', version: '1.0.0' });
    const result = await applyFixes(dir, [makeSafeUpdate()], 'pnpm-v9');

    expect(result.applied).toHaveLength(1);
    expect(safeExecMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = safeExecMock.mock.calls[0];
    expect(cmd).toBe('pnpm');
    expect(args).toEqual(['install', '--lockfile-only']);

    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    expect(pkg.pnpm?.overrides?.['vulnerable-pkg']).toBe('1.5.1');
  });

  it('preserves existing pnpm config when adding overrides', async () => {
    writePkgJson(dir, {
      name: 'test',
      version: '1.0.0',
      pnpm: { peerDependencyRules: { ignoreMissing: ['react'] } },
    });
    await applyFixes(dir, [makeSafeUpdate()], 'pnpm-v9');

    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    expect(pkg.pnpm.peerDependencyRules).toBeDefined();
    expect(pkg.pnpm.overrides['vulnerable-pkg']).toBe('1.5.1');
  });
});
