import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../../src/core/config.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-config-test-'));
}

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('loadConfig', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTempDir();
  });

  afterEach(() => {
    cleanupDir(tmpDir);
    vi.restoreAllMocks();
  });

  it('returns defaults when no config file is found', async () => {
    const config = await loadConfig({}, tmpDir);
    expect(config).toEqual(DEFAULT_CONFIG);
  });

  it('merges config file values over defaults', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify({ severity: 'high' }));

    const config = await loadConfig({}, tmpDir);

    expect(config.severity).toBe('high');
    // Other defaults should be preserved
    expect(config.productionOnly).toBe(DEFAULT_CONFIG.productionOnly);
    expect(config.output).toBe(DEFAULT_CONFIG.output);
    expect(config.ci).toEqual(DEFAULT_CONFIG.ci);
  });

  it('CLI overrides take precedence over config file', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({ severity: 'high', productionOnly: true }),
    );

    const config = await loadConfig({ severity: 'critical' }, tmpDir);

    expect(config.severity).toBe('critical');
    // Config file value not overridden by CLI should still apply
    expect(config.productionOnly).toBe(true);
  });

  it('ignores undefined CLI override values', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify({ severity: 'high' }));

    const config = await loadConfig(
      { severity: undefined, productionOnly: undefined } as Partial<
        typeof DEFAULT_CONFIG
      >,
      tmpDir,
    );

    // Config file value should not be clobbered by undefined
    expect(config.severity).toBe('high');
    expect(config.productionOnly).toBe(DEFAULT_CONFIG.productionOnly);
  });

  it('warns and returns defaults for invalid config file', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, '{ this is not valid json !!!');

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to load config file'),
    );
    expect(config).toEqual(DEFAULT_CONFIG);
  });

  it('deep merges nested ci config', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({
        ci: {
          sarifUpload: true,
        },
      }),
    );

    const config = await loadConfig({}, tmpDir);

    // sarifUpload from config file
    expect(config.ci.sarifUpload).toBe(true);
    // failOn should retain default
    expect(config.ci.failOn).toBe(DEFAULT_CONFIG.ci.failOn);
  });

  it('CLI ci overrides merge over config file ci values', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({
        ci: {
          sarifUpload: true,
          failOn: 'any',
        },
      }),
    );

    const config = await loadConfig(
      { ci: { failOn: 'production-high', sarifUpload: false } },
      tmpDir,
    );

    expect(config.ci.failOn).toBe('production-high');
    expect(config.ci.sarifUpload).toBe(false);
  });

  it('merge order is defaults -> file -> CLI', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({
        severity: 'medium',
        output: 'json',
      }),
    );

    const config = await loadConfig({ output: 'sarif' }, tmpDir);

    // severity from file (overrides default 'low')
    expect(config.severity).toBe('medium');
    // output from CLI (overrides file 'json')
    expect(config.output).toBe('sarif');
    // autoFix from default (not set in file or CLI)
    expect(config.autoFix).toBe(DEFAULT_CONFIG.autoFix);
  });
});
