import { describe, it, expect, vi, beforeEach, afterEach, expectTypeOf } from 'vitest';
import { loadConfig } from '../../src/core/config.js';
import {
  AuditfixConfigSchema,
  DEFAULT_CONFIG,
  PartialAuditfixConfigSchema,
  type AuditfixConfig,
} from '../../src/types/config.js';
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

  it('warns and falls back to defaults when config file severity is invalid', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify({ severity: 'catastrophic' }));

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/Invalid config file .*severity/),
    );
    expect(config.severity).toBe(DEFAULT_CONFIG.severity);
  });

  it('warns when output format is not a known value', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify({ output: 'xml' }));

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('output'));
    expect(config.output).toBe(DEFAULT_CONFIG.output);
  });

  it('warns when ci.failOn is not a known value', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({ ci: { failOn: 'whenever', sarifUpload: true } }),
    );

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('ci.failOn'));
    // Falls back to full defaults since the whole file object failed validation
    expect(config.ci.failOn).toBe(DEFAULT_CONFIG.ci.failOn);
  });

  it('warns when a boolean field is the wrong type', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify({ productionOnly: 'yes' }));

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('productionOnly'),
    );
    expect(config.productionOnly).toBe(DEFAULT_CONFIG.productionOnly);
  });

  it('silently ignores unknown top-level keys (preserves pre-zod behavior)', async () => {
    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(
      rcPath,
      JSON.stringify({ unknownKey: 42, severity: 'high' }),
    );

    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig({}, tmpDir);

    // No warning for unknown key — matches old loader behavior
    expect(warnSpy).not.toHaveBeenCalled();
    expect(config.severity).toBe('high');
  });

  it('warns and drops invalid CLI overrides', async () => {
    const warnSpy = vi.spyOn(await import('../../src/utils/logger.js'), 'warn');

    const config = await loadConfig(
      { severity: 'nope' as unknown as AuditfixConfig['severity'] },
      tmpDir,
    );

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/Invalid CLI overrides.*severity/),
    );
    expect(config.severity).toBe(DEFAULT_CONFIG.severity);
  });

  it('accepts all documented severity values in a config file', async () => {
    for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      const rcPath = path.join(tmpDir, '.auditfixrc.json');
      fs.writeFileSync(rcPath, JSON.stringify({ severity }));
      const config = await loadConfig({}, tmpDir);
      expect(config.severity).toBe(severity);
    }
  });

  it('round-trips a full valid config through the schema and loader', async () => {
    const full: AuditfixConfig = {
      severity: 'high',
      productionOnly: true,
      autoFix: true,
      ignoreDev: true,
      communityAllowList: true,
      maxAdvisoryStaleness: '24h',
      output: 'sarif',
      ci: { failOn: 'any', sarifUpload: true },
    };

    // Schema accepts the canonical shape
    expect(AuditfixConfigSchema.safeParse(full).success).toBe(true);

    const rcPath = path.join(tmpDir, '.auditfixrc.json');
    fs.writeFileSync(rcPath, JSON.stringify(full));

    const config = await loadConfig({}, tmpDir);
    expect(config).toEqual(full);
  });
});

describe('AuditfixConfigSchema (type inference)', () => {
  it('infers the AuditfixConfig type from the schema', () => {
    // Compile-time check: if the inferred type drifts from the exported
    // AuditfixConfig, this test fails at `tsc --noEmit`.
    type Inferred = typeof AuditfixConfigSchema._type;
    expectTypeOf<Inferred>().toEqualTypeOf<AuditfixConfig>();
  });

  it('rejects cvss-style out-of-range values only where schema enforces it', () => {
    // Sanity: partial schema rejects unknown enum values with a useful message.
    const result = PartialAuditfixConfigSchema.safeParse({ severity: 'none' });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0].path).toEqual(['severity']);
    }
  });
});
