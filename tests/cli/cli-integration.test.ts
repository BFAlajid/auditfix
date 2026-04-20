import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createProgram } from '../../src/cli/index.js';
import * as path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('CLI integration', () => {
  it('--version outputs a version string', async () => {
    const program = createProgram();
    program.exitOverride();

    let output = '';
    program.configureOutput({ writeOut: (str) => { output += str; } });

    try {
      await program.parseAsync(['node', 'test', '--version']);
    } catch {
      // exitOverride throws on --version
    }

    expect(output).toMatch(/\d+\.\d+\.\d+/);
  });

  it('--severity with invalid value is rejected', async () => {
    const program = createProgram();
    program.exitOverride();

    let errOutput = '';
    program.configureOutput({ writeErr: (str) => { errOutput += str; } });

    try {
      await program.parseAsync(['node', 'test', '--severity', 'invalid']);
    } catch {
      // expected
    }

    expect(errOutput).toContain("'invalid'");
  });

  it('--help shows key options', async () => {
    const program = createProgram();
    program.exitOverride();

    let output = '';
    program.configureOutput({ writeOut: (str) => { output += str; } });

    try {
      await program.parseAsync(['node', 'test', '--help']);
    } catch {
      // exitOverride throws on --help
    }

    expect(output).toContain('--prod-only');
    expect(output).toContain('--severity');
    expect(output).toContain('--fix');
    expect(output).toContain('--sarif');
    expect(output).toContain('--workspace');
  });

  it('--help does NOT advertise the removed update-index subcommand', async () => {
    const program = createProgram();
    program.exitOverride();

    let output = '';
    program.configureOutput({ writeOut: (str) => { output += str; } });

    try {
      await program.parseAsync(['node', 'test', '--help']);
    } catch {
      // exitOverride throws on --help
    }

    expect(output).not.toContain('update-index');
  });
});

describe('--dir restriction under GitHub Actions', () => {
  let tmpRoot: string;
  let origActions: string | undefined;
  let origWorkspace: string | undefined;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorLogSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmpRoot = mkdtempSync(path.join(tmpdir(), 'auditfix-dir-'));
    mkdirSync(path.join(tmpRoot, 'ws'), { recursive: true });
    mkdirSync(path.join(tmpRoot, 'ws', 'sub'), { recursive: true });
    mkdirSync(path.join(tmpRoot, 'outside'), { recursive: true });
    // Create minimal lockfile so downstream code doesn't fail before exit
    writeFileSync(path.join(tmpRoot, 'ws', 'package-lock.json'), JSON.stringify({ name: 'x', version: '1.0.0', lockfileVersion: 3, packages: {} }));

    origActions = process.env.GITHUB_ACTIONS;
    origWorkspace = process.env.GITHUB_WORKSPACE;

    // process.exit throws instead of exiting so we can assert the code
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`__EXIT__${code ?? 0}`);
    }) as never);
    errorLogSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorLogSpy.mockRestore();
    if (origActions === undefined) delete process.env.GITHUB_ACTIONS;
    else process.env.GITHUB_ACTIONS = origActions;
    if (origWorkspace === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = origWorkspace;
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('rejects --dir outside GITHUB_WORKSPACE with exit 2', async () => {
    process.env.GITHUB_ACTIONS = 'true';
    process.env.GITHUB_WORKSPACE = path.join(tmpRoot, 'ws');

    const program = createProgram();
    program.exitOverride();

    let caught: Error | undefined;
    try {
      await program.parseAsync(['node', 'test', '--dir', path.join(tmpRoot, 'outside')]);
    } catch (err) {
      caught = err as Error;
    }

    expect(caught?.message).toBe('__EXIT__2');
  });

  it('accepts --dir inside GITHUB_WORKSPACE', async () => {
    process.env.GITHUB_ACTIONS = 'true';
    process.env.GITHUB_WORKSPACE = path.join(tmpRoot, 'ws');

    const program = createProgram();
    program.exitOverride();

    let caught: Error | undefined;
    try {
      await program.parseAsync(['node', 'test', '--dir', path.join(tmpRoot, 'ws', 'sub')]);
    } catch (err) {
      caught = err as Error;
    }

    // Should pass the --dir gate. It may exit later with a different code
    // (e.g. no lockfile found, advisory errors), but *not* with the dir-check
    // exit 2 that triggers before anything else.
    //
    // We assert that if it exited, the message doesn't indicate the dir-check
    // failed. We can't trivially distinguish exit-2 from dir-check vs exit-2
    // from analyzer failure, but we CAN assert the specific error log from
    // dir-check did not run.
    const dirCheckErrors = errorLogSpy.mock.calls
      .map(c => String(c[0] ?? ''))
      .filter(s => s.includes('must be within GITHUB_WORKSPACE'));
    expect(dirCheckErrors).toHaveLength(0);
    // Process should have attempted to exit (the analyzer runs and exits),
    // confirming we got past the dir gate.
    expect(caught).toBeDefined();
  });

  it('accepts --dir equal to GITHUB_WORKSPACE exactly', async () => {
    process.env.GITHUB_ACTIONS = 'true';
    process.env.GITHUB_WORKSPACE = path.join(tmpRoot, 'ws');

    const program = createProgram();
    program.exitOverride();

    try {
      await program.parseAsync(['node', 'test', '--dir', path.join(tmpRoot, 'ws')]);
    } catch {
      // expected: downstream exit
    }
    const dirCheckErrors = errorLogSpy.mock.calls
      .map(c => String(c[0] ?? ''))
      .filter(s => s.includes('must be within GITHUB_WORKSPACE'));
    expect(dirCheckErrors).toHaveLength(0);
  });

  it('rejects sibling directory with similar prefix (e.g. /tmp/x-evil vs /tmp/x)', async () => {
    // Prevent substring-prefix bypass: /ws-evil should NOT match /ws.
    const wsEvil = path.join(tmpRoot, 'ws-evil');
    mkdirSync(wsEvil, { recursive: true });
    process.env.GITHUB_ACTIONS = 'true';
    process.env.GITHUB_WORKSPACE = path.join(tmpRoot, 'ws');

    const program = createProgram();
    program.exitOverride();

    let caught: Error | undefined;
    try {
      await program.parseAsync(['node', 'test', '--dir', wsEvil]);
    } catch (err) {
      caught = err as Error;
    }

    expect(caught?.message).toBe('__EXIT__2');
    const dirCheckErrors = errorLogSpy.mock.calls
      .map(c => String(c[0] ?? ''))
      .filter(s => s.includes('must be within GITHUB_WORKSPACE'));
    expect(dirCheckErrors.length).toBeGreaterThanOrEqual(1);
  });

  it('rejects when GITHUB_ACTIONS=true but GITHUB_WORKSPACE unset', async () => {
    process.env.GITHUB_ACTIONS = 'true';
    delete process.env.GITHUB_WORKSPACE;

    const program = createProgram();
    program.exitOverride();

    let caught: Error | undefined;
    try {
      await program.parseAsync(['node', 'test', '--dir', path.join(tmpRoot, 'ws')]);
    } catch (err) {
      caught = err as Error;
    }

    expect(caught?.message).toBe('__EXIT__2');
  });

  it('no restriction when GITHUB_ACTIONS is not set', async () => {
    delete process.env.GITHUB_ACTIONS;
    process.env.GITHUB_WORKSPACE = path.join(tmpRoot, 'ws');

    const program = createProgram();
    program.exitOverride();

    try {
      await program.parseAsync(['node', 'test', '--dir', path.join(tmpRoot, 'outside')]);
    } catch {
      // expected: downstream exit
    }
    const dirCheckErrors = errorLogSpy.mock.calls
      .map(c => String(c[0] ?? ''))
      .filter(s => s.includes('must be within GITHUB_WORKSPACE'));
    expect(dirCheckErrors).toHaveLength(0);
  });
});
