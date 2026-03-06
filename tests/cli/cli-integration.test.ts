import { describe, it, expect } from 'vitest';
import { createProgram } from '../../src/cli/index.js';

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
});
