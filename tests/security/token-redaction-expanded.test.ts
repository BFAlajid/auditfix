import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { warn, setLogLevel } from '../../src/utils/logger.js';

describe('Expanded token redaction', () => {
  let spy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    setLogLevel('debug');
    spy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    spy.mockRestore();
    setLogLevel('info');
  });

  it('redacts npm tokens (npm_...)', () => {
    warn('token is npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901');
    const output = spy.mock.calls[0][0] as string;
    expect(output).toContain('[REDACTED]');
    expect(output).not.toContain('npm_aBcD');
  });

  it('redacts GitLab PATs (glpat-...)', () => {
    warn('secret: glpat-abcdefghijklmnopqrst');
    const output = spy.mock.calls[0][0] as string;
    expect(output).toContain('[REDACTED]');
    expect(output).not.toContain('glpat-');
  });

  it('redacts AWS access keys (AKIA...)', () => {
    warn('key is AKIAIOSFODNN7EXAMPLE');
    const output = spy.mock.calls[0][0] as string;
    expect(output).toContain('[REDACTED]');
    expect(output).not.toContain('AKIAIOSF');
  });
});
