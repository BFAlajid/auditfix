import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { debug, info, warn, error, setLogLevel } from '../../src/utils/logger.js';

describe('token redaction', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    setLogLevel('debug');
    stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    setLogLevel('info');
  });

  it('redacts GitHub personal access tokens (ghp_)', () => {
    const token = 'ghp_ABCDEFghijklmnopqrstuvwxyz0123456789';
    debug(`Using token: ${token}`);

    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('[REDACTED]'),
    );
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.not.stringContaining(token),
    );
  });

  it('redacts GitHub secret tokens (ghs_)', () => {
    const token = 'ghs_ABCDEFghijklmnopqrstuvwxyz0123456789';
    info(`Token: ${token}`);

    expect(stderrSpy).toHaveBeenCalledWith(
      expect.not.stringContaining(token),
    );
  });

  it('redacts github_pat_ tokens', () => {
    const token = 'github_pat_' + 'A'.repeat(82);
    warn(`Found token ${token} in env`);

    expect(stderrSpy).toHaveBeenCalledWith(
      expect.not.stringContaining(token),
    );
  });

  it('redacts Bearer tokens', () => {
    const message = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature';
    error(message);

    expect(stderrSpy).toHaveBeenCalledWith(
      expect.not.stringContaining('eyJhbGciOiJIUzI1NiJ9'),
    );
  });

  it('does not redact normal messages', () => {
    info('Scanning 847 packages');

    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Scanning 847 packages'),
    );
  });

  it('redacts multiple tokens in same message', () => {
    const msg = 'token1=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm token2=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm';
    debug(msg);

    const output = stderrSpy.mock.calls[0][0] as string;
    expect(output).not.toContain('ghp_');
    expect(output).not.toContain('ghs_');
    expect(output.match(/\[REDACTED\]/g)!.length).toBeGreaterThanOrEqual(2);
  });
});
