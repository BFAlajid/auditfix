import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AppliedFix } from '../../src/core/fixer/lockfile-writer.js';

type ShellResult = { stdout: string; stderr: string; exitCode: number };

// safeExec mock — tests configure per-call responses with mockResolvedValueOnce
const safeExecMock = vi.hoisted(() =>
  vi.fn<(...args: unknown[]) => Promise<ShellResult>>().mockResolvedValue({
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

const { createFixPr } = await import('../../src/core/fixer/pr-creator.js');

function makeFix(overrides: Partial<AppliedFix> = {}): AppliedFix {
  return {
    packageName: 'vulnerable-pkg',
    from: '1.5.0',
    to: '1.5.1',
    ...overrides,
  };
}

const OK: ShellResult = { stdout: '', stderr: '', exitCode: 0 };
const ghVersion: ShellResult = { stdout: 'gh version 2.40.0', stderr: '', exitCode: 0 };
const ghAuthOk: ShellResult = { stdout: 'Logged in to github.com', stderr: '', exitCode: 0 };

describe('createFixPr', () => {
  beforeEach(() => {
    safeExecMock.mockReset();
    safeExecMock.mockResolvedValue(OK);
  });

  // -------------------------------------------------------------------------
  // gh missing
  // -------------------------------------------------------------------------

  it('returns a structured error when gh CLI is not installed', async () => {
    // First call: gh --version — simulate "command not found"
    safeExecMock.mockResolvedValueOnce({ stdout: '', stderr: 'command not found', exitCode: 127 });

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/GitHub CLI/i);
    // Should NOT have proceeded to auth or git calls
    expect(safeExecMock).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // gh auth fail
  // -------------------------------------------------------------------------

  it('surfaces gh auth failures without attempting branch work', async () => {
    safeExecMock
      .mockResolvedValueOnce(ghVersion)
      .mockResolvedValueOnce({ stdout: '', stderr: 'not logged in', exitCode: 1 });

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not authenticated/i);
    // Should have checked gh --version + gh auth status, then stopped.
    expect(safeExecMock).toHaveBeenCalledTimes(2);
  });

  // -------------------------------------------------------------------------
  // Branch creation failure
  // -------------------------------------------------------------------------

  it('returns error when git branch creation fails', async () => {
    safeExecMock
      .mockResolvedValueOnce(ghVersion)          // gh --version
      .mockResolvedValueOnce(ghAuthOk)            // gh auth status
      .mockResolvedValueOnce({                    // git checkout -b
        stdout: '',
        stderr: 'fatal: a branch named X already exists',
        exitCode: 128,
      });

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to create branch/i);
    expect(result.error).toContain('already exists');
  });

  // -------------------------------------------------------------------------
  // Commit failure (restores branch)
  // -------------------------------------------------------------------------

  it('returns error and restores the original branch when commit fails', async () => {
    safeExecMock
      .mockResolvedValueOnce(ghVersion)           // gh --version
      .mockResolvedValueOnce(ghAuthOk)             // gh auth status
      .mockResolvedValueOnce(OK)                   // git checkout -b
      .mockResolvedValueOnce(OK)                   // git add
      .mockResolvedValueOnce({                     // git commit
        stdout: '',
        stderr: 'nothing to commit',
        exitCode: 1,
      })
      .mockResolvedValueOnce(OK);                  // git checkout -

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to commit/i);

    // Last call must be `git checkout -` (branch restore)
    const lastCall = safeExecMock.mock.calls[safeExecMock.mock.calls.length - 1];
    expect(lastCall[0]).toBe('git');
    expect(lastCall[1]).toEqual(['checkout', '-']);
  });

  // -------------------------------------------------------------------------
  // Push failure
  // -------------------------------------------------------------------------

  it('returns error when git push fails', async () => {
    safeExecMock
      .mockResolvedValueOnce(ghVersion)
      .mockResolvedValueOnce(ghAuthOk)
      .mockResolvedValueOnce(OK)   // git checkout -b
      .mockResolvedValueOnce(OK)   // git add
      .mockResolvedValueOnce(OK)   // git commit
      .mockResolvedValueOnce({ stdout: '', stderr: 'Permission denied', exitCode: 1 }); // git push

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to push/i);
    expect(result.error).toContain('Permission denied');
  });

  // -------------------------------------------------------------------------
  // gh pr create fails (branch exists / PR exists)
  // -------------------------------------------------------------------------

  it('returns structured error when gh pr create reports a conflict', async () => {
    safeExecMock
      .mockResolvedValueOnce(ghVersion)
      .mockResolvedValueOnce(ghAuthOk)
      .mockResolvedValueOnce(OK)    // git checkout -b
      .mockResolvedValueOnce(OK)    // git add
      .mockResolvedValueOnce(OK)    // git commit
      .mockResolvedValueOnce(OK)    // git push
      .mockResolvedValueOnce({       // gh pr create
        stdout: '',
        stderr: 'a pull request for branch X already exists',
        exitCode: 1,
      });

    const result = await createFixPr('/tmp/project', [makeFix()]);

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to create PR/i);
    expect(result.error).toContain('already exists');
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('returns the PR URL on success', async () => {
    const prUrl = 'https://github.com/owner/repo/pull/42';

    safeExecMock
      .mockResolvedValueOnce(ghVersion)
      .mockResolvedValueOnce(ghAuthOk)
      .mockResolvedValueOnce(OK)                                          // git checkout -b
      .mockResolvedValueOnce(OK)                                          // git add
      .mockResolvedValueOnce(OK)                                          // git commit
      .mockResolvedValueOnce(OK)                                          // git push
      .mockResolvedValueOnce({ stdout: prUrl + '\n', stderr: '', exitCode: 0 }) // gh pr create
      .mockResolvedValueOnce(OK);                                         // git checkout -

    const result = await createFixPr('/tmp/project', [
      makeFix({ packageName: 'a', from: '1.0.0', to: '1.0.1' }),
      makeFix({ packageName: 'b', from: '2.0.0', to: '2.0.1' }),
    ]);

    expect(result.success).toBe(true);
    expect(result.prUrl).toBe(prUrl);

    // Sanity-check the pr create invocation carried both packages in the body
    const prCreateCall = safeExecMock.mock.calls.find(
      (c) => c[0] === 'gh' && Array.isArray(c[1]) && (c[1] as string[])[0] === 'pr',
    );
    expect(prCreateCall).toBeDefined();
    const args = prCreateCall![1] as string[];
    const bodyIdx = args.indexOf('--body');
    expect(bodyIdx).toBeGreaterThanOrEqual(0);
    const body = args[bodyIdx + 1];
    expect(body).toContain('a: 1.0.0 → 1.0.1');
    expect(body).toContain('b: 2.0.0 → 2.0.1');
  });

  // -------------------------------------------------------------------------
  // No crash on unexpected exceptions from safeExec
  // -------------------------------------------------------------------------

  it('does not crash when the first gh invocation throws', async () => {
    safeExecMock.mockRejectedValueOnce(new Error('spawn ENOENT'));

    await expect(createFixPr('/tmp/project', [makeFix()])).rejects.toThrow();
    // This test documents current behavior: safeExec already returns a structured
    // error instead of throwing in production, so a thrown error here surfaces as a
    // reject. The value is that we don't swallow the exception silently.
  });
});
