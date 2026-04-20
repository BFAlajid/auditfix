import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadPolicy, PolicyLoadError } from '../../../src/core/policy/loader.js';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as logger from '../../../src/utils/logger.js';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

const VALID_POLICY_YAML = `
version: 1
rules:
  - name: block-critical
    match:
      all:
        - severity: [critical]
        - scope: production
    action: fail
  - name: warn-medium
    match:
      all:
        - severity: [medium]
    action: warn
`;

const POLICY_WITH_OVERRIDE = `
version: 1
rules:
  - name: block-critical
    match:
      all:
        - severity: [critical]
    action: fail
overrides:
  - rule: block-critical
    action: warn
    reason: "Testing override"
    expires: "2099-12-31"
`;

const POLICY_WITH_EXPIRED_OVERRIDE = `
version: 1
rules:
  - name: block-critical
    match:
      all:
        - severity: [critical]
    action: fail
overrides:
  - rule: block-critical
    action: warn
    reason: "Expired"
    expires: "2020-01-01"
`;

describe('Policy loader', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns null when no policy file exists', async () => {
    vi.mocked(existsSync).mockReturnValue(false);
    const result = await loadPolicy('/project');
    expect(result).toBeNull();
  });

  it('loads valid YAML policy', async () => {
    vi.mocked(existsSync).mockImplementation((p) => {
      return String(p).includes('.auditfix-policy.yml');
    });
    vi.mocked(readFileSync).mockReturnValue(VALID_POLICY_YAML);

    const result = await loadPolicy('/project');
    expect(result).not.toBeNull();
    expect(result!.rules).toHaveLength(2);
    expect(result!.rules[0].name).toBe('block-critical');
    expect(result!.rules[0].action).toBe('fail');
    expect(result!.rules[1].name).toBe('warn-medium');
    expect(result!.rules[1].action).toBe('warn');
  });

  it('throws on invalid YAML', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue('{ invalid yaml:::');

    await expect(loadPolicy('/project', '/project/.auditfix-policy.yml')).rejects.toThrow(
      PolicyLoadError,
    );
  });

  it('throws on unsupported version', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue('version: 2\nrules: []');

    await expect(loadPolicy('/project', '/project/.auditfix-policy.yml')).rejects.toThrow(
      /version/i,
    );
  });

  it('applies overrides', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(POLICY_WITH_OVERRIDE);

    const result = await loadPolicy('/project', '/project/.auditfix-policy.yml');
    expect(result!.rules[0].action).toBe('warn');
    expect(result!.rules[0].overridden).toBeDefined();
    expect(result!.rules[0].overridden!.originalAction).toBe('fail');
  });

  it('ignores expired overrides', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(POLICY_WITH_EXPIRED_OVERRIDE);

    const result = await loadPolicy('/project', '/project/.auditfix-policy.yml');
    expect(result!.rules[0].action).toBe('fail'); // not overridden
    expect(result!.rules[0].overridden).toBeUndefined();
  });

  it('throws on invalid rule name', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(
      'version: 1\nrules:\n  - name: "Invalid Name!"\n    match:\n      all: [{ severity: [critical] }]\n    action: fail',
    );

    await expect(loadPolicy('/project', '/project/.auditfix-policy.yml')).rejects.toThrow(
      /kebab-case/,
    );
  });

  it('throws when auto-ignore lacks reason', async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(
      'version: 1\nrules:\n  - name: suppress\n    match:\n      all: [{ scope: dev }]\n    action: auto-ignore',
    );

    await expect(loadPolicy('/project', '/project/.auditfix-policy.yml')).rejects.toThrow(
      /reason/,
    );
  });

  describe('security hardening', () => {
    // Use `resolve` on both sides so the mock matches what loader produces on
    // Windows (`C:\project\...`) and POSIX (`/project/...`).
    const PROJECT_DIR = 'project';
    const POLICY_ABS = resolve(PROJECT_DIR, '.auditfix-policy.yml');
    const SHARED_ABS = resolve(PROJECT_DIR, 'shared.yml');

    it('rejects extends path that escapes the project root', async () => {
      // A malicious PR author commits a policy file whose `extends` points outside
      // the repo. The loader must warn and skip — never open the file.
      const MALICIOUS_POLICY = `
version: 1
extends:
  - ../../../../etc/passwd
rules:
  - name: noop
    match:
      all:
        - severity: [critical]
    action: warn
`;
      vi.mocked(existsSync).mockImplementation((p) => String(p) === POLICY_ABS);
      vi.mocked(readFileSync).mockImplementation((p) => {
        if (String(p) === POLICY_ABS) return MALICIOUS_POLICY;
        throw new Error(`Unexpected read of ${p}`);
      });

      const result = await loadPolicy(PROJECT_DIR, POLICY_ABS);

      // The out-of-root path must have been skipped (not read) — readFileSync must
      // only have seen the main policy file.
      const readPaths = vi.mocked(readFileSync).mock.calls.map((c) => String(c[0]));
      expect(readPaths).toEqual([POLICY_ABS]);

      // A warning must have been logged mentioning "escapes project root"
      const warnings = vi.mocked(logger.warn).mock.calls.map((c) => String(c[0]));
      expect(warnings.some((m) => /escapes project root/.test(m))).toBe(true);

      // Local rule still loads
      expect(result!.rules).toHaveLength(1);
      expect(result!.rules[0].name).toBe('noop');
    });

    it('accepts extends path that stays inside the project root', async () => {
      const ROOT_POLICY = `
version: 1
extends:
  - ./shared.yml
rules: []
`;
      const SHARED_POLICY = `
version: 1
rules:
  - name: shared-rule
    match:
      all:
        - severity: [high]
    action: warn
`;
      vi.mocked(existsSync).mockImplementation((p) => {
        const path = String(p);
        return path === POLICY_ABS || path === SHARED_ABS;
      });
      vi.mocked(readFileSync).mockImplementation((p) => {
        const path = String(p);
        if (path === POLICY_ABS) return ROOT_POLICY;
        if (path === SHARED_ABS) return SHARED_POLICY;
        throw new Error(`Unexpected read of ${path}`);
      });

      const result = await loadPolicy(PROJECT_DIR, POLICY_ABS);
      expect(result!.rules.map((r) => r.name)).toContain('shared-rule');
    });

    it('truncates malformed-YAML error messages to single line ≤200 chars', async () => {
      // js-yaml normally emits multi-line errors containing surrounding source text.
      // Our wrapping must collapse newlines and cap the length to prevent file-content
      // leakage into logs.
      const LONG_MALFORMED = `version: 1
rules:
  - name: bad
    match:
      all:
        - severity: [critical
# the unclosed bracket above triggers a parse error.
# js-yaml normally echoes a source snippet that could contain secrets if the file
# we read were, say, a private key. We must truncate to one line of ≤200 chars.
${'payload-secret-content-that-should-never-leak-'.repeat(20)}
`;
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFileSync).mockReturnValue(LONG_MALFORMED);

      let caught: unknown;
      try {
        await loadPolicy('/project', '/project/.auditfix-policy.yml');
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(PolicyLoadError);
      const msg = (caught as Error).message;
      expect(msg).not.toMatch(/\r|\n/);
      // `YAML parse error in /project/.auditfix-policy.yml: ` prefix plus ≤200-char detail.
      // Allow an extra ~60 chars of prefix; core constraint is the truncation did fire.
      expect(msg.length).toBeLessThanOrEqual(260);
      // Sensitive payload must not appear in full — truncated output should not contain
      // the repeated secret string in its entirety.
      expect(msg).not.toContain('payload-secret-content-that-should-never-leak-'.repeat(5));
    });
  });
});
