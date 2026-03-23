import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadPolicy, PolicyLoadError } from '../../../src/core/policy/loader.js';
import { existsSync, readFileSync } from 'node:fs';

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
});
