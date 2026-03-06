import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadLocalAllowList,
  applyAllowList,
  addToAllowList,
} from '../../src/core/allowlist/local.js';
import type { AdvisoryMatch, Advisory } from '../../src/types/advisory.js';

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'auditfix-allowlist-'));
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function makeAdvisory(id: string, aliases: string[] = []): Advisory {
  return {
    id,
    aliases,
    summary: 'Test vulnerability',
    details: '',
    severity: [],
    affectedRange: '>=1.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
  };
}

function makeMatch(id: string, pkg: string, aliases: string[] = []): AdvisoryMatch {
  return {
    advisory: makeAdvisory(id, aliases),
    package: pkg,
    installedVersion: '1.0.0',
    dependencyPath: [pkg],
    isProduction: true,
  };
}

function futureDate(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().split('T')[0];
}

function pastDate(): string {
  return '2020-01-01';
}

describe('loadLocalAllowList', () => {
  it('returns empty list when no file exists', () => {
    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(0);
  });

  it('loads valid allow-list', () => {
    const allowList = {
      ignore: [
        {
          id: 'GHSA-rp65-9cf3-cjxr',
          package: 'nth-check',
          reason: 'Dev-only, not reachable',
          expires: futureDate(),
        },
      ],
    };
    writeFileSync(join(tempDir, '.auditfixignore'), JSON.stringify(allowList));

    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(1);
    expect(result.ignore[0].id).toBe('GHSA-rp65-9cf3-cjxr');
  });

  it('skips expired entries', () => {
    const allowList = {
      ignore: [
        {
          id: 'GHSA-rp65-9cf3-cjxr',
          package: 'nth-check',
          reason: 'Expired',
          expires: pastDate(),
        },
      ],
    };
    writeFileSync(join(tempDir, '.auditfixignore'), JSON.stringify(allowList));

    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(0);
  });

  it('skips entries with invalid advisory IDs', () => {
    const allowList = {
      ignore: [
        {
          id: 'INVALID-ID',
          package: 'pkg',
          reason: 'test',
          expires: futureDate(),
        },
      ],
    };
    writeFileSync(join(tempDir, '.auditfixignore'), JSON.stringify(allowList));

    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(0);
  });

  it('skips entries missing required fields', () => {
    const allowList = {
      ignore: [
        { id: 'GHSA-rp65-9cf3-cjxr' }, // missing package, reason, expires
      ],
    };
    writeFileSync(join(tempDir, '.auditfixignore'), JSON.stringify(allowList));

    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(0);
  });

  it('returns empty on invalid JSON', () => {
    writeFileSync(join(tempDir, '.auditfixignore'), '{broken json');

    const result = loadLocalAllowList(tempDir);
    expect(result.ignore).toHaveLength(0);
  });
});

describe('applyAllowList', () => {
  it('suppresses matching entries', () => {
    const matches = [
      makeMatch('GHSA-rp65-9cf3-cjxr', 'nth-check'),
      makeMatch('GHSA-xxxx-yyyy-zzzz', 'express'),
    ];

    const allowList = {
      ignore: [
        {
          id: 'GHSA-rp65-9cf3-cjxr',
          package: 'nth-check',
          reason: 'Dev only',
          expires: futureDate(),
        },
      ],
    };

    const { kept, ignored } = applyAllowList(matches, allowList);
    expect(kept).toHaveLength(1);
    expect(kept[0].advisory.id).toBe('GHSA-xxxx-yyyy-zzzz');
    expect(ignored).toHaveLength(1);
    expect(ignored[0].match.advisory.id).toBe('GHSA-rp65-9cf3-cjxr');
    expect(ignored[0].reason).toBe('Dev only');
    expect(ignored[0].source).toBe('local-allowlist');
  });

  it('matches by alias (GHSA in allow-list, CVE in advisory)', () => {
    const matches = [
      makeMatch('CVE-2024-1234', 'lodash', ['GHSA-abcd-efgh-ijkl']),
    ];

    const allowList = {
      ignore: [
        {
          id: 'GHSA-abcd-efgh-ijkl',
          package: 'lodash',
          reason: 'False positive',
          expires: futureDate(),
        },
      ],
    };

    const { kept, ignored } = applyAllowList(matches, allowList);
    expect(kept).toHaveLength(0);
    expect(ignored).toHaveLength(1);
  });

  it('does not suppress if package name differs', () => {
    const matches = [
      makeMatch('GHSA-rp65-9cf3-cjxr', 'nth-check'),
    ];

    const allowList = {
      ignore: [
        {
          id: 'GHSA-rp65-9cf3-cjxr',
          package: 'different-pkg',
          reason: 'Wrong package',
          expires: futureDate(),
        },
      ],
    };

    const { kept, ignored } = applyAllowList(matches, allowList);
    expect(kept).toHaveLength(1);
    expect(ignored).toHaveLength(0);
  });

  it('keeps all matches when allow-list is empty', () => {
    const matches = [
      makeMatch('GHSA-rp65-9cf3-cjxr', 'nth-check'),
    ];

    const { kept, ignored } = applyAllowList(matches, { ignore: [] });
    expect(kept).toHaveLength(1);
    expect(ignored).toHaveLength(0);
  });
});

describe('addToAllowList', () => {
  it('creates new .auditfixignore file', () => {
    addToAllowList(tempDir, {
      id: 'GHSA-rp65-9cf3-cjxr',
      package: 'nth-check',
      reason: 'Dev only',
      expires: futureDate(),
    });

    const content = readFileSync(join(tempDir, '.auditfixignore'), 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.ignore).toHaveLength(1);
    expect(parsed.ignore[0].id).toBe('GHSA-rp65-9cf3-cjxr');
  });

  it('appends to existing file', () => {
    const existing = {
      ignore: [
        {
          id: 'GHSA-rp65-9cf3-cjxr',
          package: 'nth-check',
          reason: 'Dev only',
          expires: futureDate(),
        },
      ],
    };
    writeFileSync(join(tempDir, '.auditfixignore'), JSON.stringify(existing));

    addToAllowList(tempDir, {
      id: 'CVE-2024-1234',
      package: 'express',
      reason: 'Not exploitable',
      expires: futureDate(),
    });

    const content = readFileSync(join(tempDir, '.auditfixignore'), 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.ignore).toHaveLength(2);
  });

  it('updates existing entry with same id+package', () => {
    addToAllowList(tempDir, {
      id: 'GHSA-rp65-9cf3-cjxr',
      package: 'nth-check',
      reason: 'Old reason',
      expires: futureDate(),
    });

    addToAllowList(tempDir, {
      id: 'GHSA-rp65-9cf3-cjxr',
      package: 'nth-check',
      reason: 'Updated reason',
      expires: futureDate(),
    });

    const content = readFileSync(join(tempDir, '.auditfixignore'), 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.ignore).toHaveLength(1);
    expect(parsed.ignore[0].reason).toBe('Updated reason');
  });
});
