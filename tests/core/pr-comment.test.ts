import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { postPrComment, escapeMarkdown } from '../../src/core/notify/pr-comment.js';
import type { AuditReport, ScoredVulnerability } from '../../src/types/report.js';

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

function makeReport(vulnCount: number = 0): AuditReport {
  return {
    vulnerabilities: Array.from({ length: vulnCount }, (_, i) => ({
      match: {
        advisory: { id: `GHSA-test-${i}`, aliases: [], summary: `Vuln ${i}`, details: '', severity: [{ type: 'CVSS_V3' as const, score: '7.5' }], affectedRange: '<2.0.0', fixVersion: '2.0.0', publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' as const },
        package: `pkg-${i}`,
        installedVersion: '1.0.0',
        dependencyPath: [`pkg-${i}`],
        isProduction: i % 2 === 0,
      },
      risk: {
        score: 70,
        label: (i === 0 ? 'critical' : 'high') as 'critical' | 'high',
        factors: { cvssScore: 7.5, cvssVector: '', productionReachable: true, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: true, fixVersion: '2.0.0', depth: 1, directDependency: true },
      },
    })),
    metadata: {
      totalPackages: 50,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API',
      advisoryCount: 100,
      confidence: 'HIGH',
      scanDurationMs: 500,
      lockfileType: 'npm-v3',
    },
    ignored: [],
  };
}

function makeVuln(overrides: {
  pkg?: string;
  version?: string;
  fixVersion?: string | null;
  label?: 'critical' | 'high' | 'medium' | 'low';
}): ScoredVulnerability {
  return {
    match: {
      advisory: {
        id: 'GHSA-xxxx-xxxx-xxxx',
        aliases: [],
        summary: 'Summary',
        details: '',
        severity: [{ type: 'CVSS_V3', score: '7.5' }],
        affectedRange: '<2.0.0',
        fixVersion: overrides.fixVersion ?? '2.0.0',
        publishedAt: '',
        modifiedAt: '',
        references: [],
        source: 'osv-api',
      },
      package: overrides.pkg ?? 'some-pkg',
      installedVersion: overrides.version ?? '1.0.0',
      dependencyPath: [overrides.pkg ?? 'some-pkg'],
      isProduction: true,
    },
    risk: {
      score: 70,
      label: overrides.label ?? 'high',
      factors: {
        cvssScore: 7.5,
        cvssVector: '',
        productionReachable: true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: true,
        fixVersion: overrides.fixVersion === undefined ? '2.0.0' : overrides.fixVersion,
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReportWithVulns(vulns: ScoredVulnerability[]): AuditReport {
  return {
    vulnerabilities: vulns,
    metadata: {
      totalPackages: 50,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API',
      advisoryCount: 100,
      confidence: 'HIGH',
      scanDurationMs: 500,
      lockfileType: 'npm-v3',
    },
    ignored: [],
  };
}

const COMMENT_MARKER = '<!-- auditfix-scan -->';

async function capturePostedBody(report: AuditReport): Promise<string> {
  let capturedBody = '';
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
    const method = ((init as RequestInit)?.method ?? 'GET').toUpperCase();
    if (method === 'GET') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    capturedBody = (init as RequestInit).body as string;
    return new Response(
      JSON.stringify({ id: 1, html_url: 'https://github.com/owner/repo/pull/42#issuecomment-1' }),
      { status: 201 },
    );
  });

  const result = await postPrComment(report);
  expect(result.success).toBe(true);
  const parsed = JSON.parse(capturedBody);
  return parsed.body as string;
}

describe('PR comment bot', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('GITHUB_TOKEN', '');
    vi.stubEnv('GITHUB_REPOSITORY', '');
    vi.stubEnv('GITHUB_REF', '');
    vi.stubEnv('GITHUB_EVENT_PATH', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('returns error when no GitHub token', async () => {
    const result = await postPrComment(makeReport(1));

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error!.toLowerCase()).toContain('token');
  });

  it('returns error when no PR number detected', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    // GITHUB_REF is empty — no PR number can be extracted

    const result = await postPrComment(makeReport(1));

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error!.toLowerCase()).toContain('pr number');
  });

  it('posts comment to GitHub API', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    vi.stubEnv('GITHUB_REF', 'refs/pull/42/merge');

    let capturedUrl = '';
    let capturedBody = '';
    let capturedHeaders: Record<string, string> = {};

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      // First call: GET existing comments — return empty
      if ((init as RequestInit)?.method === 'GET' || !init?.method) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      // Second call: POST new comment
      capturedUrl = url;
      capturedBody = (init as RequestInit).body as string;
      capturedHeaders = Object.fromEntries(
        Object.entries((init as RequestInit).headers as Record<string, string>),
      );
      return new Response(JSON.stringify({ id: 1, html_url: 'https://github.com/owner/repo/pull/42#issuecomment-1' }), { status: 201 });
    });

    const result = await postPrComment(makeReport(2));

    expect(result.success).toBe(true);
    expect(capturedUrl).toContain('/repos/owner/repo/issues/42/comments');
    expect(capturedBody).toContain(COMMENT_MARKER);
    expect(capturedHeaders['Authorization']).toContain('ghp_test123');
  });

  it('updates existing comment when marker found', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    vi.stubEnv('GITHUB_REF', 'refs/pull/42/merge');

    let patchUrl = '';
    let patchMethod = '';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      const method = ((init as RequestInit)?.method ?? 'GET').toUpperCase();

      if (method === 'GET') {
        // Return an existing comment that contains the marker
        return new Response(JSON.stringify([
          { id: 999, body: `Old report\n${COMMENT_MARKER}\nstale data` },
        ]), { status: 200 });
      }

      // Capture the update call
      patchUrl = url;
      patchMethod = method;
      return new Response(JSON.stringify({ id: 999, html_url: 'https://github.com/owner/repo/pull/42#issuecomment-999' }), { status: 200 });
    });

    const result = await postPrComment(makeReport(1));

    expect(result.success).toBe(true);
    expect(patchMethod).toBe('PATCH');
    expect(patchUrl).toContain('/repos/owner/repo/issues/comments/999');
  });

  it('creates new comment when no existing marker', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    vi.stubEnv('GITHUB_REF', 'refs/pull/42/merge');

    let postUrl = '';
    let postMethod = '';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      const method = ((init as RequestInit)?.method ?? 'GET').toUpperCase();

      if (method === 'GET') {
        // No existing comments with the marker
        return new Response(JSON.stringify([]), { status: 200 });
      }

      postUrl = url;
      postMethod = method;
      return new Response(JSON.stringify({ id: 2, html_url: 'https://github.com/owner/repo/pull/42#issuecomment-2' }), { status: 201 });
    });

    const result = await postPrComment(makeReport(1));

    expect(result.success).toBe(true);
    expect(postMethod).toBe('POST');
    expect(postUrl).toContain('/repos/owner/repo/issues/42/comments');
  });

  it('formats markdown with vulnerability summary', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    vi.stubEnv('GITHUB_REF', 'refs/pull/42/merge');

    let capturedBody = '';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      const method = ((init as RequestInit)?.method ?? 'GET').toUpperCase();

      if (method === 'GET') {
        return new Response(JSON.stringify([]), { status: 200 });
      }

      capturedBody = (init as RequestInit).body as string;
      return new Response(JSON.stringify({ id: 3, html_url: 'https://github.com/owner/repo/pull/42#issuecomment-3' }), { status: 201 });
    });

    const report = makeReport(3);
    const result = await postPrComment(report);

    expect(result.success).toBe(true);

    const parsed = JSON.parse(capturedBody);
    const commentBody: string = parsed.body;

    // Should contain the marker
    expect(commentBody).toContain(COMMENT_MARKER);

    // Should reference severity labels from the report
    expect(commentBody.toLowerCase()).toMatch(/critical|high/);

    // Should contain package names
    expect(commentBody).toContain('pkg-0');
    expect(commentBody).toContain('pkg-1');
    expect(commentBody).toContain('pkg-2');
  });
});

describe('escapeMarkdown', () => {
  it('escapes pipe characters (prevents table break)', () => {
    expect(escapeMarkdown('a|b')).toBe('a\\|b');
  });

  it('escapes backticks (prevents code-span break)', () => {
    expect(escapeMarkdown('`hostile`')).toBe('\\`hostile\\`');
  });

  it('escapes backslash before any other escape (no double-escape artifacts)', () => {
    expect(escapeMarkdown('a\\b')).toBe('a\\\\b');
  });

  it('escapes brackets and parentheses (prevents link injection)', () => {
    expect(escapeMarkdown('](javascript:alert(1))')).toBe('\\]\\(javascript:alert\\(1\\)\\)');
  });

  it('neutralizes @mentions with zero-width space', () => {
    const out = escapeMarkdown('@octocat');
    expect(out).toBe('@\u200Boctocat');
    expect(out).not.toMatch(/^@octocat$/);
  });

  it('replaces newlines with spaces (prevents heading / list injection)', () => {
    expect(escapeMarkdown('line1\nline2')).toBe('line1 line2');
    expect(escapeMarkdown('a\r\nb')).toBe('a  b');
  });

  it('escapes < and > to HTML entities (blocks HTML comment / tag injection)', () => {
    expect(escapeMarkdown('<!-- -->')).toBe('&lt;!-- --&gt;');
    expect(escapeMarkdown('<script>')).toBe('&lt;script&gt;');
    // Critical: the output must not contain literal `<` or `>` that GitHub would render.
    expect(escapeMarkdown('<!-- auditfix-scan -->')).not.toMatch(/<[^/]|[^/]>/);
  });

  it('passes through benign ASCII unchanged', () => {
    expect(escapeMarkdown('lodash')).toBe('lodash');
    expect(escapeMarkdown('1.2.3')).toBe('1.2.3');
    expect(escapeMarkdown('@scope/pkg')).toBe('@\u200Bscope/pkg'); // scoped pkg gets zwsp on @
  });

  it('handles null/undefined-like inputs safely', () => {
    expect(escapeMarkdown('')).toBe('');
    // @ts-expect-error — intentionally exercising runtime guard
    expect(escapeMarkdown(null)).toBe('');
    // @ts-expect-error — intentionally exercising runtime guard
    expect(escapeMarkdown(undefined)).toBe('');
  });
});

describe('PR comment markdown injection defenses', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('GITHUB_TOKEN', 'ghp_test123');
    vi.stubEnv('GITHUB_REPOSITORY', 'owner/repo');
    vi.stubEnv('GITHUB_REF', 'refs/pull/42/merge');
    vi.stubEnv('GITHUB_EVENT_PATH', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('escapes pipe in package name so table row stays intact', async () => {
    const report = makeReportWithVulns([
      makeVuln({ pkg: 'evil|injected', version: '1.0.0', fixVersion: '2.0.0' }),
    ]);
    const body = await capturePostedBody(report);

    // The escaped form must appear; raw unescaped pipe must not break the row.
    expect(body).toContain('evil\\|injected');
    // Sanity: the "Top vulnerabilities" table header plus data row should each have
    // the expected column count (5 separators for 5 columns + leading/trailing).
    // Find the row for our package and assert it has exactly the right pipe count.
    const row = body
      .split('\n')
      .find((line) => line.includes('evil\\|injected'));
    expect(row).toBeDefined();
    // 5-column row: leading `|`, 5 column separators → 6 literal pipes.
    const pipeCount = (row!.match(/(?<!\\)\|/g) ?? []).length;
    expect(pipeCount).toBe(6);
  });

  it('neutralizes @mentions in package name (no autolink)', async () => {
    const report = makeReportWithVulns([
      makeVuln({ pkg: '@octocat', version: '1.0.0' }),
    ]);
    const body = await capturePostedBody(report);

    // Must not contain a bare "@octocat" that GitHub would turn into a mention.
    expect(body).not.toMatch(/[^\u200B]@octocat\b/);
    // Should contain the zero-width-space escaped form.
    expect(body).toContain('@\u200Boctocat');
  });

  it('escapes link-injection payload in package name', async () => {
    const report = makeReportWithVulns([
      makeVuln({ pkg: 'pkg](javascript:alert(1))', version: '1.0.0' }),
    ]);
    const body = await capturePostedBody(report);

    // Raw link syntax must not appear.
    expect(body).not.toContain('](javascript:alert(1))');
    // Escaped form should appear (the `(` / `)` / `]` are backslash-escaped).
    expect(body).toContain('\\]\\(javascript:alert\\(1\\)\\)');
  });

  it('escapes newlines in version so no heading injection', async () => {
    const report = makeReportWithVulns([
      makeVuln({ pkg: 'ok-pkg', version: '1.0.0\n## Pwned', fixVersion: '2.0.0' }),
    ]);
    const body = await capturePostedBody(report);

    // Must not contain an injected heading on its own line.
    expect(body).not.toMatch(/^## Pwned/m);
    // Newline must be collapsed to a space.
    expect(body).toContain('1.0.0 ## Pwned');
  });

  it('escapes injection in fix version', async () => {
    const report = makeReportWithVulns([
      makeVuln({ pkg: 'ok-pkg', version: '1.0.0', fixVersion: '2.0.0|broken' }),
    ]);
    const body = await capturePostedBody(report);

    expect(body).toContain('2.0.0\\|broken');
  });

  it('escapes injection attempts in advisorySource footer', async () => {
    const base = makeReport(1);
    base.metadata.advisorySource = 'OSV|injection\n## Heading';
    const body = await capturePostedBody(base);

    expect(body).toContain('OSV\\|injection');
    expect(body).not.toMatch(/^## Heading/m);
  });
});
