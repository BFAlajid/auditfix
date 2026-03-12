import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { postPrComment } from '../../src/core/notify/pr-comment.js';
import type { AuditReport } from '../../src/types/report.js';

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

const COMMENT_MARKER = '<!-- auditfix-scan -->';

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
