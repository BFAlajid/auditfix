import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sendWebhook } from '../../src/core/notify/webhook.js';
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
        isProduction: true,
      },
      risk: { score: 70, label: 'high' as const, factors: { cvssScore: 7.5, cvssVector: '', productionReachable: true, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: true, fixVersion: '2.0.0', depth: 1, directDependency: true } },
    })),
    metadata: {
      totalPackages: 50,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API',
      advisoryCount: 100,
      confidence: 'HIGH',
      scanDurationMs: 500,
    },
    ignored: [],
  };
}

describe('Webhook notifications', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('sends generic payload to non-Slack URLs', async () => {
    let capturedBody: unknown;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      capturedBody = JSON.parse((init as RequestInit).body as string);
      return new Response('ok', { status: 200 });
    });

    const result = await sendWebhook('https://example.com/hook', makeReport(2), 'my-app');

    expect(result.success).toBe(true);
    expect((capturedBody as Record<string, unknown>).event).toBe('auditfix.scan');
    expect((capturedBody as Record<string, unknown>).project).toBe('my-app');
  });

  it('sends Slack-formatted payload to hooks.slack.com', async () => {
    let capturedBody: unknown;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      capturedBody = JSON.parse((init as RequestInit).body as string);
      return new Response('ok', { status: 200 });
    });

    const result = await sendWebhook('https://hooks.slack.com/services/T00/B00/xxx', makeReport(1));

    expect(result.success).toBe(true);
    expect((capturedBody as Record<string, unknown>)).toHaveProperty('blocks');
  });

  it('handles HTTP errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      return new Response('Forbidden', { status: 403 });
    });

    const result = await sendWebhook('https://example.com/hook', makeReport());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
  });

  it('handles network errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('ECONNREFUSED');
    });

    const result = await sendWebhook('https://example.com/hook', makeReport());

    expect(result.success).toBe(false);
    expect(result.error).toContain('ECONNREFUSED');
  });
});
