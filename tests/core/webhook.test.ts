import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sendWebhook, detectPlatform, isValidWebhookUrl, isPrivateIp } from '../../src/core/notify/webhook.js';
import type { AuditReport } from '../../src/types/report.js';

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

// Mock node:dns/promises so we can control DNS resolution deterministically.
// The production code imports via `import * as dns from 'node:dns/promises'`.
const dnsLookupMock = vi.fn();
vi.mock('node:dns/promises', () => ({
  lookup: (...args: unknown[]) => dnsLookupMock(...args),
  default: { lookup: (...args: unknown[]) => dnsLookupMock(...args) },
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

// Mock dns.lookup to return a public address by default so sendWebhook happy-path tests
// don't hit the network. Individual SSRF tests override this.
function mockDnsPublic() {
  dnsLookupMock.mockImplementation(async (_host: string, opts?: unknown) => {
    const all = typeof opts === 'object' && opts !== null && 'all' in opts && (opts as { all: boolean }).all;
    if (all) return [{ address: '93.184.216.34', family: 4 }];
    return { address: '93.184.216.34', family: 4 };
  });
}

function mockDnsReturns(addresses: { address: string; family: 4 | 6 }[]) {
  dnsLookupMock.mockImplementation(async (_host: string, opts?: unknown) => {
    const all = typeof opts === 'object' && opts !== null && 'all' in opts && (opts as { all: boolean }).all;
    if (all) return addresses;
    return addresses[0];
  });
}

function mockDnsRejects(err: Error) {
  dnsLookupMock.mockRejectedValue(err);
}

describe('Webhook notifications', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    dnsLookupMock.mockReset();
  });

  it('sends generic payload to non-Slack URLs', async () => {
    mockDnsPublic();
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
    mockDnsPublic();
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
    mockDnsPublic();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      return new Response('Forbidden', { status: 403 });
    });

    const result = await sendWebhook('https://example.com/hook', makeReport());

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
  });

  it('handles network errors', async () => {
    mockDnsPublic();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('ECONNREFUSED');
    });

    const result = await sendWebhook('https://example.com/hook', makeReport());

    expect(result.success).toBe(false);
    expect(result.error).toContain('ECONNREFUSED');
  });

  it('sends Teams-formatted payload to webhook.office.com', async () => {
    mockDnsPublic();
    let capturedBody: unknown;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      capturedBody = JSON.parse((init as RequestInit).body as string);
      return new Response('ok', { status: 200 });
    });

    const result = await sendWebhook('https://webhook.office.com/webhookb2/xxx', makeReport(2), 'my-app');

    expect(result.success).toBe(true);
    const body = capturedBody as Record<string, unknown>;
    expect(body['@type']).toBe('MessageCard');
    expect(Array.isArray(body.sections)).toBe(true);
    expect((body.sections as unknown[]).length).toBeGreaterThan(0);
  });

  it('sends Discord-formatted payload to discord.com/api/webhooks', async () => {
    mockDnsPublic();
    let capturedBody: unknown;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      capturedBody = JSON.parse((init as RequestInit).body as string);
      return new Response('ok', { status: 200 });
    });

    const result = await sendWebhook('https://discord.com/api/webhooks/123/abc', makeReport(1));

    expect(result.success).toBe(true);
    const body = capturedBody as Record<string, unknown>;
    expect(Array.isArray(body.embeds)).toBe(true);
    expect((body.embeds as unknown[]).length).toBeGreaterThan(0);
  });

  it('detectPlatform identifies platforms correctly', () => {
    expect(detectPlatform('https://hooks.slack.com/services/T00/B00/xxx')).toBe('slack');
    expect(detectPlatform('https://hooks.slack-gov.com/services/T00/B00/xxx')).toBe('slack');
    expect(detectPlatform('https://webhook.office.com/webhookb2/xxx')).toBe('teams');
    expect(detectPlatform('https://outlook.office.com/webhook/xxx')).toBe('teams');
    expect(detectPlatform('https://discord.com/api/webhooks/123/abc')).toBe('discord');
    expect(detectPlatform('https://example.com/hook')).toBe('generic');
  });
});

describe('isPrivateIp', () => {
  it('classifies IPv4 loopback', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('127.255.255.254')).toBe(true);
  });

  it('classifies IPv4 RFC1918 ranges', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('10.255.255.255')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
    expect(isPrivateIp('172.15.0.1')).toBe(false); // not in range
    expect(isPrivateIp('172.32.0.1')).toBe(false); // not in range
    expect(isPrivateIp('192.168.0.1')).toBe(true);
    expect(isPrivateIp('192.168.255.255')).toBe(true);
  });

  it('classifies IPv4 link-local 169.254/16', () => {
    expect(isPrivateIp('169.254.169.254')).toBe(true); // AWS/GCP metadata
  });

  it('classifies IPv4 CGNAT 100.64/10', () => {
    expect(isPrivateIp('100.64.0.1')).toBe(true);
    expect(isPrivateIp('100.127.255.255')).toBe(true);
    expect(isPrivateIp('100.63.0.1')).toBe(false); // not in CGNAT
    expect(isPrivateIp('100.128.0.1')).toBe(false); // not in CGNAT
  });

  it('classifies IPv4 unspecified', () => {
    expect(isPrivateIp('0.0.0.0')).toBe(true);
    expect(isPrivateIp('0.1.2.3')).toBe(true);
  });

  it('allows public IPv4', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('93.184.216.34')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
  });

  it('classifies IPv6 loopback and unspecified', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('::')).toBe(true);
    expect(isPrivateIp('0:0:0:0:0:0:0:1')).toBe(true);
  });

  it('classifies IPv6 ULA fc00::/7', () => {
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fd12:3456:789a::1')).toBe(true);
    expect(isPrivateIp('fdff:ffff:ffff:ffff::1')).toBe(true);
  });

  it('classifies IPv6 link-local fe80::/10', () => {
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('fe80::1%eth0')).toBe(true); // with zone-id
    expect(isPrivateIp('febf::1')).toBe(true);
  });

  it('classifies IPv4-mapped IPv6 by underlying IPv4', () => {
    expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIp('::ffff:10.0.0.1')).toBe(true);
    expect(isPrivateIp('::ffff:192.168.1.1')).toBe(true);
    expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false);
  });

  it('allows public IPv6', () => {
    expect(isPrivateIp('2606:4700:4700::1111')).toBe(false); // Cloudflare
    expect(isPrivateIp('2001:4860:4860::8888')).toBe(false); // Google
  });

  it('rejects invalid input defensively', () => {
    expect(isPrivateIp('')).toBe(true);
    expect(isPrivateIp('not-an-ip')).toBe(true);
    expect(isPrivateIp('999.999.999.999')).toBe(true);
  });
});

describe('isValidWebhookUrl (SSRF guard)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    dnsLookupMock.mockReset();
  });

  it('rejects literal IPv4 RFC1918 addresses without DNS lookup', async () => {
    dnsLookupMock.mockReset();
    const r1 = await isValidWebhookUrl('http://10.0.0.1/hook');
    const r2 = await isValidWebhookUrl('http://172.16.0.1/hook');
    const r3 = await isValidWebhookUrl('http://192.168.1.1/hook');
    expect(r1.valid).toBe(false);
    expect(r2.valid).toBe(false);
    expect(r3.valid).toBe(false);
    expect(dnsLookupMock).not.toHaveBeenCalled();
  });

  it('rejects literal IPv6 private addresses', async () => {
    expect((await isValidWebhookUrl('http://[::1]/hook')).valid).toBe(false);
    expect((await isValidWebhookUrl('http://[fe80::1]/hook')).valid).toBe(false);
    expect((await isValidWebhookUrl('http://[fc00::1]/hook')).valid).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 addresses pointing to loopback', async () => {
    const r = await isValidWebhookUrl('http://[::ffff:127.0.0.1]/hook');
    expect(r.valid).toBe(false);
    expect(r.reason).toContain('private');
  });

  it('rejects CGNAT 100.64.0.0/10', async () => {
    const r = await isValidWebhookUrl('http://100.64.1.1/hook');
    expect(r.valid).toBe(false);
  });

  it('rejects AWS/GCP metadata service 169.254.169.254', async () => {
    const r = await isValidWebhookUrl('http://169.254.169.254/latest/meta-data/');
    expect(r.valid).toBe(false);
  });

  it('rejects localhost alias', async () => {
    const r1 = await isValidWebhookUrl('http://localhost/hook');
    const r2 = await isValidWebhookUrl('http://LOCALHOST/hook');
    expect(r1.valid).toBe(false);
    expect(r2.valid).toBe(false);
  });

  it('rejects non-HTTP schemes', async () => {
    expect((await isValidWebhookUrl('file:///etc/passwd')).valid).toBe(false);
    expect((await isValidWebhookUrl('ftp://example.com/')).valid).toBe(false);
    expect((await isValidWebhookUrl('gopher://example.com/')).valid).toBe(false);
  });

  it('rejects non-80/443 ports', async () => {
    mockDnsPublic();
    const r1 = await isValidWebhookUrl('http://example.com:22/hook');
    const r2 = await isValidWebhookUrl('http://example.com:6379/hook');
    const r3 = await isValidWebhookUrl('http://example.com:8080/hook');
    expect(r1.valid).toBe(false);
    expect(r1.reason).toContain('Port');
    expect(r2.valid).toBe(false);
    expect(r3.valid).toBe(false);
  });

  it('allows default ports (implicit 80/443)', async () => {
    mockDnsPublic();
    const r1 = await isValidWebhookUrl('http://example.com/hook');
    const r2 = await isValidWebhookUrl('https://example.com/hook');
    expect(r1.valid).toBe(true);
    expect(r2.valid).toBe(true);
  });

  it('allows explicit :80 and :443', async () => {
    mockDnsPublic();
    expect((await isValidWebhookUrl('http://example.com:80/hook')).valid).toBe(true);
    expect((await isValidWebhookUrl('https://example.com:443/hook')).valid).toBe(true);
  });

  it('rejects DNS rebinding: public name resolving to private IP', async () => {
    mockDnsReturns([{ address: '10.0.0.1', family: 4 }]);
    const r = await isValidWebhookUrl('http://evil.attacker.example/hook');
    expect(r.valid).toBe(false);
    expect(r.reason).toContain('10.0.0.1');
  });

  it('rejects when ANY resolved address is private (mixed A records)', async () => {
    mockDnsReturns([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ]);
    const r = await isValidWebhookUrl('http://multi.example.com/hook');
    expect(r.valid).toBe(false);
  });

  it('accepts public IPv4', async () => {
    mockDnsReturns([{ address: '93.184.216.34', family: 4 }]);
    const r = await isValidWebhookUrl('https://example.com/hook');
    expect(r.valid).toBe(true);
  });

  it('accepts public IPv6', async () => {
    mockDnsReturns([{ address: '2606:4700:4700::1111', family: 6 }]);
    const r = await isValidWebhookUrl('https://cloudflare-dns.example/hook');
    expect(r.valid).toBe(true);
  });

  it('rejects invalid URLs', async () => {
    expect((await isValidWebhookUrl('not a url')).valid).toBe(false);
    expect((await isValidWebhookUrl('')).valid).toBe(false);
  });

  it('rejects when DNS lookup fails', async () => {
    mockDnsRejects(new Error('ENOTFOUND'));
    const r = await isValidWebhookUrl('https://does-not-exist.example/hook');
    expect(r.valid).toBe(false);
    expect(r.reason).toContain('DNS');
  });

  it('bypasses textual tricks: 10.evil.com resolving public is allowed (text match removed), 10.0.0.1.nip.io resolving to 10.0.0.1 is rejected', async () => {
    // 10.evil.com → resolves to public IP → allowed (proves we are not doing dumb text matching)
    mockDnsReturns([{ address: '93.184.216.34', family: 4 }]);
    const r1 = await isValidWebhookUrl('https://10.evil.com/hook');
    expect(r1.valid).toBe(true);

    // 10.0.0.1.nip.io → resolves to 10.0.0.1 → rejected post-resolution
    vi.restoreAllMocks();
    mockDnsReturns([{ address: '10.0.0.1', family: 4 }]);
    const r2 = await isValidWebhookUrl('https://10.0.0.1.nip.io/hook');
    expect(r2.valid).toBe(false);
  });
});

describe('sendWebhook SSRF integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    dnsLookupMock.mockReset();
  });

  it('refuses to fetch when URL resolves to private IP', async () => {
    mockDnsReturns([{ address: '10.0.0.1', family: 4 }]);
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const result = await sendWebhook('https://rebind.example/hook', makeReport(1));

    expect(result.success).toBe(false);
    expect(result.error).toContain('rejected');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refuses to fetch loopback literal', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const result = await sendWebhook('http://127.0.0.1:80/hook', makeReport(1));
    expect(result.success).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refuses disallowed port even with public host', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const result = await sendWebhook('http://example.com:22/hook', makeReport(1));
    expect(result.success).toBe(false);
    expect(result.error).toContain('Port');
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
