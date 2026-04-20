/**
 * Webhook/Slack notification sender.
 * Posts audit results to a webhook URL (Slack-compatible or generic).
 */
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import type { AuditReport } from '../../types/report.js';
import * as logger from '../../utils/logger.js';

export type WebhookResult = {
  success: boolean;
  statusCode?: number;
  error?: string;
};

export type WebhookValidationResult = {
  valid: boolean;
  reason?: string;
};

const ALLOWED_PORTS = new Set([80, 443]);
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/**
 * Classify an IP string (IPv4 or IPv6) as private/reserved.
 * Covers loopback, RFC1918, link-local, CGNAT, IPv6 ULA/link-local,
 * unspecified, and IPv4-mapped IPv6 addresses.
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  // Strip zone-id from IPv6 link-local (e.g., fe80::1%eth0 -> fe80::1)
  const bare = ip.includes('%') ? ip.slice(0, ip.indexOf('%')) : ip;
  const family = net.isIP(bare);
  if (family === 4) return isPrivateIPv4(bare);
  if (family === 6) return isPrivateIPv6(bare);
  // Not a valid IP — treat as unsafe (defense-in-depth).
  return true;
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts as [number, number, number, number];
  // 0.0.0.0/8 — "this network" / unspecified
  if (a === 0) return true;
  // 10.0.0.0/8 — RFC1918
  if (a === 10) return true;
  // 127.0.0.0/8 — loopback
  if (a === 127) return true;
  // 169.254.0.0/16 — link-local
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 — RFC1918 (172.16.0.0 – 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 — RFC1918
  if (a === 192 && b === 168) return true;
  // 100.64.0.0/10 — CGNAT (100.64.0.0 – 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224+ multicast/reserved
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return true;
  if (a === 203 && b === 0) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  // Normalize to lowercase hex groups. Rely on net.isIP having already validated.
  const lower = ip.toLowerCase();

  // Unspecified ::  and loopback ::1
  if (lower === '::' || lower === '::1' || lower === '0:0:0:0:0:0:0:0' || lower === '0:0:0:0:0:0:0:1') return true;

  // IPv4-mapped IPv6: ::ffff:a.b.c.d or ::ffff:X:Y  → classify underlying IPv4.
  // Common textual forms: "::ffff:127.0.0.1", "::ffff:7f00:1"
  const mapped = /^::ffff:([0-9a-f:.]+)$/i.exec(ip);
  if (mapped) {
    const inner = mapped[1];
    if (net.isIPv4(inner)) return isPrivateIPv4(inner);
    // Hex form ::ffff:X:Y — convert 2 hex groups to IPv4 octets.
    const hexParts = inner.split(':');
    if (hexParts.length === 2 && /^[0-9a-f]{1,4}$/i.test(hexParts[0]) && /^[0-9a-f]{1,4}$/i.test(hexParts[1])) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      const a = (hi >> 8) & 0xff;
      const b = hi & 0xff;
      const c = (lo >> 8) & 0xff;
      const d = lo & 0xff;
      return isPrivateIPv4(`${a}.${b}.${c}.${d}`);
    }
    return true;
  }

  // IPv4-compatible IPv6: ::a.b.c.d (legacy, deprecated) — treat underlying IPv4.
  const compat = /^::([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/.exec(lower);
  if (compat && net.isIPv4(compat[1])) return isPrivateIPv4(compat[1]);

  // Expand to full 8 groups for prefix checks.
  const groups = expandIPv6(lower);
  if (!groups) return true;
  const first = groups[0];

  // fc00::/7 — Unique Local Addresses (fc00 – fdff)
  if ((first & 0xfe00) === 0xfc00) return true;
  // fe80::/10 — link-local (fe80 – febf)
  if ((first & 0xffc0) === 0xfe80) return true;
  // ff00::/8 — multicast
  if ((first & 0xff00) === 0xff00) return true;
  // 2001:db8::/32 — documentation
  if (first === 0x2001 && groups[1] === 0x0db8) return true;
  // ::/128 already handled above; block any remaining all-zeros with trailing bits.
  if (groups.every((g) => g === 0)) return true;

  return false;
}

function expandIPv6(ip: string): number[] | null {
  // Handle :: shorthand
  let head: string[];
  let tail: string[];
  if (ip.includes('::')) {
    const parts = ip.split('::');
    if (parts.length !== 2) return null;
    head = parts[0] ? parts[0].split(':') : [];
    tail = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    const fill = new Array(missing).fill('0');
    const all = [...head, ...fill, ...tail];
    return all.map((g) => parseInt(g || '0', 16));
  }
  const groups = ip.split(':');
  if (groups.length !== 8) return null;
  return groups.map((g) => parseInt(g || '0', 16));
}

/**
 * Validate a webhook URL against SSRF attacks.
 * Parses the URL, checks the scheme and port, then resolves the hostname via DNS
 * and rejects if any resolved address is private/reserved. Done at fetch-time
 * to mitigate DNS rebinding.
 *
 * Returns a reason string when invalid so callers/logs can explain the rejection.
 */
export async function isValidWebhookUrl(url: string): Promise<WebhookValidationResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, reason: 'Invalid URL' };
  }

  // Scheme: only http(s)
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return { valid: false, reason: `Protocol ${parsed.protocol} not allowed` };
  }

  // Port: explicit port must be 80 or 443. Empty string means default port for scheme.
  if (parsed.port !== '') {
    const portNum = Number(parsed.port);
    if (!ALLOWED_PORTS.has(portNum)) {
      return { valid: false, reason: `Port ${parsed.port} not allowed` };
    }
  }

  // Hostname: strip IPv6 brackets if present.
  const hostname = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;

  if (!hostname) {
    return { valid: false, reason: 'Missing hostname' };
  }

  // If the hostname is a literal IP, check it directly (no DNS).
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      return { valid: false, reason: `Resolved address ${hostname} is in a private/reserved range` };
    }
    return { valid: true };
  }

  // Cheap textual reject: localhost alias (case-insensitive).
  if (hostname.toLowerCase() === 'localhost') {
    return { valid: false, reason: 'Hostname localhost is not allowed' };
  }

  // DNS resolution — reject if ANY resolved address is private.
  try {
    const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    if (addresses.length === 0) {
      return { valid: false, reason: `DNS resolution returned no addresses for ${hostname}` };
    }
    for (const addr of addresses) {
      if (isPrivateIp(addr.address)) {
        return { valid: false, reason: `Resolved address ${addr.address} is in a private/reserved range` };
      }
    }
    return { valid: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { valid: false, reason: `DNS resolution failed: ${msg}` };
  }
}

/**
 * Validate that a webhook URL is safe (no SSRF to internal networks).
 */
export function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    const hostname = parsed.hostname.toLowerCase();
    // Block localhost, loopback, link-local, and metadata endpoints
    if (['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'].includes(hostname)) return false;
    if (hostname.startsWith('169.254.')) return false; // AWS/cloud metadata
    if (hostname.startsWith('10.')) return false;
    if (hostname.startsWith('172.') && parseInt(hostname.split('.')[1]) >= 16 && parseInt(hostname.split('.')[1]) <= 31) return false;
    if (hostname.startsWith('192.168.')) return false;
    if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Send audit results to a webhook URL.
 * Supports Slack incoming webhooks (detects hooks.slack.com) and generic POST endpoints.
 */
export async function sendWebhook(
  webhookUrl: string,
  report: AuditReport,
  projectName?: string,
): Promise<WebhookResult> {
  // SSRF guard — must run before fetch.
  const validation = await isValidWebhookUrl(webhookUrl);
  if (!validation.valid) {
    const reason = validation.reason ?? 'Invalid webhook URL';
    logger.warn(`Webhook URL rejected: ${reason}`);
    return { success: false, error: `Webhook URL rejected: ${reason}` };
  }

  const platform = detectPlatform(webhookUrl);
  const body = platform === 'slack' ? buildSlackPayload(report, projectName)
    : platform === 'teams' ? buildTeamsPayload(report, projectName)
    : platform === 'discord' ? buildDiscordPayload(report, projectName)
    : buildGenericPayload(report, projectName);

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      return { success: false, statusCode: response.status, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
    }

    logger.info(`Webhook notification sent successfully (${response.status})`);
    return { success: true, statusCode: response.status };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

export function detectPlatform(url: string): 'slack' | 'teams' | 'discord' | 'generic' {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (hostname === 'hooks.slack.com' || hostname === 'hooks.slack-gov.com') return 'slack';
    if (hostname.endsWith('.webhook.office.com') || hostname === 'webhook.office.com' ||
        hostname.endsWith('.outlook.office.com') || hostname === 'outlook.office.com') return 'teams';
    if (hostname === 'discord.com' || hostname === 'discordapp.com') return 'discord';
  } catch {
    // Invalid URL — fall through to generic
  }
  return 'generic';
}

function severityColor(report: AuditReport): string {
  const crit = report.vulnerabilities.some(v => v.risk.label === 'critical');
  const high = report.vulnerabilities.some(v => v.risk.label === 'high');
  if (crit) return 'FF0000';
  if (high) return 'FF8C00';
  if (report.vulnerabilities.length > 0) return 'FFD700';
  return '00CC00';
}

function vulnSummary(report: AuditReport) {
  const total = report.vulnerabilities.length;
  const prod = report.vulnerabilities.filter(v => v.match.isProduction).length;
  const crit = report.vulnerabilities.filter(v => v.risk.label === 'critical').length;
  const high = report.vulnerabilities.filter(v => v.risk.label === 'high').length;
  const med = report.vulnerabilities.filter(v => v.risk.label === 'medium').length;
  const low = report.vulnerabilities.filter(v => v.risk.label === 'low').length;
  return { total, prod, crit, high, med, low };
}

function buildTeamsPayload(report: AuditReport, projectName?: string) {
  const s = vulnSummary(report);
  const color = severityColor(report);
  const title = s.total === 0
    ? `No vulnerabilities found${projectName ? ` in ${projectName}` : ''}`
    : `${s.total} vulnerabilities found${projectName ? ` in ${projectName}` : ''}`;

  const facts = [
    { name: 'Packages', value: String(report.metadata.totalPackages) },
    { name: 'Critical', value: String(s.crit) },
    { name: 'High', value: String(s.high) },
    { name: 'Medium', value: String(s.med) },
    { name: 'Low', value: String(s.low) },
    { name: 'Production', value: String(s.prod) },
    { name: 'Confidence', value: report.metadata.confidence },
  ];

  const payload: Record<string, unknown> = {
    '@type': 'MessageCard',
    '@context': 'https://schema.org/extensions',
    themeColor: color,
    summary: title,
    sections: [{
      activityTitle: `auditfix: ${title}`,
      facts,
      markdown: true,
    }],
  };

  const ghRepo = process.env.GITHUB_REPOSITORY;
  if (ghRepo) {
    payload.potentialAction = [{
      '@type': 'OpenUri',
      name: 'View on GitHub',
      targets: [{ os: 'default', uri: `https://github.com/${ghRepo}/security` }],
    }];
  }

  return payload;
}

function buildDiscordPayload(report: AuditReport, projectName?: string) {
  const s = vulnSummary(report);
  const color = parseInt(severityColor(report), 16);
  const title = s.total === 0
    ? `No vulnerabilities found${projectName ? ` in ${projectName}` : ''}`
    : `${s.total} vulnerabilities found${projectName ? ` in ${projectName}` : ''}`;

  const description = [
    `**Packages scanned:** ${report.metadata.totalPackages}`,
    `**Critical:** ${s.crit} | **High:** ${s.high} | **Medium:** ${s.med} | **Low:** ${s.low}`,
    `**Production:** ${s.prod} | **Confidence:** ${report.metadata.confidence}`,
  ].join('\n');

  const fields = report.vulnerabilities.slice(0, 5).map(v => ({
    name: `${v.risk.label.toUpperCase()}: ${v.match.package}@${v.match.installedVersion}`,
    value: `${v.match.advisory.id} (score: ${v.risk.score})${v.risk.factors.fixVersion ? ` → fix: ${v.risk.factors.fixVersion}` : ''}`,
    inline: false,
  }));

  return {
    embeds: [{
      title: `auditfix: ${title}`,
      description,
      color,
      fields,
      footer: { text: `auditfix | ${report.metadata.advisorySource}` },
      timestamp: new Date().toISOString(),
    }],
  };
}

function buildSlackPayload(report: AuditReport, projectName?: string) {
  const vulnCount = report.vulnerabilities.length;
  const prodCount = report.vulnerabilities.filter(v => v.match.isProduction).length;
  const critCount = report.vulnerabilities.filter(v => v.risk.label === 'critical').length;
  const highCount = report.vulnerabilities.filter(v => v.risk.label === 'high').length;

  const emoji = critCount > 0 ? ':rotating_light:' : highCount > 0 ? ':warning:' : vulnCount > 0 ? ':information_source:' : ':white_check_mark:';
  const project = projectName ? ` for *${projectName}*` : '';

  const blocks: unknown[] = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${vulnCount === 0 ? 'No vulnerabilities' : `${vulnCount} vulnerabilities`} found${projectName ? ` in ${projectName}` : ''}` },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: [
          `${emoji} *auditfix scan results*${project}`,
          `Packages scanned: ${report.metadata.totalPackages}`,
          `Vulnerabilities: ${vulnCount} (${prodCount} production)`,
          critCount > 0 ? `:rotating_light: Critical: ${critCount}` : null,
          highCount > 0 ? `:warning: High: ${highCount}` : null,
          `Confidence: ${report.metadata.confidence}`,
          `Source: ${report.metadata.advisorySource}`,
        ].filter(Boolean).join('\n'),
      },
    },
  ];

  // Add top 5 vulns as context
  if (vulnCount > 0) {
    const top5 = report.vulnerabilities.slice(0, 5);
    const vulnLines = top5.map(v =>
      `• \`${v.match.package}@${v.match.installedVersion}\` — ${v.risk.label.toUpperCase()} (score: ${v.risk.score})${v.risk.factors.fixVersion ? ` → fix: ${v.risk.factors.fixVersion}` : ''}`
    );
    if (vulnCount > 5) vulnLines.push(`_...and ${vulnCount - 5} more_`);

    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: vulnLines.join('\n') },
    });
  }

  return { blocks };
}

function buildGenericPayload(report: AuditReport, projectName?: string) {
  return {
    event: 'auditfix.scan',
    project: projectName ?? null,
    timestamp: new Date().toISOString(),
    summary: {
      totalPackages: report.metadata.totalPackages,
      vulnerabilities: report.vulnerabilities.length,
      production: report.vulnerabilities.filter(v => v.match.isProduction).length,
      critical: report.vulnerabilities.filter(v => v.risk.label === 'critical').length,
      high: report.vulnerabilities.filter(v => v.risk.label === 'high').length,
      medium: report.vulnerabilities.filter(v => v.risk.label === 'medium').length,
      low: report.vulnerabilities.filter(v => v.risk.label === 'low').length,
      ignored: report.ignored.length,
      confidence: report.metadata.confidence,
      source: report.metadata.advisorySource,
    },
    vulnerabilities: report.vulnerabilities.map(v => ({
      id: v.match.advisory.id,
      package: v.match.package,
      version: v.match.installedVersion,
      severity: v.risk.label,
      score: v.risk.score,
      production: v.match.isProduction,
      fixVersion: v.risk.factors.fixVersion,
    })),
  };
}
