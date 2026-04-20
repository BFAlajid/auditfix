/**
 * Webhook/Slack notification sender.
 * Posts audit results to a webhook URL (Slack-compatible or generic).
 */
import type { AuditReport } from '../../types/report.js';
import * as logger from '../../utils/logger.js';

export type WebhookResult = {
  success: boolean;
  statusCode?: number;
  error?: string;
};

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
  if (!isValidWebhookUrl(webhookUrl)) {
    return { success: false, error: 'Webhook URL rejected: internal/private network addresses are not allowed' };
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
