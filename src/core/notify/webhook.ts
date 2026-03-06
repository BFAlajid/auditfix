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
 * Send audit results to a webhook URL.
 * Supports Slack incoming webhooks (detects hooks.slack.com) and generic POST endpoints.
 */
export async function sendWebhook(
  webhookUrl: string,
  report: AuditReport,
  projectName?: string,
): Promise<WebhookResult> {
  const isSlack = webhookUrl.includes('hooks.slack.com') || webhookUrl.includes('hooks.slack-gov.com');
  const body = isSlack ? buildSlackPayload(report, projectName) : buildGenericPayload(report, projectName);

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
