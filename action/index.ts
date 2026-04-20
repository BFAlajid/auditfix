/**
 * auditfix GitHub Action entry point.
 * Uses native GitHub Actions protocol (GITHUB_OUTPUT, ::warning::, etc.)
 * No @actions/core dependency required.
 */
import { appendFileSync, writeFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { analyze } from '../src/core/analyzer.js';
import { renderSarifReport } from '../src/cli/output/sarif.js';
import { renderJsonReport } from '../src/cli/output/json.js';
import { postPrComment } from '../src/core/notify/pr-comment.js';
import { sendWebhook } from '../src/core/notify/webhook.js';
import { getExitCodeForStrategy } from '../src/cli/output/terminal.js';
import type { AuditReport } from '../src/types/report.js';

// ── GitHub Actions protocol helpers ────────────────────────────────────────

function getInput(name: string): string {
  return process.env[`INPUT_${name.replace(/-/g, '_').toUpperCase()}`] ?? '';
}

function getBooleanInput(name: string): boolean {
  return getInput(name).toLowerCase() === 'true';
}

function setOutput(name: string, value: string | number): void {
  const filePath = process.env.GITHUB_OUTPUT;
  if (filePath) {
    appendFileSync(filePath, `${name}=${value}\n`);
  }
}

function setFailed(message: string): void {
  console.log(`::error::${message}`);
  process.exitCode = 1;
}

function warning(message: string, title?: string): void {
  const titlePart = title ? ` title=${title}` : '';
  console.log(`::warning${titlePart}::${message}`);
}

function startGroup(name: string): void {
  console.log(`::group::${name}`);
}

function endGroup(): void {
  console.log(`::endgroup::`);
}

// ── SARIF upload ───────────────────────────────────────────────────────────

async function uploadSarif(sarifContent: string, category: string): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const sha = process.env.GITHUB_SHA;
  const ref = process.env.GITHUB_REF;

  if (!token || !repo || !sha || !ref) {
    warning('Cannot upload SARIF: missing GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA, or GITHUB_REF');
    return;
  }

  // Basic token format validation
  const validTokenPattern = /^(ghp_|ghs_|github_pat_|v\d+\.)[A-Za-z0-9_]+$/;
  if (!validTokenPattern.test(token)) {
    warning('GITHUB_TOKEN does not match expected GitHub token format');
    return;
  }

  try {
    const gzipped = gzipSync(Buffer.from(sarifContent));
    const encoded = gzipped.toString('base64');

    const res = await fetch(
      `https://api.github.com/repos/${repo}/code-scanning/sarifs`,
      {
        method: 'POST',
        headers: {
          Authorization: `token ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'auditfix-action',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          commit_sha: sha,
          ref,
          sarif: encoded,
          tool_name: 'auditfix',
          checkout_uri: `file:///github/workspace`,
        }),
        signal: AbortSignal.timeout(30_000),
      },
    );

    if (res.ok) {
      console.log('SARIF uploaded to GitHub Code Scanning');
    } else {
      const text = await res.text().catch(() => '');
      warning(`SARIF upload failed: HTTP ${res.status} ${text.slice(0, 200)}`);
    }
  } catch (err) {
    warning(`SARIF upload error: ${err instanceof Error ? err.message : err}`);
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

async function run(): Promise<void> {
  try {
    const severity = getInput('severity') || 'low';
    const failOn = getInput('fail-on') || 'any';
    const prodOnly = getBooleanInput('production-only');
    const workDir = resolve(getInput('working-directory') || '.');
    const generateSarif = getBooleanInput('sarif');
    const prComment = getBooleanInput('pr-comment');
    const jsonOutputPath = getInput('json-output');
    const webhookUrl = getInput('webhook-url');
    const sarifCategory = getInput('sarif-category') || 'auditfix';
    const checkTyposquats = getBooleanInput('check-typosquats');
    const checkProvenance = getBooleanInput('check-provenance');
    const scanBehavior = getBooleanInput('scan-behavior');

    // Validate severity input
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    if (!validSeverities.includes(severity)) {
      setFailed(`Invalid severity: ${severity}. Must be one of: ${validSeverities.join(', ')}`);
      return;
    }

    // Validate fail-on input
    const validFailOn = ['production-critical', 'production-high', 'any', 'none'];
    if (!validFailOn.includes(failOn)) {
      setFailed(`Invalid fail-on: ${failOn}. Must be one of: ${validFailOn.join(', ')}`);
      return;
    }

    // Run scan
    startGroup('Running auditfix scan');
    const report = await analyze({
      projectDir: workDir,
      productionOnly: prodOnly,
      severityThreshold: severity,
    });
    endGroup();

    const vulns = report.vulnerabilities;

    // Set structured outputs
    setOutput('vulnerability-count', vulns.length);
    setOutput('critical-count', vulns.filter(v => v.risk.label === 'critical').length);
    setOutput('high-count', vulns.filter(v => v.risk.label === 'high').length);
    setOutput('production-count', vulns.filter(v => v.match.isProduction).length);
    setOutput('fixable-count', vulns.filter(v => v.risk.factors.fixAvailable).length);
    setOutput('exit-code', failOn === 'none' ? 0 : getExitCodeForStrategy(report, failOn));

    // Generate and upload SARIF
    if (generateSarif) {
      const sarifContent = renderSarifReport(report, '2.0.0');
      writeFileSync('auditfix-results.sarif', sarifContent);
      setOutput('sarif-file', 'auditfix-results.sarif');
      await uploadSarif(sarifContent, sarifCategory);
    }

    // Write JSON report
    if (jsonOutputPath) {
      writeFileSync(jsonOutputPath, renderJsonReport(report));
      setOutput('json-file', jsonOutputPath);
    }

    // PR comment
    if (prComment && process.env.GITHUB_EVENT_NAME === 'pull_request') {
      const prResult = await postPrComment(report);
      if (!prResult.success) {
        warning(`PR comment failed: ${prResult.error}`);
      }
    }

    // Webhook
    if (webhookUrl) {
      const whResult = await sendWebhook(webhookUrl, report);
      if (!whResult.success) {
        warning(`Webhook failed: ${whResult.error}`);
      }
    }

    // Annotations for critical/high vulns
    for (const vuln of vulns.filter(v => v.risk.label === 'critical' || v.risk.label === 'high')) {
      warning(
        `${vuln.match.package}@${vuln.match.installedVersion}: ${vuln.match.advisory.summary}`,
        vuln.match.advisory.id,
      );
    }

    // Summary
    console.log(`\nauditfix: ${vulns.length} vulnerabilities found`);
    if (vulns.length > 0) {
      const crit = vulns.filter(v => v.risk.label === 'critical').length;
      const high = vulns.filter(v => v.risk.label === 'high').length;
      const prod = vulns.filter(v => v.match.isProduction).length;
      console.log(`  Critical: ${crit} | High: ${high} | Production: ${prod}`);
    }

    // Gate decision
    if (failOn !== 'none') {
      const exitCode = getExitCodeForStrategy(report, failOn);
      if (exitCode !== 0) {
        setFailed(`auditfix found ${vulns.length} vulnerabilities (fail-on: ${failOn})`);
      }
    }
  } catch (error) {
    setFailed(error instanceof Error ? error.message : String(error));
  }
}

run();
