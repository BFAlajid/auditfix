/**
 * GitHub PR comment bot — posts audit scan results as PR comments.
 * Uses native fetch and the GitHub Issues API. No external dependencies.
 */
import { readFileSync } from 'node:fs';
import type { AuditReport } from '../../types/report.js';
import * as logger from '../../utils/logger.js';

const COMMENT_MARKER = '<!-- auditfix-scan -->';
const API_BASE = 'https://api.github.com';
const TIMEOUT_MS = 15_000;
const VERSION = '2.0.0';

// ── Exported types ──────────────────────────────────────────────────────────

export type PrCommentOptions = {
  token?: string;          // override GITHUB_TOKEN
  repo?: string;           // override GITHUB_REPOSITORY
  prNumber?: number;       // override auto-detected PR number
  updateExisting?: boolean; // default true
};

export type PrCommentResult = {
  success: boolean;
  commentUrl?: string;
  error?: string;
};

// ── GitHub API types (internal) ─────────────────────────────────────────────

type GitHubComment = {
  id: number;
  body?: string;
  html_url: string;
};

// ── Environment detection ───────────────────────────────────────────────────

/**
 * Extract PR number from the GitHub Actions environment.
 * Tries GITHUB_REF (refs/pull/123/merge) first, then falls back to
 * reading the event payload JSON at GITHUB_EVENT_PATH.
 */
function getPrNumber(): number | null {
  const ref = process.env.GITHUB_REF ?? '';
  const refMatch = /^refs\/pull\/(\d+)\/merge$/.exec(ref);
  if (refMatch) {
    return Number(refMatch[1]);
  }

  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath) {
    try {
      const raw = readFileSync(eventPath, 'utf-8');
      const event: unknown = JSON.parse(raw);
      if (
        typeof event === 'object' &&
        event !== null &&
        'pull_request' in event
      ) {
        const pr = (event as Record<string, unknown>).pull_request;
        if (typeof pr === 'object' && pr !== null && 'number' in pr) {
          const num = (pr as Record<string, unknown>).number;
          if (typeof num === 'number' && Number.isInteger(num) && num > 0) {
            return num;
          }
        }
      }
    } catch {
      logger.debug(`Failed to read event payload at ${eventPath}`);
    }
  }

  return null;
}

// ── GitHub API helpers ──────────────────────────────────────────────────────

function apiHeaders(token: string): Record<string, string> {
  return {
    Authorization: `token ${token}`,
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'auditfix',
    'Content-Type': 'application/json',
  };
}

async function findExistingComment(
  token: string,
  repo: string,
  prNumber: number,
): Promise<GitHubComment | null> {
  const url = `${API_BASE}/repos/${repo}/issues/${prNumber}/comments`;
  let page = 1;

  // Paginate through comments (100 per page) looking for our marker.
  while (page <= 10) {
    const res = await fetch(`${url}?per_page=100&page=${page}`, {
      method: 'GET',
      headers: apiHeaders(token),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!res.ok) {
      logger.warn(`Failed to list PR comments: HTTP ${res.status}`);
      return null;
    }

    const comments: GitHubComment[] = (await res.json()) as GitHubComment[];
    if (comments.length === 0) break;

    const existing = comments.find(
      (c) => typeof c.body === 'string' && c.body.includes(COMMENT_MARKER),
    );
    if (existing) return existing;

    page++;
  }

  return null;
}

// ── Markdown formatting ─────────────────────────────────────────────────────

/**
 * Escape user-controlled strings for safe embedding in GitHub-flavored markdown.
 *
 * Mitigates:
 *   - Table-break:     `|` in cells.
 *   - Code-break:      backtick inside inline code spans.
 *   - Heading / list injection: newlines (`\n`, `\r`).
 *   - Link injection:  `[` `]` `(` `)`.
 *   - Mention spam:    `@username` → `@\u200Busername` (zero-width space).
 *   - HTML/comment injection: `<` `>` → `&lt;` `&gt;` (also neutralizes `<!-- -->` comment attempts).
 *   - Backslash escape collisions: leading `\\`.
 */
export function escapeMarkdown(s: string): string {
  if (s == null) return '';
  const str = String(s);
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    switch (ch) {
      case '\\': out += '\\\\'; break;
      case '`':  out += '\\`'; break;
      case '|':  out += '\\|'; break;
      case '[':  out += '\\['; break;
      case ']':  out += '\\]'; break;
      case '(':  out += '\\('; break;
      case ')':  out += '\\)'; break;
      case '<':  out += '&lt;'; break;
      case '>':  out += '&gt;'; break;
      case '@':  out += '@\u200B'; break; // zero-width space defeats @mention autolink
      case '\r': out += ' '; break;
      case '\n': out += ' '; break;
      default:   out += ch;
    }
  }
  return out;
}

function severityEmoji(label: string): string {
  switch (label) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🟢';
    default: return '⚪';
  }
}

function headerEmoji(report: AuditReport): string {
  const labels = report.vulnerabilities.map((v) => v.risk.label);
  if (labels.includes('critical')) return '🚨';
  if (labels.includes('high')) return '⚠️';
  if (report.vulnerabilities.length > 0) return 'ℹ️';
  return '✅';
}

function buildCommentBody(report: AuditReport): string {
  const vulns = report.vulnerabilities;
  const total = vulns.length;
  const prod = vulns.filter((v) => v.match.isProduction).length;
  const crit = vulns.filter((v) => v.risk.label === 'critical').length;
  const high = vulns.filter((v) => v.risk.label === 'high').length;
  const med = vulns.filter((v) => v.risk.label === 'medium').length;
  const low = vulns.filter((v) => v.risk.label === 'low').length;

  const emoji = headerEmoji(report);
  const lines: string[] = [];

  // Marker must be first
  lines.push(COMMENT_MARKER);
  lines.push('');

  // Header
  if (total === 0) {
    lines.push(`## ${emoji} auditfix — No vulnerabilities found`);
  } else {
    lines.push(`## ${emoji} auditfix — ${total} ${total === 1 ? 'vulnerability' : 'vulnerabilities'} found`);
  }
  lines.push('');

  // Summary table
  lines.push('### Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('| --- | --- |');
  lines.push(`| Total | ${total} |`);
  lines.push(`| Production | ${prod} |`);
  lines.push(`| ${severityEmoji('critical')} Critical | ${crit} |`);
  lines.push(`| ${severityEmoji('high')} High | ${high} |`);
  lines.push(`| ${severityEmoji('medium')} Medium | ${med} |`);
  lines.push(`| ${severityEmoji('low')} Low | ${low} |`);
  lines.push('');

  // Top 10 vulnerabilities
  if (total > 0) {
    const top = vulns.slice(0, 10);
    lines.push('### Top vulnerabilities');
    lines.push('');
    lines.push('| Package | Version | Severity | Score | Fix |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const v of top) {
      const fix = v.risk.factors.fixVersion ? escapeMarkdown(v.risk.factors.fixVersion) : '—';
      const sev = `${severityEmoji(v.risk.label)} ${escapeMarkdown(v.risk.label)}`;
      const pkg = escapeMarkdown(v.match.package);
      const ver = escapeMarkdown(v.match.installedVersion);
      lines.push(`| \`${pkg}\` | ${ver} | ${sev} | ${v.risk.score} | ${fix} |`);
    }
    if (total > 10) {
      lines.push('');
      lines.push(`> _...and ${total - 10} more not shown._`);
    }
    lines.push('');
  }

  // Auto-fix suggestions
  const fixable = vulns.filter((v) => v.risk.factors.fixAvailable && v.risk.factors.fixVersion);
  if (fixable.length > 0) {
    lines.push('### Auto-fix suggestions');
    lines.push('');
    lines.push(`${fixable.length} ${fixable.length === 1 ? 'vulnerability has' : 'vulnerabilities have'} a known fix:`);
    lines.push('');
    for (const v of fixable.slice(0, 10)) {
      const pkg = escapeMarkdown(v.match.package);
      const ver = escapeMarkdown(v.match.installedVersion);
      const fix = escapeMarkdown(v.risk.factors.fixVersion ?? '');
      lines.push(`- \`${pkg}\` ${ver} → **${fix}**`);
    }
    if (fixable.length > 10) {
      lines.push(`- _...and ${fixable.length - 10} more_`);
    }
    lines.push('');
  }

  // Footer
  lines.push('---');
  lines.push(
    `<sub>auditfix v${VERSION} | ${escapeMarkdown(report.metadata.advisorySource)} | ` +
    `${report.metadata.totalPackages} packages scanned | ` +
    `confidence: ${escapeMarkdown(report.metadata.confidence)} | ` +
    `${report.metadata.scanDurationMs}ms</sub>`,
  );

  return lines.join('\n');
}

// ── Main export ─────────────────────────────────────────────────────────────

/**
 * Post (or update) a PR comment with the audit scan results.
 *
 * Automatically detects GitHub Actions environment variables.
 * Returns a result object indicating success/failure and the comment URL.
 */
export async function postPrComment(
  report: AuditReport,
  options?: PrCommentOptions,
): Promise<PrCommentResult> {
  const token = options?.token ?? process.env.GITHUB_TOKEN;
  if (!token) {
    return { success: false, error: 'No GitHub token available (set GITHUB_TOKEN or pass options.token)' };
  }

  const repo = options?.repo ?? process.env.GITHUB_REPOSITORY;
  if (!repo) {
    return { success: false, error: 'No repository detected (set GITHUB_REPOSITORY or pass options.repo)' };
  }

  const prNumber = options?.prNumber ?? getPrNumber();
  if (!prNumber) {
    return { success: false, error: 'Could not detect PR number from environment (set GITHUB_REF, provide GITHUB_EVENT_PATH, or pass options.prNumber)' };
  }

  const updateExisting = options?.updateExisting ?? true;
  const body = buildCommentBody(report);

  try {
    // Try to find and update an existing comment
    if (updateExisting) {
      const existing = await findExistingComment(token, repo, prNumber);
      if (existing) {
        logger.info(`Updating existing PR comment ${existing.id}`);
        const patchUrl = `${API_BASE}/repos/${repo}/issues/comments/${existing.id}`;
        const res = await fetch(patchUrl, {
          method: 'PATCH',
          headers: apiHeaders(token),
          body: JSON.stringify({ body }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });

        if (!res.ok) {
          const text = await res.text().catch(() => '');
          return { success: false, error: `Failed to update comment: HTTP ${res.status} ${text.slice(0, 200)}` };
        }

        const updated = (await res.json()) as GitHubComment;
        logger.info(`PR comment updated: ${updated.html_url}`);
        return { success: true, commentUrl: updated.html_url };
      }
    }

    // Create new comment
    logger.info(`Posting new PR comment on ${repo}#${prNumber}`);
    const postUrl = `${API_BASE}/repos/${repo}/issues/${prNumber}/comments`;
    const res = await fetch(postUrl, {
      method: 'POST',
      headers: apiHeaders(token),
      body: JSON.stringify({ body }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { success: false, error: `Failed to create comment: HTTP ${res.status} ${text.slice(0, 200)}` };
    }

    const created = (await res.json()) as GitHubComment;
    logger.info(`PR comment created: ${created.html_url}`);
    return { success: true, commentUrl: created.html_url };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`PR comment failed: ${msg}`);
    return { success: false, error: msg };
  }
}
