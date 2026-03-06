#!/usr/bin/env tsx
/**
 * Build-time script: fetch OSV npm ecosystem dump and generate offline advisory index.
 *
 * Usage:
 *   npx tsx scripts/build-offline-index.ts
 *
 * What it does:
 *   1. Downloads https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 *   2. Extracts each JSON vulnerability from the ZIP
 *   3. Converts to OfflineEntry format (filtering for actionable advisories only)
 *   4. Writes src/core/advisory/offline-index.generated.ts
 *
 * Only includes advisories modified in the last 2 years with semver ranges and fix versions.
 */

import { createWriteStream, createReadStream } from 'node:fs';
import { writeFile, unlink, mkdir, readdir } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createUnzip } from 'node:zlib';
import { createInterface } from 'node:readline';

import type { OsvVulnerability } from '../src/types/advisory.js';
import type { OfflineEntry } from '../src/core/advisory/offline-index.js';
import { convertOsvBatch } from '../src/core/advisory/osv-to-offline.js';

const OSV_NPM_DUMP_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';
const OUTPUT_PATH = resolve(import.meta.dirname ?? '.', '..', 'src', 'core', 'advisory', 'offline-index.generated.ts');
const CUTOFF_YEARS = 2;
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024; // 500MB safety limit

async function main(): Promise<void> {
  const cutoffDate = new Date();
  cutoffDate.setFullYear(cutoffDate.getFullYear() - CUTOFF_YEARS);

  console.log(`[build-offline-index] Starting OSV npm dump download...`);
  console.log(`[build-offline-index] Cutoff date: ${cutoffDate.toISOString()}`);

  // Download ZIP to temp file
  const tempZipPath = join(tmpdir(), `osv-npm-dump-${Date.now()}.zip`);

  try {
    await downloadFile(OSV_NPM_DUMP_URL, tempZipPath);
    console.log(`[build-offline-index] Downloaded to ${tempZipPath}`);

    // Extract and parse vulnerabilities
    const vulns = await extractVulnerabilities(tempZipPath);
    console.log(`[build-offline-index] Parsed ${vulns.length} vulnerabilities from ZIP`);

    // Convert to offline entries
    const entries = convertOsvBatch(vulns, cutoffDate);
    console.log(`[build-offline-index] ${entries.length} actionable entries after filtering`);

    // Generate TypeScript file
    await generateTypescriptFile(entries);
    console.log(`[build-offline-index] Written to ${OUTPUT_PATH}`);
  } finally {
    // Clean up temp file
    try {
      await unlink(tempZipPath);
    } catch {
      // Ignore cleanup errors
    }
  }
}

async function downloadFile(url: string, destPath: string): Promise<void> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status} ${response.statusText}`);
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_DOWNLOAD_SIZE) {
    throw new Error(`Download too large: ${contentLength} bytes (max ${MAX_DOWNLOAD_SIZE})`);
  }

  if (!response.body) {
    throw new Error('Response body is null');
  }

  const fileStream = createWriteStream(destPath);
  // Node 20+ supports ReadableStream -> Writable pipeline via Readable.fromWeb
  const { Readable } = await import('node:stream');
  const nodeStream = Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);
  await pipeline(nodeStream, fileStream);
}

/**
 * Extract all JSON vulnerability files from the OSV ZIP dump.
 * The ZIP contains individual JSON files, one per vulnerability.
 *
 * Uses the 'unzipper' approach via Node's built-in zlib for individual entries.
 * Since Node doesn't have built-in ZIP support, we use a simple approach:
 * extract to a temp directory using the `unzip` command if available,
 * or fall back to reading with a minimal ZIP parser.
 */
async function extractVulnerabilities(zipPath: string): Promise<OsvVulnerability[]> {
  // Use a temp directory for extraction
  const extractDir = join(tmpdir(), `osv-extract-${Date.now()}`);
  await mkdir(extractDir, { recursive: true });

  try {
    // Try using system unzip command (available on most systems)
    const { execSync } = await import('node:child_process');
    execSync(`unzip -q -o "${zipPath}" -d "${extractDir}"`, {
      stdio: 'pipe',
      timeout: 120_000, // 2 minutes
    });

    // Read all extracted JSON files
    const files = await readdir(extractDir);
    const jsonFiles = files.filter((f) => f.endsWith('.json'));
    console.log(`[build-offline-index] Found ${jsonFiles.length} JSON files in ZIP`);

    const vulns: OsvVulnerability[] = [];
    let parseErrors = 0;

    for (const file of jsonFiles) {
      try {
        const filePath = join(extractDir, file);
        const { readFile } = await import('node:fs/promises');
        const content = await readFile(filePath, 'utf-8');
        const parsed = JSON.parse(content) as OsvVulnerability;

        if (parsed.id && parsed.affected) {
          vulns.push(parsed);
        }
      } catch {
        parseErrors++;
      }
    }

    if (parseErrors > 0) {
      console.warn(`[build-offline-index] ${parseErrors} files failed to parse`);
    }

    return vulns;
  } finally {
    // Clean up extraction directory
    try {
      const { rm } = await import('node:fs/promises');
      await rm(extractDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Generate the TypeScript file containing the offline index.
 */
async function generateTypescriptFile(entries: OfflineEntry[]): Promise<void> {
  // Sort entries by package name then ID for deterministic output
  entries.sort((a, b) => {
    const pkgCmp = a.pkg.localeCompare(b.pkg);
    if (pkgCmp !== 0) return pkgCmp;
    return a.id.localeCompare(b.id);
  });

  const lines: string[] = [
    '/**',
    ' * AUTO-GENERATED FILE - DO NOT EDIT MANUALLY',
    ` * Generated by scripts/build-offline-index.ts on ${new Date().toISOString()}`,
    ` * Source: OSV npm ecosystem dump (${OSV_NPM_DUMP_URL})`,
    ` * Entries: ${entries.length} advisories`,
    ' */',
    `import type { OfflineEntry } from './offline-index.js';`,
    '',
    'export const GENERATED_INDEX: OfflineEntry[] = [',
  ];

  for (const entry of entries) {
    const escaped = {
      id: escapeString(entry.id),
      pkg: escapeString(entry.pkg),
      range: escapeString(entry.range),
      fix: entry.fix !== null ? `'${escapeString(entry.fix)}'` : 'null',
      severity: escapeString(entry.severity),
      summary: escapeString(truncate(entry.summary, 120)),
    };

    lines.push(
      `  { id: '${escaped.id}', pkg: '${escaped.pkg}', range: '${escaped.range}', fix: ${escaped.fix}, severity: '${escaped.severity}', summary: '${escaped.summary}' },`,
    );
  }

  lines.push('];');
  lines.push('');

  await writeFile(OUTPUT_PATH, lines.join('\n'), 'utf-8');
}

function escapeString(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 3) + '...';
}

// Run
main().catch((err) => {
  console.error('[build-offline-index] Fatal error:', err);
  process.exit(1);
});
