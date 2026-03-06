/**
 * Local allow-list (.auditfixignore).
 * Project-level vulnerability suppression with mandatory expiry dates.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { AllowList, AllowListEntry } from './types.js';
import type { AdvisoryMatch } from '../../types/advisory.js';
import type { IgnoredVulnerability } from '../../types/report.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import { isValidAdvisoryId } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

const ALLOWLIST_FILENAME = '.auditfixignore';

/**
 * Load the local allow-list from the project directory.
 * Returns an empty list if file doesn't exist or is invalid.
 */
export function loadLocalAllowList(projectDir: string): AllowList {
  const filePath = join(projectDir, ALLOWLIST_FILENAME);

  if (!existsSync(filePath)) {
    return { ignore: [] };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = safeJsonParse<AllowList>(content);

    if (!parsed.ignore || !Array.isArray(parsed.ignore)) {
      logger.warn(`${ALLOWLIST_FILENAME}: missing or invalid "ignore" array — ignoring file`);
      return { ignore: [] };
    }

    // Validate and filter entries
    const valid: AllowListEntry[] = [];
    for (const entry of parsed.ignore) {
      if (!entry.id || !entry.package || !entry.reason || !entry.expires) {
        logger.warn(`${ALLOWLIST_FILENAME}: skipping entry missing required fields (id, package, reason, expires)`);
        continue;
      }

      if (!isValidAdvisoryId(entry.id)) {
        logger.warn(`${ALLOWLIST_FILENAME}: skipping entry with invalid advisory ID: ${entry.id}`);
        continue;
      }

      // Check expiry
      const expiryDate = new Date(entry.expires);
      if (isNaN(expiryDate.getTime())) {
        logger.warn(`${ALLOWLIST_FILENAME}: skipping entry with invalid expiry date: ${entry.expires}`);
        continue;
      }

      if (expiryDate < new Date()) {
        logger.info(`${ALLOWLIST_FILENAME}: entry expired for ${entry.id} (${entry.package}) — no longer suppressed`);
        continue;
      }

      valid.push(entry);
    }

    return { ignore: valid };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(`Failed to parse ${ALLOWLIST_FILENAME}: ${msg}`);
    return { ignore: [] };
  }
}

/**
 * Filter advisory matches against the allow-list.
 * Returns matches split into kept (still reported) and ignored (suppressed).
 */
export function applyAllowList(
  matches: AdvisoryMatch[],
  allowList: AllowList,
): { kept: AdvisoryMatch[]; ignored: IgnoredVulnerability[] } {
  const kept: AdvisoryMatch[] = [];
  const ignored: IgnoredVulnerability[] = [];

  for (const match of matches) {
    const entry = allowList.ignore.find(
      (e) => e.id === match.advisory.id && e.package === match.package,
    );

    if (entry) {
      ignored.push({
        match,
        reason: entry.reason,
        source: 'local-allowlist',
      });
    } else {
      // Also check aliases (GHSA might be in allow-list, OSV returns CVE or vice versa)
      const aliasEntry = allowList.ignore.find(
        (e) =>
          e.package === match.package &&
          match.advisory.aliases.includes(e.id),
      );

      if (aliasEntry) {
        ignored.push({
          match,
          reason: aliasEntry.reason,
          source: 'local-allowlist',
        });
      } else {
        kept.push(match);
      }
    }
  }

  return { kept, ignored };
}

/**
 * Add a new entry to the local allow-list file.
 */
export function addToAllowList(
  projectDir: string,
  entry: AllowListEntry,
): void {
  const filePath = join(projectDir, ALLOWLIST_FILENAME);
  let allowList: AllowList;

  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    allowList = safeJsonParse<AllowList>(content);
    if (!allowList.ignore || !Array.isArray(allowList.ignore)) {
      allowList = { ignore: [] };
    }
  } else {
    allowList = { ignore: [] };
  }

  // Check for duplicate
  const exists = allowList.ignore.some(
    (e) => e.id === entry.id && e.package === entry.package,
  );

  if (exists) {
    // Update existing entry
    allowList.ignore = allowList.ignore.map((e) =>
      e.id === entry.id && e.package === entry.package ? entry : e,
    );
  } else {
    allowList.ignore.push(entry);
  }

  writeFileSync(filePath, JSON.stringify(allowList, null, 2) + '\n', 'utf-8');
}
