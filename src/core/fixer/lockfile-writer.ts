/**
 * Lockfile writer.
 * Applies safe updates by writing npm overrides to package.json,
 * then running `npm install --package-lock-only` to regenerate the lockfile.
 *
 * Security (S3): All shell commands use execFile with argument arrays.
 * Overrides are written via JSON.stringify only — never string interpolation.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { SafeUpdate } from './safe-update.js';
import { safeExec, validateFixInputs } from '../../utils/shell.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

export type FixResult = {
  applied: AppliedFix[];
  failed: FailedFix[];
};

export type AppliedFix = {
  packageName: string;
  from: string;
  to: string;
};

export type FailedFix = {
  packageName: string;
  reason: string;
};

/**
 * Apply safe updates to the project.
 * 1. Write overrides to package.json
 * 2. Run npm install --package-lock-only
 * 3. Remove overrides from package.json
 * 4. Return results
 */
export async function applyFixes(
  projectDir: string,
  updates: SafeUpdate[],
): Promise<FixResult> {
  if (updates.length === 0) {
    return { applied: [], failed: [] };
  }

  const packageJsonPath = join(projectDir, 'package.json');
  const applied: AppliedFix[] = [];
  const failed: FailedFix[] = [];

  // Validate all inputs before touching any files
  for (const update of updates) {
    try {
      validateFixInputs(update.packageName, update.fixVersion);
    } catch (err) {
      failed.push({
        packageName: update.packageName,
        reason: err instanceof Error ? err.message : String(err),
      });
      return { applied, failed };
    }
  }

  // Read original package.json
  let originalContent: string;
  let packageJson: Record<string, unknown>;
  try {
    originalContent = readFileSync(packageJsonPath, 'utf-8');
    packageJson = safeJsonParse<Record<string, unknown>>(originalContent);
  } catch (err) {
    failed.push({
      packageName: '*',
      reason: `Failed to read package.json: ${err instanceof Error ? err.message : err}`,
    });
    return { applied, failed };
  }

  // Build overrides map
  const overrides: Record<string, string> = {};
  for (const update of updates) {
    overrides[update.packageName] = update.fixVersion;
  }

  // Write overrides to package.json (safely via JSON.stringify)
  const existingOverrides = (packageJson.overrides as Record<string, string>) ?? {};
  packageJson.overrides = { ...existingOverrides, ...overrides };

  try {
    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');
    logger.debug(`Wrote ${Object.keys(overrides).length} overrides to package.json`);
  } catch (err) {
    failed.push({
      packageName: '*',
      reason: `Failed to write package.json: ${err instanceof Error ? err.message : err}`,
    });
    // Restore original
    writeFileSync(packageJsonPath, originalContent, 'utf-8');
    return { applied, failed };
  }

  // Run npm install --package-lock-only
  logger.info('Running npm install --package-lock-only...');
  const result = await safeExec('npm', ['install', '--package-lock-only'], {
    cwd: projectDir,
    timeout: 120_000,
  });

  if (result.exitCode !== 0) {
    logger.warn(`npm install failed (exit ${result.exitCode}): ${result.stderr}`);
    // Restore original package.json
    writeFileSync(packageJsonPath, originalContent, 'utf-8');

    for (const update of updates) {
      failed.push({
        packageName: update.packageName,
        reason: `npm install failed: ${result.stderr.slice(0, 200)}`,
      });
    }

    return { applied, failed };
  }

  // Mark all as applied
  for (const update of updates) {
    applied.push({
      packageName: update.packageName,
      from: update.currentVersion,
      to: update.fixVersion,
    });
  }

  // Clean up: remove our overrides (restore original overrides if any)
  if (Object.keys(existingOverrides).length > 0) {
    packageJson.overrides = existingOverrides;
  } else {
    delete packageJson.overrides;
  }
  writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');

  logger.info(`Applied ${applied.length} fixes`);
  return { applied, failed };
}
