/**
 * Lockfile writer.
 * Applies safe updates via package manager-specific override mechanisms:
 * - npm: `overrides` in package.json + `npm install --package-lock-only`
 * - yarn: `resolutions` in package.json + `yarn install`
 * - pnpm: `pnpm.overrides` in package.json + `pnpm install --lockfile-only`
 *
 * Security (S3): All shell commands use execFile with argument arrays.
 * Overrides are written via JSON.stringify only — never string interpolation.
 */
import { readFileSync, writeFileSync, existsSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { SafeUpdate } from './safe-update.js';
import type { LockfileType } from '../../types/package.js';
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
 * Detect the lockfile type in a project directory.
 */
function detectLockfileType(projectDir: string): LockfileType {
  if (existsSync(join(projectDir, 'pnpm-lock.yaml'))) return 'pnpm-v9';
  if (existsSync(join(projectDir, 'yarn.lock'))) return 'yarn-classic';
  return 'npm-v3';
}

/**
 * Apply safe updates to the project.
 * Detects the package manager and uses the appropriate override mechanism.
 */
export async function applyFixes(
  projectDir: string,
  updates: SafeUpdate[],
  lockfileType?: LockfileType,
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

  // H3: Reject writing to symlinked package.json
  try {
    if (lstatSync(packageJsonPath).isSymbolicLink()) {
      failed.push({ packageName: '*', reason: 'Refusing to write to symlinked package.json' });
      return { applied, failed };
    }
  } catch { /* file doesn't exist yet — that's fine, will fail below */ }

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

  // Detect package manager strategy
  const type = lockfileType ?? detectLockfileType(projectDir);
  const strategy = getOverrideStrategy(type);

  // Write overrides using the correct strategy
  const existingOverrides = strategy.getExisting(packageJson);
  strategy.setOverrides(packageJson, { ...existingOverrides, ...overrides });

  // S8: Re-check symlink immediately before write to mitigate TOCTOU
  try {
    if (lstatSync(packageJsonPath).isSymbolicLink()) {
      failed.push({ packageName: '*', reason: 'Refusing to write to symlinked package.json (detected at write time)' });
      return { applied, failed };
    }
  } catch { /* file removed between reads — writeFileSync will fail below */ }

  try {
    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');
    logger.debug(`Wrote ${Object.keys(overrides).length} overrides to package.json (${strategy.name})`);
  } catch (err) {
    failed.push({
      packageName: '*',
      reason: `Failed to write package.json: ${err instanceof Error ? err.message : err}`,
    });
    writeFileSync(packageJsonPath, originalContent, 'utf-8');
    return { applied, failed };
  }

  // Run the appropriate install command
  logger.info(`Running ${strategy.installCmd.join(' ')}...`);
  const result = await safeExec(strategy.installCmd[0], strategy.installCmd.slice(1), {
    cwd: projectDir,
    timeout: 120_000,
  });

  if (result.exitCode !== 0) {
    logger.warn(`Install failed (exit ${result.exitCode}): ${result.stderr}`);
    writeFileSync(packageJsonPath, originalContent, 'utf-8');

    for (const update of updates) {
      failed.push({
        packageName: update.packageName,
        reason: `Install failed: ${result.stderr.slice(0, 200)}`,
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

  // Clean up: restore original overrides
  if (Object.keys(existingOverrides).length > 0) {
    strategy.setOverrides(packageJson, existingOverrides);
  } else {
    strategy.removeOverrides(packageJson);
  }
  writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');

  logger.info(`Applied ${applied.length} fixes`);
  return { applied, failed };
}

// --- Override strategies per package manager ---

type OverrideStrategy = {
  name: string;
  installCmd: string[];
  getExisting: (pkg: Record<string, unknown>) => Record<string, string>;
  setOverrides: (pkg: Record<string, unknown>, overrides: Record<string, string>) => void;
  removeOverrides: (pkg: Record<string, unknown>) => void;
};

function safeGetRecord(value: unknown): Record<string, string> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, string>)
    : {};
}

function getOverrideStrategy(type: LockfileType): OverrideStrategy {
  if (type.startsWith('yarn')) {
    return {
      name: 'yarn resolutions',
      installCmd: ['yarn', 'install'],
      getExisting: (pkg) => safeGetRecord(pkg.resolutions),
      setOverrides: (pkg, overrides) => { pkg.resolutions = overrides; },
      removeOverrides: (pkg) => { delete pkg.resolutions; },
    };
  }

  if (type.startsWith('pnpm')) {
    return {
      name: 'pnpm overrides',
      installCmd: ['pnpm', 'install', '--lockfile-only'],
      getExisting: (pkg) => {
        const pnpmConfig = safeGetRecord(pkg.pnpm);
        return safeGetRecord(pnpmConfig.overrides);
      },
      setOverrides: (pkg, overrides) => {
        const existing = safeGetRecord(pkg.pnpm);
        pkg.pnpm = { ...existing, overrides };
      },
      removeOverrides: (pkg) => {
        const existing = safeGetRecord(pkg.pnpm);
        delete existing.overrides;
        if (Object.keys(existing).length === 0) {
          delete pkg.pnpm;
        } else {
          pkg.pnpm = existing;
        }
      },
    };
  }

  // Default: npm
  return {
    name: 'npm overrides',
    installCmd: ['npm', 'install', '--package-lock-only'],
    getExisting: (pkg) => safeGetRecord(pkg.overrides),
    setOverrides: (pkg, overrides) => { pkg.overrides = overrides; },
    removeOverrides: (pkg) => { delete pkg.overrides; },
  };
}
