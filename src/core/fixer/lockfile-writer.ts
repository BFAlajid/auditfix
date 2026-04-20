/**
 * Lockfile writer.
 * Applies safe updates via package manager-specific override mechanisms:
 * - npm: `overrides` in package.json + `npm install --package-lock-only`
 * - yarn Berry: `resolutions` in package.json + `yarn install --mode=update-lockfile`
 * - yarn Classic: `resolutions` in package.json + `yarn install` (full install — requires approval)
 * - pnpm: `pnpm.overrides` in package.json + `pnpm install --lockfile-only`
 *
 * Security (S3): All shell commands use execFile with argument arrays.
 * Overrides are written via JSON.stringify only — never string interpolation.
 *
 * C-B5 fix: overrides are NOT removed after a successful install — they remain in
 * package.json so the fix is durable. A sentinel file `.auditfix/pending-overrides.json`
 * records which overrides were just applied, so downstream tooling / humans know the
 * overrides need to be committed. On install failure we DO restore the original
 * package.json (rollback).
 */
import { readFileSync, writeFileSync, existsSync, lstatSync, mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { SafeUpdate } from './safe-update.js';
import type { LockfileType } from '../../types/package.js';
import { safeExec, validateFixInputs } from '../../utils/shell.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

export type FixResult = {
  applied: AppliedFix[];
  failed: FailedFix[];
  /** True when the writer intentionally refused to run (e.g. yarn Classic without --yes). */
  skipped?: boolean;
  /** Human-readable explanation when `skipped` is true. */
  skipReason?: string;
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

export type ApplyFixesOptions = {
  /** Grant approval for yarn Classic full install. Required because we cannot produce a lockfile-only update there. */
  yes?: boolean;
  /** Max bytes allowed for package.json (default 1MB). Oversized files are rejected. */
  maxPackageJsonBytes?: number;
};

const DEFAULT_MAX_PACKAGE_JSON_BYTES = 1_048_576; // 1 MB

/**
 * Detect the lockfile type in a project directory.
 * Distinguishes yarn Classic from yarn Berry by inspecting lockfile content.
 */
function detectLockfileType(projectDir: string): LockfileType {
  if (existsSync(join(projectDir, 'pnpm-lock.yaml'))) return 'pnpm-v9';
  const yarnPath = join(projectDir, 'yarn.lock');
  if (existsSync(yarnPath)) {
    try {
      const content = readFileSync(yarnPath, 'utf-8');
      return content.includes('__metadata') ? 'yarn-berry' : 'yarn-classic';
    } catch {
      return 'yarn-classic';
    }
  }
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
  options: ApplyFixesOptions = {},
): Promise<FixResult> {
  if (updates.length === 0) {
    return { applied: [], failed: [] };
  }

  const packageJsonPath = join(projectDir, 'package.json');
  const applied: AppliedFix[] = [];
  const failed: FailedFix[] = [];
  const maxBytes = options.maxPackageJsonBytes ?? DEFAULT_MAX_PACKAGE_JSON_BYTES;

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

  // H3: Reject writing to symlinked package.json (first check — pre-read)
  try {
    if (lstatSync(packageJsonPath).isSymbolicLink()) {
      failed.push({ packageName: '*', reason: 'Refusing to write to symlinked package.json' });
      return { applied, failed };
    }
  } catch { /* file doesn't exist yet — that's fine, will fail below */ }

  // File size guard — reject oversized package.json before reading.
  try {
    const st = statSync(packageJsonPath);
    if (st.size > maxBytes) {
      failed.push({
        packageName: '*',
        reason: `Refusing to modify oversized package.json (${st.size} bytes > ${maxBytes}).`,
      });
      return { applied, failed };
    }
  } catch { /* file doesn't exist yet — error will surface on read */ }

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

  // TOCTOU: re-check that the path hasn't been swapped for a symlink between stat and write.
  try {
    if (lstatSync(packageJsonPath).isSymbolicLink()) {
      failed.push({ packageName: '*', reason: 'Refusing to write to symlinked package.json (TOCTOU)' });
      return { applied, failed };
    }
  } catch {
    failed.push({ packageName: '*', reason: 'package.json disappeared during apply' });
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

  // Yarn Classic requires approval because there's no --lockfile-only mode.
  if (type === 'yarn-classic' && !options.yes) {
    logger.warn(
      'yarn Classic does not support lockfile-only install. Running full `yarn install` would ' +
      'mutate node_modules. Re-run with --yes to proceed.',
    );
    return {
      applied: [],
      failed: [],
      skipped: true,
      skipReason: 'yarn-classic requires --yes to run a full install',
    };
  }

  // Write overrides using the correct strategy
  const existingOverrides = strategy.getExisting(packageJson);
  strategy.setOverrides(packageJson, { ...existingOverrides, ...overrides });

  try {
    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');
    logger.debug(`Wrote ${Object.keys(overrides).length} overrides to package.json (${strategy.name})`);
  } catch (err) {
    failed.push({
      packageName: '*',
      reason: `Failed to write package.json: ${err instanceof Error ? err.message : err}`,
    });
    // Attempt rollback even on write failure (write may have partially succeeded)
    try { writeFileSync(packageJsonPath, originalContent, 'utf-8'); } catch { /* ignore */ }
    return { applied, failed };
  }

  // Run the appropriate install command
  logger.info(`Running ${strategy.installCmd.join(' ')}...`);
  const result = await safeExec(strategy.installCmd[0], strategy.installCmd.slice(1), {
    cwd: projectDir,
    timeout: 120_000,
  });

  if (result.exitCode !== 0) {
    // Rollback: restore the original package.json so we don't leave overrides
    // pointing at a broken install state.
    logger.warn(`Install failed (exit ${result.exitCode}): ${result.stderr}`);
    try { writeFileSync(packageJsonPath, originalContent, 'utf-8'); } catch { /* best effort */ }

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

  // C-B5 fix: DO NOT restore original overrides on the success path.
  // Keeping the overrides in package.json is what makes the fix durable across
  // future `npm install` runs. Write a sentinel so tooling / humans know the
  // overrides are uncommitted and must be persisted.
  try {
    writePendingOverridesSentinel(projectDir, overrides, strategy.name);
  } catch (err) {
    logger.warn(
      `Applied fixes but failed to write pending-overrides sentinel: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  logger.info(`Applied ${applied.length} fixes`);
  return { applied, failed };
}

/**
 * Write a sentinel file recording which overrides were just applied by auditfix.
 * Downstream tooling (review bots, CI) can check for this file to know that
 * package.json has auditfix-generated overrides that still need to be committed.
 */
function writePendingOverridesSentinel(
  projectDir: string,
  overrides: Record<string, string>,
  strategyName: string,
): void {
  const sentinelDir = join(projectDir, '.auditfix');
  if (!existsSync(sentinelDir)) {
    mkdirSync(sentinelDir, { recursive: true });
  }
  const sentinelPath = join(sentinelDir, 'pending-overrides.json');
  const payload = {
    schemaVersion: 1,
    strategy: strategyName,
    writtenAt: new Date().toISOString(),
    overrides,
  };
  writeFileSync(sentinelPath, JSON.stringify(payload, null, 2) + '\n', 'utf-8');
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
  if (type === 'yarn-berry') {
    return {
      name: 'yarn resolutions (berry)',
      // Berry supports updating the lockfile without touching node_modules.
      installCmd: ['yarn', 'install', '--mode=update-lockfile'],
      getExisting: (pkg) => safeGetRecord(pkg.resolutions),
      setOverrides: (pkg, overrides) => { pkg.resolutions = overrides; },
      removeOverrides: (pkg) => { delete pkg.resolutions; },
    };
  }

  if (type === 'yarn-classic') {
    return {
      name: 'yarn resolutions (classic)',
      // Classic has no lockfile-only flag. Caller must pass { yes: true } to allow.
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
