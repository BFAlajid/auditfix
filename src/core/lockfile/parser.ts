/**
 * Lockfile detection and dispatch.
 * Auto-detects lockfile type and routes to the correct parser.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { LockfileParseResult } from '../../types/package.js';
import { parseNpmLockfile } from './npm.js';
import * as logger from '../../utils/logger.js';

const LOCKFILE_PRIORITY = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
] as const;

export function detectAndParseLockfile(projectDir: string): LockfileParseResult {
  for (const lockfileName of LOCKFILE_PRIORITY) {
    const lockfilePath = join(projectDir, lockfileName);
    if (existsSync(lockfilePath)) {
      logger.debug(`Found lockfile: ${lockfilePath}`);
      return parseLockfile(lockfilePath, lockfileName);
    }
  }

  throw new Error(
    'No lockfile found. auditfix requires a package-lock.json, yarn.lock, or pnpm-lock.yaml. Run `npm install` to generate one.'
  );
}

function parseLockfile(path: string, filename: string): LockfileParseResult {
  const content = readFileSync(path, 'utf-8');

  if (content.trim().length === 0) {
    throw new Error(`Lockfile ${filename} is empty. Run \`npm install\` to regenerate.`);
  }

  switch (filename) {
    case 'package-lock.json': {
      const result = parseNpmLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped,
      };
    }
    case 'yarn.lock': {
      // TODO: Milestone 10 — Yarn parser
      throw new Error('Yarn lockfile support is not yet implemented. Coming in v1.0.');
    }
    case 'pnpm-lock.yaml': {
      // TODO: Milestone 10 — pnpm parser
      throw new Error('pnpm lockfile support is not yet implemented. Coming in v1.0.');
    }
    default:
      throw new Error(`Unknown lockfile: ${filename}`);
  }
}
