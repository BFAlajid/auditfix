/**
 * Lockfile detection and dispatch.
 * Auto-detects lockfile type and routes to the correct parser.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { LockfileParseResult } from '../../types/package.js';
import { parseNpmLockfile } from './npm.js';
import { parseYarnClassicLockfile } from './yarn-classic.js';
import { parseYarnBerryLockfile } from './yarn-berry.js';
import { parsePnpmLockfile } from './pnpm.js';
import { parseBunLockfile } from './bun.js';
import { parseDenoLockfile } from './deno.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

// Order matters: npm/yarn/pnpm take precedence when multiple lockfiles
// are present so established toolchains keep their canonical parser. Bun
// and Deno fall in below them.
const LOCKFILE_PRIORITY = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
  'deno.lock',
] as const;

export function detectAndParseLockfile(projectDir: string): LockfileParseResult {
  for (const lockfileName of LOCKFILE_PRIORITY) {
    const lockfilePath = join(projectDir, lockfileName);
    if (existsSync(lockfilePath)) {
      logger.debug(`Found lockfile: ${lockfilePath}`);
      return parseLockfile(projectDir, lockfilePath, lockfileName);
    }
  }

  throw new Error(
    'No lockfile found. auditfix requires a package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, or deno.lock. Run `npm install` to generate one.'
  );
}

function parseLockfile(projectDir: string, path: string, filename: string): LockfileParseResult {
  // bun.lockb is binary — read raw and let the bun parser decide.
  const isBunBinary = filename === 'bun.lockb';
  const content = readFileSync(path, isBunBinary ? 'binary' : 'utf-8');

  if (!isBunBinary && content.trim().length === 0) {
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
      const manifest = readManifest(projectDir);
      const isBerry = content.includes('__metadata');
      if (isBerry) {
        const result = parseYarnBerryLockfile(content, manifest);
        return {
          type: 'yarn-berry',
          graph: result.graph,
          packageCount: result.graph.size,
          skipped: result.skipped,
        };
      } else {
        const result = parseYarnClassicLockfile(content, manifest);
        return {
          type: 'yarn-classic',
          graph: result.graph,
          packageCount: result.graph.size,
          skipped: result.skipped,
        };
      }
    }
    case 'pnpm-lock.yaml': {
      const result = parsePnpmLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped,
      };
    }
    case 'bun.lock':
    case 'bun.lockb': {
      const result = parseBunLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped,
      };
    }
    case 'deno.lock': {
      const result = parseDenoLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped,
      };
    }
    default:
      throw new Error(`Unknown lockfile: ${filename}`);
  }
}

function readManifest(projectDir: string): {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
} {
  try {
    const content = readFileSync(join(projectDir, 'package.json'), 'utf-8');
    return safeJsonParse<Record<string, Record<string, string>>>(content);
  } catch {
    return {};
  }
}
