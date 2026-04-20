/**
 * Shared helper for reading a project's name from its package.json.
 *
 * The CLI needs the project name in several places (SBOM, VEX, webhook
 * notifications, PR comments). package.json may be missing or malformed; in
 * those cases we return undefined rather than throwing — the callers all treat
 * the name as optional metadata.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { safeJsonParse } from './sanitize.js';

export function readProjectName(dir: string): string | undefined {
  try {
    const pkg = safeJsonParse<Record<string, string>>(
      readFileSync(join(dir, 'package.json'), 'utf-8'),
    );
    return pkg.name;
  } catch {
    return undefined;
  }
}
