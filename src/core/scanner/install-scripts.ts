/**
 * Install script scanner.
 * Detects suspicious postinstall/preinstall/install scripts in dependencies.
 * Flags scripts that execute binaries, download from URLs, or use obfuscation patterns.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { DependencyGraph } from '../../types/package.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall'] as const;

const SUSPICIOUS_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /curl\s|wget\s|fetch\(/, reason: 'Downloads external content' },
  { pattern: /eval\(|Function\(/, reason: 'Dynamic code execution' },
  { pattern: /\\x[0-9a-f]{2}/i, reason: 'Hex-encoded strings (possible obfuscation)' },
  { pattern: /Buffer\.from\(.+,\s*'base64'\)/, reason: 'Base64 decoding (possible obfuscation)' },
  { pattern: /child_process|exec\(|execSync|spawn/, reason: 'Spawns child process' },
  { pattern: /\.env|process\.env\.(TOKEN|SECRET|KEY|PASSWORD|AUTH)/i, reason: 'Accesses sensitive env vars' },
  { pattern: /http:\/\/|https:\/\//, reason: 'Contains URLs (potential exfiltration)' },
  { pattern: /powershell|cmd\.exe|\/bin\/sh -c/, reason: 'Shell execution' },
  { pattern: /npm\s+config\s+set|npm\s+token/, reason: 'Modifies npm config or tokens' },
];

export type ScriptFinding = {
  package: string;
  version: string;
  scriptName: string;
  scriptContent: string;
  reasons: string[];
  isProduction: boolean;
};

/**
 * Scan all packages in the dependency graph for suspicious install scripts.
 * Reads package.json from node_modules for each package.
 */
export function scanInstallScripts(
  graph: DependencyGraph,
  projectDir: string,
): ScriptFinding[] {
  const findings: ScriptFinding[] = [];
  const scanned = new Set<string>();

  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (scanned.has(key)) continue;
    scanned.add(key);

    const pkgJsonPath = resolvePackageJson(projectDir, node.name);
    if (!pkgJsonPath) continue;

    try {
      const content = readFileSync(pkgJsonPath, 'utf-8');
      const pkg = safeJsonParse<Record<string, unknown>>(content);
      const scripts = pkg.scripts as Record<string, string> | undefined;
      if (!scripts || typeof scripts !== 'object') continue;

      for (const scriptName of LIFECYCLE_SCRIPTS) {
        const scriptContent = scripts[scriptName];
        if (!scriptContent || typeof scriptContent !== 'string') continue;

        const reasons = analyzeScript(scriptContent);
        if (reasons.length > 0) {
          findings.push({
            package: node.name,
            version: node.version,
            scriptName,
            scriptContent: scriptContent.slice(0, 500),
            reasons,
            isProduction: node.isProduction,
          });
        }
      }
    } catch {
      // Can't read package.json — skip silently
    }
  }

  logger.debug(`Script scanner: ${scanned.size} packages scanned, ${findings.length} findings`);
  return findings;
}

function analyzeScript(script: string): string[] {
  const reasons: string[] = [];
  for (const { pattern, reason } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(script)) {
      reasons.push(reason);
    }
  }
  return reasons;
}

function resolvePackageJson(projectDir: string, packageName: string): string | null {
  // Try standard node_modules path
  const direct = join(projectDir, 'node_modules', packageName, 'package.json');
  if (existsSync(direct)) return direct;
  return null;
}
