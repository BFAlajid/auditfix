/**
 * Deep behavioral analysis of package source code.
 * Scans package source (not just install scripts) for suspicious patterns
 * like eval, child_process, network calls, env var harvesting, obfuscated code.
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { DependencyGraph } from '../../types/package.js';

export type BehaviorFinding = {
  package: string;
  version: string;
  file: string;
  behaviors: BehaviorFlag[];
  isProduction: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
};

export type BehaviorFlag = {
  type: string;
  description: string;
  line?: number;
};

const BEHAVIOR_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  description: string;
  risk: 'critical' | 'high' | 'medium' | 'low';
}> = [
  // Code execution
  { name: 'eval', pattern: /\beval\s*\(/g, description: 'Dynamic code execution via eval()', risk: 'critical' },
  { name: 'Function-constructor', pattern: /new\s+Function\s*\(/g, description: 'Dynamic code execution via Function constructor', risk: 'critical' },
  { name: 'child_process', pattern: /require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]/g, description: 'Child process spawning', risk: 'high' },
  { name: 'vm-module', pattern: /require\s*\(\s*['"]vm['"]\s*\)|from\s+['"]vm['"]/g, description: 'VM module (code sandbox escape risk)', risk: 'high' },

  // Network access
  { name: 'http-request', pattern: /require\s*\(\s*['"]https?['"]\s*\)|from\s+['"]https?['"]/g, description: 'HTTP/HTTPS module imported', risk: 'medium' },
  { name: 'fetch-call', pattern: /\bfetch\s*\(\s*[`'"]/g, description: 'Fetch API call with URL', risk: 'medium' },
  { name: 'dns-lookup', pattern: /require\s*\(\s*['"]dns['"]\s*\)|from\s+['"]dns['"]/g, description: 'DNS module (potential data exfiltration)', risk: 'high' },

  // Environment / secrets
  { name: 'env-access', pattern: /process\.env\[?\s*['"`](?!NODE_ENV|PATH|HOME|TERM)\w*['"` ]/g, description: 'Accesses specific environment variables', risk: 'medium' },
  { name: 'env-bulk', pattern: /process\.env(?!\[|\.\w)/g, description: 'Accesses entire process.env object', risk: 'high' },

  // Filesystem
  { name: 'fs-sensitive', pattern: /readFileSync\s*\(\s*['"`](?:\/etc\/|~\/\.|\.ssh|\.npmrc|\.env)/g, description: 'Reads sensitive filesystem paths', risk: 'critical' },
  { name: 'homedir', pattern: /os\.homedir\s*\(\)|require\s*\(\s*['"]os['"]\s*\).*homedir/g, description: 'Accesses user home directory', risk: 'medium' },

  // Obfuscation
  { name: 'hex-strings', pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/g, description: 'Long hex-encoded strings (potential obfuscation)', risk: 'high' },
  { name: 'base64-decode', pattern: /(?:atob|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]/g, description: 'Decodes long base64 string', risk: 'high' },
  { name: 'char-code', pattern: /String\.fromCharCode\s*\([^)]{20,}\)/g, description: 'String.fromCharCode with many characters (obfuscation)', risk: 'high' },

  // Supply chain attack patterns
  { name: 'ci-env-gate', pattern: /process\.env\.(?:CI|GITHUB_ACTIONS|GITLAB_CI|TRAVIS|JENKINS|CIRCLECI)\b/g, description: 'Checks for CI environment variables (potential conditional activation)', risk: 'medium' },
  { name: 'delayed-exec', pattern: /setTimeout\s*\([^,]+,\s*\d{5,}\)/g, description: 'Long delayed execution (>10s timer, potential evasion technique)', risk: 'high' },
  { name: 'crypto-mining', pattern: /stratum\+tcp|cryptonight|coinhive|monero|xmrig/gi, description: 'Cryptocurrency mining indicators', risk: 'critical' },
  { name: 'exfil-service', pattern: /webhook\.site|requestbin\.com|pipedream\.net|ngrok\.io|burpcollaborator/gi, description: 'Known data exfiltration service URL', risk: 'critical' },
  { name: 'credential-paths', pattern: /\.npmrc|\.ssh\/id_|authorized_keys|\.gnupg|\.aws\/credentials/g, description: 'References credential or key file paths', risk: 'critical' },
  { name: 'dynamic-url-exfil', pattern: /https?:\/\/[^'"]*\$\{?process\.env/g, description: 'Constructs URL using environment variable data', risk: 'critical' },
  { name: 'wasm-load', pattern: /WebAssembly\.(?:instantiate|compile|Instance)/g, description: 'WebAssembly loading (opaque binary execution)', risk: 'medium' },
  { name: 'geoip', pattern: /geoip|ip-api\.com|ipinfo\.io|maxmind|freegeoip/gi, description: 'IP geolocation lookup (potential geofenced payload)', risk: 'high' },
];

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);
const MAX_FILE_SIZE = 500_000; // 500KB
const MAX_FILES_PER_PACKAGE = 50;

/**
 * Scan package source code for suspicious behavioral patterns.
 */
export function scanBehavior(
  graph: DependencyGraph,
  projectDir: string,
): BehaviorFinding[] {
  const findings: BehaviorFinding[] = [];
  const checked = new Set<string>();

  for (const [, node] of graph) {
    if (checked.has(node.name)) continue;
    checked.add(node.name);

    const pkgDir = join(projectDir, 'node_modules', node.name);
    if (!existsSync(pkgDir)) continue;

    const pkgFindings = scanPackageDir(pkgDir, node.name, node.version, node.isProduction);
    findings.push(...pkgFindings);
  }

  // Sort by risk level
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  return findings;
}

function scanPackageDir(
  pkgDir: string,
  packageName: string,
  version: string,
  isProduction: boolean,
): BehaviorFinding[] {
  const findings: BehaviorFinding[] = [];
  const files = collectJsFiles(pkgDir, MAX_FILES_PER_PACKAGE);

  for (const filePath of files) {
    try {
      const stat = statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;

      const content = readFileSync(filePath, 'utf-8');
      const behaviors = analyzeContent(content);

      if (behaviors.length > 0) {
        const relativePath = filePath.replace(pkgDir, '').replace(/\\/g, '/');
        const highestRisk = behaviors.reduce((worst, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3 };
          const pattern = BEHAVIOR_PATTERNS.find(p => p.name === b.type);
          const risk = pattern?.risk ?? 'low';
          return order[risk] < order[worst] ? risk : worst;
        }, 'low' as BehaviorFinding['riskLevel']);

        findings.push({
          package: packageName,
          version,
          file: relativePath,
          behaviors,
          isProduction,
          riskLevel: highestRisk,
        });
      }
    } catch {
      // Skip unreadable files
    }
  }

  return findings;
}

function analyzeContent(content: string): BehaviorFlag[] {
  const flags: BehaviorFlag[] = [];
  const lines = content.split('\n');

  for (const bp of BEHAVIOR_PATTERNS) {
    bp.pattern.lastIndex = 0;
    let match;
    while ((match = bp.pattern.exec(content)) !== null) {
      // Find line number
      const beforeMatch = content.slice(0, match.index);
      const lineNum = beforeMatch.split('\n').length;

      flags.push({
        type: bp.name,
        description: bp.description,
        line: lineNum,
      });
      break; // One match per pattern per file is enough
    }
  }

  // Check for minified/obfuscated code (very long lines)
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 5000 && !lines[i].includes('sourceMappingURL')) {
      flags.push({
        type: 'minified-suspicious',
        description: 'Extremely long line (potential obfuscation/minification)',
        line: i + 1,
      });
      break;
    }
  }

  return flags;
}

function collectJsFiles(dir: string, maxFiles: number): string[] {
  const files: string[] = [];

  function walk(currentDir: string) {
    if (files.length >= maxFiles) return;
    try {
      const entries = readdirSync(currentDir);
      for (const entry of entries) {
        if (files.length >= maxFiles) return;
        if (entry === 'node_modules' || entry === '.git' || entry === 'test' || entry === 'tests' || entry === '__tests__') continue;

        const fullPath = join(currentDir, entry);
        try {
          const stat = statSync(fullPath);
          if (stat.isDirectory()) {
            walk(fullPath);
          } else if (stat.isFile() && JS_EXTENSIONS.has(extname(entry))) {
            files.push(fullPath);
          }
        } catch {
          // Skip
        }
      }
    } catch {
      // Skip
    }
  }

  walk(dir);
  return files;
}
