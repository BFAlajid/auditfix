/**
 * Policy loader — find, parse, validate, and merge policy files.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve, sep } from 'node:path';
import { safeYamlParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';
import type {
  PolicyFile,
  PolicyRule,
  PolicyOverride,
  ResolvedPolicy,
  ResolvedRule,
  PolicySettings,
  PolicyAction,
  PolicyMatch,
  PolicyCondition,
} from './types.js';

/**
 * Truncate an error message for safe logging/re-throwing.
 *
 * YAML parse errors from js-yaml echo surrounding source lines, which leaks file
 * content when a malicious PR author tricks the loader into reading a secret file
 * (e.g. via an out-of-tree `extends:` path). Collapsing to a single line of 200 chars
 * strips the contextual snippet while keeping enough detail for debugging.
 */
function truncateErrorMessage(msg: string, max = 200): string {
  const singleLine = msg.replace(/[\r\n]+/g, ' ').trim();
  return singleLine.length > max ? singleLine.slice(0, max) + '...' : singleLine;
}

const POLICY_FILENAMES = ['.auditfix-policy.yml', '.auditfix-policy.yaml'];
const MAX_EXTENDS_DEPTH = 3;

/**
 * Load and resolve a policy file. Returns null if no policy file found.
 */
export async function loadPolicy(
  projectDir: string,
  policyPath?: string,
): Promise<ResolvedPolicy | null> {
  const filePath = policyPath
    ? resolve(policyPath)
    : findPolicyFile(projectDir);

  if (!filePath) return null;

  if (policyPath && !existsSync(filePath)) {
    throw new PolicyLoadError(`Policy file not found: ${filePath}`, filePath);
  }

  // Resolve the project root once up-front so `extends:` paths can be sandboxed.
  // Untrusted PR authors otherwise could point at /home/runner/.ssh/id_rsa etc.
  const projectRoot = resolve(projectDir);

  const policy = loadPolicyFile(filePath);
  const allRules: ResolvedRule[] = [];
  const sources: string[] = [];

  // Load extends chain (relative paths only for now)
  if (policy.extends) {
    await loadExtends(policy.extends, dirname(filePath), projectRoot, allRules, sources, 0);
  }

  // Add local rules (later rules win on name collision)
  for (const rule of policy.rules) {
    validateRule(rule);
    allRules.push({ ...rule, source: filePath });
  }
  sources.push(filePath);

  // Apply overrides
  const resolvedRules = applyOverrides(allRules, policy.overrides ?? []);

  return {
    rules: resolvedRules,
    settings: policy.settings ?? {},
    sources,
  };
}

function findPolicyFile(projectDir: string): string | null {
  for (const name of POLICY_FILENAMES) {
    const p = join(projectDir, name);
    if (existsSync(p)) return p;
  }
  return null;
}

function loadPolicyFile(filePath: string): PolicyFile {
  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? truncateErrorMessage(err.message) : '';
    throw new PolicyLoadError(
      msg ? `Cannot read policy file: ${filePath} (${msg})` : `Cannot read policy file: ${filePath}`,
      filePath,
    );
  }

  let parsed: unknown;
  try {
    // safeYamlParse uses js-yaml DEFAULT_SCHEMA (no !!js/function RCE) and strips
    // prototype-pollution keys at every depth before returning.
    parsed = safeYamlParse(raw);
  } catch (err) {
    // js-yaml error messages include multi-line source context — truncate to stop
    // the file contents (potentially a secret like ~/.ssh/id_rsa) leaking into logs.
    const msg = err instanceof Error ? truncateErrorMessage(err.message) : String(err);
    throw new PolicyLoadError(`YAML parse error in ${filePath}: ${msg}`, filePath);
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new PolicyLoadError(`Policy file is not a YAML object: ${filePath}`, filePath);
  }

  const doc = parsed as Record<string, unknown>;

  if (doc.version !== 1) {
    throw new PolicyLoadError(
      `Unsupported policy version: ${doc.version} (expected 1)`,
      filePath,
    );
  }

  if (!Array.isArray(doc.rules)) {
    throw new PolicyLoadError(`Policy file must have a "rules" array: ${filePath}`, filePath);
  }

  return doc as unknown as PolicyFile;
}

async function loadExtends(
  extendsList: string[],
  baseDir: string,
  projectRoot: string,
  allRules: ResolvedRule[],
  sources: string[],
  depth: number,
): Promise<void> {
  if (depth >= MAX_EXTENDS_DEPTH) {
    logger.warn(`Policy extends depth limit (${MAX_EXTENDS_DEPTH}) reached — skipping further extends`);
    return;
  }

  for (const ext of extendsList) {
    if (ext.startsWith('https://') || ext.startsWith('http://')) {
      logger.warn(`Remote policy extends not yet supported: ${ext}`);
      continue;
    }

    const extPath = resolve(baseDir, ext);

    // Sandbox: the resolved path MUST stay inside the project root. Tolerant skip
    // (warn + continue) rather than throwing, to match the existing extends policy.
    // Without this, a malicious PR author could set `extends: ["../../../etc/passwd"]`
    // and have the file contents surface via a YAML parse-error log line.
    if (!isInsideRoot(extPath, projectRoot)) {
      logger.warn(
        `Policy extends path escapes project root — skipping: ${ext}`,
      );
      continue;
    }

    if (!existsSync(extPath)) {
      logger.warn(`Extended policy file not found: ${extPath}`);
      continue;
    }

    if (sources.includes(extPath)) {
      logger.warn(`Circular policy extends detected: ${extPath}`);
      continue;
    }

    const extPolicy = loadPolicyFile(extPath);

    // Recurse into further extends
    if (extPolicy.extends) {
      await loadExtends(extPolicy.extends, dirname(extPath), projectRoot, allRules, sources, depth + 1);
    }

    for (const rule of extPolicy.rules) {
      validateRule(rule);
      allRules.push({ ...rule, source: extPath });
    }
    sources.push(extPath);
  }
}

/**
 * True iff `candidate` is the project root or a descendant of it.
 * Uses a trailing-separator check so `/proj` does not match `/proj-sibling`.
 */
function isInsideRoot(candidate: string, projectRoot: string): boolean {
  const normRoot = projectRoot.endsWith(sep) ? projectRoot : projectRoot + sep;
  return candidate === projectRoot || candidate.startsWith(normRoot);
}

function applyOverrides(
  rules: ResolvedRule[],
  overrides: PolicyOverride[],
): ResolvedRule[] {
  const overrideMap = new Map<string, PolicyOverride>();
  for (const o of overrides) {
    overrideMap.set(o.rule, o);
  }

  return rules.map((rule) => {
    const override = overrideMap.get(rule.name);
    if (!override) return rule;

    // Check expiry
    if (override.expires) {
      const expiryDate = new Date(override.expires);
      if (expiryDate < new Date()) {
        logger.warn(
          `Policy override for "${rule.name}" expired on ${override.expires} — using original action "${rule.action}"`,
        );
        return rule;
      }
    }

    return {
      ...rule,
      action: override.action,
      overridden: {
        originalAction: rule.action,
        reason: override.reason,
        expires: override.expires,
      },
    };
  });
}

const VALID_ACTIONS: PolicyAction[] = ['fail', 'warn', 'notify', 'auto-ignore'];
const RULE_NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

function validateRule(rule: PolicyRule): void {
  if (!rule.name || !RULE_NAME_RE.test(rule.name)) {
    throw new PolicyLoadError(
      `Invalid rule name "${rule.name}" — must be kebab-case (a-z, 0-9, hyphens)`,
      'validation',
    );
  }

  if (!VALID_ACTIONS.includes(rule.action)) {
    throw new PolicyLoadError(
      `Invalid action "${rule.action}" in rule "${rule.name}" — must be one of: ${VALID_ACTIONS.join(', ')}`,
      'validation',
    );
  }

  if (rule.action === 'auto-ignore' && !rule.reason) {
    throw new PolicyLoadError(
      `Rule "${rule.name}" with action "auto-ignore" must have a "reason" field`,
      'validation',
    );
  }

  if (!rule.match || (!rule.match.all && !rule.match.any)) {
    throw new PolicyLoadError(
      `Rule "${rule.name}" must have at least one "all" or "any" condition block`,
      'validation',
    );
  }
}

export class PolicyLoadError extends Error {
  constructor(
    message: string,
    public source: string,
  ) {
    super(message);
    this.name = 'PolicyLoadError';
  }
}
