/**
 * Policy loader — find, parse, validate, and merge policy files.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import yaml from 'js-yaml';
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

  const policy = loadPolicyFile(filePath);
  const allRules: ResolvedRule[] = [];
  const sources: string[] = [];

  // Load extends chain (relative paths only for now)
  if (policy.extends) {
    await loadExtends(policy.extends, dirname(filePath), allRules, sources, 0);
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
  } catch {
    throw new PolicyLoadError(`Cannot read policy file: ${filePath}`, filePath);
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
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
      await loadExtends(extPolicy.extends, dirname(extPath), allRules, sources, depth + 1);
    }

    for (const rule of extPolicy.rules) {
      validateRule(rule);
      allRules.push({ ...rule, source: extPath });
    }
    sources.push(extPath);
  }
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
