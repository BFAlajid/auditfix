/**
 * Policy evaluator — pure function that evaluates rules against findings.
 */
import type {
  ResolvedPolicy,
  ResolvedRule,
  PolicyFinding,
  PolicyResult,
  PolicyViolation,
  PolicyCondition,
  PolicyMatch,
  NumericComparison,
  SeverityLevel,
} from './types.js';

/**
 * Evaluate all policy rules against all findings.
 * Returns violations, warnings, auto-ignored findings, and overall pass/fail.
 */
export function evaluatePolicy(
  policy: ResolvedPolicy,
  findings: PolicyFinding[],
): PolicyResult {
  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];
  const autoIgnored: PolicyViolation[] = [];

  for (const finding of findings) {
    for (const rule of policy.rules) {
      if (!matchesRule(finding, rule.match)) continue;

      const violation: PolicyViolation = {
        rule,
        finding,
        action: rule.action,
        message:
          rule.message ??
          `${finding.package}@${finding.version}: policy "${rule.name}" triggered (${rule.action})`,
      };

      switch (rule.action) {
        case 'fail':
          violations.push(violation);
          break;
        case 'warn':
        case 'notify':
          warnings.push(violation);
          break;
        case 'auto-ignore':
          autoIgnored.push(violation);
          break;
      }

      // First matching rule wins for this finding
      break;
    }
  }

  return {
    violations,
    warnings,
    autoIgnored,
    passed: violations.length === 0,
    rulesEvaluated: policy.rules.length,
    findingsEvaluated: findings.length,
  };
}

function matchesRule(finding: PolicyFinding, match: PolicyMatch): boolean {
  const allMatch = match.all ? match.all.every((c) => matchCondition(finding, c)) : true;
  const anyMatch = match.any ? match.any.some((c) => matchCondition(finding, c)) : true;
  return allMatch && anyMatch;
}

function matchCondition(finding: PolicyFinding, condition: PolicyCondition): boolean {
  const key = Object.keys(condition)[0];
  const value = (condition as Record<string, unknown>)[key];

  switch (key) {
    case 'severity':
      return (
        finding.severity !== undefined &&
        (value as SeverityLevel[]).includes(finding.severity)
      );

    case 'scope':
      return finding.scope === value;

    case 'epss':
      return finding.epss !== undefined && matchNumeric(finding.epss, value as NumericComparison);

    case 'kev':
      return finding.kev === value;

    case 'fix-available':
      return finding.fixAvailable === value;

    case 'license':
      return finding.license !== undefined && (value as string[]).includes(finding.license);

    case 'provenance':
      return finding.provenance === value;

    case 'behavior':
      // ALL listed behaviors must be present
      return (
        finding.behaviors !== undefined &&
        (value as string[]).every((b) => finding.behaviors!.includes(b))
      );

    case 'dep-age':
      return (
        finding.depAgeMonths !== undefined &&
        matchNumeric(finding.depAgeMonths, value as NumericComparison)
      );

    case 'typosquat':
      return finding.typosquat === value;

    case 'package':
      return (value as string[]).some((pattern) => matchGlob(finding.package, pattern));

    case 'depth':
      return matchNumeric(finding.depth, value as NumericComparison);

    case 'direct-dep':
      return finding.directDep === value;

    default:
      // Unknown condition: treat as not matching (fail-closed)
      return false;
  }
}

function matchNumeric(actual: number, comparison: NumericComparison): boolean {
  if (comparison.gt !== undefined && !(actual > comparison.gt)) return false;
  if (comparison.gte !== undefined && !(actual >= comparison.gte)) return false;
  if (comparison.lt !== undefined && !(actual < comparison.lt)) return false;
  if (comparison.lte !== undefined && !(actual <= comparison.lte)) return false;
  if (comparison.eq !== undefined && actual !== comparison.eq) return false;
  return true;
}

function matchGlob(name: string, pattern: string): boolean {
  if (!pattern.includes('*')) return name === pattern;
  // Convert simple glob to regex: * -> [^/]*
  const regex = new RegExp(
    '^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$',
  );
  return regex.test(name);
}
