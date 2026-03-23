import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../../../src/core/policy/evaluator.js';
import type { ResolvedPolicy, PolicyFinding, ResolvedRule } from '../../../src/core/policy/types.js';

function makeRule(overrides: Partial<ResolvedRule> = {}): ResolvedRule {
  return {
    name: 'test-rule',
    match: { all: [{ severity: ['critical'] }] },
    action: 'fail',
    source: 'test',
    ...overrides,
  };
}

function makeFinding(overrides: Partial<PolicyFinding> = {}): PolicyFinding {
  return {
    id: 'GHSA-test',
    severity: 'critical',
    package: 'lodash',
    version: '4.17.20',
    scope: 'production',
    depth: 1,
    directDep: true,
    fixAvailable: true,
    kev: false,
    findingType: 'vulnerability',
    ...overrides,
  };
}

function makePolicy(rules: ResolvedRule[]): ResolvedPolicy {
  return { rules, settings: {}, sources: ['test'] };
}

describe('Policy evaluator', () => {
  it('matches severity condition', () => {
    const policy = makePolicy([makeRule({ match: { all: [{ severity: ['critical', 'high'] }] } })]);
    const result = evaluatePolicy(policy, [makeFinding({ severity: 'critical' })]);
    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);
  });

  it('does not match when severity is excluded', () => {
    const policy = makePolicy([makeRule({ match: { all: [{ severity: ['critical'] }] } })]);
    const result = evaluatePolicy(policy, [makeFinding({ severity: 'medium' })]);
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('matches scope condition', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ severity: ['critical'] }, { scope: 'production' }] } }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding({ scope: 'production' })]);
    expect(result.passed).toBe(false);
  });

  it('rejects when scope does not match', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ severity: ['critical'] }, { scope: 'production' }] } }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding({ scope: 'dev' })]);
    expect(result.passed).toBe(true);
  });

  it('matches all/any combinators', () => {
    const policy = makePolicy([
      makeRule({
        match: {
          all: [{ severity: ['critical', 'high'] }, { scope: 'production' }],
          any: [{ epss: { gte: 0.5 } }, { kev: true }],
        },
      }),
    ]);

    // Has high severity + production + kev=true -> match
    const r1 = evaluatePolicy(policy, [
      makeFinding({ severity: 'high', scope: 'production', kev: true, epss: 0.1 }),
    ]);
    expect(r1.passed).toBe(false);

    // Has high severity + production + epss=0.8 -> match via epss
    const r2 = evaluatePolicy(policy, [
      makeFinding({ severity: 'high', scope: 'production', epss: 0.8 }),
    ]);
    expect(r2.passed).toBe(false);

    // Has high severity + production but no kev/epss -> no match
    const r3 = evaluatePolicy(policy, [
      makeFinding({ severity: 'high', scope: 'production', kev: false, epss: 0.1 }),
    ]);
    expect(r3.passed).toBe(true);
  });

  it('matches numeric comparison (epss gte)', () => {
    const policy = makePolicy([makeRule({ match: { all: [{ epss: { gte: 0.5 } }] } })]);
    expect(evaluatePolicy(policy, [makeFinding({ epss: 0.7 })]).passed).toBe(false);
    expect(evaluatePolicy(policy, [makeFinding({ epss: 0.5 })]).passed).toBe(false);
    expect(evaluatePolicy(policy, [makeFinding({ epss: 0.3 })]).passed).toBe(true);
  });

  it('matches kev boolean', () => {
    const policy = makePolicy([makeRule({ match: { all: [{ kev: true }] } })]);
    expect(evaluatePolicy(policy, [makeFinding({ kev: true })]).passed).toBe(false);
    expect(evaluatePolicy(policy, [makeFinding({ kev: false })]).passed).toBe(true);
  });

  it('handles auto-ignore action', () => {
    const policy = makePolicy([
      makeRule({
        name: 'suppress-dev',
        action: 'auto-ignore',
        reason: 'dev only',
        match: { all: [{ scope: 'dev' }] },
      }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding({ scope: 'dev' })]);
    expect(result.passed).toBe(true);
    expect(result.autoIgnored).toHaveLength(1);
    expect(result.violations).toHaveLength(0);
  });

  it('handles warn action', () => {
    const policy = makePolicy([
      makeRule({ action: 'warn', match: { all: [{ severity: ['medium'] }] } }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding({ severity: 'medium' })]);
    expect(result.passed).toBe(true);
    expect(result.warnings).toHaveLength(1);
  });

  it('treats unknown conditions as not matching', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ 'future-condition': true } as unknown as import('../../../src/core/policy/types.js').PolicyCondition] } }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding()]);
    expect(result.passed).toBe(true);
  });

  it('matches package glob patterns', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ package: ['lodash', '@types/*'] }] } }),
    ]);
    expect(evaluatePolicy(policy, [makeFinding({ package: 'lodash' })]).passed).toBe(false);
    expect(evaluatePolicy(policy, [makeFinding({ package: '@types/node' })]).passed).toBe(false);
    expect(evaluatePolicy(policy, [makeFinding({ package: 'express' })]).passed).toBe(true);
  });

  it('matches behavior conditions (all behaviors must be present)', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ behavior: ['eval', 'http-request'] }] } }),
    ]);
    expect(
      evaluatePolicy(policy, [makeFinding({ behaviors: ['eval', 'http-request', 'env-access'] })]).passed,
    ).toBe(false);
    expect(
      evaluatePolicy(policy, [makeFinding({ behaviors: ['eval'] })]).passed,
    ).toBe(true); // missing http-request
  });

  it('first matching rule wins per finding', () => {
    const policy = makePolicy([
      makeRule({ name: 'warn-first', action: 'warn', match: { all: [{ severity: ['critical'] }] } }),
      makeRule({ name: 'fail-second', action: 'fail', match: { all: [{ severity: ['critical'] }] } }),
    ]);
    const result = evaluatePolicy(policy, [makeFinding({ severity: 'critical' })]);
    expect(result.passed).toBe(true); // warn, not fail
    expect(result.warnings).toHaveLength(1);
    expect(result.violations).toHaveLength(0);
  });

  it('reports correct counts', () => {
    const policy = makePolicy([
      makeRule({ match: { all: [{ severity: ['critical'] }] } }),
    ]);
    const findings = [
      makeFinding({ severity: 'critical', package: 'a' }),
      makeFinding({ severity: 'high', package: 'b' }),
      makeFinding({ severity: 'critical', package: 'c' }),
    ];
    const result = evaluatePolicy(policy, findings);
    expect(result.rulesEvaluated).toBe(1);
    expect(result.findingsEvaluated).toBe(3);
    expect(result.violations).toHaveLength(2);
  });
});
