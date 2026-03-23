/**
 * Policy engine types — YAML-based security policies with condition combinators.
 */

export type PolicyVersion = 1;

export type PolicyFile = {
  version: PolicyVersion;
  extends?: string[];
  settings?: PolicySettings;
  rules: PolicyRule[];
  overrides?: PolicyOverride[];
};

export type PolicySettings = {
  'enable-scans'?: ScanType[];
};

export type ScanType = 'licenses' | 'typosquats' | 'provenance' | 'behavior' | 'dep-age';

export type PolicyRule = {
  name: string;
  description?: string;
  match: PolicyMatch;
  action: PolicyAction;
  reason?: string;
  message?: string;
};

export type PolicyMatch = {
  all?: PolicyCondition[];
  any?: PolicyCondition[];
};

export type PolicyCondition =
  | { severity: SeverityLevel[] }
  | { scope: 'production' | 'dev' }
  | { epss: NumericComparison }
  | { kev: boolean }
  | { 'fix-available': boolean }
  | { license: string[] }
  | { provenance: boolean }
  | { behavior: string[] }
  | { 'dep-age': NumericComparison }
  | { typosquat: boolean }
  | { package: string[] }
  | { depth: NumericComparison }
  | { 'direct-dep': boolean };

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type NumericComparison = {
  gt?: number;
  gte?: number;
  lt?: number;
  lte?: number;
  eq?: number;
};

export type PolicyAction = 'fail' | 'warn' | 'notify' | 'auto-ignore';

export type PolicyOverride = {
  rule: string;
  action: PolicyAction;
  reason: string;
  expires?: string;
  'approved-by'?: string;
};

// --- Resolved types ---

export type ResolvedPolicy = {
  rules: ResolvedRule[];
  settings: PolicySettings;
  sources: string[];
};

export type ResolvedRule = PolicyRule & {
  source: string;
  overridden?: {
    originalAction: PolicyAction;
    reason: string;
    expires?: string;
  };
};

// --- Unified finding record ---

export type PolicyFinding = {
  id?: string;
  severity?: SeverityLevel;
  epss?: number;
  kev?: boolean;
  fixAvailable?: boolean;
  package: string;
  version: string;
  scope: 'production' | 'dev';
  depth: number;
  directDep: boolean;
  license?: string;
  provenance?: boolean;
  behaviors?: string[];
  depAgeMonths?: number;
  typosquat?: boolean;
  findingType: 'vulnerability' | 'license' | 'provenance' | 'behavior' | 'dep-age' | 'typosquat';
};

// --- Evaluation results ---

export type PolicyResult = {
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  autoIgnored: PolicyViolation[];
  passed: boolean;
  rulesEvaluated: number;
  findingsEvaluated: number;
};

export type PolicyViolation = {
  rule: ResolvedRule;
  finding: PolicyFinding;
  action: PolicyAction;
  message: string;
};
