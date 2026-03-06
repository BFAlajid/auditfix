import type { AdvisoryMatch } from './advisory.js';

export type RiskScore = {
  score: number; // 0-100
  label: 'critical' | 'high' | 'medium' | 'low' | 'info';
  factors: {
    cvssScore: number;
    cvssVector: string;
    productionReachable: boolean;
    exploitAvailable: boolean;
    fixAvailable: boolean;
    fixVersion: string | null;
    depth: number;
    directDependency: boolean;
  };
};

export type ScoredVulnerability = {
  match: AdvisoryMatch;
  risk: RiskScore;
};

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNRELIABLE';

export type ScanMetadata = {
  totalPackages: number;
  skippedPackages: number;
  skippedReasons: { key: string; reason: string }[];
  advisorySource: string;
  advisoryCount: number;
  confidence: ConfidenceLevel;
  scanDurationMs: number;
  workspaceCount?: number;
};

export type AuditReport = {
  vulnerabilities: ScoredVulnerability[];
  metadata: ScanMetadata;
  ignored: IgnoredVulnerability[];
};

export type IgnoredVulnerability = {
  match: AdvisoryMatch;
  reason: string;
  source: 'local-allowlist' | 'community-allowlist';
};
