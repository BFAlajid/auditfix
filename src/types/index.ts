export type {
  DependencyGraph,
  DependencyNode,
  LockfileType,
  LockfileParseResult,
  SkippedDependency,
} from './package.js';

export type {
  OsvEvent,
  OsvRange,
  OsvAffected,
  OsvSeverity,
  OsvVulnerability,
  OsvBatchQuery,
  OsvBatchResponse,
  Advisory,
  AdvisoryMatch,
} from './advisory.js';

export type {
  RiskScore,
  ScoredVulnerability,
  ConfidenceLevel,
  ScanMetadata,
  AuditReport,
  IgnoredVulnerability,
} from './report.js';

export type { AuditfixConfig } from './config.js';
export { DEFAULT_CONFIG } from './config.js';
