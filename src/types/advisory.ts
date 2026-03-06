export type OsvEvent = {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
};

export type OsvRange = {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  events: OsvEvent[];
};

export type OsvAffected = {
  package: {
    ecosystem: string;
    name: string;
  };
  ranges: OsvRange[];
  versions?: string[];
};

export type OsvSeverity = {
  type: 'CVSS_V3' | 'CVSS_V2';
  score: string; // CVSS vector string
};

export type OsvVulnerability = {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified: string;
  published?: string;
  affected: OsvAffected[];
  severity?: OsvSeverity[];
  references?: { type: string; url: string }[];
};

export type OsvBatchQuery = {
  queries: {
    version: string;
    package: {
      name: string;
      ecosystem: string;
    };
  }[];
};

export type OsvBatchResponse = {
  results: {
    vulns?: { id: string; modified: string }[];
  }[];
};

export type Advisory = {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  severity: OsvSeverity[];
  affectedRange: string; // converted semver range string
  fixVersion: string | null;
  publishedAt: string;
  modifiedAt: string;
  references: { type: string; url: string }[];
  source: 'osv-api' | 'bundled-index' | 'npm-bulk' | 'cache';
};

export type AdvisoryMatch = {
  advisory: Advisory;
  package: string;
  installedVersion: string;
  dependencyPath: string[];
  isProduction: boolean;
};
