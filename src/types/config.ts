export type AuditfixConfig = {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  productionOnly: boolean;
  autoFix: boolean;
  ignoreDev: boolean;
  communityAllowList: boolean;
  maxAdvisoryStaleness: string;
  output: 'terminal' | 'json' | 'sarif';
  ci: {
    failOn: 'production-critical' | 'production-high' | 'any';
    sarifUpload: boolean;
  };
};

export const DEFAULT_CONFIG: AuditfixConfig = {
  severity: 'low',
  productionOnly: false,
  autoFix: false,
  ignoreDev: false,
  communityAllowList: false,
  maxAdvisoryStaleness: '7d',
  output: 'terminal',
  ci: {
    failOn: 'production-critical',
    sarifUpload: false,
  },
};
