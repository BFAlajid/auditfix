export type DependencyGraph = Map<string, DependencyNode>;

export type DependencyNode = {
  name: string;
  version: string;
  resolved: string;
  integrity: string;
  dependencies: string[]; // keys into the graph ("name@version")
  isProduction: boolean;
  isDev: boolean;
  isOptional: boolean;
  depth: number;
  dependencyPath: string[];
};

export type LockfileType =
  | 'npm-v1'
  | 'npm-v2'
  | 'npm-v3'
  | 'yarn-classic'
  | 'yarn-berry'
  | 'pnpm-v5'
  | 'pnpm-v6'
  | 'pnpm-v9'
  | 'bun'
  | 'deno';

export type LockfileParseResult = {
  type: LockfileType;
  graph: DependencyGraph;
  packageCount: number;
  skipped: SkippedDependency[];
};

export type SkippedDependency = {
  key: string;
  reason: 'local-file' | 'git-dep' | 'unparseable' | 'workspace';
};
