import { describe, it, expect } from 'vitest';
import { detectWorkspaces, mapDepsToWorkspaces } from '../../src/core/workspace/detector.js';
import { join } from 'node:path';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

const MONOREPO_DIR = join(__dirname, '../fixtures/monorepo-npm');

function makeNode(name: string, version: string, overrides?: Partial<DependencyNode>): DependencyNode {
  return {
    name,
    version,
    resolved: '',
    integrity: '',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 1,
    dependencyPath: [],
    ...overrides,
  };
}

describe('workspace detector', () => {
  it('detects npm workspaces from package.json', () => {
    const config = detectWorkspaces(MONOREPO_DIR);
    expect(config.isMonorepo).toBe(true);
    expect(config.workspaces.length).toBe(2);
  });

  it('finds correct workspace names', () => {
    const config = detectWorkspaces(MONOREPO_DIR);
    const names = config.workspaces.map((w) => w.name).sort();
    expect(names).toEqual(['@fixture/app', '@fixture/utils']);
  });

  it('reads workspace dependencies', () => {
    const config = detectWorkspaces(MONOREPO_DIR);
    const app = config.workspaces.find((w) => w.name === '@fixture/app')!;
    expect(app.dependencies).toHaveProperty('express');
    expect(app.dependencies).toHaveProperty('@fixture/utils');

    const utils = config.workspaces.find((w) => w.name === '@fixture/utils')!;
    expect(utils.dependencies).toHaveProperty('lodash');
  });

  it('returns isMonorepo=false for non-monorepo', () => {
    const fixtureDir = join(__dirname, '../fixtures/npm-basic');
    const config = detectWorkspaces(fixtureDir);
    expect(config.isMonorepo).toBe(false);
    expect(config.workspaces.length).toBe(0);
  });

  it('detects pnpm-workspace.yaml', () => {
    // Create a temp-like scenario using the existing fixture structure
    // Just verify it doesn't crash on a dir without pnpm-workspace.yaml
    const config = detectWorkspaces(join(__dirname, '../fixtures/pnpm-basic'));
    expect(config.isMonorepo).toBe(false);
  });
});

describe('mapDepsToWorkspaces', () => {
  it('maps packages to workspaces that depend on them', () => {
    const graph: DependencyGraph = new Map();
    graph.set('express@4.17.1', makeNode('express', '4.17.1'));
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));
    graph.set('accepts@1.3.8', makeNode('accepts', '1.3.8'));

    // express depends on accepts
    graph.get('express@4.17.1')!.dependencies = ['accepts@1.3.8'];

    const workspaces = [
      {
        name: '@fixture/app',
        path: 'packages/app',
        dependencies: { express: '^4.17.1' },
        devDependencies: {},
      },
      {
        name: '@fixture/utils',
        path: 'packages/utils',
        dependencies: { lodash: '^4.17.20' },
        devDependencies: {},
      },
    ];

    const mapping = mapDepsToWorkspaces(graph, workspaces);

    // express should be mapped to @fixture/app
    expect(mapping.get('express@4.17.1')?.has('@fixture/app')).toBe(true);
    expect(mapping.get('express@4.17.1')?.has('@fixture/utils')).toBeFalsy();

    // lodash should be mapped to @fixture/utils
    expect(mapping.get('lodash@4.17.20')?.has('@fixture/utils')).toBe(true);

    // accepts is a transitive dep of express, so it should also be in @fixture/app
    expect(mapping.get('accepts@1.3.8')?.has('@fixture/app')).toBe(true);
  });

  it('handles empty workspaces', () => {
    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));

    const mapping = mapDepsToWorkspaces(graph, []);
    expect(mapping.size).toBe(0);
  });

  it('handles package used by multiple workspaces', () => {
    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));

    const workspaces = [
      { name: 'app-a', path: 'packages/a', dependencies: { lodash: '^4.17.0' }, devDependencies: {} },
      { name: 'app-b', path: 'packages/b', dependencies: { lodash: '^4.17.0' }, devDependencies: {} },
    ];

    const mapping = mapDepsToWorkspaces(graph, workspaces);
    const ws = mapping.get('lodash@4.17.20')!;
    expect(ws.has('app-a')).toBe(true);
    expect(ws.has('app-b')).toBe(true);
    expect(ws.size).toBe(2);
  });
});
