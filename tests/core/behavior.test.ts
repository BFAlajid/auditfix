import { describe, it, expect, vi } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

// Mock fs to avoid reading actual node_modules
vi.mock('node:fs', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:fs')>();
  return {
    ...original,
    existsSync: vi.fn((p: string) => {
      const norm = typeof p === 'string' ? p.replace(/\\/g, '/') : '';
      if (norm.includes('node_modules/evil-pkg')) return true;
      if (norm.includes('node_modules/safe-pkg')) return true;
      return false;
    }),
    readdirSync: vi.fn((dir: string) => {
      const norm = dir.replace(/\\/g, '/');
      if (norm.includes('evil-pkg')) return ['index.js'];
      if (norm.includes('safe-pkg')) return ['index.js'];
      return [];
    }),
    statSync: vi.fn((p: string) => ({
      isDirectory: () => !p.endsWith('.js'),
      isFile: () => p.endsWith('.js'),
      size: 100,
    })),
    readFileSync: vi.fn((p: string) => {
      const norm = p.replace(/\\/g, '/');
      if (norm.includes('evil-pkg')) {
        return `
          const cp = require('child_process');
          eval(Buffer.from('c2VjcmV0', 'base64').toString());
          process.env.SECRET_KEY;
        `;
      }
      if (norm.includes('safe-pkg')) {
        return `module.exports = function add(a, b) { return a + b; };`;
      }
      return '';
    }),
  };
});

const { scanBehavior } = await import('../../src/core/scanner/behavior.js');

function makeGraph(packages: Array<{ name: string; version?: string; isProduction?: boolean }>): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const pkg of packages) {
    const node: DependencyNode = {
      name: pkg.name,
      version: pkg.version ?? '1.0.0',
      isProduction: pkg.isProduction ?? true,
      dependencies: [],
      integrity: null,
      resolved: null,
    };
    graph.set(`${pkg.name}@${pkg.version ?? '1.0.0'}`, node);
  }
  return graph;
}

describe('behavioral analysis', () => {
  it('detects suspicious patterns in evil-pkg', () => {
    const graph = makeGraph([{ name: 'evil-pkg' }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const types = findings.flatMap(f => f.behaviors.map(b => b.type));
    expect(types).toContain('child_process');
    expect(types).toContain('eval');
  });

  it('finds nothing suspicious in safe-pkg', () => {
    const graph = makeGraph([{ name: 'safe-pkg' }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings).toHaveLength(0);
  });

  it('marks production flag correctly', () => {
    const graph = makeGraph([{ name: 'evil-pkg', isProduction: false }]);
    const findings = scanBehavior(graph, '/fake/project');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].isProduction).toBe(false);
  });
});
