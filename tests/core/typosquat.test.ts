import { describe, it, expect } from 'vitest';
import { detectTyposquats } from '../../src/core/scanner/typosquat.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

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

describe('typosquat detection', () => {
  it('detects 1-character difference from popular package', () => {
    const graph = makeGraph([{ name: 'lodasj' }]); // 1 char from lodash
    const findings = detectTyposquats(graph);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].similarTo).toBe('lodash');
    expect(findings[0].distance).toBe(1);
  });

  it('does not flag actual popular packages', () => {
    const graph = makeGraph([{ name: 'lodash' }, { name: 'express' }, { name: 'react' }]);
    const findings = detectTyposquats(graph);
    expect(findings).toHaveLength(0);
  });

  it('does not flag packages with very different names', () => {
    const graph = makeGraph([{ name: 'my-unique-package-xyz' }]);
    const findings = detectTyposquats(graph);
    expect(findings).toHaveLength(0);
  });

  it('detects common substitutions', () => {
    // 'rn' → 'm' substitution: 'charn' could be confused with 'charm'
    // Let's use a known case: 'co1ors' → 'colors' (1→l)
    const graph = makeGraph([{ name: 'co1ors' }]);
    const findings = detectTyposquats(graph);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].similarTo).toBe('colors');
  });

  it('preserves isProduction in findings', () => {
    const graph = makeGraph([{ name: 'lodasj', isProduction: false }]);
    const findings = detectTyposquats(graph);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].isProduction).toBe(false);
  });
});
