import { describe, it, expect } from 'vitest';
import { generateSbom } from '../../src/cli/output/sbom.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

function makeNode(name: string, version: string, overrides?: Partial<DependencyNode>): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: true, isDev: false,
    isOptional: false, depth: 1, dependencyPath: [],
    ...overrides,
  };
}

describe('CycloneDX SBOM generation', () => {
  it('generates valid CycloneDX 1.5 JSON', () => {
    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.21', makeNode('lodash', '4.17.21'));

    const sbom = JSON.parse(generateSbom(graph, '1.1.0', 'test-app'));

    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components).toHaveLength(1);
    expect(sbom.components[0].name).toBe('lodash');
    expect(sbom.components[0].purl).toBe('pkg:npm/lodash@4.17.21');
    expect(sbom.metadata.component.name).toBe('test-app');
  });

  it('handles scoped packages in purl', () => {
    const graph: DependencyGraph = new Map();
    graph.set('@babel/core@7.0.0', makeNode('@babel/core', '7.0.0'));

    const sbom = JSON.parse(generateSbom(graph, '1.1.0'));

    expect(sbom.components[0].purl).toBe('pkg:npm/%40babel/core@7.0.0');
  });

  it('marks dev dependencies as excluded scope', () => {
    const graph: DependencyGraph = new Map();
    graph.set('vitest@1.0.0', makeNode('vitest', '1.0.0', { isProduction: false, isDev: true }));

    const sbom = JSON.parse(generateSbom(graph, '1.1.0'));

    expect(sbom.components[0].scope).toBe('excluded');
  });

  it('includes dependency relationships', () => {
    const graph: DependencyGraph = new Map();
    graph.set('express@4.18.0', makeNode('express', '4.18.0', { dependencies: ['accepts@1.3.8'] }));
    graph.set('accepts@1.3.8', makeNode('accepts', '1.3.8'));

    const sbom = JSON.parse(generateSbom(graph, '1.1.0'));

    const expressDep = sbom.dependencies.find((d: { ref: string }) => d.ref.includes('express'));
    expect(expressDep.dependsOn).toHaveLength(1);
    expect(expressDep.dependsOn[0]).toContain('accepts');
  });
});
