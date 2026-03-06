import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkDepAge } from '../../src/core/scanner/dep-age.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

function makeNode(name: string, version: string): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: true, isDev: false,
    isOptional: false, depth: 1, dependencyPath: [],
  };
}

describe('Dependency age checker', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('flags packages older than threshold', async () => {
    // Mock registry response with old modified date (3 years ago)
    const threeYearsAgo = new Date();
    threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      return new Response(JSON.stringify({ modified: threeYearsAgo.toISOString() }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const graph: DependencyGraph = new Map();
    graph.set('old-pkg@1.0.0', makeNode('old-pkg', '1.0.0'));

    const findings = await checkDepAge(graph);

    expect(findings).toHaveLength(1);
    expect(findings[0].package).toBe('old-pkg');
    expect(findings[0].ageMonths).toBeGreaterThanOrEqual(36);
  });

  it('does not flag recently updated packages', async () => {
    const recentDate = new Date();
    recentDate.setMonth(recentDate.getMonth() - 6); // 6 months ago

    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      return new Response(JSON.stringify({ modified: recentDate.toISOString() }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const graph: DependencyGraph = new Map();
    graph.set('fresh-pkg@2.0.0', makeNode('fresh-pkg', '2.0.0'));

    const findings = await checkDepAge(graph);

    expect(findings).toHaveLength(0);
  });

  it('handles fetch errors gracefully', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('ECONNREFUSED');
    });

    const graph: DependencyGraph = new Map();
    graph.set('pkg@1.0.0', makeNode('pkg', '1.0.0'));

    const findings = await checkDepAge(graph);

    expect(findings).toHaveLength(0); // Graceful failure
  });
});
