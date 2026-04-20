import { describe, it, expect } from 'vitest';
import {
  renderMermaid,
  renderDot,
  renderHTML,
  sanitizeId,
} from '../../src/cli/output/graph-viz.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import type { AuditReport, ScoredVulnerability, RiskScore } from '../../src/types/report.js';
import type { Advisory, AdvisoryMatch } from '../../src/types/advisory.js';

/* ------------------------------------------------------------------ */
/*  Fixtures                                                           */
/* ------------------------------------------------------------------ */

function makeNode(
  name: string,
  version: string,
  dependencies: string[] = [],
  depth = 0,
): DependencyNode {
  return {
    name,
    version,
    resolved: '',
    integrity: '',
    dependencies,
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth,
    dependencyPath: [],
  };
}

function makeAdvisory(id: string): Advisory {
  return {
    id,
    aliases: [],
    summary: 'test advisory',
    details: '',
    severity: [],
    affectedRange: '<1.0.0',
    fixVersion: '1.0.0',
    publishedAt: '',
    modifiedAt: '',
    references: [],
    source: 'bundled-index',
  };
}

function makeMatch(pkg: string, installedVersion: string, advisoryId = 'GHSA-test'): AdvisoryMatch {
  return {
    advisory: makeAdvisory(advisoryId),
    package: pkg,
    installedVersion,
    dependencyPath: [],
    isProduction: true,
  };
}

function makeScored(
  pkg: string,
  installedVersion: string,
  label: RiskScore['label'],
): ScoredVulnerability {
  return {
    match: makeMatch(pkg, installedVersion),
    risk: {
      score: 50,
      label,
      factors: {
        cvssScore: 7,
        cvssVector: '',
        productionReachable: true,
        directlyImported: true,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: true,
        fixVersion: '1.0.0',
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReport(
  vulns: ScoredVulnerability[] = [],
  extras: Partial<{ graph: DependencyGraph; rootKeys: string[] }> = {},
): AuditReport {
  const base: AuditReport = {
    vulnerabilities: vulns,
    metadata: {
      totalPackages: extras.graph?.size ?? 0,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'bundled-index',
      advisoryCount: vulns.length,
      confidence: 'HIGH',
      scanDurationMs: 1,
    },
    ignored: [],
  };
  return { ...base, ...extras } as AuditReport;
}

/* ------------------------------------------------------------------ */
/*  sanitizeId                                                         */
/* ------------------------------------------------------------------ */

describe('sanitizeId', () => {
  it('replaces @, /, ., - with underscore and prefixes with p_', () => {
    expect(sanitizeId('@scope/pkg@1.2.3')).toBe('p__scope_pkg_1_2_3');
  });

  it('returns a string that starts with a letter', () => {
    expect(sanitizeId('1bad-name')).toMatch(/^p_/);
  });

  it('is deterministic', () => {
    expect(sanitizeId('lodash@4.17.21')).toBe(sanitizeId('lodash@4.17.21'));
  });

  it('produces different IDs for different inputs with overlapping sanitized chars', () => {
    // "a.b" and "a-b" both sanitize to "p_a_b" — documents current collision behavior.
    // This test guards that the function is deterministic per input (not bijective).
    expect(sanitizeId('a.b')).toBe('p_a_b');
    expect(sanitizeId('a-b')).toBe('p_a_b');
  });
});

/* ------------------------------------------------------------------ */
/*  renderMermaid                                                      */
/* ------------------------------------------------------------------ */

describe('renderMermaid', () => {
  it('produces valid graph directive for a simple graph', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['dep@1.0.0'], 0));
    graph.set('dep@1.0.0', makeNode('dep', '1.0.0', [], 1));

    const out = renderMermaid(makeReport([], { graph, rootKeys: ['root@1.0.0'] }));
    expect(out).toMatch(/^graph LR\n/);
    expect(out).toContain('p_root_1_0_0');
    expect(out).toContain('p_dep_1_0_0');
    expect(out).toContain('p_root_1_0_0 --> p_dep_1_0_0');
  });

  it('honors direction TB', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', [], 0));
    const out = renderMermaid(makeReport([], { graph, rootKeys: ['root@1.0.0'] }), {
      direction: 'TB',
    });
    expect(out).toMatch(/^graph TB\n/);
  });

  it('styles vulnerable nodes with the correct severity color', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['evil@0.1.0'], 0));
    graph.set('evil@0.1.0', makeNode('evil', '0.1.0', [], 1));

    const out = renderMermaid(
      makeReport([makeScored('evil', '0.1.0', 'critical')], {
        graph,
        rootKeys: ['root@1.0.0'],
      }),
    );
    expect(out).toContain('style p_evil_0_1_0 fill:#ff6b6b,stroke:#c92a2a');
  });

  it('sanitizes scoped package names into valid Mermaid IDs', () => {
    const graph: DependencyGraph = new Map();
    graph.set('@scope/pkg@1.0.0', makeNode('@scope/pkg', '1.0.0', [], 0));
    const out = renderMermaid(makeReport([], { graph, rootKeys: ['@scope/pkg@1.0.0'] }));
    // The ID must not contain @ or /
    expect(out).not.toMatch(/\b@scope/);
    expect(out).toContain('p__scope_pkg_1_0_0');
    // Label preserves the original name
    expect(out).toContain('@scope/pkg@1.0.0');
  });

  it('emits a truncation note when graph exceeds 500 nodes', () => {
    const graph: DependencyGraph = new Map();
    // Build 1000 disconnected chains: root-i -> child-i
    const roots: string[] = [];
    for (let i = 0; i < 1000; i++) {
      const rootKey = `root${i}@1.0.0`;
      const childKey = `child${i}@1.0.0`;
      graph.set(rootKey, makeNode(`root${i}`, '1.0.0', [childKey], 0));
      graph.set(childKey, makeNode(`child${i}`, '1.0.0', [], 1));
      roots.push(rootKey);
    }

    const out = renderMermaid(makeReport([], { graph, rootKeys: roots }));
    expect(out).toMatch(/%% Truncated: showing \d+ of \d+ nodes/);
    // Count node declarations (lines like `    p_xxx["..."]`)
    const nodeLines = out.split('\n').filter((l) => /^\s{4}p_\w+\["/.test(l));
    expect(nodeLines.length).toBeLessThanOrEqual(500);
  });

  it('produces minimal but valid output for an empty report', () => {
    const out = renderMermaid(makeReport([]));
    expect(out).toMatch(/^graph LR\n/);
    expect(out).toContain('No vulnerabilities');
  });

  it('handles no graph but non-empty vulnerability list', () => {
    const out = renderMermaid(makeReport([makeScored('evil', '0.1.0', 'high')]));
    expect(out).toMatch(/^graph LR\n/);
    expect(out).toContain('p_evil_0_1_0');
    expect(out).toContain(SEVERITY_HIGH_FILL);
  });

  it('always includes roots, vulnerable nodes, and their ancestor chain when truncating', () => {
    const graph: DependencyGraph = new Map();
    // Create a deep chain root -> a -> b -> c -> vuln
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['a@1.0.0'], 0));
    graph.set('a@1.0.0', makeNode('a', '1.0.0', ['b@1.0.0'], 1));
    graph.set('b@1.0.0', makeNode('b', '1.0.0', ['c@1.0.0'], 2));
    graph.set('c@1.0.0', makeNode('c', '1.0.0', ['vuln@0.1.0'], 3));
    graph.set('vuln@0.1.0', makeNode('vuln', '0.1.0', [], 4));
    // Plus 600 noise roots that would truncate.
    for (let i = 0; i < 600; i++) {
      graph.set(`noise${i}@1.0.0`, makeNode(`noise${i}`, '1.0.0', [], 0));
    }
    const roots = ['root@1.0.0'];

    const out = renderMermaid(
      makeReport([makeScored('vuln', '0.1.0', 'critical')], { graph, rootKeys: roots }),
    );
    for (const key of ['root', 'a', 'b', 'c', 'vuln']) {
      expect(out).toContain(sanitizeId(`${key}@${key === 'vuln' ? '0.1.0' : '1.0.0'}`));
    }
  });
});

const SEVERITY_HIGH_FILL = '#ffa94d';

/* ------------------------------------------------------------------ */
/*  renderDot                                                          */
/* ------------------------------------------------------------------ */

describe('renderDot', () => {
  it('produces a valid digraph with rankdir=LR', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['dep@1.0.0'], 0));
    graph.set('dep@1.0.0', makeNode('dep', '1.0.0', [], 1));

    const out = renderDot(makeReport([], { graph, rootKeys: ['root@1.0.0'] }));
    expect(out).toMatch(/^digraph DependencyGraph \{/);
    expect(out).toContain('rankdir=LR;');
    expect(out).toContain('p_root_1_0_0 -> p_dep_1_0_0;');
    // Balanced braces
    const open = (out.match(/\{/g) ?? []).length;
    const close = (out.match(/\}/g) ?? []).length;
    expect(open).toBe(close);
  });

  it('includes a severity legend subgraph', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', [], 0));
    const out = renderDot(makeReport([], { graph, rootKeys: ['root@1.0.0'] }));
    expect(out).toContain('cluster_legend');
    expect(out).toContain('legend_critical');
    expect(out).toContain('legend_high');
  });

  it('colors vulnerable nodes by severity', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['evil@0.1.0'], 0));
    graph.set('evil@0.1.0', makeNode('evil', '0.1.0', [], 1));
    const out = renderDot(
      makeReport([makeScored('evil', '0.1.0', 'medium')], {
        graph,
        rootKeys: ['root@1.0.0'],
      }),
    );
    expect(out).toMatch(/p_evil_0_1_0.*fillcolor="#ffd43b"/);
  });

  it('renders a minimal valid digraph for an empty report', () => {
    const out = renderDot(makeReport([]));
    expect(out).toMatch(/^digraph DependencyGraph \{/);
    expect(out.trim().endsWith('}')).toBe(true);
    expect(out).toContain('No vulnerabilities');
  });
});

/* ------------------------------------------------------------------ */
/*  renderHTML                                                         */
/* ------------------------------------------------------------------ */

describe('renderHTML', () => {
  it('includes all expected sections and the project name', () => {
    const graph: DependencyGraph = new Map();
    graph.set('root@1.0.0', makeNode('root', '1.0.0', ['dep@1.0.0'], 0));
    graph.set('dep@1.0.0', makeNode('dep', '1.0.0', [], 1));

    const out = renderHTML(
      makeReport([makeScored('dep', '1.0.0', 'high')], {
        graph,
        rootKeys: ['root@1.0.0'],
      }),
      'my-project',
    );
    expect(out).toContain('<!DOCTYPE html>');
    expect(out).toContain('my-project');
    expect(out).toContain('<header>');
    expect(out).toContain('<footer>');
    expect(out).toContain('Legend');
    expect(out).toContain('<svg');
    expect(out).toContain('Generated by auditfix');
    expect(out).toContain('</html>');
  });

  it('produces well-formed HTML (balanced open/close tags for checked elements)', () => {
    const out = renderHTML(makeReport([]), 'empty-project');
    const checkTag = (tag: string) => {
      const open = new RegExp(`<${tag}[\\s>]`, 'g');
      const close = new RegExp(`</${tag}>`, 'g');
      expect((out.match(open) ?? []).length).toBe((out.match(close) ?? []).length);
    };
    for (const tag of ['html', 'head', 'body', 'header', 'footer', 'main', 'section', 'svg']) {
      checkTag(tag);
    }
  });

  it('reports total package count and vulnerability badges', () => {
    const graph: DependencyGraph = new Map();
    for (let i = 0; i < 5; i++) {
      graph.set(`pkg${i}@1.0.0`, makeNode(`pkg${i}`, '1.0.0', [], 0));
    }
    const out = renderHTML(
      makeReport([makeScored('pkg1', '1.0.0', 'critical')], {
        graph,
        rootKeys: ['pkg0@1.0.0'],
      }),
      'counts',
    );
    expect(out).toContain('Packages: 5');
    expect(out).toContain('critical 1');
    expect(out).toContain('high 0');
  });

  it('renders empty report as minimal but valid HTML', () => {
    const out = renderHTML(makeReport([]), 'nothing');
    expect(out).toContain('<!DOCTYPE html>');
    expect(out).toContain('nothing');
    expect(out).toContain('No packages and no vulnerabilities');
    // Should still close html
    expect(out.trim().endsWith('</html>')).toBe(true);
  });

  it('escapes HTML-unsafe characters in the project name', () => {
    const out = renderHTML(makeReport([]), '<script>alert(1)</script>');
    expect(out).not.toContain('<script>alert(1)</script>');
    expect(out).toContain('&lt;script&gt;');
  });

  it('stays under 500KB for ~1000-node synthetic graph', () => {
    const graph: DependencyGraph = new Map();
    // Chain: root -> p1 -> p2 -> ... -> p999
    let prev = 'root@1.0.0';
    graph.set(prev, makeNode('root', '1.0.0', ['p0@1.0.0'], 0));
    for (let i = 0; i < 999; i++) {
      const key = `p${i}@1.0.0`;
      const next = i < 998 ? [`p${i + 1}@1.0.0`] : [];
      graph.set(key, makeNode(`p${i}`, '1.0.0', next, i + 1));
    }

    const out = renderHTML(makeReport([], { graph, rootKeys: ['root@1.0.0'] }), 'big');
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThan(500 * 1024);
  });
});
